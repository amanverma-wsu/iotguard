"""Simulated smart-building devices and the authorized controller.

- TemperatureSensor publishes a reading on its own topic at a set rate. Each reading
  carries a `canary` marker: a unique test value that should never reach an
  unauthorized subscriber (that is how the unauthorized-reading scenario is scored).
- Door and Cooling apply commands they receive and publish their new state.
- Controller watches telemetry, switches cooling on/off by average temperature, and can
  send door commands and time the round trip (command -> state ack) in one process.
"""
from __future__ import annotations

import json
import random
import threading
import time
import uuid

from . import topics
from .connection import BrokerTarget, connect_blocking, make_client
from .events import EventLog


class Component:
    identity: str = "component"

    def __init__(self, target: BrokerTarget, log: EventLog, identity: str | None = None):
        self.target = target
        self.log = log
        if identity:
            self.identity = identity
        self.client = make_client(target, self.identity)
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect
        self.connected = False

    def subscriptions(self) -> list[str]:
        return []

    def start(self) -> bool:
        def on_connect(c, u, flags, rc, props):
            # also runs after paho auto-reconnects, so subscriptions come back
            for t in self.subscriptions():
                c.subscribe(t, qos=1)

        self.client.on_connect = on_connect
        self.connected = connect_blocking(self.client, self.target)
        if self.connected:
            for t in self.subscriptions():
                self.client.subscribe(t, qos=1)
        self.log.emit(self.identity, "connect", outcome="ok" if self.connected else "refused")
        return self.connected

    def stop(self) -> None:
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()

    def _on_disconnect(self, c, u, flags, rc, props):
        if rc.is_failure:
            self.log.emit(self.identity, "disconnect", outcome="dropped", reason=str(rc))

    def _on_message(self, c, u, msg):
        try:
            payload = json.loads(msg.payload)
        except (ValueError, UnicodeDecodeError):
            self.log.emit(self.identity, "bad_payload", msg.topic, "ignored")
            return
        self.handle(msg.topic, payload)

    def handle(self, topic: str, payload: dict) -> None:  # pragma: no cover - overridden
        pass


# ------------------------------------------------------------------------- sensors
class TemperatureSensor(Component):
    def __init__(self, target, log, sensor_id: str, *, rate_hz: float = 1.0, seed: int = 0,
                 base_temp: float = 22.0):
        super().__init__(target, log, identity=sensor_id)
        self.sensor_id = sensor_id
        self.topic = topics.telemetry_topic(sensor_id)
        self.rate_hz = rate_hz
        self.rng = random.Random(f"{seed}-{sensor_id}")
        self.temp = base_temp
        self.offset = 0.0  # tests/workloads can heat the room
        self.seq = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def reading(self) -> dict:
        self.seq += 1
        self.temp += self.rng.uniform(-0.2, 0.2)
        return {"sensor": self.sensor_id, "seq": self.seq, "ts": time.time(),
                "temp_c": round(self.temp + self.offset, 2),
                "canary": f"CONF-{self.log.run_id}-{self.sensor_id}-{self.seq}"}

    def publish_once(self) -> dict:
        r = self.reading()
        self.client.publish(self.topic, json.dumps(r), qos=0)
        self.log.emit(self.identity, "telemetry_sent", self.topic, seq=r["seq"], canary=r["canary"])
        return r

    def _run(self):
        while not self._stop.is_set():
            if self.rate_hz > 0:
                self.publish_once()
                self._stop.wait(1.0 / self.rate_hz)
            else:
                self._stop.wait(0.1)  # quiet period

    def start(self) -> bool:
        ok = super().start()
        if ok:
            self._thread = threading.Thread(target=self._run, daemon=True, name=self.sensor_id)
            self._thread.start()
        return ok

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(2)
        super().stop()


# ------------------------------------------------------------------------- actuators
class _Actuator(Component):
    cmd_topic = ""
    state_topic = ""
    valid: dict[str, str] = {}  # action -> resulting state

    def __init__(self, target, log, initial: str):
        super().__init__(target, log)
        self.state = initial
        self.history: list[dict] = []

    def subscriptions(self):
        return [self.cmd_topic]

    def handle(self, topic, payload):
        action = payload.get("action")
        if action not in self.valid:
            self.log.emit(self.identity, "command_rejected", topic, "invalid", action=str(action))
            return
        old, self.state = self.state, self.valid[action]
        cmd_id = payload.get("cmd_id")
        self.history.append({"ts": time.time(), "from": old, "to": self.state, "cmd_id": cmd_id})
        self.log.emit(
            self.identity, "command_applied", topic,
            "changed" if old != self.state else "unchanged",
            action=action, state=self.state, cmd_id=cmd_id,
        )
        self.client.publish(self.state_topic, json.dumps({"state": self.state, "cmd_id": cmd_id,
                                                          "ts": time.time()}), qos=1)


class Door(_Actuator):
    identity = "door"
    cmd_topic = topics.DOOR_CMD
    state_topic = topics.DOOR_STATE
    valid = {"lock": "locked", "unlock": "unlocked"}

    def __init__(self, target, log):
        super().__init__(target, log, "locked")


class Cooling(_Actuator):
    identity = "cooling"
    cmd_topic = topics.COOLING_CMD
    state_topic = topics.COOLING_STATE
    valid = {"on": "on", "off": "off"}

    def __init__(self, target, log):
        super().__init__(target, log, "off")


# ------------------------------------------------------------------------- controller
class Controller(Component):
    identity = "controller"

    def __init__(self, target, log, *, cool_on_above: float = 26.0, cool_off_below: float = 24.0):
        super().__init__(target, log)
        self.latest: dict[str, float] = {}
        self.cooling_on = False
        self.cool_on_above = cool_on_above
        self.cool_off_below = cool_off_below
        self.received = 0
        self._pending: dict[str, float] = {}
        self._acks: dict[str, threading.Event] = {}
        self.latencies: list[float] = []
        self._lock = threading.Lock()

    def subscriptions(self):
        return [topics.SENSOR_TELEMETRY_ALL, topics.DOOR_STATE, topics.COOLING_STATE]

    def handle(self, topic, payload):
        sensor = topics.sensor_from_topic(topic)
        if sensor is not None:
            # trust the topic (pinned by the ACL in B/C), not payload["sensor"]
            with self._lock:
                self.received += 1
                if isinstance(payload.get("temp_c"), (int, float)):
                    self.latest[sensor] = float(payload["temp_c"])
                avg = sum(self.latest.values()) / len(self.latest) if self.latest else None
            self.log.emit(
                self.identity, "telemetry_received", topic, sensor=sensor, seq=payload.get("seq")
            )
            if avg is not None:
                self._maybe_cool(avg)
            return
        if topic == topics.DOOR_STATE:
            cmd_id = payload.get("cmd_id")
            with self._lock:
                sent = self._pending.pop(cmd_id, None)
                ev = self._acks.get(cmd_id)
            if sent is not None:
                rtt = (time.perf_counter() - sent) * 1000
                self.latencies.append(rtt)
                self.log.emit(self.identity, "command_ack", topic, cmd_id=cmd_id, rtt_ms=rtt,
                              state=payload.get("state"))
                if ev:
                    ev.set()

    def _maybe_cool(self, avg: float):
        if not self.cooling_on and avg > self.cool_on_above:
            self.cooling_on = True
            self._send(topics.COOLING_CMD, "on")
        elif self.cooling_on and avg < self.cool_off_below:
            self.cooling_on = False
            self._send(topics.COOLING_CMD, "off")

    def _send(self, topic, action) -> str:
        cmd_id = uuid.uuid4().hex[:12]
        self.client.publish(
            topic, json.dumps({"action": action, "cmd_id": cmd_id, "ts": time.time()}), qos=1
        )
        self.log.emit(self.identity, "command_sent", topic, action=action, cmd_id=cmd_id)
        return cmd_id

    def door_command(self, action: str, timeout: float = 2.0) -> float | None:
        """Send a door command and wait for the door's state ack. Returns RTT in ms or
        None if no ack arrived (counts as a lost legitimate command)."""
        cmd_id = uuid.uuid4().hex[:12]
        ev = threading.Event()
        with self._lock:
            self._acks[cmd_id] = ev
            self._pending[cmd_id] = time.perf_counter()
        self.client.publish(topics.DOOR_CMD, json.dumps({"action": action, "cmd_id": cmd_id,
                                                         "ts": time.time()}), qos=1)
        self.log.emit(self.identity, "command_sent", topics.DOOR_CMD, action=action, cmd_id=cmd_id)
        got = ev.wait(timeout)
        with self._lock:
            self._acks.pop(cmd_id, None)
            if not got:
                self._pending.pop(cmd_id, None)
        if not got:
            self.log.emit(self.identity, "command_ack", topics.DOOR_CMD, "timeout", cmd_id=cmd_id)
            return None
        return self.latencies[-1]


# ------------------------------------------------------------------------- building
class Building:
    """Starts every legitimate device + the controller. Used by demos, tests and trials."""

    def __init__(
        self, target: BrokerTarget, log: EventLog, *,
        sensors: int = topics.DEFAULT_SENSOR_COUNT, rate_hz: float = 1.0, seed: int = 0,
    ):
        self.door = Door(target, log)
        self.cooling = Cooling(target, log)
        self.controller = Controller(target, log)
        self.sensors = [TemperatureSensor(target, log, sid, rate_hz=rate_hz, seed=seed)
                        for sid in topics.sensor_ids(sensors)]

    @property
    def components(self):
        return [self.door, self.cooling, self.controller, *self.sensors]

    def start(self) -> bool:
        ok = all([self.door.start(), self.cooling.start(), self.controller.start()])
        ok = all([s.start() for s in self.sensors]) and ok
        return ok

    def stop(self):
        for c in reversed(self.components):
            try:
                c.stop()
            except Exception:
                pass

    def __enter__(self):
        if not self.start():
            self.stop()
            raise RuntimeError("some building components failed to connect")
        return self

    def __exit__(self, *exc):
        self.stop()
