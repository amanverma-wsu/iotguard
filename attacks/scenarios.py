"""Test probes for the scenarios the project evaluates, starting with unauthorized reading.

Each probe runs ONLY against our own lab broker (loopback or the Docker service name) and
refuses anything else. They exist so the experiment can measure what each configuration
allows. Later phases add the unauthorized-command and flood probes to this file.

Probe kinds:
  "unknown" - a client with no valid login (anonymous in A; a bad login guess in B/C)
  "sensor"  - a real, logged-in sensor identity doing something outside its role
"""
from __future__ import annotations

import threading
import uuid
import json
import time
from dataclasses import dataclass, field

from iotguard import topics
from iotguard.connection import BrokerTarget, connect_blocking, make_client
from iotguard.events import EventLog

LAB_HOSTS = {"127.0.0.1", "localhost", "::1", "mosquitto"}
MAX_FLOOD_RATE = 2000      # messages/sec cap
MAX_FLOOD_SECONDS = 30     # duration cap

def _assert_lab(target: BrokerTarget) -> None:
    if target.host not in LAB_HOSTS:
        raise RuntimeError(f"probes only run against the lab broker, not {target.host!r}")

@dataclass
class ProbeResult:
    scenario: str
    config: str
    connected: bool = False
    canaries_seen: int = 0          # confidential readings an unauthorized client saw
    command_delivered: bool = False # the broker accepted the published command
    state_changed: bool = False     # the door actually changed state
    sent: int = 0                   # flood messages published
    accepted: int = 0               # flood messages the broker accepted
    notes: dict = field(default_factory=dict)

def flood(target: BrokerTarget, log: EventLog, *, as_identity: str = "temp-1", rate_hz: float = 200,
          seconds: float = 3.0) -> ProbeResult:
    """A valid sensor publishes telemetry far above its normal rate on its own topic. This
    is the one scenario a logged-in device can do in every config (it stays within its ACL),
    which is why config C adds rate detection. Capped in rate and duration for safety."""
    _assert_lab(target)
    rate_hz = min(rate_hz, MAX_FLOOD_RATE)
    seconds = min(seconds, MAX_FLOOD_SECONDS)
    res = ProbeResult("flood", target.config)
    topic = topics.telemetry_topic(as_identity)
    client = make_client(target, as_identity)
    res.connected = connect_blocking(client, target)
    log.emit(as_identity, "probe_connect", outcome="ok" if res.connected else "refused",
             scenario=res.scenario)
    if not res.connected:
        return res
    interval = 1.0 / rate_hz
    deadline = time.monotonic() + seconds
    next_t = time.monotonic()
    while time.monotonic() < deadline:
        payload = json.dumps({"sensor": as_identity, "seq": res.sent, "ts": time.time(),
                              "temp_c": 22.0, "flood": True})
        info = client.publish(topic, payload, qos=0)
        res.sent += 1
        if info.rc == 0:
            res.accepted += 1
        next_t += interval
        sleep = next_t - time.monotonic()
        if sleep > 0:
            time.sleep(sleep)
    client.disconnect()
    client.loop_stop()
    res.notes = {"rate_hz": rate_hz, "seconds": seconds}
    log.emit(as_identity, "probe_result", topic, "flooded", scenario=res.scenario,
             sent=res.sent, accepted=res.accepted)
    return res

def unauthorized_read(target: BrokerTarget, log: EventLog, *, listen_seconds: float = 2.0,
                      as_identity: str | None = None) -> ProbeResult:
    """A client that should not see telemetry subscribes to every sensor topic and counts
    the confidential canary values it receives.

    as_identity=None  -> an unknown client (anonymous in A; rejected at login in B)
    as_identity="temp-2" -> a real sensor login whose ACL does not allow reading telemetry

    In config A this leaks; in config B the unknown client can't connect and a sensor
    identity can connect but can't subscribe to telemetry.
    """
    _assert_lab(target)
    res = ProbeResult("unauthorized_read", target.config)
    seen: list[int] = []
    client = make_client(target, as_identity)

    def on_message(c, u, msg):
        try:
            if "canary" in json.loads(msg.payload):
                seen.append(1)
        except (ValueError, UnicodeDecodeError):
            pass

    client.on_message = on_message
    res.connected = connect_blocking(client, target)
    log.emit(as_identity or "unknown", "probe_connect",
             outcome="ok" if res.connected else "refused", scenario=res.scenario)
    if res.connected:
        client.subscribe(topics.SENSOR_TELEMETRY_ALL, qos=1)
        time.sleep(listen_seconds)
        client.disconnect()
        client.loop_stop()
    res.canaries_seen = len(seen)
    log.emit(as_identity or "unknown", "probe_result", topics.SENSOR_TELEMETRY_ALL,
             "leaked" if res.canaries_seen else "blocked", scenario=res.scenario,
             canaries_seen=res.canaries_seen)
    return res
def unauthorized_command(target: BrokerTarget, log: EventLog, *, as_identity: str | None = None,
                         action: str = "unlock", watch_seconds: float = 1.5) -> ProbeResult:
    """A client that is not the controller tries to publish a door command. We watch the
    door state topic to see whether the door actually changed.

    as_identity=None     -> an unknown client (anonymous in A; rejected at login in B)
    as_identity="temp-1" -> a real sensor identity whose ACL does not allow door commands

    In config A the door opens; in config B the ACL blocks a sensor or unknown client from
    publishing to the door command topic.
    """
    _assert_lab(target)
    res = ProbeResult("unauthorized_command", target.config)
    cmd_id = uuid.uuid4().hex[:12]
    acked = threading.Event()

    watcher_identity = None if target.config == "A" else "controller"
    watcher = make_client(target, watcher_identity)

    def on_message(c, u, msg):
        try:
            if json.loads(msg.payload).get("cmd_id") == cmd_id:
                res.state_changed = True
                acked.set()
        except (ValueError, UnicodeDecodeError):
            pass

    watcher.on_message = on_message
    if connect_blocking(watcher, target):
        watcher.subscribe(topics.DOOR_STATE, qos=1)
        time.sleep(0.2)

    attacker = make_client(target, as_identity)
    res.connected = connect_blocking(attacker, target)
    log.emit(as_identity or "unknown", "probe_connect",
             outcome="ok" if res.connected else "refused", scenario=res.scenario)
    if res.connected:
        info = attacker.publish(topics.DOOR_CMD, json.dumps({"action": action, "cmd_id": cmd_id,
                                                            "ts": time.time()}), qos=1)
        try:
            info.wait_for_publish(2)
        except Exception:
            pass
        res.command_delivered = info.rc == 0
        acked.wait(watch_seconds)
        attacker.disconnect()
        attacker.loop_stop()
    watcher.disconnect()
    watcher.loop_stop()
    log.emit(as_identity or "unknown", "probe_result", topics.DOOR_CMD,
             "door_changed" if res.state_changed else "blocked", scenario=res.scenario,
             state_changed=res.state_changed)
    return res
