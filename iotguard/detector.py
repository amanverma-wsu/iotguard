"""Config C: rate detection with quarantine.

The monitor subscribes to all telemetry and counts messages per sensor over a fixed
sliding window, attributed by topic (which the broker ACL pins to the identity in B/C).
When a sensor crosses a frozen threshold, the monitor records a detection, raises an
alert, and - when quarantine is enabled - disables the device through the broker's
Dynamic Security admin API, which drops its connection and blocks it from reconnecting.

The threshold and window are set once (tuned on benign traffic, frozen before
evaluation) and passed in; the detector never changes them itself.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from . import topics
from .connection import BrokerTarget, connect_blocking, make_client
from .dynsec import DynsecAdmin
from .events import EventLog


@dataclass(frozen=True)
class DetectorConfig:
    window_seconds: float = 1.0
    max_msgs_per_window: int = 30   # frozen after tuning on benign bursts
    quarantine: bool = True         # False = detection-only (alerts, no disable)


class RateDetector:
    def __init__(self, target: BrokerTarget, log: EventLog, config: DetectorConfig,
                 *, admin: DynsecAdmin | None = None):
        self.target = target
        self.log = log
        self.cfg = config
        self.identity = "monitor"
        self.client = make_client(target, self.identity)
        self.client.on_message = self._on_message
        self._times: dict[str, deque[float]] = defaultdict(deque)
        self._flagged: set[str] = set()
        self.detected_at: dict[str, float] = {}
        self.quarantined_at: dict[str, float] = {}
        self._lock = threading.Lock()
        self._owns_admin = admin is None
        self._admin = admin
        self.connected = False

    def start(self) -> bool:
        if self._owns_admin and self.cfg.quarantine:
            self._admin = DynsecAdmin(self.target).__enter__()
        subscribed = threading.Event()
        self.client.on_subscribe = lambda *a: subscribed.set()
        self.connected = connect_blocking(self.client, self.target)
        if self.connected:
            self.client.subscribe(topics.SENSOR_TELEMETRY_ALL, qos=0)
            subscribed.wait(3)
        return self.connected

    def stop(self) -> None:
        try:
            self.client.disconnect()
            self.client.loop_stop()
        finally:
            if self._owns_admin and self._admin is not None:
                self._admin.__exit__(None, None, None)
                self._admin = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def _on_message(self, c, u, msg):
        sensor = topics.sensor_from_topic(msg.topic)
        if sensor is not None:
            self._record(sensor, time.monotonic())

    def _record(self, sensor: str, now: float) -> None:
        with self._lock:
            if sensor in self._flagged:
                return
            q = self._times[sensor]
            q.append(now)
            cutoff = now - self.cfg.window_seconds
            while q and q[0] < cutoff:
                q.popleft()
            count = len(q)
            breached = count > self.cfg.max_msgs_per_window
        if breached:
            self._on_breach(sensor, count, now)

    def _on_breach(self, sensor: str, count: int, now: float) -> None:
        with self._lock:
            if sensor in self._flagged:
                return
            self._flagged.add(sensor)
            self.detected_at.setdefault(sensor, now)
        self.log.emit(self.identity, "detection", topics.telemetry_topic(sensor), "flood",
                      sensor=sensor, count_in_window=count,
                      threshold=self.cfg.max_msgs_per_window, window_s=self.cfg.window_seconds)
        self.client.publish(topics.ALERTS, json.dumps({"sensor": sensor, "reason": "rate",
                                                       "ts": time.time()}), qos=1)
        if self.cfg.quarantine and self._admin is not None:
            try:
                self._admin.disable_client(sensor)
                self.quarantined_at[sensor] = time.monotonic()
                self.log.emit(self.identity, "quarantine", topics.telemetry_topic(sensor),
                              "disabled", sensor=sensor)
            except Exception as e:
                self.log.emit(self.identity, "quarantine", topics.telemetry_topic(sensor),
                              "error", sensor=sensor, error=str(e))

    def is_flagged(self, sensor: str) -> bool:
        with self._lock:
            return sensor in self._flagged

    def is_quarantined(self, sensor: str) -> bool:
        with self._lock:
            return sensor in self.quarantined_at

    def containment_ms(self, sensor: str) -> float | None:
        if sensor in self.detected_at and sensor in self.quarantined_at:
            return (self.quarantined_at[sensor] - self.detected_at[sensor]) * 1000
        return None
