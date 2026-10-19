"""Config C, part 1: rate detection.

The monitor subscribes to all telemetry and counts messages per sensor over a fixed
sliding window. A sensor is attributed by its topic (building/sensors/<id>/telemetry),
which the broker ACL pins to that identity in B/C, so the count cannot be dodged by lying
in the payload. When a sensor's rate over the window crosses the threshold, the monitor
records a detection and publishes an alert.

The threshold and window are set once (tuned on benign traffic, frozen before evaluation)
and passed in; the detector never changes them itself. Quarantine is added in Phase 4b.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from . import topics
from .connection import BrokerTarget, connect_blocking, make_client
from .events import EventLog


@dataclass(frozen=True)
class DetectorConfig:
    window_seconds: float = 1.0
    max_msgs_per_window: int = 30   # frozen after tuning on benign bursts


class RateDetector:
    def __init__(self, target: BrokerTarget, log: EventLog, config: DetectorConfig):
        self.target = target
        self.log = log
        self.cfg = config
        self.identity = "monitor"
        self.client = make_client(target, self.identity)
        self.client.on_message = self._on_message
        self._times: dict[str, deque[float]] = defaultdict(deque)
        self._flagged: set[str] = set()
        self.detected_at: dict[str, float] = {}
        self._lock = threading.Lock()
        self.connected = False

    def start(self) -> bool:
        subscribed = threading.Event()
        self.client.on_subscribe = lambda *a: subscribed.set()
        self.connected = connect_blocking(self.client, self.target)
        if self.connected:
            self.client.subscribe(topics.SENSOR_TELEMETRY_ALL, qos=0)
            subscribed.wait(3)
        return self.connected

    def stop(self) -> None:
        self.client.disconnect()
        self.client.loop_stop()

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
            self.detected_at[sensor] = now
        self.log.emit(self.identity, "detection", topics.telemetry_topic(sensor), "flood",
                      sensor=sensor, count_in_window=count,
                      threshold=self.cfg.max_msgs_per_window, window_s=self.cfg.window_seconds)
        self.client.publish(topics.ALERTS, json.dumps({"sensor": sensor, "reason": "rate",
                                                       "ts": time.time()}), qos=1)

    def is_flagged(self, sensor: str) -> bool:
        with self._lock:
            return sensor in self._flagged
