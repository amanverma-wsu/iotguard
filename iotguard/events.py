"""Shared event log. Every component writes the same fields so results line up:

    run_id, config, ts, client, event_type, topic, outcome, + optional extra fields

`client` is the identity the component itself runs as (its broker login in B/C). We never
fill it from a device name written inside a received payload.
JSON Lines on disk; experiments/analysis loads it into pandas/SQLite later.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path


class EventLog:
    def __init__(self, path: Path | str | None, run_id: str = "dev", config: str = "A"):
        self.path = Path(path) if path else None
        self.run_id = run_id
        self.config = config
        self._lock = threading.Lock()
        self._fh = None
        self.memory: list[dict] = []  # handy for tests and the live harness
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "a", buffering=1)

    def emit(
        self, client: str, event_type: str, topic: str = "", outcome: str = "ok", **extra
    ) -> dict:
        ev = {"run_id": self.run_id, "config": self.config, "ts": time.time(), "client": client,
              "event_type": event_type, "topic": topic, "outcome": outcome, **extra}
        with self._lock:
            self.memory.append(ev)
            if self._fh:
                self._fh.write(json.dumps(ev) + "\n")
        return ev

    def of_type(self, event_type: str) -> list[dict]:
        with self._lock:
            return [e for e in self.memory if e["event_type"] == event_type]

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def read_events(path: Path | str) -> list[dict]:
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]
