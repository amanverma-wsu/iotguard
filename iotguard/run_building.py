"""Run the simulated building against a broker that is already up.

    IOTGUARD_CONFIG=B python -m iotguard.run_building --seconds 60

Connection settings come from env (see BrokerTarget.from_env). Events go to
data/events-<run_id>.jsonl. Ctrl-C to stop early.
"""
from __future__ import annotations

import argparse
import time
import uuid
from pathlib import Path

from .connection import BrokerTarget
from .devices import Building
from .events import EventLog

DATA = Path(__file__).resolve().parents[1] / "data"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=0, help="0 = run until Ctrl-C")
    ap.add_argument("--sensors", type=int, default=5)
    ap.add_argument("--rate", type=float, default=1.0, help="telemetry per sensor per second")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--door-every", type=float, default=10.0, help="seconds between test door commands")
    args = ap.parse_args(argv)

    target = BrokerTarget.from_env()
    run_id = f"live-{uuid.uuid4().hex[:6]}"
    log = EventLog(DATA / f"events-{run_id}.jsonl", run_id=run_id, config=target.config)
    print(f"[{run_id}] config {target.config} -> {target.host}:{target.port}")
    start = time.monotonic()
    action = "unlock"
    try:
        with Building(target, log, sensors=args.sensors, rate_hz=args.rate, seed=args.seed) as b:
            next_door = time.monotonic() + args.door_every
            while not args.seconds or time.monotonic() - start < args.seconds:
                time.sleep(0.2)
                if time.monotonic() >= next_door:
                    rtt = b.controller.door_command(action)
                    print(f"door {action}: " + (f"{rtt:.1f} ms" if rtt else "no ack"))
                    action = "lock" if action == "unlock" else "unlock"
                    next_door += args.door_every
    except KeyboardInterrupt:
        pass
    finally:
        log.close()
    print(f"events -> {log.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
