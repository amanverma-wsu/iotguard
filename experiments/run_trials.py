"""Run the attack scenarios against each configuration, repeatedly, and record results.

Each trial starts a fresh broker (so quarantines and state never carry over) and uses a
seed, so the sweep is reproducible. Run order is randomized per repeat. Output goes to
data/results-<run_id>.csv and data/run_meta-<run_id>.json.

    python -m experiments.run_trials --repeats 10
"""
from __future__ import annotations

import argparse
import random
import time
import uuid

from attacks import scenarios
from iotguard.broker import BrokerProcess
from iotguard.detector import DetectorConfig, RateDetector
from iotguard.devices import Building
from iotguard.events import EventLog

from .trial import DATA, TrialResult, write_metadata, write_results

SCENARIOS = ["unauthorized_read", "unauthorized_command", "flood"]
CONFIGS = ["A", "B", "C"]


def run_one(run_id: str, config: str, scenario: str, repeat: int, seed: int) -> TrialResult:
    log = EventLog(None, config=config)
    connected = False
    success = False
    detail = ""
    with BrokerProcess(config) as b:
        t = b.target
        if scenario == "flood":
            det = None
            if config == "C":
                det = RateDetector(t, log, DetectorConfig(quarantine=True))
                det.start()
                time.sleep(0.2)
            res = scenarios.flood(t, log, as_identity="temp-1", rate_hz=200, seconds=1.5)
            connected = res.connected
            quarantined = False
            if det is not None:
                for _ in range(20):
                    if det.is_quarantined("temp-1"):
                        quarantined = True
                        break
                    time.sleep(0.05)
                det.stop()
            success = connected and not quarantined
            detail = f"accepted={res.accepted} quarantined={quarantined}"
        else:
            with Building(t, log, sensors=5, rate_hz=20, seed=seed):
                time.sleep(0.2)
                if scenario == "unauthorized_read":
                    res = scenarios.unauthorized_read(t, log, listen_seconds=1.5)
                    connected = res.connected
                    success = res.canaries_seen > 0
                    detail = f"readings={res.canaries_seen}"
                else:
                    res = scenarios.unauthorized_command(t, log, action="unlock")
                    connected = res.connected
                    success = res.state_changed
                    detail = f"door_changed={res.state_changed}"
    return TrialResult(run_id, config, scenario, repeat, seed, connected, success,
                       detail, time.time())


def run_sweep(repeats: int, seed: int) -> tuple[list[TrialResult], str, float, float]:
    run_id = f"run-{uuid.uuid4().hex[:6]}"
    rng = random.Random(seed)
    rows: list[TrialResult] = []
    started = time.time()
    for repeat in range(repeats):
        combos = [(c, s) for c in CONFIGS for s in SCENARIOS]
        rng.shuffle(combos)
        for config, scenario in combos:
            rows.append(run_one(run_id, config, scenario, repeat, seed + repeat))
    return rows, run_id, started, time.time()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args(argv)

    rows, run_id, started, finished = run_sweep(args.repeats, args.seed)
    results_path = DATA / f"results-{run_id}.csv"
    meta_path = DATA / f"run_meta-{run_id}.json"
    write_results(results_path, rows)
    write_metadata(meta_path, run_id, args.seed, started, finished, len(rows))

    ok = sum(1 for r in rows if r.attack_success)
    print(f"{len(rows)} trials, {ok} attacks succeeded -> {results_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
