"""Result schema, CSV output, and run metadata for the experiment harness."""
from __future__ import annotations

import csv
import json
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"


@dataclass(frozen=True)
class TrialResult:
    run_id: str
    config: str
    scenario: str
    repeat: int
    seed: int
    connected: bool
    attack_success: bool
    detail: str
    ts: float


FIELDS = list(TrialResult.__annotations__.keys())


def write_results(path: Path, rows: list[TrialResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))


def write_metadata(path: Path, run_id: str, seed: int, started: float,
                   finished: float, n_trials: int) -> None:
    meta = {
        "run_id": run_id,
        "seed": seed,
        "started": started,
        "finished": finished,
        "n_trials": n_trials,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, indent=2))
