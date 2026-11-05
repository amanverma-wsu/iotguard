"""Aggregate a results CSV into per-configuration security metrics.

Reads a sweep written by experiments.run_trials and reports, for each
configuration and scenario, how often the attack succeeded. For the flood
scenario it also reports how often config C contained the attacker (quarantine)
and the mean number of messages the broker accepted before containment.

    python -m experiments.metrics                 # newest sweep in data/
    python -m experiments.metrics data/results-run-abc123.csv
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

from .trial import DATA, FIELDS

CONFIGS = ["A", "B", "C"]
SCENARIOS = ["unauthorized_read", "unauthorized_command", "flood"]


def latest_results() -> Path:
    runs = sorted(DATA.glob("results-*.csv"), key=lambda p: p.stat().st_mtime)
    if not runs:
        raise FileNotFoundError("no results-*.csv in data/; run experiments.run_trials first")
    return runs[-1]


def load(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    missing = set(FIELDS) - set(rows[0]) if rows else set(FIELDS)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")
    return rows


def parse_detail(detail: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in detail.split():
        if "=" in part:
            key, val = part.split("=", 1)
            out[key] = val
    return out


def _rate(flags: list[bool]) -> float:
    return sum(flags) / len(flags) if flags else 0.0


def summarize(rows: list[dict]) -> dict:
    """Return per-(config, scenario) success rates plus flood containment on C."""
    summary: dict = {"configs": {}, "n_trials": len(rows)}
    for config in CONFIGS:
        by_scenario: dict = {}
        for scenario in SCENARIOS:
            hits = [r["attack_success"] == "True"
                    for r in rows if r["config"] == config and r["scenario"] == scenario]
            by_scenario[scenario] = {"n": len(hits), "success_rate": _rate(hits)}
        summary["configs"][config] = by_scenario

    floods_c = [r for r in rows if r["config"] == "C" and r["scenario"] == "flood"]
    contained = [parse_detail(r["detail"]).get("quarantined") == "True" for r in floods_c]
    accepted = [int(parse_detail(r["detail"]).get("accepted", 0)) for r in floods_c]
    summary["flood_containment_C"] = {
        "n": len(floods_c),
        "containment_rate": _rate(contained),
        "mean_accepted": sum(accepted) / len(accepted) if accepted else 0.0,
    }
    return summary


def format_table(summary: dict) -> str:
    lines = [f"attack-success rate by configuration ({summary['n_trials']} trials)", ""]
    header = f"{'scenario':<24}" + "".join(f"{c:>10}" for c in CONFIGS)
    lines += [header, "-" * len(header)]
    for scenario in SCENARIOS:
        cells = ""
        for config in CONFIGS:
            s = summary["configs"][config][scenario]
            cells += f"{s['success_rate']:>9.0%} " if s["n"] else f"{'-':>10}"
        lines.append(f"{scenario:<24}{cells}")
    fc = summary["flood_containment_C"]
    if fc["n"]:
        lines += ["", f"config C flood containment: {fc['containment_rate']:.0%} "
                  f"({fc['n']} trials), mean {fc['mean_accepted']:.0f} msgs accepted "
                  f"before quarantine"]
    return "\n".join(lines)


def write_summary(path: Path, summary: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["config", "scenario", "n", "attack_success_rate"])
        for config in CONFIGS:
            for scenario in SCENARIOS:
                s = summary["configs"][config][scenario]
                w.writerow([config, scenario, s["n"], f"{s['success_rate']:.4f}"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="?", help="results CSV (default: newest in data/)")
    args = ap.parse_args(argv)

    path = Path(args.results) if args.results else latest_results()
    rows = load(path)
    summary = summarize(rows)
    print(format_table(summary))

    run_id = path.stem.replace("results-", "")
    out = DATA / f"metrics-{run_id}.csv"
    write_summary(out, summary)
    print(f"\nwrote {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
