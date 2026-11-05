"""Draw comparison graphs from a results CSV.

Produces two figures under figures/:
  attack-success-<run_id>.png   grouped bars: attack-success rate per scenario, per config
  flood-accepted-<run_id>.png   mean messages accepted during the flood, per config

    python -m experiments.plot                    # newest sweep in data/
    python -m experiments.plot data/results-run-abc123.csv
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .metrics import CONFIGS, SCENARIOS, latest_results, load, parse_detail, summarize  # noqa: E402

FIGURES = Path(__file__).resolve().parents[1] / "figures"
COLORS = {"A": "#C0392B", "B": "#2E86C1", "C": "#1E8449"}
LABELS = {"unauthorized_read": "unauth.\nread", "unauthorized_command": "unauth.\ncommand",
          "flood": "flood"}


def plot_success(summary: dict, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    width = 0.25
    xs = range(len(SCENARIOS))
    for i, config in enumerate(CONFIGS):
        vals = [summary["configs"][config][s]["success_rate"] for s in SCENARIOS]
        offs = [x + (i - 1) * width for x in xs]
        ax.bar(offs, vals, width, label=f"config {config}", color=COLORS[config])
    ax.set_xticks(list(xs))
    ax.set_xticklabels([LABELS[s] for s in SCENARIOS])
    ax.set_ylabel("attack-success rate")
    ax.set_ylim(0, 1.05)
    ax.set_title("Attack success by configuration")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_flood_accepted(rows: list[dict], path: Path) -> None:
    means = []
    for config in CONFIGS:
        accepted = [int(parse_detail(r["detail"]).get("accepted", 0))
                    for r in rows if r["config"] == config and r["scenario"] == "flood"]
        means.append(sum(accepted) / len(accepted) if accepted else 0.0)
    fig, ax = plt.subplots(figsize=(6, 4.5))
    ax.bar(CONFIGS, means, color=[COLORS[c] for c in CONFIGS])
    ax.set_ylabel("mean messages accepted")
    ax.set_xlabel("configuration")
    ax.set_title("Flood messages accepted before containment")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="?", help="results CSV (default: newest in data/)")
    args = ap.parse_args(argv)

    path = Path(args.results) if args.results else latest_results()
    rows = load(path)
    summary = summarize(rows)
    run_id = path.stem.replace("results-", "")
    FIGURES.mkdir(parents=True, exist_ok=True)

    f1 = FIGURES / f"attack-success-{run_id}.png"
    f2 = FIGURES / f"flood-accepted-{run_id}.png"
    plot_success(summary, f1)
    plot_flood_accepted(rows, f2)
    print(f"wrote {f1.name}, {f2.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
