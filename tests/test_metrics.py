"""Metrics aggregation tests. These use a synthetic CSV, so they need no broker."""
from __future__ import annotations

from experiments import metrics
from experiments.trial import FIELDS


def _row(config, scenario, success, detail="", repeat=0):
    return {
        "run_id": "t", "config": config, "scenario": scenario, "repeat": str(repeat),
        "seed": "1", "connected": "True", "attack_success": str(success),
        "detail": detail, "ts": "0",
    }


def test_parse_detail():
    d = metrics.parse_detail("accepted=32 quarantined=True")
    assert d == {"accepted": "32", "quarantined": "True"}
    assert metrics.parse_detail("") == {}


def test_success_rates():
    rows = [
        _row("A", "unauthorized_read", True, "readings=146"),
        _row("A", "unauthorized_read", True, "readings=140", repeat=1),
        _row("B", "unauthorized_read", False, "readings=0"),
        _row("B", "unauthorized_read", False, "readings=0", repeat=1),
    ]
    s = metrics.summarize(rows)
    assert s["configs"]["A"]["unauthorized_read"]["success_rate"] == 1.0
    assert s["configs"]["B"]["unauthorized_read"]["success_rate"] == 0.0
    assert s["configs"]["A"]["unauthorized_read"]["n"] == 2


def test_flood_containment_C():
    rows = [
        _row("A", "flood", True, "accepted=300 quarantined=False"),
        _row("C", "flood", False, "accepted=32 quarantined=True"),
        _row("C", "flood", False, "accepted=30 quarantined=True", repeat=1),
    ]
    s = metrics.summarize(rows)
    fc = s["flood_containment_C"]
    assert fc["n"] == 2
    assert fc["containment_rate"] == 1.0
    assert fc["mean_accepted"] == 31.0


def test_write_summary(tmp_path):
    rows = [_row("C", "flood", False, "accepted=32 quarantined=True")]
    out = tmp_path / "metrics-test.csv"
    metrics.write_summary(out, metrics.summarize(rows))
    text = out.read_text()
    assert "config,scenario,n,attack_success_rate" in text
    assert "C,flood,1,0.0000" in text


def test_fields_unchanged():
    assert FIELDS[:3] == ["run_id", "config", "scenario"]
