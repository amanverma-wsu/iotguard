"""Dashboard logic tests. Pure functions, so no broker and no Streamlit needed."""
from __future__ import annotations

from dashboard.logic import comparison_frame, interpret
from experiments.metrics import summarize


def test_interpret_read_success():
    v = interpret("A", "unauthorized_read", "readings=146", True)
    assert v["tone"] == "bad"
    assert v["metric_value"] == "146"


def test_interpret_read_blocked():
    v = interpret("B", "unauthorized_read", "readings=0", False)
    assert v["tone"] == "good"
    assert v["metric_value"] == "0"


def test_interpret_command_opened():
    v = interpret("A", "unauthorized_command", "door_changed=True", True)
    assert v["tone"] == "bad"
    assert v["metric_value"] == "opened"


def test_interpret_flood_contained():
    v = interpret("C", "flood", "accepted=32 quarantined=True", False)
    assert v["tone"] == "contained"
    assert "quarantined" in v["detail"]
    assert v["metric_value"] == "32"


def test_interpret_flood_success():
    v = interpret("B", "flood", "accepted=300 quarantined=False", True)
    assert v["tone"] == "bad"


def test_comparison_frame_shape():
    rows = [
        {"run_id": "t", "config": "A", "scenario": "flood", "repeat": "0", "seed": "1",
         "connected": "True", "attack_success": "True",
         "detail": "accepted=300 quarantined=False", "ts": "0"},
        {"run_id": "t", "config": "C", "scenario": "flood", "repeat": "0", "seed": "1",
         "connected": "True", "attack_success": "False",
         "detail": "accepted=32 quarantined=True", "ts": "0"},
    ]
    frame = comparison_frame(summarize(rows))
    assert list(frame.columns) == ["A", "B", "C"]
    assert frame.loc["Message flood", "A"] == 1.0
    assert frame.loc["Message flood", "C"] == 0.0
