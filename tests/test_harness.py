"""Phase 5: the trial runner records the expected attack outcomes per configuration."""
from experiments.run_trials import run_one
from experiments.trial import write_results

from .conftest import needs_mosquitto

pytestmark = needs_mosquitto


def test_read_succeeds_on_A():
    assert run_one("t", "A", "unauthorized_read", 0, 1).attack_success


def test_read_blocked_on_B():
    assert not run_one("t", "B", "unauthorized_read", 0, 1).attack_success


def test_flood_contained_on_C():
    assert not run_one("t", "C", "flood", 0, 1).attack_success


def test_results_write(tmp_path):
    rows = [run_one("t", "A", "unauthorized_command", 0, 1)]
    out = tmp_path / "r.csv"
    write_results(out, rows)
    text = out.read_text()
    assert "attack_success" in text and "unauthorized_command" in text
