"""Phase 4a: the rate detector flags a flooding sensor and leaves normal traffic alone."""
import time

from attacks import scenarios
from iotguard.detector import DetectorConfig, RateDetector
from iotguard.devices import Building
from iotguard.events import EventLog

from .conftest import needs_mosquitto

pytestmark = needs_mosquitto


def _wait(cond, timeout=4.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.03)
    return False


def test_detector_flags_a_flooding_sensor(broker_c):
    log = EventLog(None, config="C")
    cfg = DetectorConfig(window_seconds=1.0, max_msgs_per_window=30)
    with RateDetector(broker_c.target, log, cfg) as det:
        assert det.connected
        time.sleep(0.2)
        scenarios.flood(broker_c.target, log, as_identity="temp-1", rate_hz=200, seconds=1.5)
        assert _wait(lambda: det.is_flagged("temp-1"))
    assert log.of_type("detection")


def test_detector_ignores_normal_traffic(broker_c):
    log = EventLog(None, config="C")
    cfg = DetectorConfig(window_seconds=1.0, max_msgs_per_window=30)
    with RateDetector(broker_c.target, log, cfg) as det:
        with Building(broker_c.target, log, sensors=5, rate_hz=1):
            time.sleep(2.0)
        assert not any(det.is_flagged(f"temp-{i}") for i in range(1, 6))
