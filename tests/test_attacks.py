"""Phase 3a: the unauthorized-read scenario leaks on baseline A and is blocked on B."""
import pytest

from attacks import scenarios
from iotguard.connection import BrokerTarget
from iotguard.devices import Building
from iotguard.events import EventLog

from .conftest import needs_mosquitto

pytestmark = needs_mosquitto


def test_probes_refuse_non_lab_host():
    with pytest.raises(RuntimeError):
        scenarios.unauthorized_read(BrokerTarget("A", host="example.com"), EventLog(None))


def test_unauthorized_read_leaks_on_A(broker_a):
    log = EventLog(None, config="A")
    with Building(broker_a.target, log, sensors=3, rate_hz=20):
        res = scenarios.unauthorized_read(broker_a.target, log, listen_seconds=1.0)
    assert res.connected and res.canaries_seen > 0


def test_unknown_reader_cannot_connect_on_B(broker_b):
    log = EventLog(None, config="B")
    with Building(broker_b.target, log, sensors=3, rate_hz=20):
        res = scenarios.unauthorized_read(broker_b.target, log, listen_seconds=1.0)
    assert not res.connected and res.canaries_seen == 0


def test_sensor_identity_cannot_read_telemetry_on_B(broker_b):
    # a real sensor login connects, but its ACL forbids subscribing to telemetry
    log = EventLog(None, config="B")
    with Building(broker_b.target, log, sensors=3, rate_hz=20):
        res = scenarios.unauthorized_read(broker_b.target, log, listen_seconds=1.0, as_identity="temp-2")
    assert res.connected and res.canaries_seen == 0
def test_unauthorized_command_opens_door_on_A(broker_a):
    log = EventLog(None, config="A")
    with Building(broker_a.target, log, sensors=1, rate_hz=5):
        res = scenarios.unauthorized_command(broker_a.target, log, action="unlock")
    assert res.state_changed


def test_sensor_cannot_command_door_on_B(broker_b):
    log = EventLog(None, config="B")
    with Building(broker_b.target, log, sensors=1, rate_hz=5):
        res = scenarios.unauthorized_command(broker_b.target, log, as_identity="temp-1", action="unlock")
    assert not res.state_changed


def test_unknown_cannot_command_door_on_B(broker_b):
    log = EventLog(None, config="B")
    with Building(broker_b.target, log, sensors=1, rate_hz=5):
        res = scenarios.unauthorized_command(broker_b.target, log, action="unlock")
    assert not res.connected and not res.state_changed
