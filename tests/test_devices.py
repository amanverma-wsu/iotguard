"""Phase 2: the building works normally under both the insecure and hardened configs."""
import time

import pytest

from iotguard.devices import Building
from iotguard.events import EventLog, read_events

from .conftest import needs_mosquitto

pytestmark = needs_mosquitto


def _wait(cond, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return False


@pytest.mark.parametrize("fixture", ["broker_a", "broker_b"])
def test_building_normal_operation(fixture, request, tmp_path):
    broker = request.getfixturevalue(fixture)
    log = EventLog(tmp_path / "events.jsonl", run_id="t1", config=broker.config)
    with Building(broker.target, log, sensors=3, rate_hz=10) as b:
        # telemetry flows to the controller from every sensor
        assert _wait(lambda: len(b.controller.latest) == 3)

        # a legit door command round-trips and changes state
        rtt = b.controller.door_command("unlock")
        assert rtt is not None and rtt < 1000
        assert b.door.state == "unlocked"
        assert b.controller.door_command("lock") is not None
        assert b.door.state == "locked"

        # heating the room makes the controller turn cooling on
        for s in b.sensors:
            s.offset = 10.0
        assert _wait(lambda: b.cooling.state == "on")
        for s in b.sensors:
            s.offset = -5.0
        assert _wait(lambda: b.cooling.state == "off")
    log.close()

    events = read_events(tmp_path / "events.jsonl")
    assert {"run_id", "config", "ts", "client", "event_type", "topic", "outcome"} <= set(events[0])
    types = {e["event_type"] for e in events}
    assert {"telemetry_sent", "telemetry_received", "command_sent", "command_ack", "command_applied"} <= types
    assert all(e["config"] == broker.config for e in events)


def test_invalid_command_is_rejected(broker_a, tmp_path):
    log = EventLog(None, config="A")
    with Building(broker_a.target, log, sensors=1, rate_hz=1) as b:
        b.controller.client.publish("building/door/cmd", '{"action":"explode"}', qos=1)
        assert _wait(lambda: log.of_type("command_rejected"))
        assert b.door.state == "locked"
