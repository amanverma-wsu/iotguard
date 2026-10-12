"""Phase 1: the three broker configs behave the way the proposal says, against a real
Mosquitto process."""
import dataclasses

from iotguard import topics
from iotguard.connection import connect_blocking, make_client
from iotguard.dynsec import DynsecAdmin

from .conftest import needs_mosquitto, publish_as

pytestmark = needs_mosquitto


# ---------------------------------------------------------------- config A (baseline)
def test_a_allows_anonymous_pub_sub(broker_a, listen):
    t = broker_a.target
    lst = listen(t, None, topics.SENSOR_TELEMETRY_ALL)
    assert lst.connected
    assert publish_as(t, None, topics.telemetry_topic("temp-1"), b"21.5")
    assert lst.wait_for(1)


def test_topic_helpers():
    assert topics.sensor_from_topic("building/sensors/temp-3/telemetry") == "temp-3"
    assert topics.sensor_from_topic("building/door/cmd") is None
    assert topics.acl_for("temp-2") == [("publishClientSend", "building/sensors/temp-2/telemetry")]


# ---------------------------------------------------------------- config B (hardened)
def test_b_rejects_anonymous(broker_b):
    c = make_client(broker_b.target, None)
    assert not connect_blocking(c, broker_b.target)


def test_b_rejects_wrong_password(broker_b):
    c = make_client(broker_b.target, "temp-1", password="not-the-password")
    assert not connect_blocking(c, broker_b.target)


def test_b_rejects_plaintext_client(broker_b):
    # same port, but the client skips TLS: the handshake fails, no session
    plain = dataclasses.replace(broker_b.target, config="A")
    c = make_client(plain, None)
    assert not connect_blocking(c, plain, timeout=2)


def test_b_valid_device_reaches_controller(broker_b, listen):
    t = broker_b.target
    lst = listen(t, "controller", topics.SENSOR_TELEMETRY_ALL)
    assert lst.connected
    assert publish_as(t, "temp-1", topics.telemetry_topic("temp-1"), b"22.0")
    assert lst.wait_for(1)


def test_b_sensor_cannot_publish_door_command(broker_b, listen):
    t = broker_b.target
    door = listen(t, "door", topics.DOOR_CMD)
    assert door.connected
    assert publish_as(t, "temp-1", topics.DOOR_CMD, b'{"action":"unlock"}')
    assert not door.wait_for(1, timeout=1.0)


def test_b_sensor_cannot_spoof_another_sensor_topic(broker_b, listen):
    t = broker_b.target
    lst = listen(t, "controller", topics.SENSOR_TELEMETRY_ALL)
    assert publish_as(t, "temp-1", topics.telemetry_topic("temp-2"), b"99.9")
    assert not lst.wait_for(1, timeout=1.0)


def test_b_sensor_cannot_subscribe_to_telemetry(broker_b, listen):
    t = broker_b.target
    spy = listen(t, "temp-2", topics.SENSOR_TELEMETRY_ALL)
    assert spy.connected
    assert publish_as(t, "temp-1", topics.telemetry_topic("temp-1"), b"22.0")
    assert not spy.wait_for(1, timeout=1.0)


def test_b_disable_client_blocks_login(broker_b):
    t = broker_b.target
    with DynsecAdmin(t) as admin:
        admin.disable_client("temp-3")
        assert admin.get_client("temp-3").get("disabled") is True
    assert not connect_blocking(make_client(t, "temp-3"), t)


def test_each_trial_starts_fresh(broker_b):
    """Quarantine in one broker run must not leak into the next run."""
    with DynsecAdmin(broker_b.target) as admin:
        admin.disable_client("temp-4")
    from iotguard.broker import BrokerProcess
    with BrokerProcess("B") as fresh:
        c = make_client(fresh.target, "temp-4")
        assert connect_blocking(c, fresh.target)
        c.disconnect()
        c.loop_stop()
