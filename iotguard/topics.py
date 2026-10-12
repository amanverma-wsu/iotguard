"""Topic layout and device inventory shared by every component.

Each sensor publishes only on its own topic (building/sensors/<id>/telemetry). In the
hardened configs the broker ACL pins every identity to its own topic, so a message's
topic proves which authenticated identity sent it. The detector relies on that instead of
trusting any device name written inside the payload.
"""

ROOT = "building"

SENSOR_TELEMETRY = ROOT + "/sensors/{sensor_id}/telemetry"
SENSOR_TELEMETRY_ALL = ROOT + "/sensors/+/telemetry"
DOOR_CMD = ROOT + "/door/cmd"
DOOR_STATE = ROOT + "/door/state"
COOLING_CMD = ROOT + "/cooling/cmd"
COOLING_STATE = ROOT + "/cooling/state"
ALERTS = ROOT + "/alerts"
ALL = ROOT + "/#"

DEFAULT_SENSOR_COUNT = 5


def sensor_ids(count: int = DEFAULT_SENSOR_COUNT) -> list[str]:
    return [f"temp-{i}" for i in range(1, count + 1)]


def telemetry_topic(sensor_id: str) -> str:
    return SENSOR_TELEMETRY.format(sensor_id=sensor_id)


def sensor_from_topic(topic: str) -> str | None:
    """building/sensors/temp-3/telemetry -> 'temp-3'. None if it isn't a telemetry topic."""
    parts = topic.split("/")
    if len(parts) == 4 and parts[0] == ROOT and parts[1] == "sensors" and parts[3] == "telemetry":
        return parts[2]
    return None


def acl_for(identity: str) -> list[tuple[str, str]]:
    """(acltype, topic) pairs each identity is allowed. Used to build Dynamic Security
    roles. Anything not listed is denied (publish/subscribe default to deny)."""
    if identity.startswith("temp-"):
        return [("publishClientSend", telemetry_topic(identity))]
    table = {
        "door": [("subscribePattern", DOOR_CMD), ("publishClientSend", DOOR_STATE)],
        "cooling": [("subscribePattern", COOLING_CMD), ("publishClientSend", COOLING_STATE)],
        "controller": [
            ("subscribePattern", SENSOR_TELEMETRY_ALL),
            ("subscribePattern", DOOR_STATE),
            ("subscribePattern", COOLING_STATE),
            ("publishClientSend", DOOR_CMD),
            ("publishClientSend", COOLING_CMD),
        ],
        # the monitor watches everything and posts alerts; quarantine goes through the
        # separate admin identity
        "monitor": [("subscribePattern", ALL), ("publishClientSend", ALERTS)],
        "dashboard": [("subscribePattern", ALL)],
    }
    if identity not in table:
        raise KeyError(f"unknown identity {identity!r}")
    return table[identity]


def identities(sensor_count: int = DEFAULT_SENSOR_COUNT) -> list[str]:
    return sensor_ids(sensor_count) + ["door", "cooling", "controller", "monitor", "dashboard"]
