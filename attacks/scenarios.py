"""Test probes for the scenarios the project evaluates, starting with unauthorized reading.

Each probe runs ONLY against our own lab broker (loopback or the Docker service name) and
refuses anything else. They exist so the experiment can measure what each configuration
allows. Later phases add the unauthorized-command and flood probes to this file.

Probe kinds:
  "unknown" - a client with no valid login (anonymous in A; a bad login guess in B/C)
  "sensor"  - a real, logged-in sensor identity doing something outside its role
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from iotguard import topics
from iotguard.connection import BrokerTarget, connect_blocking, make_client
from iotguard.events import EventLog

LAB_HOSTS = {"127.0.0.1", "localhost", "::1", "mosquitto"}


def _assert_lab(target: BrokerTarget) -> None:
    if target.host not in LAB_HOSTS:
        raise RuntimeError(f"probes only run against the lab broker, not {target.host!r}")


@dataclass
class ProbeResult:
    scenario: str
    config: str
    connected: bool = False
    canaries_seen: int = 0          # confidential readings an unauthorized client saw
    notes: dict = field(default_factory=dict)


def unauthorized_read(target: BrokerTarget, log: EventLog, *, listen_seconds: float = 2.0,
                      as_identity: str | None = None) -> ProbeResult:
    """A client that should not see telemetry subscribes to every sensor topic and counts
    the confidential canary values it receives.

    as_identity=None  -> an unknown client (anonymous in A; rejected at login in B)
    as_identity="temp-2" -> a real sensor login whose ACL does not allow reading telemetry

    In config A this leaks; in config B the unknown client can't connect and a sensor
    identity can connect but can't subscribe to telemetry.
    """
    _assert_lab(target)
    res = ProbeResult("unauthorized_read", target.config)
    seen: list[int] = []
    client = make_client(target, as_identity)

    def on_message(c, u, msg):
        try:
            if "canary" in json.loads(msg.payload):
                seen.append(1)
        except (ValueError, UnicodeDecodeError):
            pass

    client.on_message = on_message
    res.connected = connect_blocking(client, target)
    log.emit(as_identity or "unknown", "probe_connect",
             outcome="ok" if res.connected else "refused", scenario=res.scenario)
    if res.connected:
        client.subscribe(topics.SENSOR_TELEMETRY_ALL, qos=1)
        time.sleep(listen_seconds)
        client.disconnect()
        client.loop_stop()
    res.canaries_seen = len(seen)
    log.emit(as_identity or "unknown", "probe_result", topics.SENSOR_TELEMETRY_ALL,
             "leaked" if res.canaries_seen else "blocked", scenario=res.scenario,
             canaries_seen=res.canaries_seen)
    return res
