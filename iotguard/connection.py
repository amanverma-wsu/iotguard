"""How every component connects to the broker.

A BrokerTarget says where the broker is and which config (A/B/C) it runs. In A there is
no TLS and no login. In B and C clients log in with their own identity over TLS.
"""
from __future__ import annotations

import json
import os
import ssl
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import paho.mqtt.client as mqtt

REPO = Path(__file__).resolve().parents[1]
DEFAULT_CERTS = REPO / "broker" / "certs"
DEFAULT_CREDS = REPO / "broker" / "dynsec" / "credentials.json"


@dataclass(frozen=True)
class BrokerTarget:
    config: str  # "A", "B" or "C"
    host: str = "127.0.0.1"
    port: int = 1883
    ca_file: str | None = None
    credentials: dict[str, str] = field(default_factory=dict, compare=False, hash=False)

    @property
    def hardened(self) -> bool:
        return self.config in ("B", "C")

    @classmethod
    def from_env(cls) -> "BrokerTarget":
        config = os.environ.get("IOTGUARD_CONFIG", "A").upper()
        hardened = config in ("B", "C")
        port = int(os.environ.get("IOTGUARD_PORT", "8883" if hardened else "1883"))
        ca = os.environ.get("IOTGUARD_CA", str(DEFAULT_CERTS / "ca.crt")) if hardened else None
        creds = (
            load_credentials(Path(os.environ.get("IOTGUARD_CREDS", DEFAULT_CREDS)))
            if hardened else {}
        )
        return cls(config, os.environ.get("IOTGUARD_HOST", "127.0.0.1"), port, ca, creds)


def load_credentials(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def make_client(
    target: BrokerTarget,
    identity: str | None,
    *,
    client_id: str | None = None,
    password: str | None = None,
) -> mqtt.Client:
    """Build (not connect) a paho client.

    identity=None means an unknown/anonymous client (used by the attack probes). In
    hardened configs a known identity logs in with its password from the credentials file
    unless an explicit password is passed (probes use that to try guesses).
    """
    cid = client_id or f"{identity or 'anon'}-{uuid.uuid4().hex[:6]}"
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, protocol=mqtt.MQTTv311)
    if target.hardened:
        if target.ca_file:
            client.tls_set(ca_certs=target.ca_file, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        if identity is not None:
            pw = password if password is not None else target.credentials.get(identity)
            client.username_pw_set(identity, pw)
    return client


def connect_blocking(client: mqtt.Client, target: BrokerTarget, timeout: float = 5.0) -> bool:
    """Connect and start the network loop. Returns True if the broker accepted us."""
    done = threading.Event()
    result = {"ok": False}
    prev = client.on_connect

    def on_connect(c, userdata, flags, reason_code, properties):
        result["ok"] = not reason_code.is_failure
        done.set()
        if prev and result["ok"]:
            prev(c, userdata, flags, reason_code, properties)

    client.on_connect = on_connect
    try:
        client.connect(target.host, target.port, keepalive=30)
    except (OSError, ssl.SSLError):
        return False
    client.loop_start()
    done.wait(timeout)
    if not result["ok"]:
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass
    else:
        client.on_connect = prev
    return result["ok"]
