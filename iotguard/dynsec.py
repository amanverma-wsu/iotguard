"""Small client for Mosquitto's Dynamic Security plugin.

Commands go to $CONTROL/dynamic-security/v1 and answers come back on .../response. Only
the admin identity has access to these topics. We use this for setup (creating roles and
clients) and for quarantine (disableClient, which also kicks any live connection and
blocks the identity from logging back in).
"""
from __future__ import annotations

import json
import threading
import time

from .connection import BrokerTarget, connect_blocking, make_client

CONTROL = "$CONTROL/dynamic-security/v1"
RESPONSE = CONTROL + "/response"


class DynsecError(RuntimeError):
    pass


class DynsecAdmin:
    def __init__(self, target: BrokerTarget, username: str = "admin", password: str | None = None):
        self.target = target
        pw = password if password is not None else target.credentials.get(username)
        self.client = make_client(target, username, password=pw)
        self._lock = threading.Lock()
        self._responses: list[dict] = []
        self._cond = threading.Condition()
        self.client.on_message = self._on_message

    def __enter__(self):
        if not connect_blocking(self.client, self.target):
            raise DynsecError("admin could not connect to broker")
        subscribed = threading.Event()
        self.client.on_subscribe = lambda *a: subscribed.set()
        self.client.subscribe(RESPONSE, qos=1)
        subscribed.wait(5)
        return self

    def __exit__(self, *exc):
        self.client.disconnect()
        self.client.loop_stop()

    def _on_message(self, client, userdata, msg):
        with self._cond:
            self._responses.extend(json.loads(msg.payload).get("responses", []))
            self._cond.notify_all()

    def run(self, *commands: dict, timeout: float = 5.0) -> list[dict]:
        """Send commands in one batch and wait for every response. Raises on any error."""
        with self._lock:
            with self._cond:
                self._responses.clear()
            self.client.publish(CONTROL, json.dumps({"commands": list(commands)}), qos=1)
            deadline = time.monotonic() + timeout
            with self._cond:
                while len(self._responses) < len(commands):
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise DynsecError(f"timed out waiting for dynsec responses to {commands}")
                    self._cond.wait(left)
                out = list(self._responses)
        errors = [r for r in out if r.get("error")]
        if errors:
            raise DynsecError(str(errors))
        return out

    # --- helpers used by setup and quarantine ---------------------------------------
    def create_role(self, role: str, acls: list[tuple[str, str]]) -> None:
        self.run({
            "command": "createRole",
            "rolename": role,
            "acls": [{"acltype": t, "topic": topic, "allow": True, "priority": 0} for t, topic in acls],
        })

    def create_client(self, username: str, password: str, role: str) -> None:
        self.run({
            "command": "createClient",
            "username": username,
            "password": password,
            "roles": [{"rolename": role}],
        })

    def disable_client(self, username: str) -> None:
        self.run({"command": "disableClient", "username": username})

    def enable_client(self, username: str) -> None:
        self.run({"command": "enableClient", "username": username})

    def get_client(self, username: str) -> dict:
        return self.run({"command": "getClient", "username": username})[0]["data"]["client"]
