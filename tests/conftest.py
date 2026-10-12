import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

from iotguard.broker import BrokerProcess  # noqa: E402
from iotguard.connection import connect_blocking, make_client  # noqa: E402

needs_mosquitto = pytest.mark.skipif(shutil.which("mosquitto") is None,
                                     reason="mosquitto not installed")


@pytest.fixture(scope="session", autouse=True)
def identities():
    """Make sure certs + the dynsec seed exist before any hardened test runs."""
    if shutil.which("mosquitto") is None:
        return
    seed = REPO / "broker" / "dynsec" / "dynamic-security.json"
    if not seed.exists():
        subprocess.run([sys.executable, "-m", "broker.setup_identities"], cwd=REPO, check=True)


@pytest.fixture
def broker_a():
    with BrokerProcess("A") as b:
        yield b


@pytest.fixture
def broker_b():
    with BrokerProcess("B") as b:
        yield b


class Listener:
    """Subscribes and records (topic, payload) pairs it receives."""

    def __init__(self, target, identity, topic):
        self.messages: list[tuple[str, bytes]] = []
        self.lock = threading.Lock()
        self.client = make_client(target, identity)
        self.client.on_message = self._on_message
        subscribed = threading.Event()
        self.granted = None

        def on_subscribe(c, u, mid, reason_codes, props):
            self.granted = reason_codes
            subscribed.set()

        self.client.on_subscribe = on_subscribe
        self.connected = connect_blocking(self.client, target)
        if self.connected:
            self.client.subscribe(topic, qos=1)
            subscribed.wait(3)

    def _on_message(self, c, u, msg):
        with self.lock:
            self.messages.append((msg.topic, msg.payload))

    def wait_for(self, n=1, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if len(self.messages) >= n:
                    return True
            time.sleep(0.02)
        return False

    def close(self):
        self.client.disconnect()
        self.client.loop_stop()


@pytest.fixture
def listen():
    made = []

    def _make(target, identity, topic):
        lst = Listener(target, identity, topic)
        made.append(lst)
        return lst

    yield _make
    for lst in made:
        lst.close()


def publish_as(target, identity, topic, payload, password=None):
    """Connect as `identity`, publish once with QoS 1, disconnect. Returns connected?"""
    c = make_client(target, identity, password=password)
    if not connect_blocking(c, target):
        return False
    info = c.publish(topic, payload, qos=1)
    try:
        info.wait_for_publish(2)
    except Exception:
        pass
    time.sleep(0.1)
    c.disconnect()
    c.loop_stop()
    return True
