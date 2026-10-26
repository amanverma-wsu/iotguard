"""Start a local Mosquitto broker for config A, B or C.

Each BrokerProcess runs in its own working directory. For B/C it copies the seeded
Dynamic Security file in fresh, so every trial starts with the same identities and no
leftover quarantines. That is how we "reset state between trials".
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from string import Template

from .connection import DEFAULT_CERTS, DEFAULT_CREDS, BrokerTarget, load_credentials

BROKER_DIR = Path(__file__).resolve().parents[1] / "broker"
DEFAULT_DYNSEC_SEED = BROKER_DIR / "dynsec" / "dynamic-security.json"

PLUGIN_CANDIDATES = [
    "/usr/lib/x86_64-linux-gnu/mosquitto_dynamic_security.so",
    "/usr/lib/aarch64-linux-gnu/mosquitto_dynamic_security.so",
    "/usr/lib/mosquitto_dynamic_security.so",
    "/usr/local/lib/mosquitto_dynamic_security.so",
    "/opt/homebrew/lib/mosquitto_dynamic_security.so",
    "/opt/homebrew/opt/mosquitto/lib/mosquitto_dynamic_security.so",
]


def find_plugin() -> str:
    env = os.environ.get("IOTGUARD_DYNSEC_PLUGIN")
    if env:
        return env
    for p in PLUGIN_CANDIDATES:
        if Path(p).exists():
            return p
    raise FileNotFoundError("mosquitto_dynamic_security.so not found; set IOTGUARD_DYNSEC_PLUGIN")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def render_config(config: str, port: int, workdir: Path, *, certs: Path = DEFAULT_CERTS,
                  dynsec_file: Path | None = None, bind: str = "127.0.0.1") -> str:
    if config == "A":
        text = Template((BROKER_DIR / "mosquitto-A.conf.template").read_text())
        out = text.substitute(PORT=port, BIND=bind)
    elif config in ("B", "C"):
        text = Template((BROKER_DIR / "mosquitto-hardened.conf.template").read_text())
        out = text.substitute(PORT=port, BIND=bind, CERTS=certs, DYNSEC_PLUGIN=find_plugin(),
                              DYNSEC_FILE=dynsec_file or workdir / "dynamic-security.json")
    else:
        raise ValueError(f"unknown config {config!r}")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        out += "\nuser root\n"  # don't drop privileges when tests run as root (CI/containers)
    return out


class BrokerProcess:
    def __init__(self, config: str, port: int | None = None, *,
                 dynsec_seed: Path = DEFAULT_DYNSEC_SEED, certs: Path = DEFAULT_CERTS,
                 credentials_file: Path = DEFAULT_CREDS):
        self.config = config.upper()
        self.port = port or free_port()
        self.dynsec_seed = dynsec_seed
        self.certs = certs
        self.credentials_file = credentials_file
        self.workdir = Path(tempfile.mkdtemp(prefix=f"iotguard-{self.config}-"))
        self.proc: subprocess.Popen | None = None

    @property
    def target(self) -> BrokerTarget:
        if self.config == "A":
            return BrokerTarget("A", "127.0.0.1", self.port)
        return BrokerTarget(self.config, "127.0.0.1", self.port, str(self.certs / "ca.crt"),
                            load_credentials(self.credentials_file))

    def start(self, timeout: float = 5.0) -> "BrokerProcess":
        dynsec_file = None
        if self.config in ("B", "C"):
            dynsec_file = self.workdir / "dynamic-security.json"
            shutil.copy(self.dynsec_seed, dynsec_file)
        conf = self.workdir / "mosquitto.conf"
        conf.write_text(render_config(self.config, self.port, self.workdir,
                                      certs=self.certs, dynsec_file=dynsec_file))
        self.log = open(self.workdir / "broker.log", "w")
        self.proc = subprocess.Popen(["mosquitto", "-c", str(conf)], stdout=self.log,
                                     stderr=subprocess.STDOUT)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"mosquitto exited:\n{(self.workdir / 'broker.log').read_text()}"
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return self
            except OSError:
                time.sleep(0.05)
        self.stop()
        raise RuntimeError("mosquitto did not start listening in time")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if getattr(self, "log", None):
            self.log.close()

    def cleanup(self) -> None:
        self.stop()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.cleanup()
