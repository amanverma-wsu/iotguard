"""Milestone 2 live demo: the two attacks under the insecure and secured brokers."""
import time

from attacks import scenarios
from iotguard.broker import BrokerProcess
from iotguard.devices import Building
from iotguard.events import EventLog


def run(config: str) -> None:
    label = "insecure baseline" if config == "A" else "secured broker"
    print(f"\n=== Config {config}  ({label}) ===")
    with BrokerProcess(config) as b:
        log = EventLog(None, config=config)
        with Building(b.target, log, sensors=5, rate_hz=20):
            time.sleep(0.3)
            r = scenarios.unauthorized_read(b.target, log, listen_seconds=2.0)
            c = scenarios.unauthorized_command(b.target, log, action="unlock")

    if r.canaries_seen:
        read_line = f"{r.canaries_seen} confidential readings captured"
    elif not r.connected:
        read_line = "0 readings (login refused)"
    else:
        read_line = "0 readings (blocked by permissions)"
    cmd_line = "DOOR OPENED" if c.state_changed else "BLOCKED (door stayed locked)"

    print(f"  Unauthorized read          : {read_line}")
    print(f"  Unauthorized door command  : {cmd_line}")


if __name__ == "__main__":
    run("A")
    run("B")
    print()
