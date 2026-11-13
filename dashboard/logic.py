"""Pure helpers for the dashboard: no Streamlit here, so these are unit-tested.

interpret() turns a trial's raw detail string into a plain-language verdict, and
comparison_frame() reshapes the metrics summary for a grouped bar chart.
"""
from __future__ import annotations

import pandas as pd

from experiments.metrics import CONFIGS, SCENARIOS, parse_detail

CONFIG_BLURB = {
    "A": {"name": "insecure baseline", "desc": "Anonymous, plaintext MQTT. No auth, no TLS."},
    "B": {"name": "hardened", "desc": "Per-device logins, topic ACLs, and TLS."},
    "C": {"name": "hardened + detection", "desc": "Config B plus a rate detector that "
          "quarantines a flooding device."},
}

SCENARIO_LABEL = {
    "unauthorized_read": "Unauthorized read (eavesdrop on sensor data)",
    "unauthorized_command": "Unauthorized command (open a door)",
    "flood": "Message flood (denial of service)",
}


def interpret(config: str, scenario: str, detail: str, success: bool) -> dict:
    """Plain-language verdict for one trial, for the status card and metric."""
    d = parse_detail(detail)
    if scenario == "unauthorized_read":
        label, value = "Readings captured", d.get("readings", "0")
    elif scenario == "unauthorized_command":
        label, value = "Door state", "opened" if d.get("door_changed") == "True" else "unchanged"
    else:
        label, value = "Messages accepted", d.get("accepted", "0")

    if success:
        return {"tone": "bad", "headline": "Attack succeeded",
                "detail": "the broker let it through", "metric_label": label,
                "metric_value": value}
    if scenario == "flood" and d.get("quarantined") == "True":
        return {"tone": "contained", "headline": "Attack contained",
                "detail": "the detector quarantined the flooding device",
                "metric_label": label, "metric_value": value}
    return {"tone": "good", "headline": "Attack blocked",
            "detail": "the broker rejected it", "metric_label": label, "metric_value": value}


def comparison_frame(summary: dict) -> pd.DataFrame:
    """Rows = scenarios, columns = configs, values = attack-success rate."""
    data = {c: [summary["configs"][c][s]["success_rate"] for s in SCENARIOS] for c in CONFIGS}
    index = [SCENARIO_LABEL[s].split(" (")[0] for s in SCENARIOS]
    return pd.DataFrame(data, index=index)
