"""IoTGuard dashboard: run attacks against each configuration and see the result.

    streamlit run dashboard/app.py

Needs the broker identities in place first (python -m broker.setup_identities).
Each "Run attack" spins a fresh Mosquitto broker, so state never carries over.
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from dashboard.logic import CONFIG_BLURB, SCENARIO_LABEL, comparison_frame, interpret  # noqa: E402
from experiments.metrics import latest_results, load, summarize  # noqa: E402
from experiments.run_trials import run_one  # noqa: E402
from iotguard.events import EventLog  # noqa: E402

st.set_page_config(page_title="IoTGuard", page_icon="shield", layout="wide")

st.title("IoTGuard")
st.caption("Does hardening a smart-building MQTT broker actually stop attacks? "
           "Pick a configuration, launch an attack, and watch what the broker does.")

with st.sidebar:
    st.header("Launch an attack")
    config = st.radio("Configuration", ["A", "B", "C"],
                      format_func=lambda c: f"{c} - {CONFIG_BLURB[c]['name']}")
    st.caption(CONFIG_BLURB[config]["desc"])
    scenario = st.selectbox("Attack", list(SCENARIO_LABEL), format_func=SCENARIO_LABEL.get)
    run = st.button("Run attack", type="primary", use_container_width=True)
    st.divider()
    st.caption("Each run starts a fresh broker on a random port. "
               "Config C also starts the rate detector.")

left, right = st.columns([3, 2], gap="large")

with left:
    st.subheader("Live attack")
    if run:
        with st.spinner(f"Attacking configuration {config}..."):
            log = EventLog(None, config=config)
            res = run_one(f"ui-{uuid.uuid4().hex[:6]}", config, scenario, 0, 1, log=log)
        verdict = interpret(config, scenario, res.detail, res.attack_success)
        {"bad": st.error, "good": st.success, "contained": st.success}[verdict["tone"]](
            f"**{verdict['headline']}** - {verdict['detail']}")
        c1, c2, c3 = st.columns(3)
        c1.metric("Broker connection", "accepted" if res.connected else "refused")
        c2.metric(verdict["metric_label"], verdict["metric_value"])
        c3.metric("Attack outcome", "succeeded" if res.attack_success else "stopped")

        events = log.memory
        if events:
            df = pd.DataFrame(events)[["client", "event_type", "topic", "outcome"]]
            st.caption(f"Broker event log for this run ({len(df)} events)")
            st.dataframe(df, use_container_width=True, height=240, hide_index=True)
    else:
        st.info("Choose a configuration and an attack in the sidebar, then **Run attack**.")

with right:
    st.subheader("How the configurations compare")
    try:
        rows = load(latest_results())
        summary = summarize(rows)
        frame = comparison_frame(summary)
        st.bar_chart(frame, height=300)
        st.caption(f"Attack-success rate across {summary['n_trials']} recorded trials "
                   "(lower is better). From the latest sweep in data/.")
        fc = summary["flood_containment_C"]
        if fc["n"]:
            st.metric("Config C flood containment", f"{fc['containment_rate']:.0%}",
                      help=f"{fc['n']} flood trials; mean "
                           f"{fc['mean_accepted']:.0f} messages accepted before quarantine")
    except FileNotFoundError:
        st.warning("No sweep yet. Run `python -m experiments.run_trials` to populate data/.")

st.divider()
with st.expander("What am I looking at?"):
    st.markdown(
        "- **Config A** is the insecure baseline: anonymous, plaintext MQTT. Every attack lands.\n"
        "- **Config B** adds per-device logins, topic ACLs, and TLS. It blocks unauthorized "
        "reads and commands, but a logged-in sensor can still flood its own topic.\n"
        "- **Config C** keeps B's hardening and adds a rate detector that quarantines a "
        "flooding device, closing the last gap.")
