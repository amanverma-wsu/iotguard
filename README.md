# IoTGuard

Our CptS 427 (Fall 2026) project: securing a simulated smart building.

**Team Ex-coworkers:** Luiz Takahashi, Chris Flores, Aman Verma, Ehzoc Chavez

We simulate a small smart building (temperature sensors, a door controller, a cooling
controller) talking over MQTT through one Mosquitto broker. We attack it, harden it, and
measure how much each setup cuts unauthorized activity and what it costs legitimate devices.
Everything runs on our laptops. No physical hardware.

**Research question.** How much do device authentication, topic permissions, and detection
with quarantine reduce unauthorized activity, and what overhead do they add for legitimate
devices?

## The three setups

| Config | What it is |
|---|---|
| **A - Baseline** | anonymous, plaintext MQTT |
| **B - Hardened** | per-device logins, topic permissions, TLS |
| **C - Hardened + Detection** | B plus a rate detector that quarantines a flooding device |

## Attacks we run against all three

- **Unauthorized reading** - an unknown client subscribes to sensor topics.
- **Unauthorized command** - an unknown client, or a sensor, publishes a door command.
- **Message flooding** - a valid sensor sends telemetry way too fast.

## Layout

\`\`\`
iotguard/     shared code: topics, event logging, devices, controller, detector
broker/       Mosquitto configs, cert + identity setup scripts
attacks/      the three attack scenarios
experiments/  trial runner, metrics, graphs
dashboard/    Streamlit dashboard
tests/        pytest suite (runs against a real Mosquitto broker)
docs/         proposal and notes
data/         logs and results (git-ignored)
\`\`\`

## Setup

\`\`\`bash
git config core.hooksPath .githooks     # blocks committing keys/certs
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
\`\`\`

You also need Mosquitto 2.x installed (\`mosquitto\`, \`mosquitto_ctrl\`) or Docker.
More instructions get added as each part lands.

## Safety

Attacks only run against our own broker on localhost or inside Docker, with fixed durations
and rate limits. No real devices, no outside networks.

## Status

Work in progress, built in phases.

- [x] Phase 0 - repo scaffold
- [x] Phase 1 - broker configs A/B/C, TLS, identities
- [x] Phase 2 - devices, controller, event logging
- [ ] Phase 3 - attack scenarios
- [ ] Phase 4 - detection + quarantine
- [ ] Phase 5 - experiment harness + metrics
- [ ] Phase 6 - dashboard, Docker Compose, docs
