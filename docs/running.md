# Running IoTGuard

How to reproduce the whole project from a fresh checkout: set up identities, run a
sweep, read the metrics and graphs, and open the dashboard. There are two paths -
run it locally, or run it in Docker.

## What you need

- Python 3.11+ and `pip`
- Mosquitto 2.x with the dynamic-security plugin (`mosquitto`, `mosquitto-clients`)
  - macOS: `brew install mosquitto`
  - Debian/Ubuntu: `sudo apt-get install -y mosquitto mosquitto-clients`

## Local: first-time setup

    pip install -r requirements.txt
    python -m broker.setup_identities

`setup_identities` writes the lab CA and broker certificate, then creates one login per
device. It only needs to run once; add `--force` to regenerate.

## Run a sweep

Each trial starts a fresh broker, so quarantines and state never carry over. Output lands
in `data/`.

    python -m experiments.run_trials --repeats 10

## Metrics and graphs

    python -m experiments.metrics      # attack-success table + metrics-<run>.csv
    python -m experiments.plot         # comparison charts in figures/

Both default to the newest sweep in `data/`; pass a specific `data/results-<run>.csv` to
pin one.

## Dashboard

    streamlit run dashboard/app.py

Pick a configuration and an attack in the sidebar and press Run attack: it launches a
real broker, runs the attack, and shows whether the broker allowed, blocked, or contained
it, with the live event log. The right-hand panel shows the A/B/C comparison from the
latest sweep.

## Docker (reproducible stack)

The image bundles Python, Mosquitto with the plugin, the dependencies, and a fresh set of
identities, so it runs the same anywhere.

    docker compose up dashboard                     # dashboard at http://localhost:8501
    docker compose --profile sweep run --rm sweep   # run a sweep; writes data/ and figures/

## Resetting

- New identities: `python -m broker.setup_identities --force`
- Clear results: delete the files under `data/` (the directory is git-ignored).
