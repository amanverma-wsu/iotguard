# Reproducible IoTGuard image: Python + Mosquitto (with the dynamic-security plugin),
# the repo, its dependencies, and a fresh set of broker identities baked in.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends mosquitto mosquitto-clients \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate the CA, broker cert, and per-device identities for configs B and C.
RUN python -m broker.setup_identities

EXPOSE 8501
CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]
