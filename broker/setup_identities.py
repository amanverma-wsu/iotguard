"""One-time setup for the hardened configs (B and C).

1. Generates the lab CA + broker certificate (broker/gen_certs.sh).
2. Creates a Dynamic Security file with an admin login.
3. Starts a temporary broker, creates one role + one login per device with a random
   password, and saves the result as broker/dynsec/dynamic-security.json (the "seed").
4. Writes every password to broker/dynsec/credentials.json (mode 600, git-ignored).

Run:  python -m broker.setup_identities [--sensors 5] [--force]
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from iotguard import topics  # noqa: E402
from iotguard.broker import BrokerProcess  # noqa: E402
from iotguard.dynsec import DynsecAdmin  # noqa: E402

DYNSEC_DIR = REPO / "broker" / "dynsec"
SEED = DYNSEC_DIR / "dynamic-security.json"
CREDS = DYNSEC_DIR / "credentials.json"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sensors", type=int, default=topics.DEFAULT_SENSOR_COUNT)
    ap.add_argument("--force", action="store_true", help="overwrite existing identities")
    args = ap.parse_args(argv)

    subprocess.run(["bash", str(REPO / "broker" / "gen_certs.sh")], check=True)

    if SEED.exists() and CREDS.exists() and not args.force:
        print(f"identities already exist ({SEED}); use --force to recreate")
        return 0

    DYNSEC_DIR.mkdir(parents=True, exist_ok=True)
    creds = {"admin": secrets.token_urlsafe(18)}
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "dynamic-security.json"
        subprocess.run(["mosquitto_ctrl", "dynsec", "init", str(fresh), "admin", creds["admin"]],
                       check=True, capture_output=True)
        tmp_creds = Path(tmp) / "credentials.json"
        tmp_creds.write_text(json.dumps(creds))

        broker = BrokerProcess("B", dynsec_seed=fresh, credentials_file=tmp_creds).start()
        try:
            with DynsecAdmin(broker.target) as admin:
                for ident in topics.identities(args.sensors):
                    pw = secrets.token_urlsafe(18)
                    admin.create_role(f"role-{ident}", topics.acl_for(ident))
                    admin.create_client(ident, pw, f"role-{ident}")
                    creds[ident] = pw
            time.sleep(0.3)  # dynsec writes its file after each change
            shutil.copy(broker.workdir / "dynamic-security.json", SEED)
        finally:
            broker.cleanup()

    CREDS.write_text(json.dumps(creds, indent=2))
    os.chmod(CREDS, 0o600)
    print(f"created {len(creds) - 1} device identities + admin -> {SEED.name}, {CREDS.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
