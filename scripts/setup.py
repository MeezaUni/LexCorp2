"""One command from a fresh clone to a running LexCorp2 (development).

    npm run setup                 # install, configure, start everything, then run the app
    npm run setup -- --no-start   # prepare everything but don't start the app
    npm run setup -- --reset-db   # also recreate a local database whose password doesn't match

Safe to run again at any time. Every step checks what already exists and keeps it:
secrets are kept, an existing ledger and contract are reused, and nothing is deleted
unless you ask (--reset-db). Secret values are never printed.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BESU = ROOT / "network" / "besu"
KEYS = BESU / "networkFiles" / "keys"
GENESIS = BESU / "networkFiles" / "genesis.json"
NODE_ENV = BESU / ".env"
DEPLOYMENT = ROOT / "contracts" / "deployments" / "besu.json"
PY = sys.executable
NPM = shutil.which("npm") or "npm"
BESU_COMPOSE = ["docker", "compose", "--env-file", str(NODE_ENV), "-f", str(BESU / "docker-compose-active.yml")]

sys.path.insert(0, str(ROOT / "scripts"))
from wait_for_chain import wait as wait_for_blocks  # noqa: E402


def step(n, text):
    print(f"\n[{n}/8] {text}", flush=True)


def fail(msg):
    print(f"\nSETUP STOPPED: {msg}", flush=True)
    sys.exit(1)


# `npm run setup` exports the parent npm's settings as npm_config_* variables; nested npm
# commands would inherit them (newer npm then refuses to install). Child commands get a clean
# environment and read .npmrc themselves, exactly as when typed in a terminal.
CLEAN_ENV = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}


def run(cmd, cwd=ROOT, check=True, quiet=False, env=None):
    r = subprocess.run(cmd, cwd=cwd, text=True, capture_output=quiet, env=env or CLEAN_ENV)
    if check and r.returncode != 0:
        if quiet:
            print((r.stdout or "") + (r.stderr or ""))
        fail(f"command failed: {' '.join(str(c) for c in cmd)}")
    return r


def rpc(method, params=()):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": list(params), "id": 1}).encode()
    req = urllib.request.Request("http://127.0.0.1:8545", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read()).get("result")


def check_prerequisites():
    step(1, "Checking prerequisites")
    if sys.version_info < (3, 11):
        fail(f"Python 3.11 or newer is needed (this is {sys.version.split()[0]}).")
    node = shutil.which("node")
    if not node:
        fail("Node.js 20 or newer is needed: https://nodejs.org")
    major = int(re.match(r"v(\d+)", run([node, "--version"], quiet=True).stdout.strip()).group(1))
    if major < 20:
        fail(f"Node.js 20 or newer is needed (found v{major}).")
    if not shutil.which("docker"):
        fail("Docker Desktop is needed: https://www.docker.com/products/docker-desktop/")
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        fail("Docker Desktop is installed but not running. Start it, wait until it says 'running', then retry.")
    print(f"Python {sys.version.split()[0]}, Node v{major}, Docker running.")


def install(skip):
    step(2, "Installing dependencies")
    if skip:
        print("Skipped (--skip-install).")
        return
    for prefix in (None, "frontend", "contracts"):
        cmd = [NPM, "install", "--no-fund", "--no-audit"] + (["--prefix", prefix] if prefix else [])
        print("npm install" + (f" ({prefix})" if prefix else ""), flush=True)
        run(cmd, quiet=True)
    print("pip install -r backend/requirements-dev.txt", flush=True)
    run([PY, "-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", "backend/requirements-dev.txt"], quiet=True)


def secrets():
    step(3, "Creating local secrets (existing values are kept)")
    run([PY, "scripts/init_secrets.py", "--environment", "development"])


def read_env(path):
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def db_login_ok():
    url = read_env(ROOT / "backend" / ".env")["DATABASE_URL"]
    probe = ("import asyncio,asyncpg,sys\n"
             "async def m():\n"
             "    try:\n"
             "        c = await asyncpg.connect(sys.argv[1].replace('postgresql+asyncpg', 'postgresql'), timeout=5)\n"
             "        await c.close(); return 0\n"
             "    except asyncpg.InvalidPasswordError: return 2\n"
             "    except Exception: return 1\n"
             "sys.exit(asyncio.run(m()))\n")
    return subprocess.run([PY, "-c", probe, url], capture_output=True).returncode


def database(reset):
    step(4, "Starting the database")
    owner = subprocess.run(["docker", "inspect", "lexcorp_postgres", "--format",
                            '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}'],
                           capture_output=True, text=True)
    if owner.returncode == 0 and owner.stdout.strip() and Path(owner.stdout.strip()).resolve() != ROOT:
        fail("a container named 'lexcorp_postgres' already exists and belongs to another folder "
             f"({owner.stdout.strip()}). Stop and rename it (docker stop lexcorp_postgres; docker rename "
             "lexcorp_postgres lexcorp_postgres_old), then retry.")
    run(["docker", "compose", "up", "-d", "postgres"], quiet=True)
    for attempt in range(2):
        deadline = time.time() + 90
        code = 1
        while time.time() < deadline:
            code = db_login_ok()
            if code in (0, 2):
                break
            time.sleep(2)
        if code == 0:
            print("Database is up and accepts this project's credentials.")
            return
        if code == 2 and reset and attempt == 0:
            print("The existing database volume has a different password: recreating it (--reset-db).")
            run(["docker", "compose", "down", "-v"], quiet=True)
            run(["docker", "compose", "up", "-d", "postgres"], quiet=True)
            continue
        if code == 2:
            fail("the local database was created earlier with a different password (for example by an older "
                 "LexCorp copy), so it rejects this project's password. If you don't need that old local database, "
                 "run: npm run setup -- --reset-db   (it deletes and recreates it). To keep a copy first: "
                 "docker exec lexcorp_postgres pg_dumpall -U lexcorp > old_db_backup.sql")
        fail("the database did not become ready. Check: docker logs lexcorp_postgres")


def ledger():
    step(5, "Starting the ledger (3 Besu validators)")
    have_keys = all((KEYS / f"node{n}" / "key").is_file() for n in (1, 2, 3)) and GENESIS.is_file()
    if not have_keys:
        print("No validator keys on this machine yet: generating a new private network.")
        # Stop any nodes still running from an earlier attempt (the enode value is irrelevant for "down").
        run(["docker", "compose", "-f", str(BESU / "docker-compose-active.yml"), "down"], check=False, quiet=True,
            env={**CLEAN_ENV, "BESU_NODE1_ENODE": "0"})
        run([PY, "scripts/generate_besu_network.py", "--force"])
    elif not NODE_ENV.is_file():
        enode = (KEYS / "node1" / "key.pub").read_text(encoding="utf-8").strip().removeprefix("0x")
        NODE_ENV.write_text(f"# Generated by scripts/setup.py (public key only)\nBESU_NODE1_ENODE={enode}\n", encoding="utf-8")
    r = run(BESU_COMPOSE + ["up", "-d"], check=False, quiet=True)
    if r.returncode != 0:
        out = (r.stdout or "") + (r.stderr or "")
        if "overlaps" in out:
            fail("Docker already has a network using 10.137.71.0/24. Run `docker network prune -f` "
                 "(removes only unused networks) and retry.")
        print(out)
        fail("the ledger containers did not start.")
    print("Waiting for the ledger to produce blocks (up to 3 minutes)...", flush=True)
    if not wait_for_blocks(180):
        fail("the ledger started but isn't producing blocks. Check `docker logs besu_node1`. If it mentions a "
             "genesis or database mismatch, run `npm run besu:down`, then "
             "`python scripts/generate_besu_network.py --force`, then `npm run setup` again.")


def contract():
    step(6, "Checking the smart contract")
    deployed = False
    if DEPLOYMENT.is_file():
        d = json.loads(DEPLOYMENT.read_text(encoding="utf-8"))
        code = rpc("eth_getCode", [d.get("address", "0x0000000000000000000000000000000000000000"), "latest"])
        deployed = bool(code) and code != "0x"
    if not deployed:
        print("No LexCorp2 contract on this ledger yet: deploying a fresh one.")
        run([NPM, "run", "contract:deploy"])
    if run([NPM, "run", "-s", "contract:verify"], check=False).returncode != 0:
        fail("the contract at contracts/deployments/besu.json did not pass verification (see the lines above). "
             "It was not replaced automatically, to avoid orphaning existing records.")


def migrate():
    step(7, "Preparing the database schema")
    run([PY, "-m", "alembic", "upgrade", "head"], cwd=ROOT / "backend")


def bootstrap():
    step(8, "First administrator")
    r = run([PY, "backend/scripts/bootstrap_admin.py", "--name", "Security Administrator",
             "--department", "Cyber Security"], check=False)
    if r.returncode not in (0, 2):
        fail("could not create the first administrator.")
    pin = ROOT / "secrets" / "bootstrap_admin_pin.txt"
    if pin.is_file():
        print("Provisioning material: secrets/bootstrap_admin_wallet.json (recovery phrase) and "
              "secrets/bootstrap_admin_pin.txt (PIN). If the PIN has expired: "
              "python backend/scripts/bootstrap_admin.py --reissue-pin")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-start", action="store_true", help="prepare everything but don't start the app")
    ap.add_argument("--reset-db", action="store_true", help="recreate a local database whose password doesn't match")
    ap.add_argument("--skip-install", action="store_true", help="skip npm/pip installs")
    a = ap.parse_args()
    os.chdir(ROOT)
    check_prerequisites()
    install(a.skip_install)
    secrets()
    database(a.reset_db)
    ledger()
    contract()
    migrate()
    bootstrap()
    print("\nSetup complete.")
    if a.no_start:
        print("Start the app with: npm start   (then open http://localhost:5173)")
        return 0
    print("Starting the app: backend on 127.0.0.1:8000, frontend on http://localhost:5173 (Ctrl+C stops it).\n", flush=True)
    return subprocess.call([NPM, "start"], cwd=ROOT, env=CLEAN_ENV)


if __name__ == "__main__":
    sys.exit(main())
