"""Wait until the local Besu network is actually producing blocks (an open port is not enough:
Docker accepts connections on 8545 even while the nodes are still starting or restarting).

  python scripts/wait_for_chain.py [--timeout 180]
"""

import argparse
import json
import sys
import time
import urllib.request

RPC = "http://127.0.0.1:8545"


def block_number():
    body = json.dumps({"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=3) as r:
        return int(json.loads(r.read())["result"], 16)


def wait(timeout: float = 180) -> bool:
    deadline = time.time() + timeout
    first = None
    while time.time() < deadline:
        try:
            n = block_number()
            if first is None:
                first = n
            elif n > first:
                print(f"Ledger is producing blocks (block {n}).")
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=180)
    a = ap.parse_args()
    print("Waiting for the ledger to produce blocks...")
    if wait(a.timeout):
        sys.exit(0)
    print("The ledger did not start producing blocks. Check `docker logs besu_node1`, or run `npm run setup`.")
    sys.exit(1)
