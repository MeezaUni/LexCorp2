"""DEVELOPMENT-ONLY credential broker for automated browser (Playwright) runs.

Browser automation must type wallet keys, PINs and TOTP codes into the real UI, but
those values must never appear in logs or in an operator's transcript. This process
holds them in memory and answers only on 127.0.0.1:

  GET  /bootstrap                 bootstrap admin wallet + PIN (from secrets/*, git-ignored)
  POST /identity/<name>           store {"key": ..., "pin": ..., "address": ...}
  GET  /identity/<name>
  POST /totp/<name>/<purpose>     store a TOTP secret captured during enrolment
  GET  /code/<name>/<purpose>     a currently valid code whose time step was not issued before

It refuses to start unless backend/.env says ENVIRONMENT=development. Nothing is written
to disk and nothing is logged. Stop it when the run ends.
"""

import base64
import hashlib
import hmac
import json
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE = {"identity": {}, "totp": {}, "issued": {}}


def env_value(name):
    for line in (ROOT / "backend" / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1].strip()
    return None


def totp_at(secret, step):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # never log requests (paths are harmless, bodies are not)
        pass

    def reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        parts = [p for p in self.path.split("/") if p]
        if parts == ["bootstrap"]:
            wallet = json.loads((ROOT / "secrets" / "bootstrap_admin_wallet.json").read_text(encoding="utf-8"))
            pin_line = [l for l in (ROOT / "secrets" / "bootstrap_admin_pin.txt").read_text(encoding="utf-8").splitlines() if "PIN" in l][0]
            return self.reply(200, {"key": wallet["recovery_phrase"], "address": wallet["address"], "pin": pin_line.rsplit(":", 1)[1].strip()})
        if len(parts) == 2 and parts[0] == "identity":
            v = STORE["identity"].get(parts[1])
            return self.reply(200 if v else 404, v or {})
        if len(parts) == 3 and parts[0] == "code":
            secret = STORE["totp"].get((parts[1], parts[2]))
            if not secret:
                return self.reply(404, {})
            key = (parts[1], parts[2])
            while True:
                now = int(time.time()) // 30
                last = STORE["issued"].get(key, -1)
                for step in (now, now + 1):
                    if step > last:
                        STORE["issued"][key] = step
                        return self.reply(200, {"code": totp_at(secret, step)})
                time.sleep(2)
        return self.reply(404, {})

    def do_POST(self):
        parts = [p for p in self.path.split("/") if p]
        if len(parts) == 2 and parts[0] == "identity":
            STORE["identity"][parts[1]] = self.body()
            return self.reply(200, {"stored": parts[1]})
        if len(parts) == 3 and parts[0] == "totp":
            STORE["totp"][(parts[1], parts[2])] = self.body()["secret"]
            STORE["issued"].pop((parts[1], parts[2]), None)
            return self.reply(200, {"stored": f"{parts[1]}/{parts[2]}"})
        return self.reply(404, {})


if __name__ == "__main__":
    if env_value("ENVIRONMENT") != "development":
        sys.exit("Refusing to run: backend/.env ENVIRONMENT is not development.")
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
