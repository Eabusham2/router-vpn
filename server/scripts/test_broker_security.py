#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import http.client
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import threading

SCRIPT_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("router_vpn_broker_security", SCRIPT_DIR / "download-broker.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load download-broker.py")
b = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(b)


def request(port: int, method: str, path: str, *, headers: dict | None = None, body: bytes | None = None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    out_headers = dict(r.getheaders())
    c.close()
    return r.status, out_headers, data


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-broker-auth-") as td:
        base = Path(td)
        (base / "config").mkdir()
        (base / "downloads").mkdir()
        (base / "client-bundle").mkdir()
        token = "setup-auth-test-token-0123456789abcdef"
        (base / "config" / "setup-center.token").write_text(token + "\n")
        private = {"bundleVersion": 4, "routerProfiles": [{"id": "home"}], "profiles": {"wg": {"wg.conf": "dGVzdA=="}}}
        (base / "client-bundle" / "router-vpn-bundle.json").write_text(json.dumps(private))

        server = b.Server(("127.0.0.1", 0), b.Handler, base, base / "downloads")
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        with contextlib.redirect_stdout(io.StringIO()):
            thread.start()
            try:
                status, _, _ = request(port, "GET", "/")
                assert status == 401, status

                status, _, data = request(port, "GET", "/api/auth/status")
                assert status == 200
                assert json.loads(data)["authenticated"] is False

                status, headers, _ = request(port, "GET", "/?token=" + token)
                assert status == 303
                assert headers.get("Location") == "/"
                cookie = headers.get("Set-Cookie", "")
                assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and token in cookie

                cookie_value = cookie.split(";", 1)[0]
                status, _, data = request(port, "GET", "/api/auth/status", headers={"Cookie": cookie_value})
                assert status == 200 and json.loads(data)["authenticated"] is True

                status, _, data = request(
                    port, "POST", "/api/pairing",
                    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Content-Length": "2"},
                    body=b"{}",
                )
                assert status == 201, (status, data)
                code = json.loads(data)["pairing"]["code"]
                payload = json.dumps({"code": code}).encode()
                pair_headers = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
                status, headers, data = request(port, "POST", "/api/pairing/redeem", headers=pair_headers, body=payload)
                assert status == 200, (status, data)
                assert headers.get("X-Router-VPN-Pairing") == "one-time"
                assert json.loads(data) == private

                status, _, _ = request(port, "POST", "/api/pairing/redeem", headers=pair_headers, body=payload)
                assert status == 403, status

                status, _, _ = request(port, "POST", "/api/download-jobs", headers={"Content-Type": "application/json", "Content-Length": "35"}, body=b'{"name":"router-vpn-client-bundle.zip"}')
                assert status == 401, status
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    print("authenticated broker + one-time pairing integration tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
