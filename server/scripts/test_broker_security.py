#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import http.client
import importlib.util
import io
import json
import os
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


def test_github_redirect_credentials() -> None:
    handler = b._SafeGitHubRedirect()
    original = b.urllib.request.Request(
        "https://api.github.com/repos/Eabusham2/router-vpn/actions/artifacts/1/zip",
        headers={"Authorization": "Bearer super-secret", "Cookie": "private-cookie"},
    )
    cross = handler.redirect_request(
        original, None, 302, "Found", {},
        "https://objects.githubusercontent.com/github-production-repository-file/blob",
    )
    assert cross is not None
    assert cross.get_header("Authorization") is None
    assert cross.get_header("Cookie") is None

    same = handler.redirect_request(
        original, None, 302, "Found", {},
        "https://api.github.com/repos/Eabusham2/router-vpn/actions/artifacts/2/zip",
    )
    assert same is not None
    assert same.get_header("Authorization") == "Bearer super-secret"
    assert same.get_header("Cookie") == "private-cookie"

    try:
        handler.redirect_request(
            original, None, 302, "Found", {},
            "http://objects.githubusercontent.com/insecure",
        )
    except RuntimeError as exc:
        assert "non-HTTPS" in str(exc)
    else:
        raise AssertionError("GitHub artifact redirect allowed HTTPS downgrade")

    try:
        b._urlopen("https://example.com/not-github")
    except RuntimeError as exc:
        assert "must start at https://api.github.com" in str(exc)
    else:
        raise AssertionError("authenticated GitHub request was allowed to start cross-origin")


def main() -> int:
    test_github_redirect_credentials()
    with tempfile.TemporaryDirectory(prefix="router-vpn-broker-auth-") as td:
        base = Path(td)
        (base / "config").mkdir()
        (base / "downloads").mkdir()
        (base / "client-bundle").mkdir()
        token = "setup-auth-test-token-0123456789abcdef"
        token_path = base / "config" / "setup-center.token"
        token_path.write_text(token + "\n")
        os.chmod(token_path, 0o600)
        private = {"bundleVersion": 4, "routerProfiles": [{"id": "home"}], "profiles": {"wg": {"wg.conf": "dGVzdA=="}}}
        bundle_path = base / "client-bundle" / "router-vpn-bundle.json"
        bundle_path.write_text(json.dumps(private))
        os.chmod(bundle_path, 0o600)

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

                # POSIX deployments require exact 0600 on private bundle
                # material. Windows does not expose equivalent ACL semantics
                # through chmod/stat, so this mode-bit failure case belongs only
                # to the Linux/server contract; Windows still runs all identity,
                # bounds, path and one-time-code tests below.
                if os.name != "nt":
                    status, _, data = request(
                        port, "POST", "/api/pairing",
                        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Content-Length": "2"},
                        body=b"{}",
                    )
                    assert status == 201, (status, data)
                    retry_code = json.loads(data)["pairing"]["code"]
                    retry_payload = json.dumps({"code": retry_code}).encode()
                    retry_headers = {"Content-Type": "application/json", "Content-Length": str(len(retry_payload))}
                    os.chmod(bundle_path, 0o644)
                    status, _, _ = request(port, "POST", "/api/pairing/redeem", headers=retry_headers, body=retry_payload)
                    assert status == 503, status
                    os.chmod(bundle_path, 0o600)
                    status, _, data = request(port, "POST", "/api/pairing/redeem", headers=retry_headers, body=retry_payload)
                    assert status == 200 and json.loads(data) == private, (status, data)

                if os.name != "nt":
                    status, _, data = request(
                        port, "POST", "/api/pairing",
                        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Content-Length": "2"},
                        body=b"{}",
                    )
                    assert status == 201, (status, data)
                    symlink_code = json.loads(data)["pairing"]["code"]
                    symlink_payload = json.dumps({"code": symlink_code}).encode()
                    symlink_headers = {"Content-Type": "application/json", "Content-Length": str(len(symlink_payload))}
                    real_bundle = bundle_path.with_name("router-vpn-bundle.real.json")
                    os.replace(bundle_path, real_bundle)
                    bundle_path.symlink_to(real_bundle)
                    status, _, _ = request(port, "POST", "/api/pairing/redeem", headers=symlink_headers, body=symlink_payload)
                    assert status == 503, status
                    bundle_path.unlink()
                    os.replace(real_bundle, bundle_path)
                    status, _, data = request(port, "POST", "/api/pairing/redeem", headers=symlink_headers, body=symlink_payload)
                    assert status == 200 and json.loads(data) == private, (status, data)

                status, _, _ = request(port, "POST", "/api/download-jobs", headers={"Content-Type": "application/json", "Content-Length": "35"}, body=b'{"name":"router-vpn-client-bundle.zip"}')
                assert status == 401, status
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    if os.name != "nt":
        for kind in ("symlink", "broad"):
            with tempfile.TemporaryDirectory(prefix=f"router-vpn-broker-token-{kind}-") as td:
                base = Path(td)
                (base / "config").mkdir()
                (base / "downloads").mkdir()
                token_path = base / "config" / "setup-center.token"
                if kind == "symlink":
                    real = base / "config" / "real-token"
                    real.write_text("setup-auth-test-token-0123456789abcdef\n")
                    os.chmod(real, 0o600)
                    token_path.symlink_to(real)
                else:
                    token_path.write_text("setup-auth-test-token-0123456789abcdef\n")
                    os.chmod(token_path, 0o644)
                try:
                    b.Server(("127.0.0.1", 0), b.Handler, base, base / "downloads")
                except RuntimeError as exc:
                    assert "safely read" in str(exc) or "private verified source" in str(exc)
                else:
                    raise AssertionError(f"broker accepted {kind} Setup Center bearer token")

    print("authenticated broker + one-time pairing integration tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
