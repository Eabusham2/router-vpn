#!/usr/bin/env python3
from __future__ import annotations

from http import client
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import tempfile
import threading

HERE = Path(__file__).resolve().parent
SPEC = spec_from_file_location("setup_center_server_tested", HERE / "setup-center-server.py")
assert SPEC and SPEC.loader
mod = module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class FakeAdminResponse:
    def __init__(self, obj: dict):
        self.status = 200
        self.headers = {"Content-Type": "application/json"}
        self._body = (json.dumps(obj) + "\n").encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit: int = -1):
        return self._body if limit < 0 else self._body[:limit]


def fake_admin_urlopen(req, timeout=0):
    assert req.full_url.startswith("http://127.0.0.1:8789/api/admin/")
    assert req.headers.get("Authorization") == "Bearer " + TOKEN
    if req.full_url.endswith("/clients"):
        return FakeAdminResponse({
            "ok": True,
            "clients": [{
                "source": "wg", "interface": "wg0", "public_key": "peer-key",
                "allowed_ips": ["10.77.0.2/32"], "latest_handshake_unix": 1,
                "handshake_age_seconds": 4, "rx_bytes": 100, "tx_bytes": 200,
                "state": "recent-handshake",
            }],
            "coverage": {"sources": ["wg"]}, "errors": [],
        })
    return FakeAdminResponse({
        "ok": True,
        "listeners": [{"protocol": "udp", "address": "0.0.0.0:51820", "port": 51820}],
        "reserved_ports": [1080, 8786, 8787, 8789, 9443, 51820],
        "active_reserved_ports": [51820],
        "forwarding": {"nft_table": "router_vpn", "rule_count": 1, "master": "runtime-table-present"},
        "capabilities": {"connected_clients": True, "service_listener_status": True, "forwarding_read_only": True, "ban_unban": False, "peer_revoke": False, "settings_write": False, "server_update": False},
        "errors": [],
    })


def request(server, method: str, path: str, token: str | None = None):
    host, port = server.server_address
    c = client.HTTPConnection(host, port, timeout=3)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    c.request(method, path, headers=headers)
    r = c.getresponse()
    body = r.read()
    status = r.status
    headers = dict(r.getheaders())
    c.close()
    return status, headers, body


TOKEN = "t" * 48


def main() -> int:
    original = mod.urllib.request.urlopen
    mod.urllib.request.urlopen = fake_admin_urlopen
    try:
        with tempfile.TemporaryDirectory(prefix="router-vpn-setup-admin-test-") as td:
            base = Path(td)
            (base / "config").mkdir()
            (base / "config" / "setup-center.token").write_text(TOKEN + "\n")
            static = base / "downloads"
            static.mkdir()
            html = '<!doctype html><body><div id="tabs"></div><section class="panel active" data-tab="start">Start</section><div id="wizard" class="overlay"></div><script>function gotoTab(name){document.querySelectorAll(\'.panel\').forEach(x=>x.classList.toggle(\'active\',x.dataset.tab===name))}</script></body>'
            (static / "index.html").write_text(html)
            (static / "router-vpn-device-setup.html").write_text(html)
            server = mod.Server(("127.0.0.1", 0), mod.Handler, base, static)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                status, _, _ = request(server, "GET", "/api/admin/status")
                assert status == 401, status
                status, _, body = request(server, "GET", "/api/admin/status", TOKEN)
                assert status == 200, (status, body)
                data = json.loads(body)
                assert data["forwarding"]["rule_count"] == 1
                assert data["capabilities"]["ban_unban"] is False

                status, _, body = request(server, "GET", "/api/admin/clients", TOKEN)
                assert status == 200
                data = json.loads(body)
                assert data["clients"][0]["state"] == "recent-handshake"

                status, _, body = request(server, "GET", "/", TOKEN)
                text = body.decode()
                assert status == 200
                assert 'data-tab="server-admin"' in text
                assert "Connected clients" in text
                assert "Protected ports & listeners" in text
                assert "Ban/unban, peer revoke, settings writes and server update controls stay disabled" in text
                assert "/api/admin/clients" in text and "/api/admin/status" in text
                assert "127.0.0.1:8789" not in text

                status, _, body = request(server, "GET", "/healthz")
                assert status == 200 and body == b"ok\n"
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
    finally:
        mod.urllib.request.urlopen = original
    print("setup-center-server admin proxy tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
