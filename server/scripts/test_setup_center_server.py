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
TOKEN = "t" * 48
STATE = {"forwarding_master": True, "lan_access": True, "banned": [], "revoked": [], "rules": []}


class FakeAdminResponse:
    def __init__(self, obj: dict, status: int = 200):
        self.status = status
        self.headers = {"Content-Type": "application/json"}
        self._body = (json.dumps(obj) + "\n").encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit: int = -1):
        return self._body if limit < 0 else self._body[:limit]


def fake_admin_urlopen(req, timeout=0):
    assert req.full_url.startswith(("http://127.0.0.1:8789/api/admin/", "http://127.0.0.1:8790/api/admin/"))
    assert req.headers.get("Authorization") == "Bearer " + TOKEN
    path = req.full_url.split("/api/admin", 1)[1]
    method = req.get_method()
    payload = json.loads(req.data) if req.data else {}

    if req.full_url.startswith("http://127.0.0.1:8789"):
        assert method == "GET"
        if path == "/clients":
            return FakeAdminResponse({
                "ok": True,
                "clients": [{
                    "source": "wg", "interface": "wg0", "public_key": "peer-key",
                    "allowed_ips": ["10.77.0.2/32"], "endpoint": "198.51.100.8:50000",
                    "latest_handshake_unix": 1, "handshake_age_seconds": 4,
                    "rx_bytes": 100, "tx_bytes": 200, "state": "recent-handshake",
                }],
                "coverage": {"sources": ["wg"]}, "errors": [],
            })
        assert path == "/status"
        return FakeAdminResponse({
            "ok": True,
            "listeners": [{"protocol": "udp", "address": "0.0.0.0:51820", "port": 51820}],
            "reserved_ports": [1080, 8786, 8787, 8789, 8790, 9443, 51820],
            "active_reserved_ports": [51820],
            "forwarding": {"nft_table": "router_vpn", "rule_count": len(STATE["rules"]), "master": "runtime-table-present"},
            "capabilities": {"connected_clients": True, "service_listener_status": True, "forwarding_read_only": True},
            "errors": [],
        })

    if path == "/settings":
        if method == "PUT":
            for key in ("forwarding_master", "lan_access"):
                if key in payload:
                    STATE[key] = bool(payload[key])
        else:
            assert method == "GET"
        return FakeAdminResponse({
            "ok": True,
            "settings": {"forwarding_master": STATE["forwarding_master"], "lan_access": STATE["lan_access"], "updated_at": 1},
            "banned_peers": STATE["banned"], "revoked_peers": STATE["revoked"],
            "capabilities": {"ban_unban": True, "peer_revoke": True, "forwarding_rule_crud": True, "persistent_state": True, "server_update": False},
        })
    if path == "/clients/ban":
        assert method == "POST"
        STATE["banned"] = [payload]
        return FakeAdminResponse({"ok": True, "banned": payload})
    if path == "/clients/unban":
        assert method == "POST"
        STATE["banned"] = [p for p in STATE["banned"] if p.get("public_key") != payload.get("public_key")]
        return FakeAdminResponse({"ok": True, "public_key": payload.get("public_key"), "banned": False})
    if path == "/clients/revoke":
        assert method == "POST"
        STATE["revoked"] = [payload]
        STATE["banned"] = [payload]
        return FakeAdminResponse({"ok": True, "revoked": payload, "live_peer_removed": True})
    if path == "/forwarding" and method == "GET":
        return FakeAdminResponse({"ok": True, "master": STATE["forwarding_master"], "rules": STATE["rules"]})
    if path == "/forwarding" and method == "POST":
        payload.setdefault("id", "rule-test")
        STATE["rules"] = [r for r in STATE["rules"] if r.get("id") != payload["id"]] + [payload]
        return FakeAdminResponse({"ok": True, "master": STATE["forwarding_master"], "rules": STATE["rules"]})
    if path.startswith("/forwarding/") and method == "DELETE":
        rule_id = path.rsplit("/", 1)[1]
        STATE["rules"] = [r for r in STATE["rules"] if r.get("id") != rule_id]
        return FakeAdminResponse({"ok": True, "rules": STATE["rules"]})
    raise AssertionError((method, path))


def request(server, method: str, path: str, token: str | None = None, obj: dict | None = None):
    host, port = server.server_address
    c = client.HTTPConnection(host, port, timeout=3)
    headers = {}
    body = None
    if token:
        headers["Authorization"] = "Bearer " + token
    if obj is not None:
        body = json.dumps(obj).encode()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    status = r.status
    response_headers = dict(r.getheaders())
    c.close()
    return status, response_headers, data


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
                assert status == 200 and json.loads(body)["active_reserved_ports"] == [51820]
                status, _, body = request(server, "GET", "/api/admin/clients", TOKEN)
                assert status == 200 and json.loads(body)["clients"][0]["state"] == "recent-handshake"

                status, _, body = request(server, "GET", "/api/admin/settings", TOKEN)
                assert status == 200 and json.loads(body)["capabilities"]["ban_unban"] is True
                status, _, body = request(server, "PUT", "/api/admin/settings", TOKEN, {"forwarding_master": False})
                assert status == 200 and json.loads(body)["settings"]["forwarding_master"] is False

                peer = {"interface": "wg0", "public_key": "peer-key", "allowed_ips": ["10.77.0.2/32"]}
                status, _, _ = request(server, "POST", "/api/admin/clients/ban", TOKEN, peer)
                assert status == 200
                status, _, body = request(server, "GET", "/api/admin/settings", TOKEN)
                assert json.loads(body)["banned_peers"][0]["public_key"] == "peer-key"
                status, _, _ = request(server, "POST", "/api/admin/clients/unban", TOKEN, {"public_key": "peer-key"})
                assert status == 200

                rule = {"protocol": "both", "from": 25565, "to": 25565, "target_ip": "10.77.0.2", "target_port": 0, "enabled": True}
                status, _, body = request(server, "POST", "/api/admin/forwarding", TOKEN, rule)
                assert status == 200 and json.loads(body)["rules"][0]["id"] == "rule-test"
                status, _, body = request(server, "DELETE", "/api/admin/forwarding/rule-test", TOKEN)
                assert status == 200 and json.loads(body)["rules"] == []

                status, _, body = request(server, "GET", "/", TOKEN)
                text = body.decode()
                assert status == 200
                for required in ("Server status & administration", "Connected clients", "Port-forwarding master", "Home LAN access", "Persistent port forwarding", "Ban", "Revoke", "/api/admin/settings", "/api/admin/forwarding"):
                    assert required in text, required
                assert "127.0.0.1:8789" not in text and "127.0.0.1:8790" not in text
                assert "appearance:none" in text and "background-color:#15213a!important" in text

                status, _, body = request(server, "GET", "/healthz")
                assert status == 200 and body == b"ok\n"
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
    finally:
        mod.urllib.request.urlopen = original
    print("setup-center-server read/mutation proxy tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
