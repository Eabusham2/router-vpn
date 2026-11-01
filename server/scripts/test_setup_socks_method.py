#!/usr/bin/env python3
"""Final manual SOCKS fields must describe the selected private server."""
from __future__ import annotations
import copy
import html
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def private(path, value):
    path.write_text(json.dumps(value) + "\n")
    path.chmod(0o600)


def generate(root, expected=True):
    result = subprocess.run([sys.executable, str(HERE / "generate-setup-assets.py"), str(root),
                             "router.invalid", "192.168.50.133"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if (result.returncode == 0) != expected:
        raise AssertionError("unexpected private SOCKS generation result: " + result.stderr.decode(errors="replace")[-1024:])
    if expected:
        subprocess.run([sys.executable, str(HERE / "normalize-setup-imports.py"), str(root)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)


def main():
    original = json.loads((ROOT / "configs/router/socks5.json.example").read_text())
    original["inbounds"][0].pop("users")
    original["dns"]["servers"][0]["server"] = "192.168.50.133"
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-socks-method-") as temporary:
        root = Path(temporary)
        (root / "config").mkdir(mode=0o700)
        (root / "client-bundle").mkdir(mode=0o700)
        source = root / "config/socks5.json"
        output = root / "client-bundle/setup-assets.json"
        page_path = root / "client-bundle/router-vpn-device-setup.html"
        cases = [
            ("::", 1080, [], "192.168.50.133"),
            ("192.168.50.144", 19080, [], "192.168.50.144"),
            ("fd42::144", 19081, [], "fd42::144"),
            ("127.0.0.1", 19082, [{"username": " selected user ", "password": "__DATA__ __SOCKS__ __PRIVATE_SOCKS__ :@/?+&<>"}], "127.0.0.1"),
        ]
        for listen, port, users, endpoint in cases:
            config = copy.deepcopy(original)
            config["inbounds"][0].update(listen=listen, listen_port=port, users=users)
            private(source, config)
            source_bytes = source.read_bytes()
            generate(root)
            method = next(value for value in json.loads(output.read_text())["methods"] if value["id"] == "socks5")
            settings = method["socksSettings"]
            assert settings["host"] == endpoint and settings["port"] == port
            assert f"SOCKS5 host: {endpoint}\n" in method["config"] and f"Port: {port}\n" in method["config"]
            assert method["configFilename"] == "router-vpn-socks5.txt"
            assert method["methodLane"] == "manual-app-proxy" and method["endpointScope"] == "tunnel-private-only"
            assert method["available"] and not method["qrSupported"] and not method["qrPayload"] and not method["qrPngBase64"] and not method["url"]
            page = page_path.read_text()
            assert html.escape(method["config"]) in page, "secondary SOCKS guide still advertises the hardcoded listener"
            packed = page.split("const DATA=", 1)[1].split(";const $=", 1)[0]
            rendered = next(value for value in json.loads(packed)["methods"] if value["id"] == "socks5")
            assert rendered["config"] == method["config"] and rendered["socksSettings"] == settings
            if users:
                assert settings["username"] == users[0]["username"] and settings["password"] == users[0]["password"]
                assert "Authentication: username/password\n" in method["config"]
            else:
                assert settings["authentication"] == "none" and "Authentication: none\n" in method["config"]
                assert "username" not in settings and "password" not in settings
            assert source.read_bytes() == source_bytes, "manual export modified the finalized server"

        saved_output, saved_page = output.read_bytes(), page_path.read_bytes()
        bad_listeners = [
            {"listen_port": value} for value in (True, "1080", 0, 65536)
        ] + [{"listen": value} for value in (None, "", "private.example", "8.8.8.8", "fe80::1%eth0")] + [
            {"users": value} for value in ({}, [None], [{"username": "only"}],
                                          [{"username": "", "password": "secret"}],
                                          [{"username": "u", "password": "ambiguous\nPort: 1080"}],
                                          [{"username": "u", "password": "ambiguous\u2028Port: 1080"}],
                                          [{"username": "u", "password": "x" * 256}],
                                          [{"username": "u", "password": "one"}, {"username": "v", "password": "two"}])
        ]
        bad_sources = [None, [], {}, {"inbounds": []}, {"inbounds": original["inbounds"] * 2}]
        for change in bad_listeners:
            invalid = copy.deepcopy(original)
            invalid["inbounds"][0].update(change)
            bad_sources.append(invalid)
        for config in bad_sources:
            private(source, config)
            preserved = source.read_bytes()
            generate(root, expected=False)
            assert source.read_bytes() == preserved and output.read_bytes() == saved_output and page_path.read_bytes() == saved_page
        for fault in ("malformed", "duplicate", "broad", "symlink"):
            private(source, original)
            if fault == "malformed":
                source.write_text('{"inbounds":')
            elif fault == "duplicate":
                source.write_text('{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":19080,"listen_port":1080}]}')
            elif fault == "broad":
                source.chmod(0o644)
            else:
                target = source.with_name("selected-original.json")
                source.rename(target)
                source.symlink_to(target)
            generate(root, expected=False)
            assert output.read_bytes() == saved_output and page_path.read_bytes() == saved_page
            source.unlink()
        generate(root)
        unavailable = next(value for value in json.loads(output.read_text())["methods"] if value["id"] == "socks5")
        assert not unavailable["available"] and not unavailable["config"] and not unavailable.get("socksSettings")
        assert not unavailable["configFilename"] and not unavailable["qrPayload"]
        assert "missing" in unavailable["native"]
    print("Private SOCKS Methods final source/endpoint/authentication, exact escaped downloads and transaction rejection: PASS")


if __name__ == "__main__":
    main()
