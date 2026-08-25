#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import tempfile

MAX_PRIVATE_BYTES = 4 << 20


def read_private_text(path: pathlib.Path, label: str) -> str:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink {label}: {path}")
    if info.st_size <= 0 or info.st_size > MAX_PRIVATE_BYTES:
        raise RuntimeError(f"{label} is empty or oversized: {path}")
    return path.read_text(encoding="utf-8")


def load_preserved_json(path: pathlib.Path) -> dict:
    try:
        text = read_private_text(path, "preserved auxiliary secret state")
    except FileNotFoundError:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("preserved auxiliary secret state is corrupt; refusing silent credential rotation") from exc
    if not isinstance(value, dict):
        raise RuntimeError("preserved auxiliary secret state is invalid; refusing silent credential rotation")
    return value


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def stage_json(path: pathlib.Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: generate-aux-proxies.py BASE ENDPOINT OVERTLS_PORT SSR_PORT", file=sys.stderr)
        return 2

    base = pathlib.Path(sys.argv[1])
    endpoint = sys.argv[2].strip().strip("[]")
    overtls_port = int(sys.argv[3])
    ssr_port = int(sys.argv[4])
    internal_port = int(os.environ.get("OVERTLS_INTERNAL_PORT", "14444"))
    for name, port in (("OVERTLS_PORT", overtls_port), ("OVERTLS_INTERNAL_PORT", internal_port), ("SSR_PORT", ssr_port)):
        if not 1 <= port <= 65535:
            raise SystemExit(f"{name} must be between 1 and 65535")

    tls_settings = base / "config" / "tls" / "settings.env"
    try:
        text = read_private_text(tls_settings, "TLS settings")
    except FileNotFoundError:
        print("TLS settings are required before OverTLS generation.", file=sys.stderr)
        return 1
    match = re.search(r"(?m)^TLS_NAME='([^']+)'$", text)
    if not match:
        print("TLS_NAME missing from TLS settings.", file=sys.stderr)
        return 1
    tls_name = match.group(1)

    aux = base / "config" / "aux"
    gen = base / "client-bundle" / "generated"
    aux.mkdir(parents=True, exist_ok=True, mode=0o700)
    (gen / "overtls").mkdir(parents=True, exist_ok=True, mode=0o700)
    (gen / "shadowsocksr").mkdir(parents=True, exist_ok=True, mode=0o700)

    secrets_path = aux / "secrets.json"
    saved = load_preserved_json(secrets_path)
    if saved:
        if not isinstance(saved.get("overtls_path"), str) or not isinstance(saved.get("ssr_password"), str):
            raise RuntimeError("preserved auxiliary secret state is incomplete; refusing silent credential rotation")
        tunnel_path = saved["overtls_path"]
        ssr_password = saved["ssr_password"]
        if len(ssr_password) < 20:
            raise RuntimeError("preserved SSR password is invalid; refusing silent credential rotation")
    else:
        tunnel_path = "/rvpn-" + secrets.token_hex(18) + "/"
        ssr_password = secrets.token_urlsafe(28)
    if not tunnel_path.startswith("/"):
        tunnel_path = "/" + tunnel_path
    if not tunnel_path.endswith("/"):
        tunnel_path += "/"
    if len(tunnel_path) > 256 or not re.fullmatch(r"/[A-Za-z0-9._~/-]+/", tunnel_path):
        raise RuntimeError("preserved OverTLS path is invalid; refusing silent credential rotation")

    overtls_server = {
        "method": "none",
        "password": "",
        "tunnel_path": tunnel_path,
        "server_settings": {
            "disable_tls": True,
            "forward_addr": "http://127.0.0.1:80",
            "listen_host": "127.0.0.1",
            "listen_port": internal_port,
        },
    }
    overtls_client = {
        "method": "none",
        "password": "",
        "tunnel_path": tunnel_path,
        "client_settings": {
            "disable_tls": False,
            "server_host": endpoint,
            "server_port": overtls_port,
            "server_domain": tls_name,
            "dangerous_mode": False,
            "listen_host": "127.0.0.1",
            "listen_port": 1080,
        },
    }

    ssr_common = {
        "password": ssr_password,
        "method": "aes-256-ctr",
        "protocol": "auth_aes128_md5",
        "protocol_param": "",
        "obfs": "tls1.2_ticket_auth",
        "obfs_param": "",
        "udp": True,
        "idle_timeout": 300,
        "connect_timeout": 6,
        "udp_timeout": 6,
    }
    ssr_server = dict(ssr_common)
    ssr_server["server_settings"] = {"listen_address": "0.0.0.0", "listen_port": ssr_port}
    ssr_server["client_settings"] = {
        "server": endpoint,
        "server_port": ssr_port,
        "listen_address": "127.0.0.1",
        "listen_port": 1080,
    }
    ssr_client = json.loads(json.dumps(ssr_server))
    meta = {
        "overtls_port": overtls_port,
        "overtls_internal_port": internal_port,
        "overtls_path": tunnel_path,
        "overtls_tls_name": tls_name,
        "ssr_port": ssr_port,
        "ssr_method": ssr_common["method"],
        "ssr_protocol": ssr_common["protocol"],
        "ssr_obfs": ssr_common["obfs"],
    }

    # Replace owned auxiliary settings instead of appending duplicate lines on
    # every finalization. All seven outputs are committed as one private batch.
    owned = re.compile(r"(?m)^(?:OVERTLS_PORT|OVERTLS_INTERNAL_PORT|OVERTLS_PATH)='[^']*'\n?")
    settings = owned.sub("", text).rstrip("\n") + "\n"
    settings += f"OVERTLS_PORT={shell_quote(str(overtls_port))}\n"
    settings += f"OVERTLS_INTERNAL_PORT={shell_quote(str(internal_port))}\n"
    settings += f"OVERTLS_PATH={shell_quote(tunnel_path)}\n"

    helper = pathlib.Path(__file__).with_name("atomic-private-batch.py")
    tmp_dir = pathlib.Path(tempfile.mkdtemp(prefix=".aux-generate-", dir=aux))
    try:
        staged = {
            "secrets.json": {"overtls_path": tunnel_path, "ssr_password": ssr_password},
            "overtls-server.json": overtls_server,
            "overtls-client.json": overtls_client,
            "ssr-server.json": ssr_server,
            "ssr-client.json": ssr_client,
            "generated.json": meta,
        }
        for name, value in staged.items():
            stage_json(tmp_dir / name, value)
        settings_tmp = tmp_dir / "settings.env"
        settings_tmp.write_text(settings, encoding="utf-8")
        os.chmod(settings_tmp, 0o600)
        subprocess.run(
            [
                sys.executable,
                str(helper),
                f"{secrets_path}={tmp_dir / 'secrets.json'}",
                f"{aux / 'overtls-server.json'}={tmp_dir / 'overtls-server.json'}",
                f"{gen / 'overtls' / 'overtls-client.json'}={tmp_dir / 'overtls-client.json'}",
                f"{aux / 'ssr-server.json'}={tmp_dir / 'ssr-server.json'}",
                f"{gen / 'shadowsocksr' / 'ssr-client.json'}={tmp_dir / 'ssr-client.json'}",
                f"{aux / 'generated.json'}={tmp_dir / 'generated.json'}",
                f"{tls_settings}={settings_tmp}",
            ],
            check=True,
        )
    finally:
        for child in tmp_dir.iterdir():
            child.unlink(missing_ok=True)
        tmp_dir.rmdir()

    print(f"Generated OverTLS TCP {overtls_port} -> loopback {internal_port} and legacy SSR TCP/UDP {ssr_port}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
