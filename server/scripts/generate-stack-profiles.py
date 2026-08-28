#!/usr/bin/env python3
"""Compile compatible combined client profiles from generated router credentials."""
from __future__ import annotations

import copy
import json
import os
import pathlib
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
VERIFIED = runpy.run_path(str(SCRIPT_DIR / "verified-regular-read.py"))
PRIVATE_DIR = runpy.run_path(str(SCRIPT_DIR / "private-directory.py"))
read_verified_regular = VERIFIED["read_verified_regular"]
ensure_private_directory = PRIVATE_DIR["ensure_private_directory"]


def read_private_bytes(path: pathlib.Path) -> bytes:
    return read_verified_regular(path, 32 << 20, private=True)


def load(path: pathlib.Path) -> dict:
    try:
        value = json.loads(read_private_bytes(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid generated JSON prerequisite: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"generated prerequisite is not a JSON object: {path}")
    return value


def write(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def tagged_proxy(config: dict) -> dict:
    for outbound in config.get("outbounds", []):
        if isinstance(outbound, dict) and outbound.get("tag") == "proxy":
            return copy.deepcopy(outbound)
    raise RuntimeError("generated profile has no proxy outbound")


def tun_inbound(config: dict, name: str, mtu: int) -> dict:
    for inbound in config.get("inbounds", []):
        if isinstance(inbound, dict) and inbound.get("type") == "tun":
            result = copy.deepcopy(inbound)
            result["interface_name"] = name
            result["mtu"] = mtu
            return result
    raise RuntimeError("generated profile has no TUN inbound")


def base_config(tun: dict, dns: dict, tcp: dict, udp: dict) -> dict:
    tcp["tag"] = "tcp-stack"
    udp["tag"] = "udp-stack"
    return {
        "log": {"level": "warn"},
        "dns": copy.deepcopy(dns),
        "inbounds": [tun],
        "outbounds": [tcp, udp, {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"protocol": "dns", "action": "hijack-dns"},
                {"network": "tcp", "action": "route", "outbound": "tcp-stack"},
                {"network": "udp", "action": "route", "outbound": "udp-stack"},
            ],
            "auto_detect_interface": True,
            "final": "tcp-stack",
        },
    }


def manifest(name: str, pq: bool, tcp_layers: list[str], udp_layers: list[str]) -> dict:
    return {
        "name": name,
        "transport": "both",
        "post_quantum": pq,
        "shared_layers": [
            "single TUN interface",
            "IPv4 + IPv6 full tunnel",
            "selected tunneled DNS policy",
            "optional DAITA-like cover traffic",
            "optional local SOCKS5-only listener",
        ],
        "tcp_stack": tcp_layers,
        "udp_stack": udp_layers,
    }


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate-stack-profiles.py BASE")
    base = pathlib.Path(os.path.abspath(sys.argv[1]))
    generated = base / "client-bundle" / "generated"
    ensure_private_directory(generated)

    reality_path = generated / "reality-vision" / "sing-box.json"
    reality_xray_path = generated / "reality-vision" / "xray.json"
    hy2_path = generated / "hysteria2" / "sing-box.json"
    hy2_cert_path = generated / "hysteria2" / "cert.pem"
    pq_xray_path = generated / "reality-pq-vision" / "xray.json"
    pq_wrapper_path = generated / "reality-pq-vision" / "sing-box.json"
    for path in (reality_path, reality_xray_path, hy2_path, hy2_cert_path, pq_xray_path, pq_wrapper_path):
        read_private_bytes(path)

    reality = load(reality_path)
    hy2 = load(hy2_path)
    pq_wrapper = load(pq_wrapper_path)
    hy2_outbound = tagged_proxy(hy2)

    tmp_root = pathlib.Path(tempfile.mkdtemp(prefix=".stack-profiles-", dir=generated))
    try:
        split = base_config(
            tun_inbound(reality, "router-vpn-split", 1340),
            reality.get("dns", {}),
            tagged_proxy(reality),
            copy.deepcopy(hy2_outbound),
        )
        split_dir = tmp_root / "split"
        write(split_dir / "xray.json", load(reality_xray_path))
        write(split_dir / "sing-box.json", split)
        (split_dir / "cert.pem").write_bytes(read_private_bytes(hy2_cert_path))
        os.chmod(split_dir / "cert.pem", 0o600)
        write(
            split_dir / "stack.json",
            manifest(
                "Dual Transport",
                False,
                ["VLESS", "REALITY", "XTLS Vision", "Chrome uTLS", "TCP"],
                ["Hysteria2", "QUIC", "TLS 1.3", "Salamander obfuscation", "UDP"],
            ),
        )

        max_tcp = {"type": "socks", "tag": "tcp-stack", "server": "127.0.0.1", "server_port": 1090, "version": "5"}
        max_config = base_config(
            tun_inbound(pq_wrapper, "router-vpn-max", 1280),
            pq_wrapper.get("dns", {}),
            max_tcp,
            copy.deepcopy(hy2_outbound),
        )
        max_dir = tmp_root / "max"
        write(max_dir / "xray.json", load(pq_xray_path))
        write(max_dir / "sing-box.json", max_config)
        (max_dir / "cert.pem").write_bytes(read_private_bytes(hy2_cert_path))
        os.chmod(max_dir / "cert.pem", 0o600)
        write(
            max_dir / "stack.json",
            manifest(
                "PQ Dual Transport",
                True,
                ["VLESS hybrid-PQ encryption", "REALITY", "XTLS Vision", "Chrome uTLS", "TCP"],
                ["Hysteria2", "QUIC", "TLS 1.3", "Salamander obfuscation", "UDP"],
            ),
        )

        catalog = {
            "generated_profiles": ["split", "max"],
            "integrated_adapters": [
                "wg-pq", "awg2-pq", "ss-v2ray", "reality-xhttp", "naive-h2", "naive-h3",
                "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg",
            ],
            "remaining_optional": {
                "exact-daita": "requires a Maybenot-enabled tunnel implementation on both ends",
                "wireguard-over-additional-transports": "use generated MAX TLS/QUIC chains unless another validated transport engine is installed",
            },
        }
        write(tmp_root / "STACK-CATALOG.json", catalog)

        for path in tmp_root.rglob("*"):
            if path.is_file() and path.stat().st_size <= 0:
                raise RuntimeError(f"empty staged combined profile: {path}")

        helper = SCRIPT_DIR / "atomic-private-batch.py"
        args = [sys.executable, str(helper)]
        for rel in (
            "split/xray.json", "split/sing-box.json", "split/cert.pem", "split/stack.json",
            "max/xray.json", "max/sing-box.json", "max/cert.pem", "max/stack.json",
            "STACK-CATALOG.json",
        ):
            src = tmp_root / rel
            dst = generated / rel
            args.append(f"{dst}={src}")
        subprocess.run(args, check=True)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
