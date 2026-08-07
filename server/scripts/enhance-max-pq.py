#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

base = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
root = base / "client-bundle" / "generated"

branches = {
    "max-tls-wg": ("wg-pq", "10.77.0.1"),
    "max-quic-wg": ("wg-pq", "10.77.0.1"),
    "max-tls-awg": ("awg2-pq", "10.78.0.1"),
    "max-quic-awg": ("awg2-pq", "10.78.0.1"),
}
files = [
    "rosenpass.toml",
    "rosenpass.env",
    "rosenpass-client-public",
    "rosenpass-client-secret",
    "rosenpass-server-public",
]

for branch, (source_name, tunnel_host) in branches.items():
    src = root / source_name
    dst = root / branch
    if not dst.is_dir():
        raise SystemExit(f"missing MAX branch: {branch}")
    for name in files:
        path = src / name
        if not path.is_file() or path.stat().st_size == 0:
            raise SystemExit(f"missing Rosenpass prerequisite: {path}")
        shutil.copy2(path, dst / name)

    toml = dst / "rosenpass.toml"
    text = toml.read_text()
    # MAX runs Rosenpass after the base tunnel exists. Exchange through that private
    # tunnel so the PQ handshake is itself carried by the selected outer MAX chain.
    text = re.sub(
        r'(?m)^endpoint\s*=\s*["\'][^"\']+["\']\s*$',
        f'endpoint = "{tunnel_host}:51822"',
        text,
    )
    toml.write_text(text)

    env = dst / "chain.env"
    e = env.read_text()
    if "PQ_BASE=" not in e:
        e += "PQ_BASE=1\n"
    else:
        e = re.sub(r"(?m)^PQ_BASE=.*$", "PQ_BASE=1", e)
    e = re.sub(
        r"(?m)^CHAIN_LAYERS=(.*)$",
        lambda m: "CHAIN_LAYERS=rosenpass-pq>" + m.group(1) if not m.group(1).startswith("rosenpass-pq>") else m.group(0),
        e,
    )
    env.write_text(e)
    for name in files:
        (dst / name).chmod(0o600)

print("added live Rosenpass PQ exchange inside all MAX WG/AWG TLS/QUIC branches")
