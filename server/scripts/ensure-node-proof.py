#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import re
import sys

BASE = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
WG_CLIENT = BASE / "client-bundle" / "generated" / "wg" / "wg.conf"
AGENT_CONFIG = BASE / "config" / "router-agent.json"
PROOF_FILE = BASE / "config" / "node-proof-id"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def peer_public_key(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"missing WireGuard client profile: {path}")
    peer = False
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            peer = line.lower() == "[peer]"
            continue
        if peer and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            if key.lower() == "publickey":
                if not value or len(value) > 128:
                    raise SystemExit("invalid WireGuard server public key in client profile")
                return value
    raise SystemExit("WireGuard server public key is missing from client profile")


def derive(public_key: str) -> str:
    return hashlib.sha256(("router-vpn-node-proof-v1\n" + public_key).encode()).hexdigest()


public_key = peer_public_key(WG_CLIENT)
node_id = derive(public_key)
if not HEX64.fullmatch(node_id):
    raise SystemExit("derived node proof id is invalid")
if not AGENT_CONFIG.is_file():
    raise SystemExit(f"missing router-agent config: {AGENT_CONFIG}")
config = json.loads(AGENT_CONFIG.read_text())
config["node_id"] = node_id
AGENT_CONFIG.write_text(json.dumps(config, indent=2) + "\n")
os.chmod(AGENT_CONFIG, 0o600)
PROOF_FILE.write_text(node_id + "\n")
os.chmod(PROOF_FILE, 0o600)
print(node_id)
