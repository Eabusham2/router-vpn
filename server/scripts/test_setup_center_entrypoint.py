#!/usr/bin/env python3
from pathlib import Path

p = Path(__file__).with_name("run-setup-center.sh")
s = p.read_text(encoding="utf-8")
required = (
    "setup-center-ai-server.py",
    "ROUTER_VPN_BASE",
    "ROUTER_VPN_SETUP_BIND",
    "ROUTER_VPN_SETUP_PORT",
    'exec python3 "$SCRIPT"',
)
for marker in required:
    assert marker in s, marker
for forbidden in ("OPENAI_API_KEY=", "--api-key", "sk-", "eval ", "sh -c"):
    assert forbidden not in s, forbidden
print("Setup Center AI-aware entrypoint contract: PASS")
