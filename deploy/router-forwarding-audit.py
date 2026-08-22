#!/usr/bin/env python3
"""Fail closed if ASUS WAN forwarding or server reserved-port protection drifts."""
from __future__ import annotations

from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "router/asus-merlin-router-vpn-forwards.sh"
text = SCRIPT.read_text(encoding="utf-8")

expected_dnat = [
    ("tcp", "$ACME_EXTERNAL_PORT", "$ACME_INTERNAL_PORT"),
    ("tcp", "$REALITY_PORT", "$REALITY_PORT"),
    ("udp", "$AWG_PORT", "$AWG_PORT"),
    ("tcp", "$SS_PORT", "$SS_PORT"),
    ("udp", "$SS_PORT", "$SS_PORT"),
    ("udp", "$HY2_PORT", "$HY2_PORT"),
    ("tcp", "$XRAY_PQ_PORT", "$XRAY_PQ_PORT"),
    ("tcp", "$XHTTP_PORT", "$XHTTP_PORT"),
    ("tcp", "$SS_V2RAY_PORT", "$SS_V2RAY_PORT"),
    ("tcp", "$NAIVE_PORT", "$NAIVE_PORT"),
    ("udp", "$NAIVE_PORT", "$NAIVE_PORT"),
    ("tcp", "$OVERTLS_PORT", "$OVERTLS_PORT"),
    ("tcp", "$SSR_PORT", "$SSR_PORT"),
    ("udp", "$SSR_PORT", "$SSR_PORT"),
    ("udp", "$WG_PORT", "$WG_PORT"),
    ("udp", "$ROSENPASS_PORT", "$ROSENPASS_PORT"),
]
expected_fwd = [(proto, internal) for proto, _external, internal in expected_dnat]


def calls(name: str, argc: int) -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith(name + " "):
            continue
        parts = re.findall(r'"([^"\n]+)"|(\S+)', line[len(name):].strip())
        tokens = tuple(a or b for a, b in parts)
        if len(tokens) == argc:
            out.append(tokens)
    return out

actual_dnat = calls("add_dnat", 3)
actual_fwd = calls("add_fwd", 2)
assert actual_dnat == expected_dnat, f"WAN DNAT allowlist drifted: {actual_dnat!r}"
assert actual_fwd == expected_fwd, f"WAN FORWARD allowlist drifted: {actual_fwd!r}"

private_ports = {22, 53, 1080, 3000, 8786, 8787, 8789, 8790, 8791, 8792, 9443, 14444, 18080, 45999}
for forbidden in private_ports:
    value = str(forbidden)
    assert all(value not in token for call in actual_dnat + actual_fwd for token in call), f"private port {forbidden} became WAN-forwarded"

# WAN scoping and destination scoping are mandatory. No broad chain jump.
for marker in (
    'ensure_jump nat PREROUTING -i "$WAN" -j "$NAT_CHAIN"',
    'ensure_jump filter FORWARD -i "$WAN" -d "$DST" -j "$FWD_CHAIN"',
    'iptables -t nat -A "$NAT_CHAIN" -p "$PROTO" --dport "$EXT" -j DNAT --to-destination "$DST:$INT"',
    'iptables -A "$FWD_CHAIN" -p "$PROTO" --dport "$PORT" -j ACCEPT',
):
    assert marker in text, f"forwarding scope marker missing: {marker}"
assert 'ensure_jump nat PREROUTING -j "$NAT_CHAIN"' not in text, "NAT chain jump lost WAN interface scope"
assert 'ensure_jump filter FORWARD -j "$FWD_CHAIN"' not in text, "FORWARD chain jump lost WAN/destination scope"

# Merlin integration must append only Router VPN's own hook line and preserve all
# unrelated nat-start/firewall-start content. Removal must likewise delete only
# Router VPN's exact lines.
for marker in (
    '[ -f "$FILE" ] || printf \'#!/bin/sh\\n\' > "$FILE"',
    'grep -Fqx "$LINE" "$FILE" 2>/dev/null || printf \'%s\\n\' "$LINE" >> "$FILE"',
    'write_hook "$NAT_START" "$RUNTIME apply-nat"',
    'write_hook "$FIREWALL_START" "$RUNTIME apply-filter"',
    "sed -i '\\|/jffs/scripts/router-vpn-forward.sh apply-nat|d' \"$NAT_START\"",
    "sed -i '\\|/jffs/scripts/router-vpn-forward.sh apply-filter|d' \"$FIREWALL_START\"",
):
    assert marker in text, f"Merlin hook preservation marker missing: {marker}"

for forbidden in (
    'cat > "$NAT_START"', 'cat > "$FIREWALL_START"',
    ': > "$NAT_START"', ': > "$FIREWALL_START"',
    'rm -f "$NAT_START"', 'rm -f "$FIREWALL_START"',
):
    assert forbidden not in text, f"Router VPN would overwrite/remove unrelated Merlin hook content: {forbidden}"

# Fresh installs and upgrades both need the same private management protection.
# New installs inherit router-agent.json.example; upgrades keep older persisted
# JSON, so reserved_dynamic.go must independently add every fixed private port.
example = json.loads((ROOT / "configs/router/router-agent.json.example").read_text(encoding="utf-8"))
example_reserved = {int(port) for port in example.get("reserved_ports", [])}
assert private_ports <= example_reserved, f"fresh-install router-agent example omits private ports: {sorted(private_ports-example_reserved)}"

dynamic = (ROOT / "cmd/router-agent/reserved_dynamic.go").read_text(encoding="utf-8")
match = re.search(r'for _, p := range \[\]int\{(.*?)\}\s*\{\s*reserved\[p\] = true', dynamic, re.S)
assert match, "upgrade-time fixed reserved-port augmentation is missing"
dynamic_fixed = {int(value) for value in re.findall(r'\b(\d{2,5})\b', re.sub(r'//.*', '', match.group(1)))}
assert private_ports <= dynamic_fixed, f"upgrade-time reserved ports omit: {sorted(private_ports-dynamic_fixed)}"
for marker in (
    '"overtls_internal_port"',
    '"overtls_port"',
    '"ssr_port"',
    '"ss_v2ray_port"',
    '"naive_port"',
    'ListenPort',
    'transports", "server.json"',
    'xray", "server.json"',
    'rosenpass", "server.toml"',
):
    assert marker in dynamic, f"dynamic custom listener reservation lost marker: {marker}"

print("ASUS WAN forwarding + upgrade-safe reserved-port audit: OK")
