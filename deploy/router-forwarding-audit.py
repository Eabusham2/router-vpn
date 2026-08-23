#!/usr/bin/env python3
"""Fail closed if ASUS WAN forwarding or server reserved-port protection drifts."""
from __future__ import annotations

from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "router/asus-merlin-router-vpn-forwards.sh"
text = SCRIPT.read_text(encoding="utf-8")

expected_nat = [
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
expected_fwd = [(proto, internal) for proto, _external, internal in expected_nat]


def calls(name: str, argc: int) -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith(name + " "):
            continue
        body = re.sub(r'(?:&&|;)\s*$', '', line[len(name):].strip()).strip()
        parts = re.findall(r'"([^"\n]+)"|(\S+)', body)
        tokens = tuple(a or b for a, b in parts)
        if len(tokens) == argc:
            out.append(tokens)
    return out


actual_nat = calls("ensure_nat", 4)
actual_fwd = calls("ensure_fwd", 3)
# Ignore function-definition body markers; only call sites have a literal WAN first argument.
actual_nat = [c[1:] for c in actual_nat if c[0] == "$WAN"]
actual_fwd = [c[1:] for c in actual_fwd if c[0] == "$WAN"]
assert actual_nat == expected_nat, f"WAN NAT allowlist drifted: {actual_nat!r}"
assert actual_fwd == expected_fwd, f"WAN FORWARD allowlist drifted: {actual_fwd!r}"

forbidden_wan_ports = {22, 53, 1080, 3000, 8786, 8787, 8788, 8789, 8790, 8791, 8792, 8793, 9443, 14444, 18080, 45999}
reserved_server_ports = forbidden_wan_ports - {8788}
for forbidden in forbidden_wan_ports:
    value = str(forbidden)
    assert all(value not in token for call in actual_nat for token in call[:2]), f"private public port {forbidden} became WAN-forwarded"

# The parent-chain hooks themselves are exact. Unrelated WAN packets never jump
# through a Router VPN catch-all chain.
for marker in (
    '"$IPTABLES" -t nat -A PREROUTING -i "$WAN" -p "$PROTO" --dport "$EXT" -m comment --comment "$TAG" -j DNAT --to-destination "$DST:$INT"',
    '"$IPTABLES" -A FORWARD -i "$WAN" -d "$DST" -p "$PROTO" --dport "$PORT" -m state --state NEW -m comment --comment "$TAG" -j ACCEPT',
    '"$IPTABLES" -t nat -C PREROUTING -i "$WAN" -p "$PROTO" --dport "$EXT"',
    '"$IPTABLES" -C FORWARD -i "$WAN" -d "$DST" -p "$PROTO" --dport "$PORT"',
    'TAG=ROUTER_VPN',
    'if ! require_health; then',
    'remove_owned_from_chain nat PREROUTING',
    'remove_owned_from_chain filter FORWARD',
    'apply) apply_all',
    'status) status',
    'verify) verify',
    'remove|uninstall) remove',
):
    assert marker in text, f"narrow/fail-open forwarding marker missing: {marker}"

for forbidden in (
    'ensure_jump nat PREROUTING -i "$WAN" -j',
    'ensure_jump filter FORWARD -i "$WAN" -d "$DST" -j',
    'iptables -t nat -I PREROUTING',
    'iptables -I FORWARD',
):
    assert forbidden not in text, f"broad/reordering Router VPN parent hook returned: {forbidden}"

# Examine only executable iptables mutation lines; comments/status prose may
# mention the forbidden concepts as assertions/documentation.
mutation_lines = []
for raw in text.splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if '"$IPTABLES"' in line and any(tok in line for tok in (" -A ", " -I ", " -D ", " -F ", " -X ", " -P ")):
        mutation_lines.append(line)
mutations = "\n".join(mutation_lines)
for forbidden_re in (
    r"\s-P\s+(INPUT|FORWARD|OUTPUT)\b",
    r"\s-F\s+(PREROUTING|INPUT|FORWARD|OUTPUT|POSTROUTING)\b",
    r"\s-j\s+(DROP|REJECT)\b",
):
    assert not re.search(forbidden_re, mutations), f"unsafe built-in/global firewall mutation detected: {forbidden_re}"
assert "ip6tables -" not in text and '"$IP6TABLES"' not in text, "Router VPN must not modify ip6tables without explicit tested IPv6 forwarding"
assert "ip6tables-save" in text, "verify should read-check IPv6 for unexpected Router VPN tags"

# No Router VPN mutation may target LAN->WAN or broad DNS/DHCP paths.
assert '-s "$LAN"' not in mutations and '-o "$WAN"' not in mutations, "Router VPN forwarding helper may not mutate LAN->WAN path"

# Hooks append one exact owned line and removal filters only exact Router VPN
# invocations; protected/unrelated JFFS lines are not named or rewritten.
for marker in (
    '[ -f "$FILE" ] || printf \'#!/bin/sh\\n\' > "$FILE"',
    'grep -Fqx "$LINE" "$FILE" 2>/dev/null || printf \'%s\\n\' "$LINE" >> "$FILE"',
    'write_hook "$NAT_START" "$RUNTIME apply-nat"',
    'write_hook "$FIREWALL_START" "$RUNTIME apply-filter"',
    'grep -Fvx -- "$LINE" "$FILE" > "$TMP" || true',
):
    assert marker in text, f"Merlin hook preservation marker missing: {marker}"
for forbidden in (
    'cat > "$NAT_START"', 'cat > "$FIREWALL_START"',
    ': > "$NAT_START"', ': > "$FIREWALL_START"',
    'rm -f "$NAT_START"', 'rm -f "$FIREWALL_START"',
):
    assert forbidden not in text, f"Router VPN would overwrite/remove unrelated Merlin hook content: {forbidden}"
for protected in ("cod-na-block.sh", "rogue-dhcp-ra-guard.sh", "att-bgw-guard.sh"):
    assert protected not in text, f"Router VPN helper must not target unrelated protected JFFS script {protected}"

# Runtime verify must reject old broad chains, foreign public ports, duplicates,
# private management exposure, LAN->WAN mutation, and Router VPN IPv6 rules.
for marker in (
    "broad legacy PREROUTING -> ROUTER_VPN_DNAT catch-all still exists",
    "broad legacy FORWARD -> ROUTER_VPN_FWD catch-all still exists",
    "forbidden/private WAN destination port",
    "outside the approved allowlist",
    "duplicate Router VPN NAT rules detected",
    "duplicate Router VPN FORWARD rules detected",
    "Router VPN IPv6 iptables rules exist",
    "Router VPN-owned rule escaped narrow inbound-only scope",
):
    assert marker in text, f"runtime verify lost check: {marker}"

# Fresh installs and upgrades both need the same private management protection.
example = json.loads((ROOT / "configs/router/router-agent.json.example").read_text(encoding="utf-8"))
example_reserved = {int(port) for port in example.get("reserved_ports", [])}
assert reserved_server_ports <= example_reserved, f"fresh-install router-agent example omits private ports: {sorted(reserved_server_ports-example_reserved)}"

dynamic = (ROOT / "cmd/router-agent/reserved_dynamic.go").read_text(encoding="utf-8")
match = re.search(r'for _, p := range \[\]int\{(.*?)\}\s*\{\s*reserved\[p\] = true', dynamic, re.S)
assert match, "upgrade-time fixed reserved-port augmentation is missing"
dynamic_fixed = {int(value) for value in re.findall(r'\b(\d{2,5})\b', re.sub(r'//.*', '', match.group(1)))}
assert reserved_server_ports <= dynamic_fixed, f"upgrade-time reserved ports omit: {sorted(reserved_server_ports-dynamic_fixed)}"
for marker in (
    '"overtls_internal_port"', '"overtls_port"', '"ssr_port"', '"ss_v2ray_port"', '"naive_port"',
    'ListenPort', 'transports", "server.json"', 'xray", "server.json"', 'rosenpass", "server.toml"',
):
    assert marker in dynamic, f"dynamic custom listener reservation lost marker: {marker}"

agent_dockerfile = (ROOT / "deploy/router-agent.Dockerfile").read_text(encoding="utf-8")
for marker in (
    "wireguard-tools", "AWGTOOLS_COMMIT=5e882890fbca2316f8ca40e992789d24f67f0118",
    "/usr/local/bin/awg", "command -v wg", "command -v awg",
):
    assert marker in agent_dockerfile, f"router-agent Emergency Stop tooling lost marker: {marker}"
server_control = (ROOT / "cmd/router-agent/admin_server_control.go").read_text(encoding="utf-8")
assert "collectWireGuardPeers()" in server_control and "removeLivePeer(peer.Interface, peer.PublicKey)" in server_control, "Emergency Stop no longer removes live WireGuard-family peers"

print("ASUS narrow fail-open WAN forwarding + reserved-port + Emergency Stop audit: OK")
