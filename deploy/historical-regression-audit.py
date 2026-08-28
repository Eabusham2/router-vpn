#!/usr/bin/env python3
"""Keep previously fixed Router VPN production regressions from silently returning."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8", errors="replace")


def require(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        assert marker in body, f"{path}: historical regression marker missing: {marker}"


# AI Board firewall compatibility: nft first, validated iptables variants second,
# and cleanup owns only Router VPN's dedicated NAT rules.
for path, table, subnet in (
    ("server/wireguard/entrypoint.sh", "router_vpn_wg0_nat", "10.77.0.0/24"),
    ("server/awg2/entrypoint.sh", "router_vpn_awg_nat", "10.78.0.0/24"),
):
    require(
        path,
        "iptables-legacy iptables-nft iptables",
        "ip6tables-legacy ip6tables-nft ip6tables",
        f"nft delete table inet {table}",
        subnet,
        "trying iptables-compatible NAT",
    )

# Kernel-module absence must not make the server silently lose its VPN dataplane.
require("server/wireguard/Dockerfile", "wireguard-tools wireguard-go", "command -v wireguard-go")
require("server/awg2/Dockerfile", "AWG_GO_COMMIT=0527dfa47639714dd8f5c9ffbd9d40d19083f0ba", "WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go" if False else "amneziawg-go")
require("server/awg2/entrypoint.sh", "WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go")

# Naive remains the pinned forward-proxy build and owns the public ACME/TLS edge.
require("server/naive/Dockerfile", "FROM pocat/naiveproxy:v2.11.4", "forward_proxy")
require(
    "server/naive/entrypoint.sh",
    "http_port ${ACME_HTTP_PORT}",
    "https_port ${NAIVE_PORT}",
    "auto_https disable_redirects",
    "forward_proxy",
    "reverse_proxy @overtls 127.0.0.1:${OVERTLS_INTERNAL_PORT}",
)

# SS+V2Ray must consume Caddy's public certificate rather than the separate
# sing-box transport certificate; this is the old dual-certificate-path failure.
require(
    "server/ss-v2ray/entrypoint.sh",
    "/caddy-data/caddy/certificates",
    "${TLS_NAME}/${TLS_NAME}.crt",
    "${TLS_NAME}/${TLS_NAME}.key",
    "cert=${CERT};key=${KEY}",
)
compose = read("server/portainer-current.yaml")
assert "/opt/router-vpn/caddy-data:/caddy-data:ro" in compose, "SS+V2Ray lost read-only Caddy certificate volume"
assert "/opt/router-vpn/config/transports/cert.pem:/etc/sing-box/cert.pem:ro" in compose, "sing-box transport certificate path drifted"

# Raw Windows WireGuard must keep its selected-DNS process/runtime/proof hint
# owned by one session. A delayed teardown from an older session may not kill or
# erase the newer session merely because the deterministic paths are reused.
require(
    "client/native-wireguard-windows.ps1",
    "function Test-RuntimeOwner",
    "function New-DnsOwner",
    "function Remove-OwnedDnsHint",
    "$dnsOwnerFile = Join-Path $runDir 'dns.owner'",
    "owner=$($script:dnsOwnerToken)",
    "if (-not (Test-RuntimeOwner)) { return }",
    "DoH3 is unavailable on raw Windows WireGuard",
    "requires a literal DNS upstream IP",
)
windows_raw = read("client/native-wireguard-windows.ps1")
assert "$Host" not in windows_raw, "Windows raw-WG helper revived the read-only $Host variable collision"

# MAX must fail closed on missing/unexpected chain state and on any component
# death; default-expansion on optional variables avoids the old set -u crash.
require(
    "modes/run-max.sh",
    "set -euo pipefail",
    "${CHAIN_READY:-0} == 1",
    "${PQ_BASE:-0} == 1",
    '${OUTER_ENGINE:-}',
    '${PIDS[@]:-}',
    "instead of silently degrading",
)

# ALL must continue through valid MAX branches without opening a cleartext gap,
# publish the branch actually selected, and fail if every branch fails.
require(
    "modes/run-all.sh",
    "HOMEVPN_ALL_RESULT_FILE",
    'python3 "$SCRIPT_DIR/all-result.py" publish "$ROOT" "$RESULT_FILE" "$candidate"',
    "HOMEVPN_KILLSWITCH_HOLD=1",
    "ALL could not establish any validated MAX TLS or MAX QUIC branch.",
)
require(
    "cmd/client/logical_modes.go",
    "func allRuntimeCandidate",
    "ALL reported unknown runtime branch",
    "ALL did not establish a healthy MAX TLS/QUIC branch before timeout",
    '"fallback_used": fallbackUsed',
)

print("historical production + Windows DNS ownership regression audit: PASS")
