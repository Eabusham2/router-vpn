#!/usr/bin/env python3
"""Router VPN repository-wide product, security and native-capability audit."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SELF_PREFIX = "deploy/full-audit"
errors: list[str] = []


def body(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing required file: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *needles: str) -> None:
    text = body(rel)
    for needle in needles:
        if needle not in text:
            errors.append(f"{rel}: missing {needle!r}")


def forbid(rel: str, *needles: str) -> None:
    text = body(rel)
    for needle in needles:
        if needle in text:
            errors.append(f"{rel}: contains forbidden/stale {needle!r}")


def repo_hits(needle: str) -> list[str]:
    hits: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "dist" in path.parts:
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(SELF_PREFIX):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if needle in text:
            hits.append(rel)
    return hits


# Trust boundary: selected private node proof, never generic Internet success.
require("cmd/client/main.go", "selected-router path proof", "PathProbeURL", "pathProofTarget")
hits = repo_hits("connectivitycheck.gstatic.com/generate_204")
if hits:
    errors.append("public connectivity-check proof remains in: " + ", ".join(hits))

# Typed connection lifecycle/progress/errors/rollback/DNS honesty.
require("cmd/client/session_state.go", "connectionSession", "typedSessionError", "PathProof", "RollbackState", "DNSProof", "/api/session")
require("cmd/client/session_state_test.go", "path_proof_failed", "DNS must not be fabricated as proven")

# Versioned profile/onboarding schemas.
require("internal/common/types.go", "RouterProfileSchemaVersion", "KillSwitchPolicy", "MTUPolicy", "DiagnosticsEnabled", "PathProbeURL")
require("internal/common/onboarding.go", "OnboardingSchemaVersion", "LastReopenedAt", '"connection-validation"')
require("internal/common/profile_schema.go", "NormalizeRouterProfile", "future", "HomeLANAccess")

# Generic application packages remain secret-free and licensed; node linking is separate.
require("deploy/check-generic-package-secrets.py", "generic package contains private bundle", "generic package contains linked router profiles", "package does not ship LICENSE")
require("server/scripts/build-download-on-demand.py", "safe_extract_zip", "safe_extract_tar", "source package is already linked to a node")
publisher = body("server/scripts/publish-downloads.sh")
for leaked_copy in (
    'copy_static "$BUNDLE/router-vpn-bundle.json"',
    'copy_static "$BUNDLE/CREDENTIALS.txt"',
    'copy_public "$BUNDLE/router-vpn-bundle.json"',
    'copy_public "$BUNDLE/CREDENTIALS.txt"',
):
    if leaked_copy in publisher:
        errors.append(f"private node material statically published: {leaked_copy}")
require("server/scripts/publish-downloads.sh", '"$OUT"/router-vpn-bundle.json', '"$OUT"/CREDENTIALS.txt', "server_cache")

# Archive traversal/bomb defense + bounded ephemeral jobs/cleanup.
require("server/scripts/build-download-on-demand.py", "MAX_UNPACKED", "archive symlink is not allowed", "unsafe archive path")
require("server/scripts/download-broker.py", "MAX_COMPRESSION_RATIO", "GitHub artifact contains a symlink", "cleanup_stale_temp")
require("server/scripts/download_jobs.py", "JOB_TTL_SECONDS", "delivery-interrupted", "cancel_requested", "_cleanup_dir")
require("server/scripts/test_download_jobs.py", "interrupted delivery temp directory was not removed")

# Typed interoperable imports/QR only.
require("server/scripts/import_payloads.py", "sip002_uri", "parse_sip002", "ssr_uri", "parse_ssr", "validate_hysteria2_uri")
require("server/scripts/normalize-setup-imports.py", '"sip002"', '"ssr-uri"', '"qrSupported"')
require("server/scripts/test_setup_imports.py", "SIP002", "SSR", "Hysteria")

# Authenticated Setup Center + router-only credential + one-time LAN pairing.
require("server/scripts/ensure-setup-auth.py", "setup-center.token", "0o600", "Never print the token")
require("server/scripts/pairing.py", "one_time", "lan_source", "MAX_FAILURES_PER_MINUTE", "invalid or expired pairing code")
require("server/scripts/download-broker.py", "hmac.compare_digest", "HttpOnly; SameSite=Strict", "/api/pairing/redeem", "apple_local_network_permission_required")
require("server/scripts/test_broker_security.py", "status == 401", "status == 403", "X-Router-VPN-Pairing")

# Sensitive router-agent mutations require bearer token + tunnel source.
require("cmd/router-agent/main.go", "ConstantTimeCompare", "source is not a tunnel peer", "validateForward", "allowedRanges", "formatDNAT")
require("cmd/router-agent/main_test.go", "missing bearer token was authorized", "Protected DMZ", "IPv6")

# Branch hygiene: detect unexpected branches; never auto-delete arbitrary refs.
for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
    text = workflow.read_text(encoding="utf-8", errors="ignore")
    if "--method DELETE" in text and "git/refs/heads" in text:
        errors.append(f"workflow blindly deletes branches: {workflow.relative_to(ROOT)}")
require(".github/workflows/keep-main-only.yml", "Unexpected non-main branch", "exit 1")

# Portable owns UI/controller lifecycle and always performs emergency stop.
require("cmd/portable-launcher/main.go", "Portable clean-exit requires", "browserCmd.Wait", "stopPortableController", 'localURL+"api/emergency-stop"')
forbid("cmd/portable-launcher/main.go", "url.dll,FileProtocolHandler")

# UI shows real session validation and policy intent != runtime readiness.
require("cmd/client/logical_ui.js", "Connection validation", "/api/session", "Selected-node path proof", "DNS proof", "policy intent", "not proof that this platform currently enforces it")
forbid("cmd/client/logical_ui.js", "always shows all 20 modes")

# Android raw WireGuard is a real embedded backend; other native families remain gated.
require("android/app/build.gradle", "com.wireguard.android:tunnel:1.0.20260102")
require("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "GoBackend", "State.UP", "Config.parse", 'optJSONObject("wg")')
require("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java", "VpnService.prepare(this)", "does not fake a live all-mode VPN connection", "automatic reconnect are still unavailable")

# Windows raw WireGuard uses official native tunnel-service operation, never WSL for raw WG.
require("client/native-wireguard-windows.ps1", "WireGuard\\wireguard.exe", "/installtunnelservice", "/uninstalltunnelservice", "Is-Administrator", "Unsafe WireGuard profile path")
if "wsl.exe" in body("client/native-wireguard-windows.ps1"):
    errors.append("native Windows raw WireGuard helper contains WSL")
require("client/Prepare-Windows-Mode-Catalog-v2.ps1", "$mode.id -eq 'wg'", "native-wireguard-windows.ps1", "requires WSL2/default Linux until its native Windows adapter is implemented")
require("cmd/client/windows_runtime.go", "Prepare-Windows-Mode-Catalog-v2.ps1")
require("cmd/portable-launcher/main.go", 'modeID == "wg"', "native-wireguard-windows.ps1")

# Apple Packet Tunnel stays fail-closed until the actual Go/native engine bridge is linked.
require("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", "Link AmneziaWGKit/Xray engine before signing this target.", "engineUnavailable")
require("ios/RouterVPN/project.yml", "NSLocalNetworkUsageDescription", "_routervpn._tcp", "packet-tunnel-provider")

# Production image tags must not float latest/main.
for line in body("server/portainer-current.yaml").splitlines():
    stripped = line.strip()
    if stripped.startswith("image:"):
        value = stripped.split(":", 1)[1].strip()
        if value.endswith(":latest") or value.endswith(":main"):
            errors.append(f"floating production image tag: {value}")

# The retired Windows catalog v1 may not be selected by any runtime path.
for rel in ("cmd/client/windows_runtime.go", "cmd/portable-launcher/main.go", "deploy/package-builds.sh", "client/Setup-Windows-Runtime.ps1"):
    text = body(rel)
    if "Prepare-Windows-Mode-Catalog.ps1" in text and "Prepare-Windows-Mode-Catalog-v2.ps1" not in text:
        errors.append(f"{rel}: selects retired Windows catalog v1")

if errors:
    print("ROUTER VPN FULL AUDIT: FAIL", file=sys.stderr)
    for item in errors:
        print(" - " + item, file=sys.stderr)
    raise SystemExit(1)
print("ROUTER VPN FULL AUDIT: PASS")
