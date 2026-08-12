#!/usr/bin/env python3
"""Repository-wide Router VPN product/security/native capability audit v2."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SELF_PREFIX = "deploy/full-audit"
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing required file: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *needles: str) -> None:
    body = read(rel)
    for needle in needles:
        if needle not in body:
            errors.append(f"{rel}: missing contract marker {needle!r}")


def forbid(rel: str, *needles: str) -> None:
    body = read(rel)
    for needle in needles:
        if needle in body:
            errors.append(f"{rel}: forbidden/stale contract marker {needle!r}")


def search_repo(needle: str, *, allow: tuple[str, ...] = ()) -> list[str]:
    found: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "dist" in path.parts:
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(SELF_PREFIX) or rel in allow:
            continue
        try:
            data = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if needle in data:
            found.append(rel)
    return found


def require_any(paths: tuple[str, ...], *needles: str) -> None:
    existing = [p for p in paths if (ROOT / p).is_file()]
    if not existing:
        errors.append("none of required alternative files exist: " + ", ".join(paths))
        return
    body = "\n".join(read(p) for p in existing)
    for needle in needles:
        if needle not in body:
            errors.append(f"{existing}: missing contract marker {needle!r}")


# Selected-node proof cannot regress to a generic Internet health URL.
require("cmd/client/main.go", "selected-router path proof", "PathProbeURL", "pathProofTarget")
stale_health = search_repo("connectivitycheck.gstatic.com/generate_204")
if stale_health:
    errors.append("public connectivity-check health proof remains in: " + ", ".join(stale_health))

# Typed session/progress/error/rollback truthfulness.
require("cmd/client/session_state.go", "connectionSession", "typedSessionError", "PathProof", "RollbackState", "DNSProof", "/api/session")
require("cmd/client/session_state_test.go", "path_proof_failed", "DNS must not be fabricated as proven")

# Shared migration-safe profile/onboarding schema.
require("internal/common/types.go", "RouterProfileSchemaVersion", "KillSwitchPolicy", "MTUPolicy", "DiagnosticsEnabled", "PathProbeURL")
require("internal/common/onboarding.go", "OnboardingSchemaVersion", "LastReopenedAt", '"connection-validation"')
require_any(("internal/common/profile_migration_test.go", "internal/common/profile_schema_test.go", "internal/common/profile_test.go"), "future", "HomeLANAccess")

# Generic app vs private node linking separation + license/secret scan.
require("deploy/check-generic-package-secrets.py", "generic package contains private bundle", "generic package contains linked router profiles", "package does not ship LICENSE")
require("server/scripts/build-download-on-demand.py", "safe_extract_zip", "safe_extract_tar", "source package is already linked to a node")
require("server/scripts/publish-downloads.sh", '"$OUT"/router-vpn-bundle.json', '"$OUT"/CREDENTIALS.txt", "server_cache")
publisher = read("server/scripts/publish-downloads.sh")
for static_copy in ('copy_static "$BUNDLE/router-vpn-bundle.json"', 'copy_static "$BUNDLE/CREDENTIALS.txt"', 'copy_public "$BUNDLE/router-vpn-bundle.json"', 'copy_public "$BUNDLE/CREDENTIALS.txt"'):
    if static_copy in publisher:
        errors.append(f"private node material is statically LAN-published: {static_copy}")

# Archive/path/bomb safety and bounded async-job cleanup.
require("server/scripts/build-download-on-demand.py", "MAX_UNPACKED", "archive symlink is not allowed", "unsafe archive path")
require("server/scripts/download-broker.py", "MAX_COMPRESSION_RATIO", "GitHub artifact contains a symlink", "cleanup_stale_temp")
require("server/scripts/download_jobs.py", "MAX_HISTORY", "JOB_TTL_SECONDS", "delivery-interrupted", "cancel_requested", "_cleanup_dir")
require("server/scripts/test_download_jobs.py", "interrupted delivery temp directory was not removed")

# Typed interoperable imports only; arbitrary JSON/text/SOCKS is not a fake QR.
require("server/scripts/import_payloads.py", "sip002_uri", "parse_sip002", "ssr_uri", "parse_ssr", "validate_hysteria2_uri")
require("server/scripts/normalize-setup-imports.py", '"sip002"', '"ssr-uri"', '"qrSupported"', "actual interoperable import payload")
require("server/scripts/test_setup_imports.py", "SIP002", "SSR", "non-Hysteria URI accepted")

# Authenticated Setup Center + router-only access token + one-time LAN pairing.
require("server/scripts/ensure-setup-auth.py", "setup-center.token", "0o600", "Never print the token")
require("server/scripts/pairing.py", "one_time", "lan_source", "MAX_FAILURES_PER_MINUTE", "invalid or expired pairing code")
require("server/scripts/download-broker.py", "hmac.compare_digest", "HttpOnly; SameSite=Strict", "/api/pairing/redeem", "apple_local_network_permission_required")
require("server/scripts/test_broker_security.py", "status == 401", "status == 403", "X-Router-VPN-Pairing")
for leaked in search_repo("setup-center.token"):
    if leaked.startswith("configs/client/"):
        errors.append(f"Setup Center credential path leaked into public client config: {leaked}")

# Forwarding/DNS mutations need client-control token plus tunnel-source CIDR.
require("cmd/router-agent/main.go", "ConstantTimeCompare", "source is not a tunnel peer", "validateForward", "allowedRanges", "formatDNAT")
require("cmd/router-agent/main_test.go", "missing bearer token was authorized", "Protected DMZ", "IPv6")

# Workflows may detect unexpected branches, never blindly delete them.
for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
    body = workflow.read_text(encoding="utf-8", errors="ignore")
    if "--method DELETE" in body and "git/refs/heads" in body:
        errors.append(f"blind branch deletion is present in workflow: {workflow.relative_to(ROOT)}")
require(".github/workflows/keep-main-only.yml", "Unexpected non-main branch", "exit 1")
forbidden_delete = search_repo('gh api --method DELETE "repos/$GITHUB_REPOSITORY/git/refs/heads')
if forbidden_delete:
    errors.append("branch-deletion command remains in repo: " + ", ".join(forbidden_delete))

# Portable lifecycle must own browser/controller lifetime and emergency-stop.
require("cmd/portable-launcher/main.go", "Portable clean-exit requires", "browserCmd.Wait", "stopPortableController", 'localURL+"api/emergency-stop"')
forbid("cmd/portable-launcher/main.go", "url.dll,FileProtocolHandler")

# UI shows real validation and separates policy intent from runtime capability.
require("cmd/client/logical_ui.js", "Connection validation", "/api/session", "Selected-node path proof", "DNS proof", "policy intent", "not proof that this platform currently enforces it")
forbid("cmd/client/logical_ui.js", "always shows all 20 modes")

# Android raw WireGuard is a real VpnService-backed engine; unsupported families remain gated.
require("android/app/build.gradle", "com.wireguard.android:tunnel:1.0.20260102")
require("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "GoBackend", "State.UP", "Config.parse", 'optJSONObject("wg")')
require("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java", "VpnService.prepare(this)", "does not fake a live all-mode VPN connection", "automatic reconnect are still unavailable")

# Windows raw WireGuard uses official native tunnel service, never WSL for the raw base.
require("client/native-wireguard-windows.ps1", "WireGuard\\wireguard.exe", "/installtunnelservice", "/uninstalltunnelservice", "Is-Administrator", "Unsafe WireGuard profile path")
if "wsl.exe" in read("client/native-wireguard-windows.ps1"):
    errors.append("native Windows WireGuard helper implements the raw tunnel through WSL")
require("client/Prepare-Windows-Mode-Catalog-v2.ps1", "$mode.id -eq 'wg'", "native-wireguard-windows.ps1", "requires WSL2/default Linux until its native Windows adapter is implemented")
require("cmd/client/windows_runtime.go", "Prepare-Windows-Mode-Catalog-v2.ps1")
require("cmd/portable-launcher/main.go", 'modeID == "wg"', "native-wireguard-windows.ps1")

# Apple stays fail-closed until its Go/native packet-engine bridge is truly linked.
require("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", "Link AmneziaWGKit/Xray engine before signing this target.", "engineUnavailable")
require("ios/RouterVPN/project.yml", "NSLocalNetworkUsageDescription", "_routervpn._tcp", "packet-tunnel-provider")

# Production compose cannot float latest/main tags.
compose = read("server/portainer-current.yaml")
for line in compose.splitlines():
    stripped = line.strip()
    if stripped.startswith("image:"):
        value = stripped.split(":", 1)[1].strip()
        if value.endswith(":latest") or value.endswith(":main"):
            errors.append(f"floating production image tag: {value}")

# Retired Windows catalog v1 may remain only as an unreferenced historical file;
# no runtime/package path can select it.
for rel in ("cmd/client/windows_runtime.go", "cmd/portable-launcher/main.go", "deploy/package-builds.sh", "client/Setup-Windows-Runtime.ps1"):
    body = read(rel)
    if "Prepare-Windows-Mode-Catalog.ps1" in body and "Prepare-Windows-Mode-Catalog-v2.ps1" not in body:
        errors.append(f"{rel}: references retired Windows catalog v1")

if errors:
    print("ROUTER VPN FULL AUDIT V2: FAIL", file=sys.stderr)
    for item in errors:
        print(" - " + item, file=sys.stderr)
    raise SystemExit(1)
print("ROUTER VPN FULL AUDIT V2: PASS")
