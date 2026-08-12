#!/usr/bin/env python3
"""Stable full Router VPN product/security/native capability audit."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        errors.append(f"missing required file: {rel}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def need(rel: str, *parts: str) -> None:
    text = read(rel)
    for part in parts:
        if part not in text:
            errors.append(f"{rel}: missing contract marker {part!r}")


def no(rel: str, *parts: str) -> None:
    text = read(rel)
    for part in parts:
        if part in text:
            errors.append(f"{rel}: stale/forbidden marker {part!r}")


def hits(needle: str) -> list[str]:
    out: list[str] = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git" in p.parts or "dist" in p.parts:
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith("deploy/full-audit"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if needle in text:
            out.append(rel)
    return out


# Connection trust: selected private node proof only.
need("cmd/client/main.go", "selected-router path proof", "PathProbeURL", "pathProofTarget")
public_health = hits("connectivitycheck.gstatic.com/generate_204")
if public_health:
    errors.append("public Internet health proof remains in: " + ", ".join(public_health))

# Typed lifecycle/progress/errors/rollback.
need("cmd/client/session_state.go", "connectionSession", "typedSessionError", "PathProof", "RollbackState", "DNSProof", "/api/session")
need("cmd/client/session_state_test.go", "path_proof_failed", "DNS must not be fabricated as proven")

# Versioned schema + migrations/onboarding.
need("internal/common/types.go", "RouterProfileSchemaVersion", "RouterProfileStoreVersion", "KillSwitchPolicy", "MTUPolicy", "DiagnosticsEnabled", "PathProbeURL")
need("internal/common/profile_schema.go", "NormalizeRouterProfile", "NormalizeRouterProfileStore", "HomeLANAccess", "newer than supported schema")
need("internal/common/onboarding.go", "OnboardingSchemaVersion", "LastReopenedAt", '"connection-validation"')

# Secret-free generic apps vs private node link material.
need("deploy/check-generic-package-secrets.py", "generic package contains private bundle", "generic package contains linked router profiles", "package does not ship LICENSE")
need("server/scripts/build-download-on-demand.py", "safe_extract_zip", "safe_extract_tar", "source package is already linked to a node")
publisher = read("server/scripts/publish-downloads.sh")
for bad in (
    'copy_static "$BUNDLE/router-vpn-bundle.json"',
    'copy_static "$BUNDLE/CREDENTIALS.txt"',
    'copy_public "$BUNDLE/router-vpn-bundle.json"',
    'copy_public "$BUNDLE/CREDENTIALS.txt"',
):
    if bad in publisher:
        errors.append(f"private node material is statically published: {bad}")
need("server/scripts/publish-downloads.sh", '"$OUT"/router-vpn-bundle.json', '"$OUT"/CREDENTIALS.txt', "server_cache")

# Archive/path/bomb defenses and bounded ephemeral jobs.
need("server/scripts/build-download-on-demand.py", "MAX_UNPACKED", "archive symlink is not allowed", "unsafe archive path")
need("server/scripts/download-broker.py", "MAX_COMPRESSION_RATIO", "GitHub artifact contains a symlink", "cleanup_stale_temp")
need("server/scripts/download_jobs.py", "JOB_TTL_SECONDS", "delivery-interrupted", "cancel_requested", "_cleanup_dir")
need("server/scripts/test_download_jobs.py", "interrupted delivery temp directory was not removed")

# Typed import payloads; no made-up arbitrary QR contract.
need("server/scripts/import_payloads.py", "sip002_uri", "parse_sip002", "ssr_uri", "parse_ssr", "validate_hysteria2_uri")
need("server/scripts/normalize-setup-imports.py", '"sip002"', '"ssr-uri"', '"qrSupported"')
need("server/scripts/test_setup_imports.py", "SIP002", "SSR", "Hysteria")

# Authenticated Setup Center + one-time LAN pairing; token remains router-side.
need("server/scripts/ensure-setup-auth.py", "setup-center.token", "0o600", "Never print the token")
need("server/scripts/pairing.py", "one_time", "lan_source", "MAX_FAILURES_PER_MINUTE", "invalid or expired pairing code")
need("server/scripts/download-broker.py", "hmac.compare_digest", "HttpOnly; SameSite=Strict", "/api/pairing/redeem", "apple_local_network_permission_required")
need("server/scripts/test_broker_security.py", "status == 401", "status == 403", "X-Router-VPN-Pairing")

# Router mutation auth + Protected DMZ/ranges/IPv6 formatting.
need("cmd/router-agent/main.go", "ConstantTimeCompare", "source is not a tunnel peer", "validateForward", "allowedRanges", "formatDNAT")
need("cmd/router-agent/main_test.go", "missing bearer token was authorized", "Protected DMZ", "IPv6")

# Branch policy is detect/fail, never blind delete.
for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
    text = wf.read_text(encoding="utf-8", errors="ignore")
    if "--method DELETE" in text and "git/refs/heads" in text:
        errors.append(f"workflow blindly deletes branches: {wf.relative_to(ROOT)}")
need(".github/workflows/keep-main-only.yml", "Unexpected non-main branch", "exit 1")

# Portable clean exit owns app-window/controller lifetime.
need("cmd/portable-launcher/main.go", "Portable clean-exit requires", "browserCmd.Wait", "stopPortableController", 'localURL+"api/emergency-stop"')
no("cmd/portable-launcher/main.go", "url.dll,FileProtocolHandler")

# Main client UI shows actual proof and clearly labels policy-only fields.
need("cmd/client/logical_ui.js", "Connection validation", "/api/session", "Selected-node path proof", "DNS proof", "policy intent", "not proof that this platform currently enforces it")
no("cmd/client/logical_ui.js", "always shows all 20 modes")

# Android raw WireGuard = real embedded backend; everything else stays capability-gated.
need("android/app/build.gradle", "com.wireguard.android:tunnel:1.0.20260102")
need("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "GoBackend", "State.UP", "Config.parse", 'optJSONObject("wg")')
need("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java", "VpnService.prepare(this)", "does not fake a live all-mode VPN connection", "automatic reconnect are still unavailable")

# Windows raw WireGuard = official native tunnel service; raw base must not use WSL.
need("client/native-wireguard-windows.ps1", "WireGuard\\wireguard.exe", "/installtunnelservice", "/uninstalltunnelservice", "Is-Administrator", "Unsafe WireGuard profile path")
if "wsl.exe" in read("client/native-wireguard-windows.ps1"):
    errors.append("native Windows raw WireGuard helper contains WSL")
need("client/Prepare-Windows-Mode-Catalog-v2.ps1", "$mode.id -eq 'wg'", "native-wireguard-windows.ps1", "requires WSL2/default Linux until its native Windows adapter is implemented")
need("cmd/client/windows_runtime.go", "Prepare-Windows-Mode-Catalog-v2.ps1")
need("cmd/portable-launcher/main.go", 'modeID == "wg"', "native-wireguard-windows.ps1")

# Apple remains deliberately fail-closed until its actual native/Go bridge is linked.
need("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", "Link AmneziaWGKit/Xray engine before signing this target.", "engineUnavailable")
need("ios/RouterVPN/project.yml", "NSLocalNetworkUsageDescription", "_routervpn._tcp", "packet-tunnel-provider")

# Production image refs cannot float latest/main.
for line in read("server/portainer-current.yaml").splitlines():
    s = line.strip()
    if s.startswith("image:"):
        ref = s.split(":", 1)[1].strip()
        if ref.endswith(":latest") or ref.endswith(":main"):
            errors.append(f"floating production image tag: {ref}")

# Runtime paths must use corrected Windows catalog v2, never retired v1.
for rel in ("cmd/client/windows_runtime.go", "cmd/portable-launcher/main.go", "deploy/package-builds.sh", "client/Setup-Windows-Runtime.ps1"):
    text = read(rel)
    if "Prepare-Windows-Mode-Catalog.ps1" in text and "Prepare-Windows-Mode-Catalog-v2.ps1" not in text:
        errors.append(f"{rel}: selects retired Windows catalog v1")

if errors:
    print("ROUTER VPN FULL AUDIT: FAIL", file=sys.stderr)
    for err in errors:
        print(" - " + err, file=sys.stderr)
    raise SystemExit(1)
print("ROUTER VPN FULL AUDIT: PASS")
