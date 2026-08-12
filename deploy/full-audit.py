#!/usr/bin/env python3
"""Repository-wide Router VPN product/security/native capability audit.

This intentionally checks *claims* as well as code presence: unsupported native
features must remain unavailable rather than being represented as working.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
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
        if rel in allow:
            continue
        try:
            data = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if needle in data:
            found.append(rel)
    return found


# 1. Selected-node trust proof must not regress to a public internet health URL.
require("cmd/client/main.go", "selected-router path proof", "PathProbeURL", "pathProofTarget")
stale_health = search_repo("connectivitycheck.gstatic.com/generate_204")
if stale_health:
    errors.append("public connectivity-check health proof remains in: " + ", ".join(stale_health))

# 2. Typed session/progress/error truthfulness.
require("cmd/client/session_state.go", "connectionSession", "typedSessionError", "PathProof", "RollbackState", "DNSProof", "/api/session")
require("cmd/client/session_state_test.go", "path_proof_failed", "DNS must not be fabricated as proven")

# 3. Shared migration-safe profile + onboarding contracts.
require("internal/common/types.go", "RouterProfileSchemaVersion", "KillSwitchPolicy", "MTUPolicy", "DiagnosticsEnabled", "PathProbeURL")
require("internal/common/onboarding.go", "OnboardingSchemaVersion", "LastReopenedAt", '"connection-validation"')
require("internal/common/profile_migration_test.go", "future", "home_lan_access")

# 4. Generic application artifacts and private node material must remain separate.
require("deploy/check-generic-package-secrets.py", "generic package contains private bundle", "generic package contains linked router profiles", "package does not ship LICENSE")
require("server/scripts/build-download-on-demand.py", "blank_profile_store", "source package is already linked to a node", "safe_extract_zip", "safe_extract_tar")
require("server/scripts/publish-downloads.sh", '"$OUT"/router-vpn-bundle.json', '"$OUT"/CREDENTIALS.txt', "server_cache")
for static_copy in ('copy_static "$BUNDLE/router-vpn-bundle.json"', 'copy_static "$BUNDLE/CREDENTIALS.txt"', 'copy_public "$BUNDLE/router-vpn-bundle.json"', 'copy_public "$BUNDLE/CREDENTIALS.txt"'):
    if static_copy in read("server/scripts/publish-downloads.sh"):
        errors.append(f"private node material is statically LAN-published: {static_copy}")

# 5. Archive/path/bomb defenses and ephemeral job cleanup.
require("server/scripts/build-download-on-demand.py", "MAX_UNPACKED", "archive symlink is not allowed", "unsafe archive path")
require("server/scripts/download-broker.py", "MAX_COMPRESSION_RATIO", "GitHub artifact contains a symlink", "cleanup_stale_temp")
require("server/scripts/download_jobs.py", "MAX_HISTORY", "JOB_TTL_SECONDS", "delivery-interrupted", "cancel_requested", "_cleanup_dir")
require("server/scripts/test_download_jobs.py", "interrupted delivery temp directory was not removed")

# 6. Typed real import payloads only; no arbitrary-config QR masquerading.
require("server/scripts/import_payloads.py", "sip002_uri", "parse_sip002", "ssr_uri", "parse_ssr", "validate_hysteria2_uri")
require("server/scripts/normalize-setup-imports.py", '"sip002"', '"ssr-uri"', '"qrSupported"', "Compact QR exists only where an actual client import contract exists")
require("server/scripts/test_setup_imports.py", "SIP002", "SSR", "non-Hysteria URI accepted")

# 7. Setup Center authentication + one-time LAN pairing; access token router-only.
require("server/scripts/ensure-setup-auth.py", "setup-center.token", "0o600", "Never print the token")
require("server/scripts/pairing.py", "one_time", "lan_source", "MAX_FAILURES_PER_MINUTE", "invalid or expired pairing code")
require("server/scripts/download-broker.py", "hmac.compare_digest", "HttpOnly; SameSite=Strict", "/api/pairing/redeem", "apple_local_network_permission_required")
require("server/scripts/test_broker_security.py", "status == 401", "status == 403", "X-Router-VPN-Pairing")
for leaked in search_repo("setup-center.token"):
    if leaked.startswith("client/") or leaked.startswith("configs/client/"):
        errors.append(f"Setup Center credential path leaked into client package source: {leaked}")

# 8. Sensitive router mutations must require both bearer credential and tunnel source.
require("cmd/router-agent/main.go", "ConstantTimeCompare", "source is not a tunnel peer", "validateForward", "allowedRanges", "formatDNAT")
require("cmd/router-agent/main_test.go", "missing bearer token was authorized", "Protected DMZ", "IPv6")

# 9. No CI workflow may blindly delete arbitrary branches.
for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
    body = workflow.read_text(encoding="utf-8", errors="ignore")
    if "--method DELETE" in body and "git/refs/heads" in body:
        errors.append(f"blind branch deletion is present in workflow: {workflow.relative_to(ROOT)}")
require(".github/workflows/keep-main-only.yml", "Unexpected non-main branch", "exit 1")
forbidden_delete = search_repo('gh api --method DELETE "repos/$GITHUB_REPOSITORY/git/refs/heads')
if forbidden_delete:
    errors.append("branch-deletion command remains in repo: " + ", ".join(forbidden_delete))

# 10. Portable lifecycle ownership and clean exit.
require("cmd/portable-launcher/main.go", "Portable clean-exit requires", "browserCmd.Wait", "stopPortableController", 'localURL+"api/emergency-stop"')
forbid("cmd/portable-launcher/main.go", "url.dll,FileProtocolHandler")

# 11. Product UI must show typed validation and must not claim stored policy == runtime enforcement.
require("cmd/client/logical_ui.js", "Connection validation", "/api/session", "Selected-node path proof", "DNS proof", "policy intent", "not proof that this platform currently enforces it")
forbid("cmd/client/logical_ui.js", "always shows all 20 modes")

# 12. Android raw WireGuard is real; unsupported native families stay gated.
require("android/app/build.gradle", "com.wireguard.android:tunnel:1.0.20260102")
require("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java", "GoBackend", "State.UP", "Config.parse", 'optJSONObject("wg")')
require("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java", "VpnService.prepare(this)", "does not fake a live all-mode VPN connection", "automatic reconnect are still unavailable")

# 13. Windows raw WireGuard must be native official tunnel-service operation, not WSL.
require("client/native-wireguard-windows.ps1", "WireGuard\\wireguard.exe", "/installtunnelservice", "/uninstalltunnelservice", "Is-Administrator", "Unsafe WireGuard profile path")
if "wsl.exe" in read("client/native-wireguard-windows.ps1"):
    errors.append("native Windows WireGuard helper implements the tunnel through WSL")
require("client/Prepare-Windows-Mode-Catalog-v2.ps1", "$mode.id -eq 'wg'", "native-wireguard-windows.ps1", "requires WSL2/default Linux until its native Windows adapter is implemented")
require("cmd/client/windows_runtime.go", "Prepare-Windows-Mode-Catalog-v2.ps1")
require("cmd/portable-launcher/main.go", 'modeID == "wg"', "native-wireguard-windows.ps1")

# 14. Apple must remain fail-closed until its packet engine bridge is truly linked.
require("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift", "Link AmneziaWGKit/Xray engine before signing this target.", "engineUnavailable")
require("ios/RouterVPN/project.yml", "NSLocalNetworkUsageDescription", "_routervpn._tcp", "packet-tunnel-provider")

# 15. Production compose may not float image tags.
compose = read("server/portainer-current.yaml")
for line in compose.splitlines():
    stripped = line.strip()
    if stripped.startswith("image:"):
        value = stripped.split(":", 1)[1].strip()
        if value.endswith(":latest") or value.endswith(":main"):
            errors.append(f"floating production image tag: {value}")

# 16. Retired PortableApps / stale static-package semantics must not return.
for needle in ("router-vpn-portableapps-amd64.zip", "router-vpn-portableapps-arm64.zip"):
    offenders = search_repo(needle, allow=("deploy/full-audit.py",))
    # Historical cleanup/removal references are okay, publication/download entries are not.
    for rel in offenders:
        body = read(rel)
        if "rm -f" not in body and "test ! -e" not in body and "retired" not in body.lower():
            errors.append(f"retired PortableApps artifact still advertised by {rel}")

if errors:
    print("ROUTER VPN FULL AUDIT: FAIL", file=sys.stderr)
    for item in errors:
        print(" - " + item, file=sys.stderr)
    raise SystemExit(1)

print("ROUTER VPN FULL AUDIT: PASS")
