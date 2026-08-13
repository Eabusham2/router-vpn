#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing required file: {rel}")
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def require(rel: str, *markers: str) -> None:
    body = read(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing {marker!r}")


def forbid(rel: str, *markers: str) -> None:
    body = read(rel)
    for marker in markers:
        if marker in body:
            errors.append(f"{rel}: forbidden/stale {marker!r}")


# Exact selected-node proof is mandatory on desktop, Android, and Apple.
require(
    "cmd/client/node_proof.go",
    "router-vpn-private-agent-v1",
    "router-vpn-node-proof-v1\\n",
    "proof.NodeID != expected",
    "proof.Proof != desktopNodeProofKind",
    "wg.conf",
)
require(
    "cmd/client/main.go",
    "validateSelectedNodeProof(p, body)",
    "newStagedBundle(",
    "nodeProofIDFromWGConfig(wgData)",
    "p.NodeProofID = derivedNodeID",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidPathProbe.java",
    'body.optString("node_id"',
    'body.optString("proof"',
)
require(
    "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift",
    'body["node_id"] as? String == expectedNodeID',
    'body["proof"] as? String == Self.proofKind',
)

# Desktop private bundle import must use bounded atomic staging, not write directly
# into generated/<profile> before the entire bundle and identity proof validate.
require(
    "cmd/client/bundle_staging.go",
    "safeBundleToken",
    "maxBundleFiles",
    "maxBundleFileBytes",
    "maxBundleTotalBytes",
    ".bundle-staging",
    "os.MkdirTemp",
    "os.Rename",
    "0o600",
)
require(
    "cmd/client/bundle_staging_test.go",
    "RejectsTraversalSeparatorsAndDriveSyntax",
    "FailureLeavesNoGeneratedProfile",
    "CommitsAtomicallyWithPrivateModes",
)
main = read("cmd/client/main.go")
if "newStagedBundle(" not in main or ".writeProfiles(" not in main or ".commit(" not in main:
    errors.append("cmd/client/main.go: atomic bundle staging helper is not wired into real import")

# Saving/editing a linked node must not silently erase or replace its immutable
# node proof identity once that identity has been established.
if not any(marker in main for marker in (
    "existing.NodeProofID",
    "node proof identity",
    "NodeProofID != p.NodeProofID",
)):
    errors.append("cmd/client/main.go: linked-node edit path does not visibly preserve/cross-check NodeProofID")

# Windows must be a real native WPF application, including Portable lifecycle.
require(
    "client/RouterVPN-Windows-App.ps1",
    "PresentationFramework",
    "ShowDialog()",
    "/api/connect-logical",
    "/api/emergency-stop",
    "$SelfTest",
)
require(
    "cmd/portable-launcher/main.go",
    "RouterVPN-Windows-App.ps1",
    "openNativeApp(nativeApp)",
    "nativeCmd.Wait()",
    "-SelfTest",
)
for rel in ("client/RouterVPN-Windows-App.ps1", "cmd/portable-launcher/main.go", "deploy/package-builds.sh"):
    forbid(rel, "msedge.exe", "chrome.exe", "--app=http://127.0.0.1", "WKWebView", "WebView2")

# macOS must ship a native AppKit .app and not a hidden WebKit wrapper.
require(
    "client/macos/RouterVPNMacNative.swift",
    "NSWindow(",
    "NSTabViewController",
    "http://127.0.0.1:8788",
    "/api/connect-logical",
    "/api/emergency-stop",
    "--self-test",
)
forbid("client/macos/RouterVPNMacNative.swift", "import WebKit", "WKWebView")
require(
    "deploy/package-macos-native.sh",
    "RouterVPN.app",
    "RouterVPN-darwin-amd64.tar.gz",
    "RouterVPN-darwin-arm64.tar.gz",
    "check-generic-package-secrets.py",
)
require(
    ".github/workflows/macos-native-app.yml",
    "Native AppKit packages amd64 + arm64",
    "retention-days: 1",
)

# Linux must ship native GTK builds on actual amd64 and ARM runners.
require(
    "client/linux/routervpn-gtk.c",
    "gtk_window_new",
    "gtk_notebook_new",
    "http://127.0.0.1:8788",
    "/api/connect-logical",
    "/api/emergency-stop",
)
forbid("client/linux/routervpn-gtk.c", "WebKit", "WebView", "xdg-open", "sensible-browser")
require(
    "client/linux/build-native-app.sh",
    "gtk+-3.0",
    "libcurl",
    "json-glib-1.0",
    "-Werror",
    "--self-test",
)
require(
    ".github/workflows/linux-native-app.yml",
    "ubuntu-24.04-arm",
    "ubuntu-24.04",
    "retention-days: 1",
)

# iOS must use the real pinned WireGuard preparation path in CI; a stale preview
# build that skips the exact checkout/compatibility preparation is not release-safe.
require(
    "ios/RouterVPN/prepare-wireguard-kit.sh",
    "2fec12a6e1f6e3460b6ee483aa00ad29cddadab1",
    "sys/types.h",
    "swift-tools-version:5.5",
)
client_ci = read(".github/workflows/client-apps-ci.yml")
for marker in ("prepare-wireguard-kit.sh", "RouterVPN-iOS-Native-WireGuard-CI"):
    if marker not in client_ci:
        errors.append(f"client-apps CI missing real iOS native marker: {marker}")

# AI Help must use a real authenticated server-side provider. Credentials are a
# private file and must never be embedded in the browser panel or command line.
require(
    "server/scripts/ai_help_provider.py",
    "https://api.openai.com/v1/responses",
    '"store": False',
    "MAX_CONCURRENT = 2",
    "MAX_REQUESTS_PER_MINUTE = 6",
    "openai-api.key",
    "permissions are too broad",
)
require(
    "server/scripts/setup-center-ai-server.py",
    "/api/ai-help/status",
    "/api/ai-help",
    "self._require_auth()",
    "credentials:'same-origin'",
    "Never return provider/key internals",
)
forbid("server/scripts/setup-center-ai-server.py", "sk-", "Authorization: Bearer", "OPENAI_API_KEY")
require(
    "server/scripts/run-setup-center.sh",
    "setup-center-ai-server.py",
    'exec python3 "$SCRIPT"',
)
require(
    ".github/workflows/ai-help-contract.yml",
    "test_ai_help_provider.py",
    "test_setup_center_ai.py",
    "test_setup_center_entrypoint.py",
)

# Production must invoke the stable wrapper entrypoint. Keep this strict so AI
# Help cannot be counted as integrated while production still starts the old server.
compose = read("server/portainer-current.yaml")
if "run-setup-center.sh" not in compose and "setup-center-ai-server.py" not in compose:
    errors.append("server/portainer-current.yaml: production Setup Center still does not invoke AI-aware authenticated entrypoint")
if re.search(r"(?m)^\s*build:\s*$", compose):
    errors.append("server/portainer-current.yaml: production compose must remain image-only")

# CI artifacts stay short-lived where packages are produced.
for rel in (
    ".github/workflows/client-apps-ci.yml",
    ".github/workflows/macos-native-app.yml",
    ".github/workflows/linux-native-app.yml",
):
    body = read(rel)
    if "retention-days: 1" not in body:
        errors.append(f"{rel}: package artifacts are not pinned to one-day retention")

if errors:
    print("ROUTER VPN RELEASE GAP AUDIT: FAIL", file=sys.stderr)
    for error in errors:
        print(" - " + error, file=sys.stderr)
    raise SystemExit(1)

print("ROUTER VPN RELEASE GAP AUDIT: PASS")
