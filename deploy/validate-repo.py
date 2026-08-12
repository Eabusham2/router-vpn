#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ERRORS: list[str] = []

def error(message: str) -> None:
    ERRORS.append(message)

def text(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        error(f"missing required file: {rel}")
        return ""
    return p.read_text()

# Raw runtime catalog + logical app catalog.
try:
    modes = json.loads(text("configs/client/modes.json"))
except Exception as exc:
    modes = []
    error(f"cannot parse configs/client/modes.json: {exc}")
expected_raw = [
    "wg", "awg2-fast", "wg-pq", "shadowsocks", "awg2-strong", "awg2-pq",
    "reality-vision", "hysteria2", "reality-pq-vision", "ss-v2ray",
    "naive-h2", "naive-h3", "split", "reality-xhttp", "max",
    "max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg", "all",
    "smart-auto", "custom",
]
ids = [m.get("id") for m in modes]
if ids != expected_raw:
    error("raw mode catalog is not the agreed 20 runtime profiles + SMART AUTO/CUSTOM order")
if len(ids) != len(set(ids)):
    error("raw mode IDs are not unique")

try:
    logical = json.loads(text("configs/client/logical-modes.json"))
except Exception as exc:
    logical = []
    error(f"cannot parse configs/client/logical-modes.json: {exc}")
if len(logical) != 16:
    error(f"expected 16 logical app modes, got {len(logical)}")
raw_ids = set(ids)
seen: set[str] = set()
for item in logical:
    mode_id = str(item.get("id", ""))
    if not mode_id or mode_id in seen:
        error(f"invalid/duplicate logical mode id: {mode_id!r}")
    seen.add(mode_id)
    variants = item.get("variants") or {}
    if not variants:
        error(f"logical mode has no variants: {mode_id}")
    for runtime in variants.values():
        if runtime not in raw_ids:
            error(f"logical mode {mode_id} references unknown runtime {runtime}")
for mode_id in ("base-raw", "base-pq", "max-quic", "max-tls", "all"):
    item = next((x for x in logical if x.get("id") == mode_id), {})
    if item.get("base_selector") is not True or item.get("fallback") is not True:
        error(f"logical mode {mode_id} must support base selection + fallback")

all_text = text("modes/run-all.sh")
for required in (
    "max-tls-awg max-tls-wg max-quic-awg max-quic-wg",
    "max-tls-wg max-tls-awg max-quic-wg max-quic-awg",
    "HOMEVPN_ALL_RESULT_FILE",
):
    if required not in all_text:
        error(f"ALL fallback/reporting contract missing: {required}")

# Honest platform/UI boundaries.
ui = text("cmd/client/ui.html")
logical_ui = text("cmd/client/logical_ui.js")
for required in (
    "Run full onboarding", "server/portainer-current.yaml",
    "SMART AUTO", "CUSTOM", "Home AdGuard", "DNS Rescue",
    "Protected DMZ", "at least 50 TCP handshake samples",
    "Multi-hop is not mislabeled as ready yet",
):
    if required not in ui:
        error(f"Web UI missing current contract: {required}")
for required in (
    "/api/logical-modes", "Base: Auto (preferred + fallback)",
    "16 logical modes", "selectable/fallback base",
):
    if required not in logical_ui:
        error(f"logical UI extension missing current contract: {required}")

android = text("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java")
for required in (
    "Run full onboarding again", "server/portainer-current.yaml",
    "AUTO / SMART AUTO / CUSTOM", "does not fake a live all-mode VPN connection",
    "14443", "15443", "14444",
):
    if required not in android:
        error(f"Android onboarding/capability contract missing: {required}")

ios = text("ios/RouterVPN/App/ContentView.swift")
for required in (
    "Run full onboarding", "server/portainer-current.yaml",
    "fail visibly rather than fake a successful VPN connection",
):
    if required not in ios:
        error(f"iOS app contract missing: {required}")
packet = text("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift")
for required in ("Link AmneziaWGKit/Xray engine before signing this target.", "completionHandler(error)"):
    if required not in packet:
        error(f"iOS PacketTunnel must fail closed until real engines are linked: {required}")

# ASUS helper contract.
helper = text("router/asus-merlin-router-vpn-forwards.sh")
for required in (
    "ACME_EXTERNAL_PORT=${ACME_EXTERNAL_PORT:-80}",
    "ACME_INTERNAL_PORT=${ACME_INTERNAL_PORT:-18080}",
    "WG_PORT=${WG_PORT:-51820}", "AWG_PORT=${AWG_PORT:-585}",
    "ROSENPASS_PORT=${ROSENPASS_PORT:-51822}",
    "OVERTLS_PORT=${OVERTLS_PORT:-14443}",
    "OverTLS loopback backend 14444 is never WAN-forwarded.",
    "SSR_PORT=${SSR_PORT:-15443}",
    'write_hook "$NAT_START" "$RUNTIME apply-nat"',
    'write_hook "$FIREWALL_START" "$RUNTIME apply-filter"',
):
    if required not in helper:
        error(f"ASUS forwarding helper missing: {required}")
if helper:
    check = subprocess.run(["/bin/sh", "-n", str(ROOT / "router/asus-merlin-router-vpn-forwards.sh")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if check.returncode:
        error("ASUS forwarding helper shell syntax failed")

# Finalizer/download architecture.
finalizer = text("server/finalize/finalize.sh")
if "publish-downloads.sh" not in finalizer:
    error("finalizer does not publish lightweight Setup Center assets")
if 'zip -qr "$BASE/router-vpn-client-bundle.zip"' in finalizer:
    error("finalizer reintroduced a permanent giant client ZIP")

broker = text("server/scripts/download-broker.py")
builder = text("server/scripts/build-download-on-demand.py")
publisher = text("server/scripts/publish-downloads.sh")
for required in (
    "router-local-generic-build",
    "requested-generic-package-only",
    "generic_packages_secret_free",
    "separate-bundle-or-pairing",
    "REQUEST_SLOTS",
    "BUILD_SLOTS",
    "ROUTER_VPN_GITHUB_SHA",
):
    if required not in broker:
        error(f"download broker missing hardened generic/fallback contract: {required}")
for required in ("compile_requested", "GOTOOLCHAIN", "LOCAL_BUILD_TIMEOUT"):
    if required not in builder:
        error(f"on-demand builder missing router-local compiler contract: {required}")
for required in ("router-local-build", "server_cache", "router-vpn-windows-portable-amd64.zip"):
    if required not in publisher:
        error(f"Setup Center publisher missing current download policy: {required}")

# Only one production Compose remains. Portainer 2.33 Git stacks are kept
# image-only; router-local compilation is for requested client packages, not
# Portainer service images.
for legacy in ("server/portainer-compose.yaml", "server/compose.yaml"):
    if (ROOT / legacy).exists():
        error(f"retired legacy deployment compose still exists: {legacy}")

compose_path = ROOT / "server/portainer-current.yaml"
compose = text("server/portainer-current.yaml")
if re.search(r"(?m)^\s*build:\s*$", compose):
    error("Portainer production compose must stay image-only; Git-stack builds are not a reliable fallback")
if "busybox:1.36" in compose:
    error("production compose still references retired BusyBox static :8786 server")
for required in (
    "ghcr.io/sagernet/sing-box:v1.13.12",
    "ghcr.io/xtls/xray-core:26.7.11",
    "/src/server/scripts/download-broker.py",
    '"http://127.0.0.1:8786/healthz"',
    "ROUTER_VPN_GITHUB_SHA:",
):
    if required not in compose:
        error(f"production compose missing: {required}")
if re.search(r"(?m)^\s*context:\s*https?://", compose):
    error("production compose reintroduced a remote Git Docker build context")

expected_images = {
    "init": 3, "agent": 1, "wireguard": 1, "awg2": 1,
    "rosenpass": 1, "naive": 1, "ss-v2ray": 1, "aux": 1,
}
all_runtime_tags: list[str] = []
for image_name, count in expected_images.items():
    matches = re.findall(rf"ghcr\.io/eabusham2/router-vpn-{re.escape(image_name)}:([0-9a-f]{{40}})", compose)
    if len(matches) != count:
        error(f"expected {count} exact-SHA references for router-vpn-{image_name}, found {len(matches)}")
    all_runtime_tags.extend(matches)
if all_runtime_tags and len(set(all_runtime_tags)) != 1:
    error("production custom images are not all pinned to one validated runtime SHA")
broker_sha = re.search(r"(?m)^\s*ROUTER_VPN_GITHUB_SHA:\s*([0-9a-f]{40})\s*$", compose)
if not broker_sha:
    error("broker is not pinned to a full GitHub source SHA")
elif all_runtime_tags and broker_sha.group(1) != all_runtime_tags[0]:
    error("broker artifact SHA does not match production runtime image SHA")
for image in re.findall(r"(?m)^\s*image:\s*([^\s#]+)", compose):
    if image.endswith(":latest"):
        error(f"production compose uses floating latest image: {image}")
for forbidden_port in ("1080", "8786", "8787", "14444", "9443"):
    if re.search(rf"(?m)^\s*ports:\s*.*{forbidden_port}", compose):
        error(f"production compose publishes protected port {forbidden_port}")
if shutil.which("docker") and compose_path.is_file():
    check = subprocess.run(["docker", "compose", "-f", str(compose_path), "config"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if check.returncode:
        error("production compose config failed: " + (check.stderr.strip().splitlines()[-1] if check.stderr else "unknown"))

# Terminal management uses the same image-only production compose and does not
# quietly switch back to a local server build path.
for rel in ("server/install.sh", "server/upgrade.sh", "server/manage.sh"):
    body = text(rel)
    if "server/portainer-current.yaml" not in body:
        error(f"{rel} is not aligned to production compose")
    if "portainer-compose.yaml" in body:
        error(f"{rel} reintroduced legacy build compose")
    if re.search(r"docker\s+compose\b[^\n]*\bbuild\b", body):
        error(f"{rel} explicitly builds server images")

# Important dependency/source pins.
pins = {
    "server/init/Dockerfile": (
        "golang:1.24-bookworm", "ghcr.io/sagernet/sing-box:v1.13.12",
        "ghcr.io/xtls/xray-core:26.7.11", "ghcr.io/rosenpass/rosenpass:sha-00569eb",
    ),
    "server/awg2/Dockerfile": ("golang:1.25.12-bookworm", "AWG_GO_TAG=v3.0.2", "AWGTOOLS_TAG=v1.0.20250901"),
    "server/rosenpass/Dockerfile": ("ghcr.io/rosenpass/rosenpass:sha-00569eb", "AWGTOOLS_TAG=v1.0.20250901"),
    "server/naive/Dockerfile": ("pocat/naiveproxy:v2.11.4", "forward_proxy"),
    "server/ss-v2ray/Dockerfile": ("golang:1.23.12-alpine", "V2RAY_PLUGIN_COMMIT=e9af1cdd2549d528deb20a4ab8d61c5fbe51f306", "ghcr.io/shadowsocks/ssserver-rust:v1.24.0"),
    "server/aux-proxies/Dockerfile": ("OVERTLS_VERSION=0.3.12", "SSR_TAG=0.9.4"),
}
for rel, required_values in pins.items():
    body = text(rel)
    for value in required_values:
        if value not in body:
            error(f"{rel} missing required pin: {value}")

# Current guide/docs boundaries.
guide = text("docs/CURRENT-GUIDE.md")
for required in ("server/portainer-current.yaml", "TCP      80      -> 18080", "14443", "15443", "14444", "DAITA-like", "router-local build of requested package only"):
    if required not in guide:
        error(f"CURRENT-GUIDE missing current setup detail: {required}")

if ERRORS:
    print("Repository validation failed:", file=sys.stderr)
    for message in ERRORS:
        print(" - " + message, file=sys.stderr)
    raise SystemExit(1)

print(
    f"Validated Router VPN product contract: {len(modes)} raw entries, {len(logical)} logical modes, "
    "honest platform boundaries, ASUS forwarding, image-only Portainer production, "
    "GitHub-first/router-local generic client fallback, dynamic ephemeral broker, exact pins and current docs."
)
