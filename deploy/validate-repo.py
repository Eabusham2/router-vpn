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

ui = text("cmd/client/ui.html")
logical_ui = text("cmd/client/logical_ui.js")
for required in (
    "Router VPN local controller", "Read-only loopback diagnostics", "native Router VPN app",
    "/api/status", "/api/session", "/api/session/events?after=0",
    "Selected-path proof", "Public exit", "DNS proof", "Rollback", "Recent typed events",
    "no connect, profile-edit, admin, forwarding or privileged mutation controls",
):
    if required not in ui:
        error(f"Loopback diagnostics UI missing current boundary: {required}")
for forbidden in (
    "beforeinstallprompt", "serviceWorker.register", "manifest.webmanifest", "installPWA(",
    "/api/auto", "/api/connect-logical", "/api/profile/delete", "/api/forward", "/api/emergency-stop",
):
    if forbidden in ui:
        error(f"Loopback diagnostics UI regained retired/mutating contract: {forbidden}")
for required in ("Compatibility asset", "native apps own daily controls", "diagnostics only"):
    if required not in logical_ui:
        error(f"logical UI compatibility boundary missing: {required}")
for forbidden in (
    "/api/logical-modes", "connectLogicalMode", "beforeinstallprompt", "serviceWorker.register", "installPWA(",
):
    if forbidden in logical_ui:
        error(f"logical UI compatibility asset regained retired product behavior: {forbidden}")

android = text("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java")
for required in (
    "Run full onboarding again", "server/portainer-current.yaml",
    "Connect native WireGuard", "Connect native AmneziaWG 2",
    "Connect embedded layered mode", "AUTO — first proven working mode",
    "SMART AUTO — simplify and restore safely", "Multihop — choose entry → exit",
    "Strict embedded libbox/Xray sessions require", "Shadowsocks or Hysteria2 exit",
    "AWG-entry multihop", "Network changes reset/revalidate libbox and native Xray",
):
    if required not in android:
        error(f"Android onboarding/capability contract missing: {required}")
for rel, required_values in {
    "android/app/src/main/java/com/eabusham/routervpn/AndroidPathProbe.java": (
        "AndroidNodeStore.stableNodeIdentity(bundle)", 'body.optString("node_id"', 'body.optString("proof"',
    ),
    "android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java": (
        'proxy.put("detour", "entry-wg")', '"shadowsocks".equals(exitMode)', '"hysteria2".equals(exitMode)',
    ),
}.items():
    body = text(rel)
    for required in required_values:
        if required not in body:
            error(f"{rel} missing current Android runtime truth: {required}")

ios = text("ios/RouterVPN/App/ContentView.swift")
for required in (
    "Run full onboarding", "server/portainer-current.yaml",
    "fail visibly rather than fake a successful VPN connection",
):
    if required not in ios:
        error(f"iOS app contract missing: {required}")
packet = text("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift")
for required in (
    "import WireGuardKit", "WireGuardAdapter(with: self)", "RouterVPNWireGuardConfig.parse",
    "strict Apple kill switch requested", 'case "libbox":', 'case "external-libbox":',
    "RouterVPNLibboxEngine", "proveExternalExit", "deriveNodeProof",
    'body["node_id"] as? String == expectedNodeID', 'body["proof"] as? String == Self.proofKind', "completionHandler(nil)",
):
    if required not in packet:
        error(f"iOS PacketTunnel missing current WireGuard/Libbox truth: {required}")
selector = text("ios/RouterVPN/App/IOSRuntimeSelection.swift")
for required in (
    'case libbox = "libbox"', "sing-box.json",
    "Xray-only, AmneziaWG-only, ALL/MAX and multihop combinations remain unavailable instead of faking Connected.",
):
    if required not in selector:
        error(f"iOS runtime selection truth boundary missing: {required}")
external_ios = text("ios/RouterVPN/App/RouterVPNModelExternal.swift")
for required in (
    "external-libbox", "External OpenVPN — unavailable on iOS until a pinned native Apple OpenVPN dataplane exists",
    "exact public-exit proof",
):
    if required not in external_ios:
        error(f"iOS external-node truth boundary missing: {required}")
if "Link AmneziaWGKit/Xray engine before signing this target." in packet:
    error("iOS PacketTunnel still contains the retired unavailable-engine stub")
models = text("ios/RouterVPN/App/Models.swift")
for required in ("nodeProofID", "node_proof_id", "nodeProofId", "Router bundle node proof ids disagree"):
    if required not in models:
        error(f"iOS bundle model does not preserve stable node proof identity: {required}")
project = text("ios/RouterVPN/project.yml")
for required in (
    "NSLocalNetworkUsageDescription", "com.apple.networkextension.packet-tunnel",
    "WireGuardKit", "2fec12a6e1f6e3460b6ee483aa00ad29cddadab1",
    "Build pinned wireguard-go bridge", "libwg-go.a",
):
    if required not in project:
        error(f"iOS pinned native build contract missing: {required}")

client_main = text("cmd/client/main.go")
for required in (
    "a.testHealth(p)", "PathProbeURL", "transport.Proxy = nil", "validateSelectedNodeProof(p, body)",
    "selected-router path proof failed", "http://10.77.0.1:8787/health", "NodeProofID",
    "newStagedBundle(", "nodeProofIDFromWGConfig(wgData)", "p.NodeProofID = derivedNodeID",
):
    if required not in client_main:
        error(f"client selected-path proof contract missing: {required}")
node_proof = text("cmd/client/node_proof.go")
for required in (
    "router-vpn-private-agent-v1", "router-vpn-node-proof-v1\\n", "generated", "wg.conf",
    "p.NodeProofID", "proof.NodeID != expected", "proof.Proof != desktopNodeProofKind",
    "selected router has no saved WireGuard identity profile",
):
    if required not in node_proof:
        error(f"desktop exact node-proof contract missing: {required}")
node_proof_test = text("cmd/client/node_proof_test.go")
for required in ("ok-only", "wrong-node", "wrong-kind", "not-ok", "persisted proof mismatch accepted"):
    if required not in node_proof_test:
        error(f"desktop node-proof negative test missing: {required}")
if "connectivitycheck.gstatic.com" in client_main:
    error("client reintroduced generic public Internet health success as a tunnel proof")

windows_app = text("client/RouterVPN-Windows-App.ps1")
for required in (
    "PresentationFramework", "http://127.0.0.1:8788", "ShowDialog()", "SelfTest",
    "/api/status", "/api/profiles", "/api/logical-modes", "/api/connect-logical", "/api/emergency-stop",
):
    if required not in windows_app:
        error(f"native Windows app contract missing: {required}")
portable = text("cmd/portable-launcher/main.go")
for required in ("RouterVPN-Windows-App.ps1", "openNativeApp(nativeApp)", "nativeCmd.Wait()", "-SelfTest"):
    if required not in portable:
        error(f"Windows Portable native-app lifecycle missing: {required}")
for forbidden in ("msedge.exe", "chrome.exe", "--app=", "openAppWindow", "browserCmd"):
    if forbidden in portable:
        error(f"Windows Portable still launches a browser shell: {forbidden}")

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

finalizer = text("server/finalize/finalize.sh")
initializer = text("server/init/noninteractive.sh")
if "publish-downloads.sh" not in finalizer:
    error("finalizer does not publish lightweight Setup Center assets")
if 'zip -qr "$BASE/router-vpn-client-bundle.zip"' in finalizer:
    error("finalizer reintroduced a permanent giant client ZIP")
if "zip -qr" in initializer and "router-vpn-client-bundle.zip" in initializer:
    error("initializer reintroduced a persistent private credential ZIP")
for required in (
    'rm -f "$BASE/downloads/router-vpn-client-bundle.zip" "$BASE/router-vpn-client-bundle.zip"',
    "builds the private link bundle only on demand",
):
    if required not in initializer:
        error(f"initializer missing private-bundle cleanup contract: {required}")

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
for required in (
    "router-local-generic-build",
    "requested-generic-package-only",
    "generic_packages_secret_free",
    "separate-bundle-or-pairing",
    "server_cache",
    "router-vpn-windows-portable-amd64.zip",
):
    if required not in publisher:
        error(f"Setup Center publisher missing current generic/private split policy: {required}")
if "On-demand home-linked no-install portable folder" in publisher:
    error("Setup Center publisher still labels generic Portable packages as home-linked")

package_builds = text("deploy/package-builds.sh")
if "check-generic-package-secrets.py" not in package_builds:
    error("generic package build does not run the secret/leak scanner")

for rel in (".github/workflows/keep-main-only.yml", ".github/workflows/build-all.yml"):
    workflow = text(rel)
    if "git/refs/heads" in workflow and "--method DELETE" in workflow:
        error(f"{rel} blindly deletes branches; inspect merge/content before any deletion")

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

for rel in ("server/install.sh", "server/upgrade.sh", "server/manage.sh"):
    body = text(rel)
    if "ROUTER_VPN_PRODUCTION_COMPOSE" not in body:
        error(f"{rel} does not require the generated exact-SHA production compose")
    if "verify-production-compose.py" not in body and rel != "server/manage.sh":
        error(f"{rel} does not verify the generated exact-SHA production compose")
    if rel == "server/manage.sh" and (
        "server/portainer-current.yaml" not in body or "intentionally rejected" not in body
    ):
        error("server/manage.sh does not clearly reject the tracked production baseline")
    if re.search(r"COMPOSE=.*server/portainer-current\.yaml", body):
        error(f"{rel} silently reintroduced the tracked baseline as a deploy target")
    if "portainer-compose.yaml" in body:
        error(f"{rel} reintroduced legacy build compose")
    if re.search(r"docker\s+compose\b[^\n]*\bbuild\b", body):
        error(f"{rel} explicitly builds server images")

release_candidate = text(".github/workflows/release-candidate.yml")
if re.search(r"(?m)^\s*dist/SHA256SUMS\s*$", release_candidate):
    error("release-candidate generic artifact ships build-tree SHA256SUMS with non-artifact-relative paths")
if "dist/packages/*" not in release_candidate or "(cd dist/packages && sha256sum -c SHA256SUMS)" not in release_candidate:
    error("release-candidate generic artifact is missing the self-contained package checksum contract")

for rel, markers in {
    "deploy/materialize-production-compose.py": ("GENERATED exact-SHA Router VPN production compose", "server/portainer-current.yaml"),
    "server/scripts/verify-production-compose.py": ("not a generated exact-SHA Router VPN production compose", "moving Router VPN image tag"),
    ".github/workflows/production-release-compose.yml": ("Exact-SHA production compose", "GITHUB_SHA", "RouterVPN-production-compose-"),
    "docs/PRODUCTION-RELEASE.md": ("template/baseline", "Exact-SHA production compose", "verify-production-compose.py"),
}.items():
    body = text(rel)
    for marker in markers:
        if marker not in body:
            error(f"{rel} missing exact-SHA production release marker: {marker}")

workflow_root = ROOT / ".github" / "workflows"
if workflow_root.is_dir():
    for workflow_path in workflow_root.glob("*.yml"):
        workflow_body = workflow_path.read_text(encoding="utf-8", errors="replace")
        if "gh issue comment" in workflow_body:
            error(f"{workflow_path.relative_to(ROOT)} uses GitHub issues as a CI status side channel")
        if re.search(r"(?m)^\s*issues:\s*write\s*$", workflow_body):
            error(f"{workflow_path.relative_to(ROOT)} grants forbidden issue-write permission")

pins = {
    "server/init/Dockerfile": (
        "golang:1.24.13-alpine", "golang:1.24.13-bookworm",
        "ghcr.io/sagernet/sing-box:v1.13.12",
        "ghcr.io/xtls/xray-core:26.7.11", "ghcr.io/rosenpass/rosenpass:sha-00569eb",
    ),
    "server/awg2/Dockerfile": (
        "golang:1.25.12-bookworm",
        "AWG_GO_COMMIT=0527dfa47639714dd8f5c9ffbd9d40d19083f0ba",
        "AWGTOOLS_COMMIT=5e882890fbca2316f8ca40e992789d24f67f0118",
    ),
    "server/rosenpass/Dockerfile": (
        "ghcr.io/rosenpass/rosenpass:sha-00569eb",
        "AWGTOOLS_COMMIT=5e882890fbca2316f8ca40e992789d24f67f0118",
    ),
    "server/naive/Dockerfile": ("pocat/naiveproxy:v2.11.4", "forward_proxy"),
    "server/ss-v2ray/Dockerfile": ("golang:1.23.12-alpine", "V2RAY_PLUGIN_COMMIT=e9af1cdd2549d528deb20a4ab8d61c5fbe51f306", "ghcr.io/shadowsocks/ssserver-rust:v1.24.0"),
    "server/aux-proxies/Dockerfile": ("OVERTLS_VERSION=0.3.12", "SSR_COMMIT=227127c4bc5a6555e0556693d084c96860e75b5e"),
}
for rel, required_values in pins.items():
    body = text(rel)
    for value in required_values:
        if value not in body:
            error(f"{rel} missing required pin: {value}")

guide = text("docs/CURRENT-GUIDE.md")
for required in ("server/portainer-current.yaml", "TCP      80      -> 18080", "14443", "15443", "14444", "DAITA-like"):
    if required not in guide:
        error(f"CURRENT-GUIDE missing current setup detail: {required}")

if ERRORS:
    print("Repository validation failed:", file=sys.stderr)
    for message in ERRORS:
        print(" - " + message, file=sys.stderr)
    raise SystemExit(1)

print(
    f"Validated Router VPN product contract: {len(modes)} raw entries, {len(logical)} logical modes, "
    "exact selected-node identity proof, honest native-app/platform boundaries, non-destructive branch policy, ASUS forwarding, "
    "image-only Portainer production, secret-free generic apps + separate private node linking, "
    "GitHub-first/router-local generic fallback, dynamic ephemeral broker, exact pins and current docs."
)
