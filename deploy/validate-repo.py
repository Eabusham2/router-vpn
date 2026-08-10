#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import shlex
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ERRORS: list[str] = []


def error(message: str) -> None:
    ERRORS.append(message)


# ----- Mode catalog / product contract -----
modes_path = ROOT / "configs" / "client" / "modes.json"
try:
    modes = json.loads(modes_path.read_text())
except Exception as exc:
    modes = []
    error(f"cannot parse configs/client/modes.json: {exc}")

ids = [m.get("id") for m in modes]
if len(ids) != len(set(ids)):
    error("mode IDs are not unique")
numbered = modes[:20]
if len(numbered) != 20:
    error("expected exactly 20 ordered strength profiles")
else:
    for index, mode in enumerate(numbered, 1):
        if not str(mode.get("name", "")).startswith(f"{index}. "):
            error(f"mode {mode.get('id')} is not numbered {index}")
        for key in (
            "ping_min_ms", "ping_max_ms", "traffic_min_pct", "traffic_max_pct",
            "speed_loss_min_pct", "speed_loss_max_pct",
        ):
            if not isinstance(mode.get(key), (int, float)):
                error(f"{mode.get('id')} missing numeric {key}")
        if mode.get("id") != "all" and not mode.get("layers"):
            error(f"{mode.get('id')} has no layer metadata")

expected_strength_order = [
    "wg", "awg2-fast", "wg-pq", "shadowsocks", "awg2-strong", "awg2-pq",
    "reality-vision", "hysteria2", "reality-pq-vision", "ss-v2ray",
    "naive-h2", "naive-h3", "split", "reality-xhttp", "max",
    "max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg", "all",
]
if ids[:20] != expected_strength_order:
    error("20 strength profiles are not in the agreed lightest-to-strongest order")
if ids[20:] != ["smart-auto", "custom"]:
    error("smart-auto and custom must follow the 20 strength profiles")
for mode in numbered[:19]:
    if not mode.get("auto_eligible"):
        error(f"AUTO strength mode is not auto_eligible: {mode.get('id')}")
if len(numbered) == 20 and numbered[19].get("id") == "all" and numbered[19].get("auto_eligible"):
    error("ALL must not be a normal AUTO candidate")

required_ids = set(expected_strength_order) | {"smart-auto", "custom"}
missing_ids = required_ids - set(ids)
if missing_ids:
    error("missing modes: " + ", ".join(sorted(missing_ids)))

scripts_dir = ROOT / "modes"
for mode in modes:
    for field in ("command", "check_command", "stop_command"):
        command = mode.get(field) or []
        if not command:
            continue
        candidate: pathlib.Path | None = None
        first = str(command[0])
        if first.startswith("./"):
            candidate = scripts_dir / first[2:]
        elif first in {"python3", "bash"} and len(command) > 1 and str(command[1]).startswith("./"):
            candidate = scripts_dir / str(command[1])[2:]
        if candidate is not None and not candidate.is_file():
            error(f"{mode.get('id')} {field} references missing {candidate.relative_to(ROOT)}")

for mode_id, layers in {
    "max-tls-wg": {"wireguard", "rosenpass-pq", "shadowsocks2022", "vless-pq", "reality", "xhttp", "finalmask"},
    "max-tls-awg": {"amneziawg2", "rosenpass-pq", "shadowsocks2022", "vless-pq", "reality", "xhttp", "finalmask"},
    "max-quic-wg": {"wireguard", "rosenpass-pq", "shadowsocks2022", "hysteria2", "quic"},
    "max-quic-awg": {"amneziawg2", "rosenpass-pq", "shadowsocks2022", "hysteria2", "quic"},
}.items():
    mode = next((item for item in modes if item.get("id") == mode_id), {})
    missing = layers - set(mode.get("layers") or [])
    if missing:
        error(f"{mode_id} missing layers: {', '.join(sorted(missing))}")

all_script = ROOT / "modes" / "run-all.sh"
all_text = all_script.read_text() if all_script.is_file() else ""
for required in (
    "max-tls-awg max-tls-wg max-quic-awg max-quic-wg",
    "max-tls-wg max-tls-awg max-quic-wg max-quic-awg",
    "ALL could not establish any validated MAX TLS or MAX QUIC branch.",
):
    if required not in all_text:
        error(f"ALL fallback contract missing: {required}")

orchestrator = ROOT / "modes" / "orchestrate.py"
orchestrator_text = orchestrator.read_text() if orchestrator.is_file() else ""
for required in (
    "SMART AUTO could not restore its last-known-good mode",
    "CUSTOM: no validated compatible stack contains that exact layer selection",
    "len(layers) - len(requested)",
):
    if required not in orchestrator_text:
        error(f"SMART/CUSTOM contract missing: {required}")

# ----- Complete first-run onboarding contract -----
ui_path = ROOT / "cmd/client/ui.html"
if ui_path.is_file():
    ui = ui_path.read_text()
    ui_lower = ui.lower()
    for stale in ("socks5 username", "socks5 password"):
        if stale in ui_lower:
            error(f"UI contains stale authenticated SOCKS wording: {stale}")
    for required in (
        "routervpn.onboarding.web.done.v2",
        "routervpn.onboarding.web.step.v2",
        "Run full onboarding again",
        "Portainer → Stacks → Add stack → Repository",
        "WAN_INTERFACE=eth0",
        "LAN_CIDR=192.168.50.0/24",
        "ADGUARD4=192.168.50.133",
        "router-vpn-init",
        "router-vpn-finalize",
        "router-vpn-client-bundle.zip",
        "asus-merlin-router-vpn-forwards.sh",
        "TCP      80      → 18080",
        "Never expose 1080, 8786, 8787, 9443",
        "SMART AUTO",
        "CUSTOM",
        "Home AdGuard",
        "DNS Rescue",
        "Protected DMZ",
        "no authentication",
        "doctor-current.sh",
        "router-vpn-forward.sh status",
        "Live WireGuard/AWG/REALITY/QUIC handshakes",
    ):
        if required not in ui:
            error(f"WebGUI missing agreed complete-onboarding text: {required}")
else:
    error("missing cmd/client/ui.html")

android_path = ROOT / "android/app/src/main/java/com/eabusham/routervpn/MainActivity.java"
android_text = android_path.read_text() if android_path.is_file() else ""
for required in (
    "onboarding_done_v2",
    "onboarding_step_v2",
    "Run full onboarding again",
    "server/portainer-current.yaml",
    "TCP 80 maps to AI Board TCP 18080",
    "router-vpn-forward.sh status",
    "AUTO / SMART AUTO / CUSTOM",
    "never forward TCP 1080 from WAN",
    "does not fake a live all-mode VPN connection",
):
    if required not in android_text:
        error(f"Android complete-onboarding contract missing: {required}")

ios_path = ROOT / "ios/RouterVPN/App/ContentView.swift"
ios_text = ios_path.read_text() if ios_path.is_file() else ""
for required in (
    "routerVPNOnboardingDoneV2",
    "routerVPNOnboardingStepV2",
    "Run full onboarding again",
    "server/portainer-current.yaml",
    "TCP 80→18080",
    "router-vpn-forward.sh status",
    "SMART AUTO",
    "Home AdGuard",
    "Protected DMZ",
    "native all-mode Packet Tunnel adapters are not linked yet",
):
    if required not in ios_text:
        error(f"iOS complete-onboarding contract missing: {required}")

# ----- Persistent ASUS Merlin WAN forwarding helper -----
forward_helper = ROOT / "router" / "asus-merlin-router-vpn-forwards.sh"
helper_text = forward_helper.read_text() if forward_helper.is_file() else ""
if not helper_text:
    error("missing ASUS Merlin forwarding helper")
else:
    syntax = subprocess.run(
        ["/bin/sh", "-n", str(forward_helper)],
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if syntax.returncode:
        detail = (syntax.stderr or "shell syntax error").strip().splitlines()[-1]
        error(f"ASUS Merlin forwarding helper shell syntax error: {detail}")
    for required in (
        "ACME_EXTERNAL_PORT=${ACME_EXTERNAL_PORT:-80}",
        "ACME_INTERNAL_PORT=${ACME_INTERNAL_PORT:-18080}",
        "WG_PORT=${WG_PORT:-51820}",
        "AWG_PORT=${AWG_PORT:-585}",
        "ROSENPASS_PORT=${ROSENPASS_PORT:-51822}",
        "HY2_PORT=${HY2_PORT:-8443}",
        "write_hook \"$NAT_START\" \"$RUNTIME apply-nat\"",
        "write_hook \"$FIREWALL_START\" \"$RUNTIME apply-filter\"",
        "Existing nat-start/firewall-start content was preserved.",
        "Never exposed by this script: 1080, 8786, 8787, 9443, SSH, Portainer, AdGuard admin.",
    ):
        if required not in helper_text:
            error(f"ASUS forwarding helper missing contract: {required}")

finalizer_path = ROOT / "server" / "finalize" / "finalize.sh"
finalizer_text = finalizer_path.read_text() if finalizer_path.is_file() else ""
for required in (
    "Certificate challenge external TCP: 80 -> AI Board TCP 18080",
    "cp /src/router/asus-merlin-router-vpn-forwards.sh",
):
    if required not in finalizer_text:
        error(f"finalizer missing bundle/onboarding contract: {required}")

guide_path = ROOT / "docs" / "CURRENT-GUIDE.md"
guide_text = guide_path.read_text() if guide_path.is_file() else ""
if "TCP      80      -> 18080" not in guide_text and "TCP      80      → 18080" not in guide_text:
    error("CURRENT-GUIDE must document external TCP 80 -> internal 18080")
if "TCP      80      -> 80" in guide_text or "TCP      80      → 192.168.50.133:80" in guide_text:
    error("CURRENT-GUIDE still contains stale external TCP 80 -> internal 80 mapping")
for required in (
    "client/install-macos-final.sh",
    "router/asus-merlin-router-vpn-forwards.sh",
    "Run full onboarding again",
):
    if required not in guide_text:
        error(f"CURRENT-GUIDE missing current setup entry: {required}")

# ----- Production Portainer compose -----
compose_path = ROOT / "server/portainer-current.yaml"
compose_text = compose_path.read_text() if compose_path.is_file() else ""
if not compose_text:
    error("missing server/portainer-current.yaml")

for dockerfile in re.findall(r"(?m)^\s*dockerfile:\s*([^\s#]+)", compose_text):
    rel = dockerfile.strip("'\"")
    if not (ROOT / rel).is_file():
        error(f"Portainer compose references missing Dockerfile: {rel}")

for image in re.findall(r"(?m)^\s*image:\s*([^\s#]+)", compose_text):
    image = image.strip("'\"")
    if image.endswith(":latest") or ":latest@" in image:
        error(f"Portainer compose uses floating latest image: {image}")

for required in (
    "ghcr.io/sagernet/sing-box:v1.13.12",
    "ghcr.io/xtls/xray-core:26.7.11",
    "busybox:1.36",
):
    if required not in compose_text:
        error(f"Portainer compose missing pinned image: {required}")

custom_runtime_tags = re.findall(
    r"ghcr\.io/eabusham2/router-vpn-(?:init|agent|wireguard|awg2|rosenpass|naive|ss-v2ray):([0-9a-f]{40})",
    compose_text,
)
if len(custom_runtime_tags) != 8:  # init appears twice: init + finalizer
    error(f"expected 8 exact-SHA custom runtime image references, found {len(custom_runtime_tags)}")
elif_tags = set(custom_runtime_tags)
if len(elif_tags) > 1:
    error("production custom runtime images are not pinned to one validated SHA")

for forbidden_port in ("1080", "8786", "8787", "9443"):
    if re.search(rf"(?m)^\s*ports:\s*.*{forbidden_port}", compose_text):
        error(f"production compose unexpectedly publishes protected port {forbidden_port}")

if shutil.which("docker") and compose_path.is_file():
    check = subprocess.run(
        ["docker", "compose", "-f", str(compose_path), "config"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if check.returncode:
        detail = (check.stderr or "docker compose config failed").strip().splitlines()[-1]
        error(f"Portainer compose invalid: {detail}")

# ----- Active Docker build files -----
active = [
    "server/init/Dockerfile",
    "deploy/router-agent.Dockerfile",
    "server/wireguard/Dockerfile",
    "server/awg2/Dockerfile",
    "server/rosenpass/Dockerfile",
    "server/naive/Dockerfile",
    "server/ss-v2ray/Dockerfile",
]


def logical_docker_lines(text: str) -> list[tuple[int, str]]:
    output: list[tuple[int, str]] = []
    pending = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if not pending:
            start = number
        piece = raw.rstrip()
        continued = piece.endswith("\\")
        if continued:
            piece = piece[:-1]
        pending += (" " if pending else "") + piece.strip()
        if not continued:
            output.append((start, pending))
            pending = ""
    if pending:
        error(f"Dockerfile has dangling continuation starting line {start}")
    return output


for rel in active:
    path = ROOT / rel
    if not path.is_file():
        error(f"missing active Dockerfile: {rel}")
        continue
    text = path.read_text()
    if "git clone" in text or "git checkout" in text:
        error(f"active Dockerfile reintroduced fragile git clone/checkout: {rel}")
    logical = logical_docker_lines(text)
    if not any(line.upper().startswith("FROM ") for _, line in logical):
        error(f"Dockerfile has no FROM: {rel}")

    for line_no, line in logical:
        keyword = line.split(None, 1)[0].upper() if line.split() else ""
        if keyword == "RUN":
            command = line[3:].lstrip()
            syntax = subprocess.run(
                ["/bin/sh", "-n", "-c", command],
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if syntax.returncode:
                detail = (syntax.stderr or "shell syntax error").strip().splitlines()[-1]
                error(f"RUN syntax error {rel}:{line_no}: {detail}")
        if keyword == "COPY" and "--from=" not in line:
            try:
                parts = shlex.split(line)
            except ValueError as exc:
                error(f"COPY syntax error {rel}:{line_no}: {exc}")
                continue
            args = [part for part in parts[1:] if not part.startswith("--")]
            if len(args) < 2:
                error(f"invalid COPY {rel}:{line_no}")
                continue
            for source in args[:-1]:
                if source == "." or any(ch in source for ch in "*$?["):
                    continue
                if not (ROOT / source).exists():
                    error(f"COPY source missing {rel}:{line_no}: {source}")

pins: dict[str, tuple[str, ...]] = {
    "server/init/Dockerfile": (
        "ghcr.io/sagernet/sing-box:v1.13.12",
        "ghcr.io/xtls/xray-core:26.7.11",
        "ghcr.io/rosenpass/rosenpass:sha-00569eb",
    ),
    "server/awg2/Dockerfile": (
        "golang:1.25.12-bookworm",
        "AWG_GO_TAG=v3.0.2",
        "AWGTOOLS_TAG=v1.0.20250901",
    ),
    "server/rosenpass/Dockerfile": (
        "ghcr.io/rosenpass/rosenpass:sha-00569eb",
        "AWGTOOLS_TAG=v1.0.20250901",
    ),
    "server/naive/Dockerfile": (
        "pocat/naiveproxy:v2.11.4",
        "list-modules",
        "forward_proxy",
    ),
    "server/ss-v2ray/Dockerfile": (
        "golang:1.23.12-alpine",
        "V2RAY_PLUGIN_COMMIT=e9af1cdd2549d528deb20a4ab8d61c5fbe51f306",
        "ghcr.io/shadowsocks/ssserver-rust:v1.24.0",
    ),
}
for rel, expected in pins.items():
    text = (ROOT / rel).read_text() if (ROOT / rel).is_file() else ""
    for value in expected:
        if value not in text:
            error(f"{rel} missing required pin: {value}")

naive_text = (ROOT / "server/naive/Dockerfile").read_text() if (ROOT / "server/naive/Dockerfile").is_file() else ""
for forbidden in ("xcaddy", "forwardproxy/archive", "go install", "go build"):
    if forbidden in naive_text:
        error(f"Naive Dockerfile reintroduced fragile source build step: {forbidden}")

if ERRORS:
    print("Repository validation failed:", file=sys.stderr)
    for message in ERRORS:
        print(" - " + message, file=sys.stderr)
    raise SystemExit(1)

print(
    f"Validated final product contract: {len(numbered)} ordered strength modes + "
    f"{max(0, len(modes)-len(numbered))} utilities; complete Web/Android/iOS onboarding; "
    f"persistent ASUS forwarding helper; production compose; {len(active)} active Dockerfiles; "
    f"pinned dependencies; COPY paths; and RUN shell syntax."
)
