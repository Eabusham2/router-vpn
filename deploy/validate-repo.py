#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import shlex
import shutil
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
modes_path = root / "configs" / "client" / "modes.json"
modes = json.loads(modes_path.read_text())

errors: list[str] = []
ids = [m.get("id") for m in modes]
if len(ids) != len(set(ids)):
    errors.append("mode IDs are not unique")

numbered = modes[:20]
if len(numbered) != 20:
    errors.append("expected 20 ordered strength profiles before utility modes")
else:
    for i, mode in enumerate(numbered, 1):
        if not str(mode.get("name", "")).startswith(f"{i}. "):
            errors.append(f"mode position {i} is not numbered {i}: {mode.get('name')}")

expected_utilities = ["smart-auto", "custom"]
if ids[20:] != expected_utilities:
    errors.append(f"utility modes must follow the 20 strength modes in order: {expected_utilities}")

required_ids = {
    "wg", "awg2-fast", "wg-pq", "shadowsocks", "awg2-strong", "awg2-pq",
    "reality-vision", "hysteria2", "reality-pq-vision", "ss-v2ray",
    "naive-h2", "naive-h3", "split", "reality-xhttp", "max",
    "max-quic-wg", "max-quic-awg", "max-tls-wg", "max-tls-awg", "all",
    "smart-auto", "custom",
}
missing = required_ids - set(ids)
if missing:
    errors.append("missing required modes: " + ", ".join(sorted(missing)))

# AUTO must be able to escalate through the heavy branches but ALL itself is a
# separate orchestrator to avoid duplicate probing.
for mode in numbered[:19]:
    if not mode.get("auto_eligible"):
        errors.append(f"numbered mode must be AUTO-eligible: {mode.get('id')}")
if numbered and numbered[-1].get("id") == "all" and numbered[-1].get("auto_eligible"):
    errors.append("ALL must not also be a normal AUTO candidate")

scripts_dir = root / "modes"
for mode in modes:
    for field in ("command", "check_command", "stop_command"):
        command = mode.get(field) or []
        if not command:
            if field == "stop_command" and mode.get("id") in {"smart-auto", "custom"}:
                continue
            if field != "check_command" or mode.get("id") in {"smart-auto", "custom"}:
                continue
        if not command:
            continue
        first = str(command[0])
        candidates: list[pathlib.Path] = []
        if first.startswith("./"):
            candidates.append(scripts_dir / first[2:])
        elif first in {"python3", "bash"} and len(command) > 1 and str(command[1]).startswith("./"):
            candidates.append(scripts_dir / str(command[1])[2:])
        for candidate in candidates:
            if not candidate.is_file():
                errors.append(f"{mode.get('id')} {field} references missing file {candidate.relative_to(root)}")

# Strength profiles must expose estimates and concrete layer metadata.
for mode in numbered:
    for key in ("ping_min_ms", "ping_max_ms", "traffic_min_pct", "traffic_max_pct", "speed_loss_min_pct", "speed_loss_max_pct"):
        if not isinstance(mode.get(key), (int, float)):
            errors.append(f"{mode.get('id')} missing numeric {key}")
    if mode.get("id") != "all" and not mode.get("layers"):
        errors.append(f"{mode.get('id')} has no layer metadata")
    if float(mode.get("ping_min_ms", 0)) > float(mode.get("ping_max_ms", 0)):
        errors.append(f"{mode.get('id')} has inverted ping range")
    if float(mode.get("traffic_min_pct", 0)) > float(mode.get("traffic_max_pct", 0)):
        errors.append(f"{mode.get('id')} has inverted traffic range")

# MAX must actually contain the requested independently keyed base + camouflage stack.
for mode_id in ("max-tls-wg", "max-tls-awg"):
    mode = next((m for m in modes if m.get("id") == mode_id), {})
    layers = set(mode.get("layers") or [])
    for required in ("rosenpass-pq", "shadowsocks2022", "vless-pq", "reality", "xhttp", "finalmask"):
        if required not in layers:
            errors.append(f"{mode_id} missing required layer {required}")
for mode_id in ("max-quic-wg", "max-quic-awg"):
    mode = next((m for m in modes if m.get("id") == mode_id), {})
    layers = set(mode.get("layers") or [])
    for required in ("rosenpass-pq", "shadowsocks2022", "hysteria2", "quic"):
        if required not in layers:
            errors.append(f"{mode_id} missing required layer {required}")

# Avoid accidentally reintroducing no-auth SOCKS credentials in current UI text.
ui = (root / "cmd" / "client" / "ui.html").read_text()
for stale in ("SOCKS5 username", "SOCKS5 password"):
    if stale.lower() in ui.lower():
        errors.append(f"UI contains stale authenticated SOCKS wording: {stale}")

# The current Portainer compose is the production deployment entrypoint.
current_compose = root / "server" / "portainer-current.yaml"
compose_text = ""
if not current_compose.is_file():
    errors.append("missing current Portainer compose: server/portainer-current.yaml")
else:
    compose_text = current_compose.read_text()
    # Every Dockerfile named by the production compose must exist.
    for dockerfile in re.findall(r"(?m)^\s*dockerfile:\s*([^\s#]+)", compose_text):
        candidate = root / dockerfile.strip("'\"")
        if not candidate.is_file():
            errors.append(f"Portainer compose references missing Dockerfile: {dockerfile}")

    # Production images must be explicitly pinned. A floating :latest caused real
    # deployment failures before, so make it a repository validation error.
    for image in re.findall(r"(?m)^\s*image:\s*([^\s#]+)", compose_text):
        image = image.strip("'\"")
        if image.endswith(":latest") or ":latest@" in image:
            errors.append(f"Portainer compose uses floating latest image: {image}")

    required_compose_images = {
        "ghcr.io/sagernet/sing-box:v1.13.12",
        "ghcr.io/xtls/xray-core:26.7.11",
        "busybox:1.36",
    }
    for required in required_compose_images:
        if required not in compose_text:
            errors.append(f"Portainer compose missing required pinned image: {required}")

    if shutil.which("docker"):
        result = subprocess.run(
            ["docker", "compose", "-f", str(current_compose), "config"],
            cwd=root,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            detail = (result.stderr or "docker compose config failed").strip().splitlines()[-1]
            errors.append(f"current Portainer compose is invalid: {detail}")

# Static preflight for every Dockerfile the production compose builds.
active_dockerfiles = [
    root / "server/init/Dockerfile",
    root / "deploy/router-agent.Dockerfile",
    root / "server/wireguard/Dockerfile",
    root / "server/awg2/Dockerfile",
    root / "server/rosenpass/Dockerfile",
    root / "server/naive/Dockerfile",
    root / "server/ss-v2ray/Dockerfile",
]
for path in active_dockerfiles:
    if not path.is_file():
        errors.append(f"missing active Dockerfile: {path.relative_to(root)}")
        continue
    text = path.read_text()
    lines = text.splitlines()
    if not lines or not any(line.lstrip().startswith("FROM ") for line in lines):
        errors.append(f"Dockerfile has no FROM instruction: {path.relative_to(root)}")
    if lines and lines[-1].rstrip().endswith("\\"):
        errors.append(f"Dockerfile ends with dangling line continuation: {path.relative_to(root)}")
    for line_no, line in enumerate(lines, 1):
        if line.rstrip().endswith("\\") and line_no == len(lines):
            errors.append(f"line {line_no} has dangling continuation in {path.relative_to(root)}")
        stripped = line.strip()
        if not stripped.startswith("COPY ") or "--from=" in stripped:
            continue
        try:
            parts = shlex.split(stripped)
        except ValueError as exc:
            errors.append(f"invalid COPY syntax at {path.relative_to(root)}:{line_no}: {exc}")
            continue
        args = [part for part in parts[1:] if not part.startswith("--")]
        if len(args) < 2:
            errors.append(f"invalid COPY instruction at {path.relative_to(root)}:{line_no}")
            continue
        for source in args[:-1]:
            if source == "." or any(ch in source for ch in "*$?["):
                continue
            if not (root / source).exists():
                errors.append(f"COPY source does not exist at {path.relative_to(root)}:{line_no}: {source}")

    # Network source builds are intentionally archive-based, not git checkout
    # based; this avoids clone/checkout exit-128 failures on Portainer hosts.
    if "git clone" in text or "git checkout" in text:
        errors.append(f"active Dockerfile uses fragile git clone/checkout: {path.relative_to(root)}")

required_dockerfile_pins = {
    "server/init/Dockerfile": [
        "ghcr.io/sagernet/sing-box:v1.13.12",
        "ghcr.io/xtls/xray-core:26.7.11",
        "ghcr.io/rosenpass/rosenpass:sha-00569eb",
    ],
    "server/awg2/Dockerfile": [
        "golang:1.25.12-bookworm",
        "AWG_GO_TAG=v3.0.2",
        "AWGTOOLS_COMMIT=05434cab7d91bbbc607d18ec5fade91f4b83774c",
    ],
    "server/rosenpass/Dockerfile": [
        "ghcr.io/rosenpass/rosenpass:sha-00569eb",
        "AWGTOOLS_COMMIT=05434cab7d91bbbc607d18ec5fade91f4b83774c",
    ],
    "server/naive/Dockerfile": [
        "XCADDY_VERSION=v0.4.5",
        "CADDY_VERSION=v2.8.4",
        "FORWARDPROXY_COMMIT=d62c80d3dd2c706b6b87579844d2397bddd18317",
        "caddy:2.8.4-alpine",
    ],
    "server/ss-v2ray/Dockerfile": [
        "V2RAY_PLUGIN_COMMIT=e9af1cdd2549d528deb20a4ab8d61c5fbe51f306",
        "ghcr.io/shadowsocks/ssserver-rust:v1.24.0",
    ],
}
for rel, pins in required_dockerfile_pins.items():
    text = (root / rel).read_text() if (root / rel).is_file() else ""
    for pin in pins:
        if pin not in text:
            errors.append(f"{rel} missing required build pin: {pin}")

if errors:
    print("Repository validation failed:", file=sys.stderr)
    for error in errors:
        print(" - " + error, file=sys.stderr)
    raise SystemExit(1)

print(f"Validated {len(numbered)} strength profiles + {len(modes)-len(numbered)} utility modes and strict Portainer build preflight.")
