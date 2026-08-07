#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
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

if errors:
    print("Repository validation failed:", file=sys.stderr)
    for error in errors:
        print(" - " + error, file=sys.stderr)
    raise SystemExit(1)

print(f"Validated {len(numbered)} strength profiles + {len(modes)-len(numbered)} utility modes.")
