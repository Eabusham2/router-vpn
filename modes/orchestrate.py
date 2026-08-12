#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client"))
PROFILE_ID = os.environ.get("HOMEVPN_PROFILE_ID", "")
SCRIPT_DIR = Path(__file__).resolve().parent
MODES_PATH = ROOT / "modes.json"
DEFAULT_PATH_PROBE_URL = "http://10.77.0.1:8787/health"
TEST_SECONDS = float(os.environ.get("HOMEVPN_AUTO_TEST_SECONDS", "6"))
WANT_JUMBO = os.environ.get("HOMEVPN_JUMBO", "false").lower() == "true"
WANT_DAITA = os.environ.get("HOMEVPN_DAITA", "false").lower() == "true"

modes = json.loads(MODES_PATH.read_text())
by_id = {m["id"]: m for m in modes}
current: subprocess.Popen | None = None
current_mode: dict | None = None


def selected_profile() -> dict:
    try:
        store = json.loads((ROOT / "routers.json").read_text())
    except Exception:
        return {}
    wanted = PROFILE_ID or store.get("selected_id", "")
    return next((p for p in store.get("profiles", []) if p.get("id") == wanted), store.get("profiles", [{}])[0] if store.get("profiles") else {})


def path_probe_url() -> str:
    explicit = os.environ.get("HOMEVPN_HEALTH_URL", "").strip()
    value = explicit or str(selected_profile().get("path_probe_url") or DEFAULT_PATH_PROBE_URL).strip()
    parsed = urlparse(value)
    host = (parsed.hostname or "").rstrip(".").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("selected router path proof URL is invalid")
    trusted = host == "localhost" or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".home.arpa")
    if not trusted:
        try:
            ip = ipaddress.ip_address(host)
            trusted = ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            trusted = False
    if not trusted:
        raise ValueError("selected router path proof URL must be private/local")
    return value


def run_command(parts: list[str], *, quiet: bool = False) -> subprocess.CompletedProcess:
    stdout = subprocess.DEVNULL if quiet else None
    stderr = subprocess.DEVNULL if quiet else None
    return subprocess.run(parts, cwd=SCRIPT_DIR, env=os.environ.copy(), stdout=stdout, stderr=stderr, check=False)


def available(mode: dict) -> bool:
    if WANT_JUMBO and not mode.get("jumbo_supported", False):
        return False
    if WANT_DAITA and not mode.get("daita_supported", False):
        return False
    cmd = mode.get("check_command") or []
    if not cmd:
        return True
    return run_command(cmd, quiet=True).returncode == 0


def health() -> tuple[bool, float]:
    started = time.perf_counter()
    try:
        target = path_probe_url()
        with urllib.request.urlopen(target, timeout=TEST_SECONDS) as r:
            if not (200 <= int(getattr(r, "status", 0)) < 300):
                return False, 0.0
            body = r.read(4096)
        proof = json.loads(body.decode("utf-8", errors="strict"))
        ok = isinstance(proof, dict) and proof.get("ok") is True
    except Exception:
        return False, 0.0
    return ok, (time.perf_counter() - started) * 1000.0


def stop_current() -> None:
    global current, current_mode
    if current is not None and current.poll() is None:
        try:
            current.send_signal(signal.SIGINT)
            current.wait(timeout=3)
        except Exception:
            try:
                current.kill()
            except Exception:
                pass
    run_command(["bash", str(SCRIPT_DIR / "stop-mode.sh")], quiet=True)
    current = None
    current_mode = None


def launch(mode: dict) -> tuple[bool, float]:
    global current, current_mode
    stop_current()
    if not available(mode):
        return False, 0.0
    cmd = mode.get("command") or []
    if not cmd:
        return False, 0.0
    print(f"Trying {mode['name']}", flush=True)
    current = subprocess.Popen(cmd, cwd=SCRIPT_DIR, env=os.environ.copy())
    current_mode = mode
    time.sleep(1.6)
    if current.poll() is not None:
        stop_current()
        return False, 0.0
    ok, latency = health()
    if not ok:
        stop_current()
        return False, 0.0
    return True, latency


def wait_selected(mode: dict, latency: float) -> int:
    print(f"Connected: {mode['name']} ({latency:.1f} ms selected-node path proof)", flush=True)
    if current is None:
        return 1
    return current.wait()


def smart_auto() -> int:
    best: dict | None = None
    best_latency = 0.0
    tested: list[str] = []
    for mode in modes:
        if not mode.get("auto_eligible") or not available(mode):
            continue
        tested.append(mode["id"])
        ok, latency = launch(mode)
        if ok:
            best, best_latency = mode, latency
            break
    if best is None:
        print("SMART AUTO: no working mode", file=sys.stderr)
        return 1

    visited = {best["id"]}
    while True:
        changed = False
        for candidate_id in best.get("smart_simplify", []):
            if candidate_id in visited or candidate_id not in by_id:
                continue
            visited.add(candidate_id)
            candidate = by_id[candidate_id]
            if not available(candidate):
                continue
            tested.append(candidate_id)
            last_good = best
            last_latency = best_latency
            ok, latency = launch(candidate)
            if ok:
                print(f"SMART removed/replaced layers: {last_good['id']} -> {candidate_id}", flush=True)
                best, best_latency, changed = candidate, latency, True
                break
            restored, restored_latency = launch(last_good)
            if not restored:
                print("SMART AUTO could not restore its last-known-good mode", file=sys.stderr)
                return 1
            best, best_latency = last_good, restored_latency or last_latency
        if not changed:
            break

    print("SMART tested: " + ", ".join(tested), flush=True)
    return wait_selected(best, best_latency)


def custom() -> int:
    profile = selected_profile()
    requested = []
    for raw in profile.get("custom_layers", []):
        value = str(raw).strip().lower()
        if value and value not in requested:
            requested.append(value)
    if not requested:
        print("CUSTOM: select at least one layer in the client first", file=sys.stderr)
        return 2
    preferred = str(profile.get("base_tunnel") or "wg").lower()

    candidates = []
    for mode in modes:
        if mode.get("id") in {"smart-auto", "custom", "all"}:
            continue
        layers = [str(x).lower() for x in mode.get("layers", [])]
        if not layers or not all(x in layers for x in requested) or not available(mode):
            continue
        has_wg = "wireguard" in layers
        has_awg = "amneziawg2" in layers
        base_penalty = 0
        if preferred.startswith("awg") or preferred.startswith("amnezia"):
            base_penalty = 0 if has_awg else 1 if has_wg else 0
        else:
            base_penalty = 0 if has_wg else 1 if has_awg else 0
        candidates.append((len(layers) - len(requested), base_penalty, float(mode.get("traffic_min_pct", 999)), float(mode.get("ping_min_ms", 999)), mode))
    candidates.sort(key=lambda item: item[:4])
    if not candidates:
        print("CUSTOM: no validated compatible stack contains that exact layer selection", file=sys.stderr)
        return 2

    for *_, mode in candidates:
        ok, latency = launch(mode)
        if ok:
            print("CUSTOM requested: " + ", ".join(requested), flush=True)
            return wait_selected(mode, latency)
    print("CUSTOM: matching stacks existed but none passed selected-node path proof", file=sys.stderr)
    return 1


def cleanup_signal(signum, _frame):
    stop_current()
    raise SystemExit(128 + signum)


signal.signal(signal.SIGINT, cleanup_signal)
signal.signal(signal.SIGTERM, cleanup_signal)

if len(sys.argv) != 2 or sys.argv[1] not in {"smart", "custom"}:
    raise SystemExit("usage: orchestrate.py smart|custom")
try:
    raise SystemExit(smart_auto() if sys.argv[1] == "smart" else custom())
finally:
    stop_current()
