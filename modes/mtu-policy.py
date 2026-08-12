#!/usr/bin/env python3
"""Resolve and apply Router VPN MTU policy to an ephemeral runtime profile.

The mode catalog's tested MTU is the ceiling. Auto mode probes the public
underlay endpoint with DF/PMTU semantics and lowers that tested value when the
underlay requires it; it never guesses a value larger than the mode's tested
ceiling. If ICMP/PMTU probing is filtered, auto falls back to the tested mode
value instead of claiming an unverified result.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
from typing import Any

MIN_MTU = 576
MAX_PROBE_MTU = 1500


def root_dir() -> Path:
    return Path(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client")).resolve()


def profile_id() -> str:
    value = os.environ.get("HOMEVPN_PROFILE_ID", "router")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value):
        raise SystemExit("invalid HOMEVPN_PROFILE_ID")
    return value


def load_store(root: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    path = root / "routers.json"
    try:
        store = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}, None
    selected = profile_id()
    profile = next((p for p in store.get("profiles", []) if isinstance(p, dict) and p.get("id") == selected), None)
    return store, profile


def catalog_default(root: Path, mode: str, fallback: int) -> int:
    try:
        modes = json.loads((root / "modes.json").read_text(encoding="utf-8"))
        for item in modes:
            if isinstance(item, dict) and item.get("id") == mode:
                value = int(item.get("mtu", 0))
                if MIN_MTU <= value <= 9000:
                    return value
    except Exception:
        pass
    return fallback if MIN_MTU <= fallback <= 9000 else 1380


def resolve_target(endpoint: str) -> tuple[str, int] | None:
    endpoint = endpoint.strip().strip("[]")
    if not endpoint:
        return None
    try:
        ip = ipaddress.ip_address(endpoint)
        return str(ip), ip.version
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(endpoint, None, type=socket.SOCK_DGRAM)
    except OSError:
        return None
    for family, *_rest, sockaddr in infos:
        if family == socket.AF_INET:
            return sockaddr[0], 4
    for family, *_rest, sockaddr in infos:
        if family == socket.AF_INET6:
            return sockaddr[0], 6
    return None


def ping_ok(host: str, version: int, outer_mtu: int) -> bool:
    override = os.environ.get("HOMEVPN_MTU_PROBE_RESULT")
    if override:
        try:
            return outer_mtu <= int(override)
        except ValueError:
            return False
    header = 28 if version == 4 else 48
    payload = max(0, outer_mtu - header)
    if sys.platform.startswith("linux"):
        cmd = ["ping", "-n", "-c", "1", "-W", "1", "-M", "do", "-s", str(payload)]
        if version == 6:
            cmd.insert(1, "-6")
        cmd.append(host)
    elif sys.platform == "darwin":
        if version == 6:
            cmd = ["ping6", "-n", "-c", "1", "-W", "1000", "-s", str(payload), host]
        else:
            cmd = ["ping", "-n", "-c", "1", "-W", "1000", "-D", "-s", str(payload), host]
    else:
        return False
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.5, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def probe_underlay(endpoint: str) -> tuple[int | None, str]:
    target = resolve_target(endpoint)
    if target is None:
        return None, "endpoint-resolution-failed"
    host, version = target
    # Establish that the path responds before binary searching. If this fails,
    # do not infer a smaller path; ICMP may simply be filtered.
    if not ping_ok(host, version, 1200):
        return None, "probe-unavailable"
    lo, hi, best = 1200, MAX_PROBE_MTU, 1200
    while lo <= hi:
        mid = (lo + hi) // 2
        if ping_ok(host, version, mid):
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return best, "proven"


def choose_effective(profile: dict[str, Any] | None, default_mtu: int, endpoint: str) -> tuple[int, str, int | None]:
    if os.environ.get("HOMEVPN_JUMBO", "false").lower() == "true":
        return 9000, "jumbo", None
    policy = str((profile or {}).get("mtu_policy") or "default").strip().lower()
    if policy == "manual":
        try:
            manual = int((profile or {}).get("manual_mtu") or 0)
        except (TypeError, ValueError):
            manual = 0
        if not MIN_MTU <= manual <= 9000:
            raise SystemExit(f"manual MTU {manual} is outside {MIN_MTU}..9000")
        return manual, "manual", None
    if policy != "auto":
        return default_mtu, "default", None
    outer, status = probe_underlay(endpoint)
    if outer is None:
        return default_mtu, "auto-fallback", None
    # The per-mode catalog already encodes the tested safety/encapsulation
    # margin for a normal 1500-byte underlay. Preserve that margin when PMTU is
    # lower, and never exceed the tested catalog ceiling.
    safety = max(60, MAX_PROBE_MTU - default_mtu)
    effective = max(MIN_MTU, min(default_mtu, outer - safety))
    return effective, "auto-proven", outer


def patch_json(value: Any, mtu: int) -> bool:
    changed = False
    if isinstance(value, dict):
        if value.get("type") == "tun":
            if value.get("mtu") != mtu:
                value["mtu"] = mtu
                changed = True
        for child in value.values():
            changed = patch_json(child, mtu) or changed
    elif isinstance(value, list):
        for child in value:
            changed = patch_json(child, mtu) or changed
    return changed


def patch_conf(path: Path, mtu: int) -> bool:
    text = path.read_text(encoding="utf-8")
    if "[Interface]" not in text:
        return False
    if re.search(r"(?mi)^MTU\s*=", text):
        updated = re.sub(r"(?mi)^MTU\s*=.*$", f"MTU = {mtu}", text)
    else:
        updated = text.replace("[Interface]\n", f"[Interface]\nMTU = {mtu}\n", 1)
    if updated != text:
        path.write_text(updated, encoding="utf-8")
        return True
    return False


def apply_tree(conf: Path, mtu: int) -> int:
    changed = 0
    for path in conf.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if patch_json(data, mtu):
                path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                changed += 1
        elif path.suffix.lower() == ".conf":
            try:
                changed += int(patch_conf(path, mtu))
            except UnicodeDecodeError:
                pass
    return changed


def persist_effective(root: Path, store: dict[str, Any], profile: dict[str, Any] | None, mtu: int) -> None:
    if profile is None or not store:
        return
    profile["effective_mtu"] = mtu
    path = root / "routers.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="routers.json.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "apply":
        print("usage: mtu-policy.py apply <runtime-profile-dir>", file=sys.stderr)
        return 2
    conf = Path(sys.argv[2]).resolve()
    if not conf.is_dir():
        print(f"runtime profile directory does not exist: {conf}", file=sys.stderr)
        return 2
    root = root_dir()
    try:
        conf.relative_to((root / "run").resolve())
    except ValueError:
        print("refusing to patch MTU outside HOMEVPN_ROOT/run", file=sys.stderr)
        return 2
    store, profile = load_store(root)
    mode = os.environ.get("HOMEVPN_MODE", "").strip()
    try:
        fallback = int(os.environ.get("HOMEVPN_MTU", "1380"))
    except ValueError:
        fallback = 1380
    default_mtu = catalog_default(root, mode, fallback)
    endpoint = os.environ.get("HOMEVPN_ENDPOINT", "")
    effective, source, outer = choose_effective(profile, default_mtu, endpoint)
    changed = apply_tree(conf, effective)
    # A profile with no MTU-bearing config is not evidence that the value was
    # applied. Do not persist observational state in that case.
    if changed > 0:
        persist_effective(root, store, profile, effective)
    details = f"MTU {effective} ({source}"
    if outer is not None:
        details += f", underlay PMTU {outer}"
    details += f", patched {changed} config file(s))"
    print(details, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
