#!/usr/bin/env python3
"""Resolve/apply Router VPN MTU policy and enforce pre-connect leak policy.

Normal connection startup owns only runtime config plus a private measurement
cache. The Go controller is the sole writer of routers.json/profile policy.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Any

from network_context import generated_profile_fingerprint, network_fingerprint
from profile_id import validate_profile_id

MIN_MTU = 576
MAX_PROBE_MTU = 1500
AUTO_CACHE_HOURS = 24
MAX_CACHE_ENTRIES = 64
CACHE_VERSION = 1


def root_dir() -> Path:
    return Path(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client")).resolve()


def profile_id() -> str:
    try:
        return validate_profile_id(os.environ.get("HOMEVPN_PROFILE_ID", "router"), default="")
    except ValueError as exc:
        raise SystemExit("invalid HOMEVPN_PROFILE_ID") from exc


def load_store(root: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        store = json.loads((root / "routers.json").read_text(encoding="utf-8"))
    except Exception:
        return {}, None
    selected = profile_id()
    profile = next(
        (p for p in store.get("profiles", []) if isinstance(p, dict) and p.get("id") == selected),
        None,
    )
    return store, profile


def catalog_default(root: Path, mode: str, fallback: int) -> int:
    try:
        for item in json.loads((root / "modes.json").read_text(encoding="utf-8")):
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
        cmd = (
            ["ping6", "-n", "-c", "1", "-W", "1000", "-s", str(payload), host]
            if version == 6
            else ["ping", "-n", "-c", "1", "-W", "1000", "-D", "-s", str(payload), host]
        )
    else:
        return False
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.5,
            check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def probe_underlay(endpoint: str) -> tuple[int | None, str]:
    target = resolve_target(endpoint)
    if target is None:
        return None, "endpoint-resolution-failed"
    host, version = target
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


def choose_effective(
    profile: dict[str, Any] | None,
    default_mtu: int,
    endpoint: str,
) -> tuple[int, str, int | None]:
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
    outer, _status = probe_underlay(endpoint)
    if outer is None:
        return default_mtu, "auto-fallback", None
    # Automatic PMTU must never increase above the runtime/catalog default.
    safety = max(60, MAX_PROBE_MTU - default_mtu)
    effective = max(MIN_MTU, min(default_mtu, outer - safety))
    return effective, "auto-proven", outer


def _fallback_generated_fingerprint(root: Path, mode: str) -> str:
    raw = f"unavailable|{profile_id()}|{mode}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def path_context(root: Path, endpoint: str, mode: str) -> tuple[str, str, str]:
    """Return cache key plus privacy-safe network/profile fingerprints."""
    base = os.environ.get("HOMEVPN_BASE", "").strip().lower()
    logical = os.environ.get("HOMEVPN_LOGICAL_MODE", "").strip().lower()
    family = os.environ.get("HOMEVPN_IP_FAMILY", "").strip().lower()
    if not family:
        target = resolve_target(endpoint)
        family = str(target[1]) if target else "unknown"
    network = network_fingerprint(endpoint)
    try:
        generated = generated_profile_fingerprint(root, profile_id(), mode)
    except RuntimeError:
        generated = _fallback_generated_fingerprint(root, mode)
    raw = "|".join(
        [
            endpoint.strip().lower(),
            mode.strip().lower(),
            logical,
            base,
            family,
            profile_id().lower(),
            network,
            generated,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24], network, generated


def path_context_key(endpoint: str, mode: str) -> str:
    """Compatibility helper used by existing tests/callers."""
    return path_context(root_dir(), endpoint, mode)[0]


def _cache_path(root: Path) -> Path:
    return root / "state" / "mtu-auto-cache.json"


def _valid_cached_entry(entry: Any, key: str) -> tuple[int, str, int | None] | None:
    if not isinstance(entry, dict) or str(entry.get("path_key") or "") != key:
        return None
    try:
        mtu = int(entry.get("effective_mtu") or 0)
        outer = int(entry.get("effective_underlay_pmtu") or 0)
    except (TypeError, ValueError):
        return None
    if not MIN_MTU <= mtu <= 9000:
        return None
    raw = str(entry.get("tested_at") or "")
    try:
        tested = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        now = datetime.datetime.now(datetime.timezone.utc)
        if tested.tzinfo is None:
            tested = tested.replace(tzinfo=datetime.timezone.utc)
        if now - tested > datetime.timedelta(hours=AUTO_CACHE_HOURS) or tested - now > datetime.timedelta(minutes=5):
            return None
    except (ValueError, TypeError):
        return None
    return mtu, "auto-cache", outer or None


def _profile_cached_auto(profile: dict[str, Any] | None, key: str) -> tuple[int, str, int | None] | None:
    if not isinstance(profile, dict) or str(profile.get("mtu_policy") or "").lower() != "auto":
        return None
    entry = {
        "path_key": profile.get("effective_mtu_path_key"),
        "effective_mtu": profile.get("effective_mtu"),
        "effective_underlay_pmtu": profile.get("effective_underlay_pmtu"),
        "tested_at": profile.get("effective_mtu_tested_at"),
    }
    return _valid_cached_entry(entry, key)


def _load_measurement_cache(root: Path) -> dict[str, Any]:
    path = _cache_path(root)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024:
            return {}
        if os.name != "nt" and info.st_mode & 0o077:
            return {}
        body = path.read_text(encoding="utf-8")
        data = json.loads(body)
        if not isinstance(data, dict) or data.get("version") != CACHE_VERSION or not isinstance(data.get("entries"), dict):
            return {}
        return data
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return {}


def cached_auto(
    profile: dict[str, Any] | None,
    key: str,
    root: Path | None = None,
) -> tuple[int, str, int | None] | None:
    profile_value = _profile_cached_auto(profile, key)
    if profile_value is not None:
        return profile_value
    if root is None:
        return None
    cache = _load_measurement_cache(root)
    return _valid_cached_entry((cache.get("entries") or {}).get(key), key)


def patch_json(value: Any, mtu: int) -> bool:
    changed = False
    if isinstance(value, dict):
        if value.get("type") == "tun" and value.get("mtu") != mtu:
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
    updated = (
        re.sub(r"(?mi)^MTU\s*=.*$", f"MTU = {mtu}", text)
        if re.search(r"(?mi)^MTU\s*=", text)
        else text.replace("[Interface]\n", f"[Interface]\nMTU = {mtu}\n", 1)
    )
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


def _ensure_cache_parent(path: Path) -> None:
    parent = path.parent
    try:
        info = parent.lstat()
    except FileNotFoundError:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink MTU cache parent: {parent}")


def _atomic_write_cache(path: Path, data: dict[str, Any]) -> None:
    _ensure_cache_parent(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    if info is not None and (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)):
        raise RuntimeError(f"refusing non-regular/symlink MTU cache: {path}")
    body = (json.dumps(data, indent=2) + "\n").encode("utf-8")
    if len(body) > 256 * 1024:
        raise RuntimeError("MTU cache exceeds safety limit")
    fd, tmp_name = tempfile.mkstemp(prefix=".mtu-auto-cache-", dir=str(path.parent))
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        _ensure_cache_parent(path)
        os.replace(tmp_name, path)
        committed = True
        try:
            dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if not committed:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def persist_effective(
    root: Path,
    store: dict[str, Any],
    profile: dict[str, Any] | None,
    mtu: int,
    source: str,
    path_key: str,
    outer: int | None,
    network: str = "",
    generated: str = "",
) -> None:
    """Persist measurement-only auto-MTU memory, never routers.json.

    `store`/`profile` stay in the signature for compatibility with older tests and
    callers, but the Go controller exclusively owns profile persistence.
    """
    del store, profile
    if source not in {"auto-proven", "auto-fallback", "auto-cache"}:
        return
    path = _cache_path(root)
    cache = _load_measurement_cache(root)
    entries = cache.get("entries") if isinstance(cache.get("entries"), dict) else {}
    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    entries[path_key] = {
        "path_key": path_key,
        "effective_mtu": mtu,
        "effective_underlay_pmtu": int(outer or 0),
        "tested_at": now,
        "network_fingerprint": network,
        "profile_fingerprint": generated,
    }
    if len(entries) > MAX_CACHE_ENTRIES:
        ordered = sorted(
            entries.items(),
            key=lambda item: str(item[1].get("tested_at") or "") if isinstance(item[1], dict) else "",
            reverse=True,
        )[:MAX_CACHE_ENTRIES]
        entries = dict(ordered)
    _atomic_write_cache(path, {"version": CACHE_VERSION, "entries": entries})


def enforce_kill_switch() -> None:
    helper = Path(__file__).with_name("kill-switch.py")
    proc = subprocess.run(
        [sys.executable, str(helper), "apply"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.stderr:
        print(proc.stderr.strip(), file=sys.stderr)
    if proc.returncode != 0:
        raise RuntimeError("strict kill switch could not be enforced; refusing to start the VPN runtime")


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
    try:
        enforce_kill_switch()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    store, profile = load_store(root)
    mode = os.environ.get("HOMEVPN_MODE", "").strip()
    endpoint = os.environ.get("HOMEVPN_ENDPOINT", "")
    key, network, generated = path_context(root, endpoint, mode)
    try:
        fallback = int(os.environ.get("HOMEVPN_MTU", "1380"))
    except ValueError:
        fallback = 1380
    default_mtu = catalog_default(root, mode, fallback)
    reuse = cached_auto(profile, key, root) if os.environ.get("HOMEVPN_JUMBO", "false").lower() != "true" else None
    if reuse is not None:
        effective, source, outer = reuse
    else:
        effective, source, outer = choose_effective(profile, default_mtu, endpoint)
    changed = apply_tree(conf, effective)
    try:
        persist_effective(root, store, profile, effective, source, key, outer, network, generated)
    except (OSError, RuntimeError) as exc:
        # Cache persistence is measurement-only and must never break an otherwise
        # valid/leak-safe connection. Refuse unsafe writes and simply remeasure.
        print(f"warning: MTU measurement cache was not persisted: {exc}", file=sys.stderr)
    details = f"MTU {effective} ({source}"
    if outer is not None:
        details += f", underlay PMTU {outer}"
    details += f", path {key}, network {network}, profile {generated}, patched {changed} config file(s))"
    print(details, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
