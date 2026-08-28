#!/usr/bin/env python3
"""Fail-closed Router VPN client kill switch for shell/native Unix runtimes.

Linux enforcement uses a dedicated nftables output chain with policy drop. Only
loopback, the physical Router VPN entry endpoint, active Router VPN tunnel
interfaces, essential link maintenance, and (optionally) private LAN ranges are
allowed. For multihop, the policy may belong to one control profile while the
physical public exception belongs to a different entry profile; both IDs are
persisted so `always` can be reasserted correctly before networking on reboot.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Any

from profile_id import validate_profile_id as _shared_validate_profile_id

TABLE = "router_vpn_killswitch"
PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
PRIVATE_V6 = ("fc00::/7", "fe80::/10")


MAX_PRIVATE_JSON_BYTES = 4 << 20


def _validate_existing_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        try:
            info = current.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RuntimeError(f"refusing non-directory/symlink private path component: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent


def _require_private_dir(path: Path, *, create: bool = False) -> os.stat_result:
    _validate_existing_ancestors(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise
        path.mkdir(mode=0o700)
        info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink private directory: {path}")
    return info


def _private_regular_bytes(path: Path, limit: int = MAX_PRIVATE_JSON_BYTES) -> bytes:
    if limit <= 0 or limit > MAX_PRIVATE_JSON_BYTES:
        limit = MAX_PRIVATE_JSON_BYTES
    _validate_existing_ancestors(path)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink private file: {path}")
    if before.st_size < 0 or before.st_size > limit:
        raise RuntimeError(f"private file exceeds safety limit: {path}")
    if before.st_mode & 0o077:
        raise RuntimeError(f"private file permissions are too broad; expected 0600: {path}")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or opened.st_dev != current.st_dev
            or opened.st_ino != current.st_ino
        ):
            raise RuntimeError(f"private file changed during open: {path}")
        body = stream.read(limit + 1)
    if len(body) > limit:
        raise RuntimeError(f"private file exceeds safety limit: {path}")
    return body


def root_dir() -> Path:
    root = Path(os.path.abspath(os.path.expanduser(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client"))))
    _require_private_dir(root)
    return root


def validate_profile_id(value: str, label: str) -> str:
    raw = str(value or "").strip()
    try:
        return _shared_validate_profile_id(raw, default="")
    except ValueError as exc:
        raise RuntimeError(f"invalid {label}") from exc


def safe_profile_id() -> str:
    return validate_profile_id(os.environ.get("HOMEVPN_PROFILE_ID", "router"), "HOMEVPN_PROFILE_ID")


def policy_profile_id(runtime_id: str) -> str:
    value = os.environ.get("HOMEVPN_POLICY_PROFILE_ID", "").strip()
    return validate_profile_id(value, "HOMEVPN_POLICY_PROFILE_ID") if value else runtime_id


def read_store(root: Path) -> dict[str, Any]:
    path = root / "routers.json"
    try:
        value = json.loads(_private_regular_bytes(path).decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot safely read routers.json: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("routers.json is not an object")
    return value


def profile_from_store(store: dict[str, Any], profile_id: str) -> dict[str, Any] | None:
    for item in store.get("profiles", []):
        if isinstance(item, dict) and item.get("id") == profile_id:
            return item
    return None


def required_profile(store: dict[str, Any], profile_id: str, role: str) -> dict[str, Any]:
    profile = profile_from_store(store, profile_id)
    if profile is None:
        raise RuntimeError(f"{role} Router VPN profile {profile_id!r} was not found")
    return profile


def resolve_literal_endpoint(endpoint: str) -> list[ipaddress._BaseAddress]:
    value = endpoint.strip().strip("[]")
    if not value:
        raise RuntimeError("selected Router VPN endpoint is empty")
    try:
        return [ipaddress.ip_address(value)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(value, None, type=socket.SOCK_DGRAM)
            resolved = sorted({str(ipaddress.ip_address(info[4][0])) for info in infos})
        except OSError:
            resolved = []
        suffix = f" (currently resolves to {', '.join(resolved)})" if resolved else ""
        raise RuntimeError(
            "strict kill switch requires the selected node endpoint to be a literal IPv4/IPv6 address; "
            f"hostname {value!r} would require pre-tunnel DNS{suffix}"
        )


def nft_prefix() -> list[str]:
    nft = shutil.which("nft")
    if nft is None:
        raise RuntimeError("nftables is required for strict Linux kill switch")
    if getattr(os, "geteuid", lambda: 1)() == 0:
        return [nft]
    sudo = shutil.which("sudo")
    if sudo is None:
        raise RuntimeError("root privileges are required for strict Linux kill switch")
    return [sudo, "-n", nft]


def run_nft(args: list[str], *, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(nft_prefix() + args, input=input_text, text=True, capture_output=True, timeout=8, check=False)
    if check and proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "nftables command failed").strip())
    return proc


def table_exists() -> bool:
    try:
        return run_nft(["list", "table", "inet", TABLE], check=False).returncode == 0
    except RuntimeError:
        return False


def render_rules(endpoint_ips: list[ipaddress._BaseAddress], lan_access: bool, replace: bool) -> str:
    lines: list[str] = []
    if replace:
        lines.append(f"delete table inet {TABLE}")
    lines += [
        f"add table inet {TABLE}",
        f"add chain inet {TABLE} output {{ type filter hook output priority -310; policy drop; }}",
        f"add rule inet {TABLE} output oifname \"lo\" accept",
        f"add rule inet {TABLE} output oifname {{ \"wg\", \"awg\", \"router-vpn\" }} accept",
        f"add rule inet {TABLE} output ip protocol udp udp sport 68 udp dport 67 accept",
        f"add rule inet {TABLE} output ip6 nexthdr ipv6-icmp icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept",
    ]
    v4 = [str(ip) for ip in endpoint_ips if ip.version == 4]
    v6 = [str(ip) for ip in endpoint_ips if ip.version == 6]
    if v4:
        lines.append(f"add rule inet {TABLE} output ip daddr {{ {', '.join(v4)} }} accept")
    if v6:
        lines.append(f"add rule inet {TABLE} output ip6 daddr {{ {', '.join(v6)} }} accept")
    if lan_access:
        lines.append(f"add rule inet {TABLE} output ip daddr {{ {', '.join(PRIVATE_V4)} }} accept")
        lines.append(f"add rule inet {TABLE} output ip6 daddr {{ {', '.join(PRIVATE_V6)} }} accept")
    return "\n".join(lines) + "\n"


def state_path(root: Path) -> Path:
    return root / "run" / "kill-switch.json"


def _runtime_state_dir(root: Path) -> tuple[Path, os.stat_result]:
    _require_private_dir(root)
    run = root / "run"
    info = _require_private_dir(run, create=True)
    if info.st_mode & 0o077:
        os.chmod(run, 0o700)
        info = run.lstat()
    return run, info


def read_state(root: Path) -> dict[str, Any]:
    path = state_path(root)
    try:
        raw = _private_regular_bytes(path)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        raise RuntimeError(f"cannot safely read persistent kill-switch state: {exc}") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(f"persistent kill-switch state is corrupt: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("persistent kill-switch state must be a JSON object")
    if value.get("policy") not in {"on-connect", "always"}:
        raise RuntimeError("persistent kill-switch state contains an invalid policy")
    return value


def write_state(root: Path, value: dict[str, Any]) -> None:
    if not isinstance(value, dict) or value.get("policy") not in {"on-connect", "always"}:
        raise RuntimeError("refusing invalid persistent kill-switch state")
    path = state_path(root)
    run, parent_before = _runtime_state_dir(root)
    prior = None
    try:
        prior = path.lstat()
    except FileNotFoundError:
        pass
    if prior is not None and (stat.S_ISLNK(prior.st_mode) or not stat.S_ISREG(prior.st_mode)):
        raise RuntimeError(f"refusing non-regular/symlink kill-switch state target: {path}")

    body = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    if not body or len(body) > MAX_PRIVATE_JSON_BYTES:
        raise RuntimeError("persistent kill-switch state is empty or oversized")
    fd, tmp_name = tempfile.mkstemp(prefix=".kill-switch.", dir=str(run))
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())

        parent_now = _require_private_dir(run)
        if parent_now.st_dev != parent_before.st_dev or parent_now.st_ino != parent_before.st_ino:
            raise RuntimeError("kill-switch state parent changed before adoption")
        try:
            current = path.lstat()
        except FileNotFoundError:
            current = None
        if prior is None:
            if current is not None:
                raise RuntimeError("kill-switch state target appeared before adoption")
        elif (
            current is None
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or current.st_dev != prior.st_dev
            or current.st_ino != prior.st_ino
        ):
            raise RuntimeError("kill-switch state target changed before adoption")
        os.replace(tmp, path)
        try:
            dir_fd = os.open(run, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        tmp.unlink(missing_ok=True)


def _require_removal_identity(
    path: Path,
    before: os.stat_result,
    run: Path,
    parent_before: os.stat_result,
) -> bool:
    parent_now = _require_private_dir(run)
    if (
        parent_now.st_dev != parent_before.st_dev
        or parent_now.st_ino != parent_before.st_ino
    ):
        raise RuntimeError("kill-switch state parent changed before removal")
    try:
        current = path.lstat()
    except FileNotFoundError:
        return False
    if not os.path.samestat(before, current):
        raise RuntimeError("kill-switch state target identity changed before removal")
    return True


def remove_state(root: Path, *, force_recovery: bool = False) -> None:
    path = state_path(root)
    run, parent_before = _runtime_state_dir(root)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        if not force_recovery:
            raise RuntimeError("refusing symlink persistent kill-switch state; use local force-off recovery")
    elif not stat.S_ISREG(info.st_mode):
        raise RuntimeError("refusing non-regular persistent kill-switch state")
    if not _require_removal_identity(path, info, run, parent_before):
        return
    path.unlink()
    try:
        dir_fd = os.open(run, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass

def remove_table() -> None:
    if os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") == "1":
        return
    if table_exists():
        run_nft(["delete", "table", "inet", TABLE])


def policy_value(profile: dict[str, Any]) -> str:
    policy = str(profile.get("kill_switch_policy") or "off").strip().lower()
    if policy not in {"off", "on-connect", "always"}:
        raise RuntimeError(f"unsupported kill switch policy: {policy}")
    return policy


def apply() -> int:
    root = root_dir()
    store = read_store(root)
    runtime_id = safe_profile_id()
    control_id = policy_profile_id(runtime_id)
    runtime_profile = required_profile(store, runtime_id, "runtime/entry")
    control_profile = required_profile(store, control_id, "policy/control")
    policy = policy_value(control_profile)
    if policy == "off":
        state = read_state(root)
        if state or table_exists():
            remove_table()
        if state:
            remove_state(root)
        print("kill switch off", file=sys.stderr)
        return 0
    if not sys.platform.startswith("linux"):
        raise RuntimeError(f"strict kill switch is not implemented for {sys.platform}; refusing protected connect")
    endpoint = os.environ.get("HOMEVPN_ENDPOINT") or str(runtime_profile.get("endpoint") or "")
    endpoint_ips = resolve_literal_endpoint(endpoint)
    lan_access = bool(control_profile.get("home_lan_access", False))
    rules = render_rules(endpoint_ips, lan_access, replace=table_exists() if os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") != "1" else False)
    if os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") != "1":
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, prefix="router-vpn-killswitch-", suffix=".nft") as f:
            f.write(rules)
            temp_name = f.name
        try:
            run_nft(["-c", "-f", temp_name])
            run_nft(["-f", temp_name])
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
    write_state(root, {
        "policy": policy,
        "profile_id": runtime_id,
        "policy_profile_id": control_id,
        "endpoint": endpoint,
        "endpoint_ips": [str(ip) for ip in endpoint_ips],
        "home_lan_access": lan_access,
        "platform": sys.platform,
        "enforced": os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") != "1",
    })
    print(f"strict kill switch {policy} applied for physical entry {endpoint}", file=sys.stderr)
    return 0


def release(force: bool = False) -> int:
    root = root_dir()
    try:
        state = read_state(root)
    except RuntimeError:
        if not force:
            raise
        # force-off is the explicit local recovery path: remove the firewall
        # first, then unlink only the poisoned leaf itself without following it.
        remove_table()
        remove_state(root, force_recovery=True)
        print("strict kill switch force-off recovery completed", file=sys.stderr)
        return 0
    if not state:
        if force:
            remove_table()
        return 0
    if not force and state.get("policy") == "always":
        print("strict kill switch remains active (always policy)", file=sys.stderr)
        return 0
    remove_table()
    remove_state(root, force_recovery=force)
    print("strict kill switch released", file=sys.stderr)
    return 0

def reassert() -> int:
    root = root_dir()
    state = read_state(root)
    state_always = state.get("policy") == "always"
    try:
        store = read_store(root)
    except RuntimeError:
        if state_always:
            raise
        print("no Router VPN profile store; no persistent always policy to reassert", file=sys.stderr)
        return 0

    control_id = str(state.get("policy_profile_id") or store.get("selected_id") or "").strip()
    if not control_id:
        if state_always:
            raise RuntimeError("persistent always kill-switch state has no policy profile id")
        print("no selected Router VPN profile; no persistent always policy to reassert", file=sys.stderr)
        return 0
    control_id = validate_profile_id(control_id, "persistent kill-switch policy profile id")
    control_profile = profile_from_store(store, control_id)
    if control_profile is None:
        if state_always:
            raise RuntimeError(f"persistent always kill-switch policy profile {control_id!r} no longer exists; use force-off recovery locally")
        return 0
    current_policy = policy_value(control_profile)
    if current_policy != "always":
        remove_table()
        remove_state(root)
        print("persistent always state cleared because the current profile policy is no longer always", file=sys.stderr)
        return 0

    runtime_id = str(state.get("profile_id") or "").strip()
    if not runtime_id:
        candidate = str(control_profile.get("multihop_entry_id") or "").strip() if bool(control_profile.get("multihop_enabled")) else ""
        runtime_id = candidate or control_id
    runtime_id = validate_profile_id(runtime_id, "persistent kill-switch runtime profile id")
    runtime_profile = profile_from_store(store, runtime_id)
    if runtime_profile is None:
        raise RuntimeError(f"persistent always kill-switch runtime/entry profile {runtime_id!r} no longer exists; use force-off recovery locally")

    os.environ["HOMEVPN_PROFILE_ID"] = runtime_id
    os.environ["HOMEVPN_POLICY_PROFILE_ID"] = control_id
    os.environ["HOMEVPN_ENDPOINT"] = str(runtime_profile.get("endpoint") or state.get("endpoint") or "")
    return apply()


def status() -> int:
    root = root_dir()
    state = read_state(root)
    if not state:
        print(json.dumps({"active": False, "policy": "off"}))
        return 1
    active = bool(os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") == "1" or (sys.platform.startswith("linux") and table_exists()))
    print(json.dumps({"active": active, **state}, sort_keys=True))
    return 0 if active else 1


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        if action == "apply":
            return apply()
        if action == "release":
            return release(False)
        if action == "force-off":
            return release(True)
        if action == "reassert":
            return reassert()
        if action == "status":
            return status()
        print("usage: kill-switch.py apply|release|force-off|reassert|status", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"kill switch error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
