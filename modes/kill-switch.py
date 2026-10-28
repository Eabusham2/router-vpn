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
import re
import shutil
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
        # Reject without resolving, even for a diagnostic suffix. The guard has
        # not installed its firewall yet; an OS lookup here would leak DNS on
        # precisely the pre-tunnel path this strict policy refuses to use.
        raise RuntimeError(
            "strict kill switch requires the selected node endpoint to be a literal IPv4/IPv6 address; "
            f"hostname {value!r} would require pre-tunnel DNS"
        ) from None


def captured_endpoint_ips(endpoint: str) -> list[ipaddress._BaseAddress]:
    primary = resolve_literal_endpoint(endpoint)
    raw = os.environ.get("HOMEVPN_NATIVE_ENDPOINTS_JSON")
    if raw is None:
        return primary
    session = os.environ.get("HOMEVPN_EXTERNAL_SESSION", "")
    if (len(raw) > 1024 or os.environ.get("HOMEVPN_STANDARD_ENGINE") != "native"
            or len(session) != 32 or any(c not in "0123456789abcdef" for c in session)):
        raise RuntimeError("native endpoint list has no captured external session")
    try:
        values = json.loads(raw)
        if not isinstance(values, list) or not 1 <= len(values) <= 16:
            raise ValueError()
        result = []
        for value in values:
            if not isinstance(value, str):
                raise ValueError()
            address = ipaddress.ip_address(value)
            if (str(address) != value or address.is_unspecified or address.is_multicast
                    or address.is_loopback or address.is_link_local or '%' in value
                    or value == '255.255.255.255'
                    or getattr(address, 'ipv4_mapped', None) is not None or address in result):
                raise ValueError()
            result.append(address)
        if result[0] != primary[0]:
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise RuntimeError("native endpoint list must retain its captured literal physical remotes") from None


def validate_native_egress(value: Any, endpoint_ips: list[ipaddress._BaseAddress]) -> list[dict[str, Any]]:
    """Accept only complete literal tuples; never coerce an invalid list to all ports."""
    failure = RuntimeError("native egress must retain exact captured physical host, port and transport tuples")
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise failure
    hosts = {str(address) for address in endpoint_ips}
    seen: set[tuple[str, int, str]] = set()
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"host", "port", "network"}:
            raise failure
        host, port, network = item["host"], item["port"], item["network"]
        if (not isinstance(host, str) or host not in hosts or type(port) is not int
                or not 1 <= port <= 65535 or network not in ("tcp", "udp")):
            raise failure
        identity = (host, port, network)
        if identity in seen:
            raise failure
        seen.add(identity)
        result.append({"host": host, "port": port, "network": network})
    if {item["host"] for item in result} != hosts:
        raise failure
    return result


def _unique_json_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native egress member")
        result[key] = value
    return result


def captured_native_egress(endpoint_ips: list[ipaddress._BaseAddress]) -> list[dict[str, Any]] | None:
    raw = os.environ.get("HOMEVPN_NATIVE_EGRESS_JSON")
    if raw is None:
        return None
    session = os.environ.get("HOMEVPN_EXTERNAL_SESSION", "")
    if (len(raw) > 4096 or os.environ.get("HOMEVPN_STANDARD_ENGINE") != "native"
            or len(session) != 32 or any(c not in "0123456789abcdef" for c in session)):
        raise RuntimeError("native egress has no captured external session")
    try:
        return validate_native_egress(json.loads(raw, object_pairs_hook=_unique_json_members), endpoint_ips)
    except (ValueError, TypeError):
        raise RuntimeError("native egress must retain exact captured physical host, port and transport tuples") from None


def retained_native_policy(state: dict[str, Any], endpoint: str):
    """Reassert an owned always guard without widening its saved outer ports."""
    if "native_egress" not in state:
        return None
    if state.get("endpoint") != endpoint:
        raise RuntimeError("saved native egress physical owner changed; reconnect before reasserting")
    values = state.get("endpoint_ips")
    if not isinstance(values, list) or not 1 <= len(values) <= 16:
        raise RuntimeError("saved native egress lost its captured physical hosts")
    addresses = []
    for value in values:
        if not isinstance(value, str):
            raise RuntimeError("saved native egress physical host is invalid")
        address = resolve_literal_endpoint(value)[0]
        if (str(address) != value or address.is_unspecified or address.is_multicast
                or address.is_loopback or address.is_link_local or '%' in value
                or value == '255.255.255.255' or getattr(address, 'ipv4_mapped', None) is not None
                or address in addresses):
            raise RuntimeError("saved native egress physical host is invalid")
        addresses.append(address)
    if addresses[0] != resolve_literal_endpoint(endpoint)[0]:
        raise RuntimeError("saved native egress lost its primary physical host")
    return addresses, validate_native_egress(state["native_egress"], addresses)


def native_socket_broker_policy(profile: dict[str, Any], runtime_id: str, control_id: str,
                               retained_state: dict[str, Any] | None) -> bool:
    """Select a closed baseline, never grant authority from a helper's output.

    The native Linux guardian independently verifies this DROP chain and owns
    every short-lived UID/full-socket-tuple exception. A retained Always policy
    restores only this empty baseline; it cannot resurrect a former guardian.
    """
    marker = os.environ.get("HOMEVPN_TOR_PHYSICAL_BROKER", "")
    retained = retained_state is not None and "native_socket_broker" in retained_state
    if not marker and not retained:
        return False
    failure = RuntimeError("native socket protection requires its captured direct Linux Tor policy")
    if not sys.platform.startswith("linux"):
        raise failure
    external = profile.get("external")
    if (runtime_id != control_id or profile.get("node_kind") != "external"
            or type(external) is not dict or external.get("protocol") not in {"tor", "tor-bridge"}
            or profile.get("multihop_enabled", False) is not False
            or policy_value(profile) not in {"on-connect", "always"}):
        raise failure
    if retained:
        if (retained_state.get("native_socket_broker") is not True
                or retained_state.get("endpoint") != ""
                or retained_state.get("endpoint_ips") != [] or "native_egress" in retained_state):
            raise failure
    else:
        if (marker != "1" or os.environ.get("HOMEVPN_STANDARD_ENGINE") != "native"
                or not re.fullmatch(r"[0-9a-f]{32}", os.environ.get("HOMEVPN_TOR_SESSION", ""))
                or not re.fullmatch(r"[0-9a-f]{64}", os.environ.get("HOMEVPN_TOR_SOURCE_SHA256", ""))):
            raise failure
    if (os.environ.get("HOMEVPN_NATIVE_ENDPOINTS_JSON") or os.environ.get("HOMEVPN_NATIVE_EGRESS_JSON")
            or os.environ.get("HOMEVPN_EXTERNAL_SESSION")
            or not retained and os.environ.get("HOMEVPN_ENDPOINT", "")):
        raise failure
    return True


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


def render_rules(endpoint_ips: list[ipaddress._BaseAddress], lan_access: bool, replace: bool, native_egress=None,
                 *, socket_broker: bool = False, socket_capture: tuple[str, str] | None = None) -> str:
    comment = ""
    if socket_broker:
        if endpoint_ips or native_egress is not None:
            raise RuntimeError("socket broker baseline cannot contain destination-wide exemptions")
        marker = "inactive"
        if socket_capture is not None:
            session, source = socket_capture
            if not re.fullmatch(r"[a-f0-9]{32}", session) or not re.fullmatch(r"[a-f0-9]{64}", source):
                raise RuntimeError("socket broker baseline has no captured source identity")
            marker = session + ":" + source
        comment = f' comment "routervpn-owned-baseline:{marker}";'
    elif socket_capture is not None:
        raise RuntimeError("socket broker identity cannot annotate an ordinary endpoint policy")
    lines: list[str] = []
    if replace:
        lines.append(f"delete table inet {TABLE}")
    lines += [
        f"add table inet {TABLE}",
        f"add chain inet {TABLE} output {{ type filter hook output priority -310; policy drop;{comment} }}",
        f"add rule inet {TABLE} output oifname \"lo\" accept",
        f"add rule inet {TABLE} output oifname {{ \"wg\", \"awg\", \"router-vpn\" }} accept",
        f"add rule inet {TABLE} output ip protocol udp udp sport 68 udp dport 67 accept",
        f"add rule inet {TABLE} output ip6 nexthdr ipv6-icmp icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept",
    ]
    v4 = [str(ip) for ip in endpoint_ips if ip.version == 4]
    v6 = [str(ip) for ip in endpoint_ips if ip.version == 6]
    if native_egress is not None:
        for item in validate_native_egress(native_egress, endpoint_ips):
            family = "ip6" if ipaddress.ip_address(item["host"]).version == 6 else "ip"
            lines.append(f"add rule inet {TABLE} output {family} daddr {item['host']} {item['network']} dport {item['port']} accept")
    else:
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


def apply(*, retained_state: dict[str, Any] | None = None) -> int:
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
    socket_broker = native_socket_broker_policy(control_profile, runtime_id, control_id, retained_state)
    endpoint = "" if socket_broker else os.environ.get("HOMEVPN_ENDPOINT") or str(runtime_profile.get("endpoint") or "")
    retained = retained_native_policy(retained_state, endpoint) if retained_state is not None and not socket_broker else None
    if socket_broker:
        endpoint_ips, native_egress = [], None
    elif retained is None:
        endpoint_ips = captured_endpoint_ips(endpoint)
        native_egress = captured_native_egress(endpoint_ips)
    else:
        endpoint_ips, native_egress = retained
    lan_access = bool(control_profile.get("home_lan_access", False))
    socket_capture = ((os.environ["HOMEVPN_TOR_SESSION"], os.environ["HOMEVPN_TOR_SOURCE_SHA256"])
                      if socket_broker and retained_state is None else None)
    rules = render_rules(endpoint_ips, lan_access, replace=table_exists() if os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") != "1" else False,
                         native_egress=native_egress, socket_broker=socket_broker, socket_capture=socket_capture)
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
    state = {
        "policy": policy,
        "profile_id": runtime_id,
        "policy_profile_id": control_id,
        "endpoint": endpoint,
        "endpoint_ips": [str(ip) for ip in endpoint_ips],
        "home_lan_access": lan_access,
        "platform": sys.platform,
        "enforced": os.environ.get("HOMEVPN_KILLSWITCH_DRY_RUN") != "1",
    }
    if native_egress is not None:
        state["native_egress"] = native_egress
    if socket_broker:
        state["native_socket_broker"] = True
    write_state(root, state)
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
    os.environ.pop("HOMEVPN_NATIVE_ENDPOINTS_JSON", None)
    os.environ.pop("HOMEVPN_NATIVE_EGRESS_JSON", None)
    os.environ.pop("HOMEVPN_TOR_PHYSICAL_BROKER", None)
    os.environ.pop("HOMEVPN_EXTERNAL_SESSION", None)
    return apply(retained_state=state)


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
