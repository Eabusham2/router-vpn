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
import subprocess
import sys
import tempfile
from typing import Any

from profile_id import validate_profile_id as _shared_validate_profile_id

TABLE = "router_vpn_killswitch"
PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
PRIVATE_V6 = ("fc00::/7", "fe80::/10")


def root_dir() -> Path:
    return Path(os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client")).resolve()


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
    try:
        value = json.loads((root / "routers.json").read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot read routers.json: {exc}") from exc
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


def read_state(root: Path) -> dict[str, Any]:
    try:
        value = json.loads(state_path(root).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def write_state(root: Path, value: dict[str, Any]) -> None:
    path = state_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="kill-switch.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
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
        if read_state(root):
            remove_table()
            state_path(root).unlink(missing_ok=True)
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
    state = read_state(root)
    if not state:
        if force:
            remove_table()
        return 0
    if not force and state.get("policy") == "always":
        print("strict kill switch remains active (always policy)", file=sys.stderr)
        return 0
    remove_table()
    state_path(root).unlink(missing_ok=True)
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
        state_path(root).unlink(missing_ok=True)
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
