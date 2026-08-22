#!/usr/bin/env python3
"""Scoped macOS PF backend for Router VPN strict kill-switch policy.

This module never rewrites /etc/pf.conf, never flushes the global PF ruleset,
and never flushes the global PF state table. It installs filter rules only in
the existing com.apple/* anchor namespace and uses pfctl's reference-counted
-E/-X lifecycle. A protected connect is two phase: pre-connect rules permit only
the selected literal node endpoint and required link maintenance; after the
tunnel starts, the controller refreshes the anchor and permits only a newly-
created Router VPN utun that also owns a public route. Existing states are
invalidated only on the proven pre-tunnel public interface(s), so strict mode
does not destroy unrelated PF state on other interfaces.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from typing import Any

PF_ANCHOR = "com.apple/router-vpn"
PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
PRIVATE_V6 = ("fc00::/7", "fe80::/10")


def _root_prefix(binary: str, purpose: str) -> list[str]:
    if getattr(os, "geteuid", lambda: 1)() == 0:
        return [binary]
    sudo = shutil.which("sudo")
    if sudo is None:
        raise RuntimeError(f"root privileges are required for {purpose}")
    return [sudo, "-n", binary]


def _pfctl() -> str:
    value = shutil.which("pfctl")
    if value:
        return value
    if os.path.exists("/sbin/pfctl"):
        return "/sbin/pfctl"
    raise RuntimeError("pfctl is required for strict macOS kill switch")


def run_pf(args: list[str], *, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        _root_prefix(_pfctl(), "strict macOS kill switch") + args,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "pfctl command failed").strip())
    return proc


def _command_output(argv: list[str]) -> str:
    try:
        proc = subprocess.run(argv, text=True, capture_output=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def current_utuns() -> list[str]:
    override = os.environ.get("HOMEVPN_KILLSWITCH_DARWIN_UTUNS")
    if override is not None:
        return sorted({x.strip() for x in override.split(",") if re.fullmatch(r"utun[0-9]+", x.strip())})
    ifconfig = shutil.which("ifconfig") or "/sbin/ifconfig"
    text = _command_output([ifconfig, "-l"])
    return sorted({x for x in text.split() if re.fullmatch(r"utun[0-9]+", x)})


def _safe_physical_interface(value: str) -> bool:
    value = value.strip()
    return bool(
        re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", value)
        and value != "lo0"
        and not re.fullmatch(r"utun[0-9]+", value)
    )


def public_route_interfaces() -> list[str]:
    override = os.environ.get("HOMEVPN_KILLSWITCH_DARWIN_PHYSICAL_INTERFACES")
    if override is not None:
        return sorted({x.strip() for x in override.split(",") if _safe_physical_interface(x)})
    route = shutil.which("route") or "/sbin/route"
    found: set[str] = set()
    commands = (
        [route, "-n", "get", "1.1.1.1"],
        [route, "-n", "get", "9.9.9.9"],
        [route, "-n", "get", "-inet6", "2606:4700:4700::1111"],
    )
    for command in commands:
        text = _command_output(command)
        match = re.search(r"(?m)^\s*interface:\s*(\S+)\s*$", text)
        if match and _safe_physical_interface(match.group(1)):
            found.add(match.group(1))
    return sorted(found)


def route_utuns() -> list[str]:
    override = os.environ.get("HOMEVPN_KILLSWITCH_DARWIN_ROUTE_UTUNS")
    if override is not None:
        return sorted({x.strip() for x in override.split(",") if re.fullmatch(r"utun[0-9]+", x.strip())})
    route = shutil.which("route") or "/sbin/route"
    found: set[str] = set()
    for target in ("1.1.1.1", "9.9.9.9"):
        text = _command_output([route, "-n", "get", target])
        match = re.search(r"(?m)^\s*interface:\s*(\S+)\s*$", text)
        if match and re.fullmatch(r"utun[0-9]+", match.group(1)):
            found.add(match.group(1))
    return sorted(found)


def render_pf_rules(
    endpoint_ips: list[ipaddress._BaseAddress],
    lan_access: bool,
    tunnel_interfaces: list[str],
) -> str:
    lines = [
        "pass out quick on lo0 all",
        "pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67",
        "pass out quick inet6 proto udp from any port 546 to any port 547",
        "pass out quick inet6 proto icmp6 from { ::, fe80::/10 } to { fe80::/10, ff00::/8 }",
    ]
    v4 = [str(ip) for ip in endpoint_ips if ip.version == 4]
    v6 = [str(ip) for ip in endpoint_ips if ip.version == 6]
    if v4:
        lines.append("pass out quick inet to { " + ", ".join(v4) + " }")
    if v6:
        lines.append("pass out quick inet6 to { " + ", ".join(v6) + " }")
    for interface in sorted(set(tunnel_interfaces)):
        if not re.fullmatch(r"utun[0-9]+", interface):
            raise RuntimeError(f"unsafe macOS tunnel interface name: {interface!r}")
        lines.append(f"pass out quick on {interface} all")
    if lan_access:
        lines.append("pass out quick inet to { " + ", ".join(PRIVATE_V4) + " }")
        lines.append("pass out quick inet to 224.0.0.0/4")
        lines.append("pass out quick inet6 to { " + ", ".join(PRIVATE_V6) + " }")
        lines.append("pass out quick inet6 to ff00::/8")
    lines.append("block drop out quick all")
    return "\n".join(lines) + "\n"


def _enable_reference(previous_state: dict[str, Any]) -> tuple[str, bool]:
    old = str(previous_state.get("pf_token") or "").strip()
    if old:
        return old, False
    proc = run_pf(["-E"])
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    match = re.search(r"(?i)token\s*:\s*([0-9]+)", text)
    if not match:
        # PF may now be enabled, but without its reference token we cannot
        # safely balance our enable without risking another component's PF use.
        raise RuntimeError("pfctl -E did not return a reference token; refusing unbalanced PF ownership")
    return match.group(1), True


def _clear_anchor(*, check: bool = False) -> None:
    run_pf(["-a", PF_ANCHOR, "-F", "rules"], check=check)


def apply_darwin(
    endpoint_ips: list[ipaddress._BaseAddress],
    lan_access: bool,
    previous_state: dict[str, Any],
    *,
    refresh: bool,
    dry_run: bool,
) -> dict[str, Any]:
    current = current_utuns()
    if refresh:
        baseline = {
            x for x in previous_state.get("darwin_baseline_utun", [])
            if isinstance(x, str) and re.fullmatch(r"utun[0-9]+", x)
        }
        physical_interfaces = sorted({
            x for x in previous_state.get("darwin_physical_interfaces", [])
            if isinstance(x, str) and _safe_physical_interface(x)
        })
        new_interfaces = set(current) - baseline
        routed = set(route_utuns())
        tunnel_interfaces = sorted(new_interfaces & routed)
        if not tunnel_interfaces:
            raise RuntimeError(
                "strict macOS kill switch could not prove a newly-created Router VPN utun on the public route; refusing protected connect"
            )
    else:
        baseline = set(current)
        physical_interfaces = public_route_interfaces()
        tunnel_interfaces = []
        if not dry_run and not physical_interfaces:
            raise RuntimeError(
                "strict macOS kill switch could not prove the pre-tunnel public interface; refusing unscoped PF state invalidation"
            )

    rules = render_pf_rules(endpoint_ips, lan_access, tunnel_interfaces)
    if dry_run:
        token = str(previous_state.get("pf_token") or "dry-run")
        return {
            "pf_token": token,
            "darwin_baseline_utun": sorted(baseline),
            "darwin_tunnel_interfaces": tunnel_interfaces,
            "darwin_physical_interfaces": physical_interfaces,
            "darwin_pf_anchor": PF_ANCHOR,
        }

    # Validate syntax before changing PF state/rules.
    run_pf(["-a", PF_ANCHOR, "-n", "-f", "-"], input_text=rules)
    token = ""
    token_created = False
    try:
        token, token_created = _enable_reference(previous_state)
        run_pf(["-a", PF_ANCHOR, "-f", "-"], input_text=rules)
        if token_created:
            # PF state is global by default, so strict protection must invalidate
            # pre-existing cleartext flows. Restrict that operation to the
            # proven pre-tunnel public interface(s); never flush the global state
            # table or states on unrelated interfaces.
            for interface in physical_interfaces:
                run_pf(["-i", interface, "-F", "states"])
    except Exception:
        if token_created and token:
            _clear_anchor(check=False)
            run_pf(["-X", token], check=False)
        raise
    return {
        "pf_token": token,
        "darwin_baseline_utun": sorted(baseline),
        "darwin_tunnel_interfaces": tunnel_interfaces,
        "darwin_physical_interfaces": physical_interfaces,
        "darwin_pf_anchor": PF_ANCHOR,
    }


def remove_darwin(state: dict[str, Any], *, dry_run: bool) -> None:
    if dry_run:
        return
    _clear_anchor(check=False)
    token = str(state.get("pf_token") or "").strip()
    if token and token != "dry-run":
        run_pf(["-X", token], check=False)


def status_darwin(state: dict[str, Any], *, dry_run: bool) -> bool:
    if dry_run:
        return bool(state)
    try:
        proc = run_pf(["-a", PF_ANCHOR, "-sr"], check=False)
    except RuntimeError:
        return False
    return proc.returncode == 0 and bool((proc.stdout or "").strip())
