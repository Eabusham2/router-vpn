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
import base64
import hashlib
import os
import re
import shutil
import subprocess
from typing import Any, Callable

PF_ANCHOR = "com.apple/router-vpn"
OWNED_PF_ANCHOR = "com.apple/000.router-vpn"
PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
PRIVATE_V6 = ("fc00::/7", "fe80::/10")


def owned_label(value: str) -> str:
    return 'rvpn:' + base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip('=')


def render_owned_pf_rules(lan_access: bool, capture: tuple[str, str] | None) -> str:
    """Empty native-owner baseline; no account, tuple or utun name is borrowed."""
    if capture is None:
        session, source = 'inactive', ''
    elif (type(capture) is not tuple or len(capture) != 2
          or not re.fullmatch('[0-9a-f]{32}', capture[0])
          or not re.fullmatch('[0-9a-f]{64}', capture[1])):
        raise RuntimeError('macOS native baseline lost its exact session/source')
    else:
        session, source = capture
    allowed = owned_label('allowed\0'+session+'\0'+source)
    reset = owned_label('unproven\0'+session+'\0'+source)
    label = owned_label('baseline\0'+session+'\0'+source)
    lines = [f'pass out all tag "{reset}" no state']
    if capture is not None:
        lines.append(f'anchor "p{session}" out')
    # Nonquick permitted packets continue through later foreign block rules.
    # Only an unmatched packet takes quick deny, before a foreign pass can
    # override protection. Stateful/translation intersections are refused by
    # preflight and by the independent native guardian.
    lines += [f'pass out on lo0 all tag "{allowed}" no state',
              f'pass out inet proto udp from any port 68 to 255.255.255.255 port 67 tag "{allowed}" no state',
              f'pass out inet6 proto udp from any port 546 to any port 547 tag "{allowed}" no state',
              f'pass out inet6 proto icmp6 from {{ ::, fe80::/10 }} to {{ fe80::/10, ff00::/8 }} tag "{allowed}" no state']
    if lan_access:
        lines += [f'pass out inet to {{ {", ".join(PRIVATE_V4)} }} tag "{allowed}" no state',
                  f'pass out inet to 224.0.0.0/4 tag "{allowed}" no state',
                  f'pass out inet6 to {{ {", ".join(PRIVATE_V6)} }} tag "{allowed}" no state',
                  f'pass out inet6 to ff00::/8 tag "{allowed}" no state']
    lines.append(f'block drop out quick all ! tagged "{allowed}" label "{label}"')
    return '\n'.join(lines)+'\n'


def physical_state_interfaces() -> dict[str, list[str]]:
    """Capture all physical addresses, including temporary IPv6 and adapters."""
    text = _command_output(['/sbin/ifconfig', '-a'])
    result: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        header = re.match(r'^([A-Za-z0-9_.:-]{1,15}): flags=[0-9a-fA-F]+<([^>]+)>', line)
        if header:
            name, flags = header.group(1), set(header.group(2).split(','))
            current = (name if 'UP' in flags and not {'LOOPBACK', 'POINTOPOINT'} & flags
                       and not name.startswith(('utun', 'ipsec')) else None)
            if current is not None:
                result[current] = []
            continue
        if current is None:
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[0] in {'inet', 'inet6'}:
            address = ipaddress.ip_address(fields[1].split('%', 1)[0])
            if address.is_unspecified or address.is_multicast:
                raise RuntimeError('macOS physical state scope has an invalid address')
            result[current].append(str(address))
    result = {name: sorted(set(addresses)) for name, addresses in result.items() if addresses}
    if not result or len(result) > 64 or sum(map(len, result.values())) > 256:
        raise RuntimeError('macOS physical state scope is absent or exceeds its bound')
    return result


def _owned_compatible_filters(text: str) -> None:
    for line in text.splitlines():
        line = line.strip()
        if not line or line == '}' or line.startswith(('anchor ', 'block ')):
            continue
        if not line.startswith('pass ') or ' no state' not in line or any(value in line for value in (' keep state', ' modulate state', ' synproxy state')):
            raise RuntimeError('native macOS protection intersects a foreign stateful or unknown filter')


def _owned_no_translation(anchor: str) -> None:
    arguments = (['-a', anchor] if anchor else []) + ['-s', 'nat']
    translation = run_pf(arguments).stdout
    if any(row.strip() and row.strip() != '}' and not row.strip().startswith(('nat-anchor ', 'rdr-anchor ', 'binat-anchor ')) for row in translation.splitlines()):
        raise RuntimeError('native macOS protection intersects foreign translation state')


def _owned_system_filters(text: str) -> None:
    # The exact stock normalization prefix precedes the first filter. It has
    # no pass authority; foreign child filters and translations are still
    # checked independently. Do not ignore other scrub actions or reorder
    # an earlier filter into a position after our required system dispatch.
    filters = '\n'.join(row.strip() for row in text.splitlines() if row.strip())
    filters = filters.removeprefix('scrub-anchor "com.apple/*" all fragment reassemble\n')
    if not (filters+'\n').startswith('anchor "com.apple/*" all\n'):
        raise RuntimeError('native macOS protection requires the existing system PF anchor dispatch')
    _owned_compatible_filters(filters)


def owned_pf_preflight(previous: dict[str, Any]) -> None:
    _owned_system_filters(run_pf(['-s', 'rules']).stdout)
    for anchor in (OWNED_PF_ANCHOR+'/physical', OWNED_PF_ANCHOR+'/physical/*'):
        if run_pf(['-a', anchor, '-s', 'rules']).stdout.strip():
            raise RuntimeError('native macOS protection retains an earlier nested physical owner; exact prior-owner recovery is required')
    for anchor in ('', OWNED_PF_ANCHOR, OWNED_PF_ANCHOR+'/*'):
        _owned_no_translation(anchor)
    for root in run_pf(['-s', 'Anchors']).stdout.split():
        if root == 'com.apple':
            continue
        if not re.fullmatch('[A-Za-z0-9_.:-]+', root):
            raise RuntimeError('native macOS protection found an unknown root PF anchor')
        for anchor in (root, root+'/*'):
            _owned_compatible_filters(run_pf(['-a', anchor, '-s', 'rules']).stdout)
            _owned_no_translation(anchor)
    anchors = run_pf(['-a', 'com.apple', '-s', 'Anchors']).stdout.splitlines()
    ours = {OWNED_PF_ANCHOR}
    if previous.get('darwin_pf_anchor') == PF_ANCHOR and previous.get('platform') == 'darwin':
        ours.add(PF_ANCHOR)
    for line in anchors:
        name = line.strip().removeprefix('com.apple/')
        if not name or 'com.apple/'+name in ours:
            continue
        if not re.fullmatch('[A-Za-z0-9_.:-]+', name):
            raise RuntimeError('native macOS protection found an unknown PF anchor')
        for anchor in ('com.apple/'+name, 'com.apple/'+name+'/*'):
            rules = run_pf(['-a', anchor, '-s', 'rules']).stdout
            if anchor.removesuffix('/*') < OWNED_PF_ANCHOR and rules.strip():
                raise RuntimeError('native macOS protection has an earlier foreign filter')
            _owned_compatible_filters(rules)
            _owned_no_translation(anchor)


def retire_physical_states(captured: dict[str, list[str]]) -> None:
    if physical_state_interfaces() != captured:
        raise RuntimeError('macOS physical state capture changed before retirement')
    for interface, addresses in captured.items():
        run_pf(['-i', interface, '-F', 'states'])
        for address in addresses:
            any_address = '::/0' if ':' in address else '0.0.0.0/0'
            run_pf(['-k', address])
            run_pf(['-k', any_address, '-k', address])
    # The native guardian independently parses and reads back all physical and
    # floating states before its first socket. No user traffic is admitted by
    # this empty baseline while that native verification is pending.
    if physical_state_interfaces() != captured:
        raise RuntimeError('macOS physical state capture changed during retirement')


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
    native_egress=None,
) -> str:
    lines = [
        "pass out quick on lo0 all",
        "pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67",
        "pass out quick inet6 proto udp from any port 546 to any port 547",
        "pass out quick inet6 proto icmp6 from { ::, fe80::/10 } to { fe80::/10, ff00::/8 }",
    ]
    v4 = [str(ip) for ip in endpoint_ips if ip.version == 4]
    v6 = [str(ip) for ip in endpoint_ips if ip.version == 6]
    if native_egress is not None:
        if not isinstance(native_egress, list) or not 1 <= len(native_egress) <= 16:
            raise RuntimeError("invalid captured native egress")
        seen = set()
        for item in native_egress:
            if not isinstance(item, dict) or set(item) != {"host", "port", "network"}:
                raise RuntimeError("invalid captured native egress tuple")
            host, port, network = item["host"], item["port"], item["network"]
            if host not in v4 + v6 or type(port) is not int or not 1 <= port <= 65535 or network not in ("tcp", "udp"):
                raise RuntimeError("invalid captured native egress tuple")
            if (host, port, network) in seen:
                raise RuntimeError("duplicate captured native egress tuple")
            seen.add((host, port, network))
            family = "inet6" if host in v6 else "inet"
            lines.append(f"pass out quick {family} proto {network} to {host} port {port}")
        if {item[0] for item in seen} != set(v4 + v6):
            raise RuntimeError("captured native egress omitted a physical host")
    else:
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


def _state_anchor(state: dict[str, Any]) -> str:
    expected = OWNED_PF_ANCHOR if state.get('native_socket_broker') is True else PF_ANCHOR
    if state.get('darwin_pf_anchor', expected) != expected:
        raise RuntimeError('macOS kill-switch state contains another PF owner')
    return expected


def _state_anchors(state: dict[str, Any]) -> list[str]:
    if not state:
        return []
    current = _state_anchor(state)
    previous = state.get('darwin_previous_pf_anchor')
    if previous is not None and (previous not in {PF_ANCHOR, OWNED_PF_ANCHOR} or previous == current):
        raise RuntimeError('macOS kill-switch transition contains another PF owner')
    return [current] + ([previous] if previous is not None else [])


def _transition_metadata(extra: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    other = [anchor for anchor in _state_anchors(previous) if anchor != extra['darwin_pf_anchor']]
    return {**extra, **({'darwin_previous_pf_anchor': other[0]} if other else {})}


def _clear_anchor(*, check: bool = False, anchor: str = PF_ANCHOR) -> None:
    if anchor not in {PF_ANCHOR, OWNED_PF_ANCHOR}:
        raise RuntimeError('macOS kill-switch cleanup has another PF owner')
    run_pf(["-a", anchor, "-F", "rules"], check=check)


def apply_darwin(
    endpoint_ips: list[ipaddress._BaseAddress],
    lan_access: bool,
    previous_state: dict[str, Any],
    *,
    refresh: bool,
    dry_run: bool,
    native_egress=None,
    socket_broker: bool = False,
    socket_capture: tuple[str, str] | None = None,
    retain_state: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    previous_anchors = _state_anchors(previous_state)
    if socket_broker:
        if endpoint_ips or native_egress is not None or refresh:
            raise RuntimeError('macOS native socket baseline cannot acquire endpoint or name-only tunnel authority')
        rules = render_owned_pf_rules(lan_access, socket_capture)
        if dry_run:
            return {'pf_token': str(previous_state.get('pf_token') or 'dry-run'),
                    'darwin_baseline_utun': [], 'darwin_tunnel_interfaces': [],
                    'darwin_physical_interfaces': [], 'darwin_pf_anchor': OWNED_PF_ANCHOR}
        # Validate all compatibility/capture inputs before replacing an owned
        # baseline. The old route watcher cannot grant this native path.
        owned_pf_preflight(previous_state)
        physical = physical_state_interfaces()
        run_pf(['-a', OWNED_PF_ANCHOR, '-n', '-f', '-'], input_text=rules)
        if retain_state is None:
            raise RuntimeError('macOS native baseline requires persisted cleanup ownership before PF mutation')
        token, token_created = _enable_reference(previous_state)
        extra = {'pf_token': token, 'darwin_baseline_utun': [], 'darwin_tunnel_interfaces': [],
                 'darwin_physical_interfaces': sorted(physical), 'darwin_pf_anchor': OWNED_PF_ANCHOR}
        try:
            retain_state(_transition_metadata(extra, previous_state))
        except Exception:
            # No filter has been changed. Balance only the reference acquired
            # by this attempt; a previous owner's reference remains untouched.
            if token_created:
                run_pf(['-X', token], check=False)
            raise
        # From this point the private saved record owns the reference and both
        # fixed anchors during handoff. A failure retains deny and exact cleanup
        # authority, including failure after the kernel applied a command.
        run_pf(['-a', OWNED_PF_ANCHOR, '-f', '-'], input_text=rules)
        retire_physical_states(physical)
        for anchor in previous_anchors:
            if anchor != OWNED_PF_ANCHOR:
                _clear_anchor(check=True, anchor=anchor)
        return extra
    if socket_capture is not None:
        raise RuntimeError('macOS socket capture requires its native baseline')
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

    rules = render_pf_rules(endpoint_ips, lan_access, tunnel_interfaces, native_egress)
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
        if OWNED_PF_ANCHOR in previous_anchors:
            if retain_state is None:
                raise RuntimeError('macOS native policy transition requires persisted cleanup ownership')
            retain_state(_transition_metadata({
                'pf_token': token, 'darwin_baseline_utun': sorted(baseline),
                'darwin_tunnel_interfaces': tunnel_interfaces,
                'darwin_physical_interfaces': physical_interfaces, 'darwin_pf_anchor': PF_ANCHOR,
            }, previous_state))
        run_pf(["-a", PF_ANCHOR, "-f", "-"], input_text=rules)
        for anchor in previous_anchors:
            if anchor != PF_ANCHOR:
                _clear_anchor(check=True, anchor=anchor)
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
    anchors = _state_anchors(state)
    for anchor in anchors:
        # Dynamic policy and in-progress handoffs must not release their PF
        # reference while an owned dispatch remains uncertain.
        checked = OWNED_PF_ANCHOR in anchors
        _clear_anchor(check=checked, anchor=anchor)
        if checked and run_pf(['-a', anchor, '-s', 'rules']).stdout.strip():
            raise RuntimeError('macOS owned policy removal did not prove an absent dispatch')
    token = str(state.get("pf_token") or "").strip()
    if token and token != "dry-run":
        run_pf(["-X", token], check=False)


def status_darwin(state: dict[str, Any], *, dry_run: bool) -> bool:
    if state.get('darwin_transition_pending') is True:
        return False
    if dry_run:
        return bool(state)
    try:
        proc = run_pf(["-a", _state_anchor(state), "-sr"], check=False)
    except RuntimeError:
        return False
    return proc.returncode == 0 and bool((proc.stdout or "").strip())
