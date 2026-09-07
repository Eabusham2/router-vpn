#!/usr/bin/env python3
"""Privacy-preserving path fingerprints for Router VPN MTU learning.

Only SHA-256 fingerprints are returned/persisted. Raw interface, gateway, local
address, SSID-like override text, profile secrets, and generated config contents
never leave this helper.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import socket
import subprocess

MAX_PROFILE_FILES = 128
MAX_PROFILE_FILE_BYTES = 4 * 1024 * 1024
MAX_PROFILE_TOTAL_BYTES = 16 * 1024 * 1024


def _digest(label: str, value: bytes) -> str:
    return hashlib.sha256(label.encode("utf-8") + b"\0" + value).hexdigest()[:24]


def _run(command: list[str], timeout: float = 2.0) -> str:
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return " ".join((proc.stdout or "").split())[:4096]


def _resolved_host(endpoint: str) -> tuple[str, int] | None:
    host = str(endpoint or "").strip().strip("[]")
    if not host:
        return None
    try:
        ip = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except OSError:
        return None
    for family, _kind, _proto, _canon, sockaddr in ip:
        if family == socket.AF_INET:
            return sockaddr[0], 4
    for family, _kind, _proto, _canon, sockaddr in ip:
        if family == socket.AF_INET6:
            return sockaddr[0], 6
    return None


def _socket_source(target: str, family: int) -> str:
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    address = (target, 9, 0, 0) if family == 6 else (target, 9)
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            local = sock.getsockname()
            return str(local[0])
    except OSError:
        return ""


def network_fingerprint(endpoint: str) -> str:
    """Hash the current underlay route identity used to reach the VPN endpoint.

    HOMEVPN_NETWORK_CONTEXT is an explicit test/operator override. It is hashed
    before return so a caller never persists the raw value.
    """
    override = os.environ.get("HOMEVPN_NETWORK_CONTEXT", "").strip()
    if override:
        return _digest("network-override-v1", override.encode("utf-8"))

    resolved = _resolved_host(endpoint)
    system = platform.system().lower()
    pieces = ["v1", system]
    if resolved is not None:
        target, family = resolved
        pieces.extend([f"family={family}", f"source={_socket_source(target, family)}"])
        if system == "linux":
            route = _run(["ip", "-6" if family == 6 else "-4", "route", "get", target])
            if not route:
                route = _run(["ip", "route", "show", "default"])
            pieces.append("route=" + route)
        elif system == "darwin":
            pieces.append("route=" + _run(["route", "-n", "get", target]))
        elif system == "windows":
            escaped = target.replace("'", "''")
            ps = (
                "$r=Find-NetRoute -RemoteIPAddress '" + escaped + "' | "
                "Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; "
                "if($r){$r.InterfaceAlias+'|'+$r.NextHop+'|'+$r.InterfaceIndex}"
            )
            pieces.append("route=" + _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps], 4.0))
    else:
        # A failed endpoint resolution must not create a reusable cross-network
        # identity. Include whatever stable default-route evidence is available.
        if system == "linux":
            pieces.append("route=" + _run(["ip", "route", "show", "default"]))
        elif system == "darwin":
            pieces.append("route=" + _run(["route", "-n", "get", "default"]))
        elif system == "windows":
            pieces.append("route=" + _run(["route", "print", "0.0.0.0"], 4.0))
        pieces.append("endpoint-resolution=failed")
    return _digest("network-route-v1", "|".join(pieces).encode("utf-8"))


def generated_profile_fingerprint(root: Path, profile_id: str, mode: str) -> str:
    """Hash immutable generated profile inputs so protocol/port/profile changes retest.

    The digest covers names and bytes of the selected generated runtime profile,
    which naturally includes endpoint port/protocol-specific config without
    persisting private keys, passwords, certificates, or raw configuration.
    Linked node identities are never allowed to borrow the legacy global home
    profile tree when their own generated tree is absent.
    """
    root = Path(root).resolve()
    profile_id = str(profile_id or "").strip()
    mode = str(mode or "").strip()
    candidates = []
    if profile_id and mode:
        candidates.append(root / "generated" / profile_id / mode)
    if profile_id == "router" and mode:
        candidates.append(root / "generated" / mode)
    selected = next((p for p in candidates if p.is_dir()), None)
    if selected is None:
        return _digest("generated-profile-v1", f"missing|{profile_id}|{mode}".encode("utf-8"))

    digest = hashlib.sha256(b"router-vpn-generated-profile-v1\0")
    count = 0
    total = 0
    for path in sorted(selected.rglob("*")):
        if not path.is_file():
            continue
        count += 1
        if count > MAX_PROFILE_FILES:
            raise RuntimeError("generated MTU path profile has too many files")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise RuntimeError("cannot stat generated MTU path profile") from exc
        if size < 0 or size > MAX_PROFILE_FILE_BYTES:
            raise RuntimeError("generated MTU path profile file exceeds safety limit")
        total += size
        if total > MAX_PROFILE_TOTAL_BYTES:
            raise RuntimeError("generated MTU path profile exceeds safety limit")
        rel = path.relative_to(selected).as_posix().encode("utf-8")
        digest.update(len(rel).to_bytes(4, "big")); digest.update(rel)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise RuntimeError("cannot read generated MTU path profile") from exc
        digest.update(len(data).to_bytes(8, "big")); digest.update(data)
    return digest.hexdigest()[:24]
