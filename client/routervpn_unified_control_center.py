#!/usr/bin/env python3
"""GTK/Linux policy adapter for the existing map-first native shell."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UnifiedControlCenterPolicy:
    experience: str = "Unified Map Control Center"
    default_mode: str = "smart-auto"
    default_node_count: int = 1
    default_ipv6: bool = True
    default_mtu_policy: str = "auto"
    require_encrypted_auto: bool = False
    require_obfuscation_auto: bool = False
    authenticated_transport: bool = True
    bottom_sheet_order: tuple[str, ...] = ("connection", "multihop", "settings", "mode", "dns")
    profile_actions: tuple[str, ...] = ("create", "load", "update", "delete", "import-router-bundle")
    bridge_types: tuple[str, ...] = ("socks5", "http-connect", "https-connect", "shadowsocks-2022", "tor-bridge")


POLICY = UnifiedControlCenterPolicy()
# A tor-bridge node means Router VPN's complete owned PT -> Tor circuit runtime,
# not the raw PT by itself. The PT is circumvention; Tor's proven circuit is the
# confidentiality/anonymity layer. Plain bridge/proxy types remain bridge-only.
FINAL_ENCRYPTED_TYPES = {
    "router-vpn", "wireguard", "amneziawg", "openvpn",
    "shadowsocks", "shadowsocks-2022", "hysteria2", "tor-bridge",
}
SECURE_SUITES = (
    "WireGuard Noise_IK + ChaCha20-Poly1305",
    "AmneziaWG Noise_IK + ChaCha20-Poly1305",
    "OpenVPN TLS 1.3 + AEAD",
    "Shadowsocks 2022 BLAKE3 + AEAD",
    "Hysteria2 QUIC + TLS 1.3",
    "Tor pluggable transport + proven ntor-v3 circuit",
)


def validate_secure_node_chain(node_types: list[str]) -> None:
    if not node_types:
        raise ValueError("Add a node before connecting.")
    final = node_types[-1].lower()
    if final not in FINAL_ENCRYPTED_TYPES:
        raise ValueError(f"{final} is a bridge only. Add an authenticated encrypted tunnel after it.")


def handshake_label(established: bool) -> str:
    return "Authenticated handshake ✓" if established else "Authenticated handshake pending"
