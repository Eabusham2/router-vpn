
#!/usr/bin/env python3
"""Canonical model/validation for the cross-platform map-first control center."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "client/unified-control-center-v2.json"


class UnifiedControlCenterError(ValueError):
    pass


@dataclass(frozen=True)
class HopMetric:
    node_id: str
    rtt_ms: float
    download_mbps: float | None = None
    upload_mbps: float | None = None


@dataclass
class ConnectionProfile:
    profile_id: str
    name: str
    mode: str = "smart-auto"
    node_ids: list[str] = field(default_factory=list)
    bridge_ids: list[str] = field(default_factory=list)
    dns_mode: str = "home"
    ipv6: bool = True
    mtu_policy: str = "auto"
    fixed_mtu: int | None = None
    require_encrypted_auto: bool = False
    require_obfuscated_auto: bool = False
    authenticated_transport: bool = True


def load_contract() -> dict:
    data = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if data.get("schema_version") != 2:
        raise UnifiedControlCenterError("Unsupported control-center schema.")
    return data


def allowed_node_types() -> dict[str, dict]:
    return {row["id"]: row for row in load_contract()["node_types"]}


def validate_secure_path(node_types: Iterable[str], *, authenticated_transport: bool = True) -> None:
    values = [str(value).strip().lower() for value in node_types if str(value).strip()]
    if not values:
        raise UnifiedControlCenterError("At least one node is required.")
    known = allowed_node_types()
    unknown = [value for value in values if value not in known]
    if unknown:
        raise UnifiedControlCenterError("Unsupported node type: " + ", ".join(unknown))
    if not authenticated_transport:
        raise UnifiedControlCenterError("Authenticated transport cannot be disabled.")
    for value in values[:-1]:
        node = known[value]
        roles = set(node.get("role", []))
        if "hop" not in roles or node.get("upstream_hop") is False:
            raise UnifiedControlCenterError(
                f"{value} cannot be used as an upstream hop; place it only where its node contract allows."
            )
    final = known[values[-1]]
    if not final.get("final_transport"):
        raise UnifiedControlCenterError(
            f"{values[-1]} is a bridge only; add an authenticated encrypted tunnel after it."
        )


def validate_profile(profile: ConnectionProfile) -> None:
    if not profile.profile_id or len(profile.profile_id) > 96:
        raise UnifiedControlCenterError("Profile id is invalid.")
    if not profile.name.strip() or len(profile.name) > 64:
        raise UnifiedControlCenterError("Profile name is invalid.")
    if profile.mode not in {"smart-auto", "auto", "custom", "preset"}:
        raise UnifiedControlCenterError("Profile mode is invalid.")
    if not 1 <= len(profile.node_ids) <= 5:
        raise UnifiedControlCenterError("A profile must contain one to five nodes.")
    if profile.mtu_policy not in {"auto", "fixed"}:
        raise UnifiedControlCenterError("MTU policy must be auto or fixed.")
    if profile.mtu_policy == "fixed" and not (576 <= int(profile.fixed_mtu or 0) <= 9000):
        raise UnifiedControlCenterError("Fixed MTU is outside the supported range.")
    validate_secure_path(profile.bridge_ids + profile.node_ids,
                         authenticated_transport=profile.authenticated_transport)


def total_live_rtt(metrics: Iterable[HopMetric]) -> float:
    values = [float(metric.rtt_ms) for metric in metrics]
    if any(value < 0 or value > 120000 for value in values):
        raise UnifiedControlCenterError("A hop RTT is outside the supported range.")
    return round(sum(values), 3)


def map_role(index: int, total: int, *, custom: bool = False, bridge: bool = False) -> str:
    if bridge:
        return "bridge"
    if custom:
        return "custom"
    if total <= 1:
        return "selected"
    if index == 0:
        return "entry"
    if index == total - 1:
        return "exit"
    return "middle"