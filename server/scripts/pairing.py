#!/usr/bin/env python3
"""In-memory one-time LAN pairing codes for Router VPN node linking."""
from __future__ import annotations

import ipaddress
import secrets
import threading
import time


DEFAULT_TTL = 300
MAX_TTL = 600
MAX_CODES = 16
MAX_FAILURES_PER_MINUTE = 10
LAN_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
))


def lan_source(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local:
        return True
    return any(ip.version == network.version and ip in network for network in LAN_NETWORKS)


class PairingManager:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.codes: dict[str, dict] = {}
        self.failures: dict[str, list[float]] = {}

    def _prune_locked(self, now: float) -> None:
        for code in list(self.codes):
            if float(self.codes[code]["expires_epoch"]) <= now:
                self.codes.pop(code, None)
        cutoff = now - 60
        for source in list(self.failures):
            self.failures[source] = [x for x in self.failures[source] if x >= cutoff]
            if not self.failures[source]:
                self.failures.pop(source, None)

    def create(self, ttl_seconds: int = DEFAULT_TTL) -> dict:
        ttl = max(60, min(int(ttl_seconds or DEFAULT_TTL), MAX_TTL))
        now = time.time()
        with self.lock:
            self._prune_locked(now)
            if len(self.codes) >= MAX_CODES:
                raise RuntimeError("too many active pairing codes")
            code = f"{secrets.randbelow(1_000_000):06d}"
            while code in self.codes:
                code = f"{secrets.randbelow(1_000_000):06d}"
            expires = now + ttl
            self.codes[code] = {
                "created_epoch": now,
                "expires_epoch": expires,
                "redeemed": False,
            }
            return {
                "code": code,
                "expires_in_seconds": ttl,
                "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires)),
                "one_time": True,
                "lan_only": True,
            }

    def redeem(self, code: str, source: str) -> None:
        code = str(code or "").strip()
        if not lan_source(source):
            raise PermissionError("pairing redemption is LAN/local-network only")
        now = time.time()
        with self.lock:
            self._prune_locked(now)
            recent = self.failures.get(source, [])
            if len(recent) >= MAX_FAILURES_PER_MINUTE:
                raise PermissionError("too many invalid pairing attempts; retry later")
            item = self.codes.get(code)
            if not item or item.get("redeemed") or float(item["expires_epoch"]) <= now:
                self.failures.setdefault(source, []).append(now)
                raise PermissionError("invalid or expired pairing code")
            item["redeemed"] = True
            self.codes.pop(code, None)

    def active_count(self) -> int:
        with self.lock:
            self._prune_locked(time.time())
            return len(self.codes)
