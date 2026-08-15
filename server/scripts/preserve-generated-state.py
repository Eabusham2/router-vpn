#!/usr/bin/env python3
"""Read previously generated private runtime state for safe same-deployment upgrades.

The generator scripts call this helper before creating new credentials. It emits
only fixed-name shell assignments quoted with shlex.quote and exits non-zero when
the existing state is incomplete/inconsistent, in which case the caller may
regenerate that credential family deliberately.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import sys
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _nonempty(value: Any, minimum: int = 1) -> str:
    text = str(value or "").strip()
    if len(text) < minimum or "\n" in text or "\r" in text or "\x00" in text:
        raise ValueError("missing/invalid preserved value")
    return text


def _emit(values: dict[str, str]) -> None:
    for key, value in values.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError("unsafe assignment name")
        print(f"{key}={shlex.quote(value)}")


def transports(base: Path) -> dict[str, str]:
    saved = _load_json(base / "config" / "transports" / "generated-secrets.json")
    return {
        "SS_KEY": _nonempty(saved.get("shadowsocks_key"), 16),
        "HY2_PASSWORD": _nonempty(saved.get("hysteria2_password"), 12),
    }


def _inbound(server: dict[str, Any], tag: str) -> dict[str, Any]:
    for item in server.get("inbounds", []):
        if isinstance(item, dict) and item.get("tag") == tag:
            return item
    raise ValueError(f"missing inbound {tag}")


def _first_client_uuid(inbound: dict[str, Any]) -> str:
    clients = (inbound.get("settings") or {}).get("clients") or []
    if not clients or not isinstance(clients[0], dict):
        raise ValueError("missing client")
    return _nonempty(clients[0].get("id"), 8)


def _reality(inbound: dict[str, Any]) -> dict[str, Any]:
    value = (inbound.get("streamSettings") or {}).get("realitySettings") or {}
    if not isinstance(value, dict):
        raise ValueError("missing reality settings")
    return value


def xray(base: Path) -> dict[str, str]:
    server = _load_json(base / "config" / "xray" / "server.json")
    saved = _load_json(base / "config" / "xray" / "generated-secrets.json")
    std = _inbound(server, "reality-in")
    pq = _inbound(server, "pq-reality-in")
    std_reality = _reality(std)
    pq_reality = _reality(pq)
    std_uuid = _first_client_uuid(std)
    pq_uuid = _first_client_uuid(pq)
    if _nonempty(saved.get("standard_uuid"), 8) != std_uuid or _nonempty(saved.get("pq_uuid"), 8) != pq_uuid:
        raise ValueError("saved Xray UUIDs disagree with server config")
    std_private = _nonempty(std_reality.get("privateKey"), 8)
    pq_private = _nonempty(pq_reality.get("privateKey"), 8)
    if std_private != pq_private:
        raise ValueError("standard/PQ REALITY private keys disagree")
    std_short = _nonempty((std_reality.get("shortIds") or [""])[0], 8)
    pq_short = _nonempty((pq_reality.get("shortIds") or [""])[0], 8)
    if _nonempty(saved.get("standard_short_id"), 8) != std_short or _nonempty(saved.get("pq_short_id"), 8) != pq_short:
        raise ValueError("saved REALITY short IDs disagree with server config")
    server_dec = _nonempty((pq.get("settings") or {}).get("decryption"), 1)
    values = {
        "STD_UUID": std_uuid,
        "PQ_UUID": pq_uuid,
        "REALITY_PRIVATE": std_private,
        "REALITY_PASSWORD": _nonempty(saved.get("reality_public_key"), 8),
        "STD_SHORT_ID": std_short,
        "PQ_SHORT_ID": pq_short,
        "SERVER_DEC": server_dec,
        "CLIENT_ENC": _nonempty(saved.get("vless_encryption"), 1),
        "MLDSA_VERIFY": str(saved.get("mldsa65_verify") or "").strip(),
    }
    return values


def tls(base: Path) -> dict[str, str]:
    path = base / "config" / "tls" / "settings.env"
    text = path.read_text(encoding="utf-8")
    values: dict[str, str] = {}
    for key in ("SS_V2RAY_PASSWORD", "NAIVE_USER", "NAIVE_PASSWORD"):
        matches = re.findall(rf"(?m)^{re.escape(key)}='([^'\r\n]+)'$", text)
        if not matches:
            raise ValueError(f"missing {key}")
        values[key] = _nonempty(matches[-1], 4)
    return values


def advanced(base: Path) -> dict[str, str]:
    server = _load_json(base / "config" / "xray" / "server.json")
    saved = _load_json(base / "config" / "xray" / "advanced-secrets.json")
    inbound = _inbound(server, "max-xhttp-in")
    reality = _reality(inbound)
    uuid = _first_client_uuid(inbound)
    short_id = _nonempty((reality.get("shortIds") or [""])[0], 8)
    if _nonempty(saved.get("xhttp_uuid"), 8) != uuid or _nonempty(saved.get("xhttp_short_id"), 8) != short_id:
        raise ValueError("saved XHTTP identity disagrees with server config")
    return {
        "UUID": uuid,
        "REALITY_PRIVATE": _nonempty(reality.get("privateKey"), 8),
        "REALITY_PASSWORD": _nonempty(saved.get("xhttp_reality_public"), 8),
        "SHORT_ID": short_id,
    }


READERS = {
    "transports": transports,
    "xray": xray,
    "tls": tls,
    "advanced": advanced,
}


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in READERS:
        print("usage: preserve-generated-state.py transports|xray|tls|advanced BASE", file=sys.stderr)
        return 2
    try:
        base = Path(sys.argv[2]).resolve()
        _emit(READERS[sys.argv[1]](base))
    except Exception as exc:
        print(f"preserved state unavailable: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
