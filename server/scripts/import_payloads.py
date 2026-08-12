#!/usr/bin/env python3
"""Typed, round-trippable import payload helpers for Router VPN Setup Center.

Only protocols with an actual interoperable compact import format get QR payloads.
Arbitrary JSON/text configs remain file/text imports and must never be presented
as magic QR codes merely because qrencode can encode the bytes.
"""
from __future__ import annotations

import base64
import json
import urllib.parse


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    value = value.strip()
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _hostport(host: str, port: int) -> str:
    host = host.strip().strip("[]")
    if not host:
        raise ValueError("host is required")
    if not 1 <= int(port) <= 65535:
        raise ValueError("port must be 1..65535")
    return f"[{host}]:{int(port)}" if ":" in host else f"{host}:{int(port)}"


def sip002_uri(method: str, password: str, host: str, port: int, *, label: str = "Router VPN", plugin: str = "") -> str:
    method = str(method).strip()
    password = str(password)
    if not method or not password:
        raise ValueError("Shadowsocks method/password are required")
    userinfo = b64url_encode(f"{method}:{password}".encode("utf-8"))
    query = urllib.parse.urlencode({"plugin": plugin}) if plugin else ""
    fragment = urllib.parse.quote(label, safe="")
    return f"ss://{userinfo}@{_hostport(host, port)}" + (f"/?{query}" if query else "") + f"#{fragment}"


def parse_sip002(uri: str) -> dict:
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme != "ss" or not parts.hostname or not parts.port or not parts.username:
        raise ValueError("invalid SIP002 URI")
    decoded = b64url_decode(parts.username).decode("utf-8")
    if ":" not in decoded:
        raise ValueError("invalid SIP002 userinfo")
    method, password = decoded.split(":", 1)
    if not method or not password:
        raise ValueError("invalid SIP002 credentials")
    query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    return {
        "method": method,
        "password": password,
        "host": parts.hostname,
        "port": parts.port,
        "plugin": query.get("plugin", [""])[0],
        "label": urllib.parse.unquote(parts.fragment),
    }


def ssr_uri(config: dict, *, label: str = "Router VPN ShadowsocksR") -> str:
    client = config.get("client_settings") if isinstance(config.get("client_settings"), dict) else {}
    host = str(client.get("server") or "").strip().strip("[]")
    port = int(client.get("server_port") or 0)
    method = str(config.get("method") or "").strip()
    protocol = str(config.get("protocol") or "origin").strip()
    obfs = str(config.get("obfs") or "plain").strip()
    password = str(config.get("password") or "")
    if not host or not method or not protocol or not obfs or not password:
        raise ValueError("SSR config is incomplete")
    if not 1 <= port <= 65535:
        raise ValueError("SSR port must be 1..65535")
    pw = b64url_encode(password.encode("utf-8"))
    remarks = b64url_encode(label.encode("utf-8"))
    protocol_param = b64url_encode(str(config.get("protocol_param") or "").encode("utf-8"))
    obfs_param = b64url_encode(str(config.get("obfs_param") or "").encode("utf-8"))
    inner = f"{host}:{port}:{protocol}:{method}:{obfs}:{pw}/?" + urllib.parse.urlencode({
        "remarks": remarks,
        "protoparam": protocol_param,
        "obfsparam": obfs_param,
    })
    return "ssr://" + b64url_encode(inner.encode("utf-8"))


def parse_ssr(uri: str) -> dict:
    if not uri.startswith("ssr://"):
        raise ValueError("invalid SSR URI")
    inner = b64url_decode(uri[6:]).decode("utf-8")
    core, _, query_text = inner.partition("/?")
    parts = core.rsplit(":", 5)
    if len(parts) != 6:
        raise ValueError("invalid SSR core")
    host, port_text, protocol, method, obfs, pw = parts
    port = int(port_text)
    if not host or not 1 <= port <= 65535:
        raise ValueError("invalid SSR endpoint")
    query = urllib.parse.parse_qs(query_text, keep_blank_values=True)
    def dec(name: str) -> str:
        value = query.get(name, [""])[0]
        return b64url_decode(value).decode("utf-8") if value else ""
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "method": method,
        "obfs": obfs,
        "password": b64url_decode(pw).decode("utf-8"),
        "protocol_param": dec("protoparam"),
        "obfs_param": dec("obfsparam"),
        "label": dec("remarks"),
    }


def validate_hysteria2_uri(uri: str) -> dict:
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme not in ("hysteria2", "hy2") or not parts.hostname or not parts.port or not parts.username:
        raise ValueError("invalid Hysteria2 URI")
    if not 1 <= int(parts.port) <= 65535:
        raise ValueError("invalid Hysteria2 port")
    return {
        "password": urllib.parse.unquote(parts.username),
        "host": parts.hostname,
        "port": parts.port,
        "query": urllib.parse.parse_qs(parts.query, keep_blank_values=True),
        "label": urllib.parse.unquote(parts.fragment),
    }


def json_config(value: str) -> dict:
    obj = json.loads(value)
    if not isinstance(obj, dict):
        raise ValueError("config must be a JSON object")
    return obj


def shadowsocks_from_singbox(config_text: str, host: str, *, label: str = "Router VPN Shadowsocks") -> str:
    doc = json_config(config_text)
    for outbound in doc.get("outbounds", []):
        if isinstance(outbound, dict) and outbound.get("tag") == "proxy":
            return sip002_uri(
                str(outbound.get("method") or ""),
                str(outbound.get("password") or ""),
                host,
                int(outbound.get("server_port") or 8388),
                label=label,
            )
    raise ValueError("Shadowsocks proxy outbound missing")


def shadowsocks_plugin_from_json(config_text: str, host: str, *, label: str = "Router VPN SS+V2Ray") -> str:
    doc = json_config(config_text)
    plugin = str(doc.get("plugin") or "")
    if doc.get("plugin_opts"):
        plugin += ";" + str(doc.get("plugin_opts"))
    return sip002_uri(
        str(doc.get("method") or ""),
        str(doc.get("password") or ""),
        host,
        int(doc.get("server_port") or 12443),
        label=label,
        plugin=plugin,
    )
