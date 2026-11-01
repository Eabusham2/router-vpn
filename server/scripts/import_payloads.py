#!/usr/bin/env python3
"""Typed, round-trippable import payload helpers for Router VPN Setup Center.

Only protocols with an actual interoperable compact import format get QR payloads.
Arbitrary JSON/text configs remain file/text imports and must never be presented
as magic QR codes merely because qrencode can encode the bytes.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
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
    # SIP002 requires percent-encoded plain userinfo for AEAD-2022; wrapping
    # those credentials in Base64URL is explicitly forbidden. Older methods
    # retain their existing recommended Base64URL encoding.
    if method.startswith("2022-"):
        userinfo = urllib.parse.quote(method, safe="") + ":" + urllib.parse.quote(password, safe="")
    else:
        userinfo = b64url_encode(f"{method}:{password}".encode("utf-8"))
    query = urllib.parse.urlencode({"plugin": plugin}) if plugin else ""
    fragment = urllib.parse.quote(label, safe="")
    result = f"ss://{userinfo}@{_hostport(host, port)}" + (f"/?{query}" if query else "") + f"#{fragment}"
    parse_sip002(result)
    return result


def _uri_decode(value: str) -> str:
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("invalid SIP002 percent escape")
    try:
        return urllib.parse.unquote(value, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid SIP002 UTF-8") from exc


def parse_sip002(uri: str) -> dict:
    if not isinstance(uri, str) or any(ord(char) <= 32 or ord(char) == 127 for char in uri):
        raise ValueError("invalid SIP002 whitespace/control character")
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme != "ss" or not parts.hostname or not parts.port or not parts.username or parts.netloc.count("@") != 1:
        raise ValueError("invalid SIP002 URI")
    if parts.path not in ("", "/") or any(char in parts.hostname for char in "%@/?#[]\\<>\"{}|^`"):
        raise ValueError("invalid SIP002 endpoint or path")
    if ":" in parts.hostname:
        ipaddress.IPv6Address(parts.hostname)
    if parts.password is not None:
        for value in (parts.username, parts.password):
            if not re.fullmatch(r"(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+", value):
                raise ValueError("plain SIP002 credentials must be percent encoded")
        method, password = _uri_decode(parts.username), _uri_decode(parts.password)
    else:
        encoded = _uri_decode(parts.username)
        if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", encoded) or ("=" in encoded and len(encoded) % 4):
            raise ValueError("invalid SIP002 Base64URL credentials")
        try:
            raw = base64.b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4), altchars=b"-_", validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("invalid SIP002 Base64URL credentials") from exc
        if b64url_encode(raw) != encoded.rstrip("=") or ":" not in decoded:
            raise ValueError("invalid SIP002 Base64URL credential representation")
        method, password = decoded.split(":", 1)
        if method.startswith("2022-"):
            raise ValueError("AEAD-2022 SIP002 userinfo must not use Base64URL")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", method) or not password:
        raise ValueError("invalid SIP002 credentials")
    _uri_decode(parts.query)
    query = urllib.parse.parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
    if len(query.get("plugin", [])) > 1:
        raise ValueError("ambiguous SIP002 plugin parameter")
    return {
        "method": method,
        "password": password,
        "host": parts.hostname,
        "port": parts.port,
        "plugin": query.get("plugin", [""])[0],
        "label": _uri_decode(parts.fragment),
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
