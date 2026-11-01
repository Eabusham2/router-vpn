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
import ssl
import urllib.parse
import uuid


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


def ssr_mihomo_profile(config: dict, home_dns: str) -> dict:
    """Export the generated SSR protocol to an unchanged Mihomo desktop client.

    The home resolver comes from finalization's explicit ADGUARD4 argument.
    System DNS is used only to bootstrap a hostname server endpoint; ordinary
    application DNS uses the captured home resolver through this SSR proxy.
    """
    client = config.get("client_settings")
    if not isinstance(client, dict):
        raise ValueError("SSR client settings are required")
    host, port = client.get("server"), client.get("server_port")
    if not isinstance(host, str) or not host or len(host) > 253 or re.search(r"[\s%@/?#\[\]\\<>\"{}|^`]", host):
        raise ValueError("invalid SSR server endpoint")
    if ":" in host:
        ipaddress.IPv6Address(host)
    elif not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError("invalid SSR server endpoint")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("invalid SSR server port")
    for field in ("password", "method", "protocol", "obfs"):
        if not isinstance(config.get(field), str) or not config[field] or len(config[field]) > 4096:
            raise ValueError("invalid SSR " + field)
    for field in ("protocol_param", "obfs_param"):
        if not isinstance(config.get(field, ""), str) or len(config.get(field, "")) > 4096:
            raise ValueError("invalid SSR " + field)
    if config.get("udp") is not True:
        raise ValueError("the home-DNS SSR profile requires the generated UDP support")
    over_tls = config.get("over_tls_settings")
    if over_tls is not None and (not isinstance(over_tls, dict) or over_tls.get("enable", False) is not False):
        raise ValueError("an SSR-over-TLS configuration cannot be reduced to plain SSR")
    if not isinstance(home_dns, str) or "%" in home_dns:
        raise ValueError("invalid selected home DNS resolver")
    dns = ipaddress.ip_address(home_dns)
    if dns.is_unspecified or dns.is_multicast:
        raise ValueError("invalid selected home DNS resolver")
    name = "RouterVPN-SSR"
    proxy = {"name": name, "type": "ssr", "server": host, "port": port,
             "cipher": config["method"], "password": config["password"],
             "protocol": config["protocol"], "protocol-param": config.get("protocol_param", ""),
             "obfs": config["obfs"], "obfs-param": config.get("obfs_param", ""), "udp": True}
    return {
        "socks-port": 1080, "allow-lan": False, "bind-address": "127.0.0.1", "ipv6": True,
        "mode": "rule", "log-level": "warning", "external-controller": "",
        "profile": {"store-selected": False, "store-fake-ip": False},
        "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": True,
                "enhanced-mode": "redir-host", "use-hosts": False, "use-system-hosts": False,
                "default-nameserver": ["system"], "proxy-server-nameserver": ["system"],
                "nameserver": ["udp://" + _hostport(str(dns), 53) + "#" + name], "fallback": []},
        "proxies": [proxy], "rules": ["MATCH," + name],
    }


class OverTLSJSONRequired(ValueError):
    """A valid configuration needs the native JSON import to retain its fields."""


def overtls_uri(config: dict, *, label: str = "Router VPN OverTLS") -> str:
    """Match the pinned native OverTLS 0.3.12 import, including selected trust.

    This is OverTLS's extension of ssr://, not a generic SSR client import.
    Its upstream parser cannot represent IPv6 endpoints or local listener
    policy faithfully; those configurations retain the real JSON download.
    """
    client = config.get("client_settings")
    if not isinstance(client, dict):
        raise ValueError("OverTLS client settings are required")
    if config.get("method", "none") != "none" or not isinstance(config.get("password", ""), str):
        raise ValueError("invalid OverTLS method/password")
    if client.get("disable_tls", False) is not False or client.get("dangerous_mode", False) is not False:
        raise ValueError("OverTLS imports require TLS and certificate verification")
    host, domain, path = client.get("server_host"), client.get("server_domain"), config.get("tunnel_path")
    port = client.get("server_port")
    if not isinstance(host, str) or not host or len(host) > 253 or re.search(r"[\s%@/?#\[\]\\<>\"{}|^`]", host):
        raise ValueError("invalid OverTLS endpoint")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("invalid OverTLS port")
    if not isinstance(domain, str) or not domain or len(domain) > 253 or re.search(r"[\s%@/?#\[\]\\<>\"{}|^`]", domain):
        raise ValueError("OverTLS TLS name is required")
    paths = path if isinstance(path, list) else [path]
    if not paths or any(not isinstance(item, str) or not re.fullmatch(r"/[A-Za-z0-9._~/-]+/", item) or len(item) > 256 for item in paths):
        raise ValueError("invalid OverTLS tunnel path")
    is_ipv6 = ":" in host
    if is_ipv6:
        ipaddress.IPv6Address(host)
    elif not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError("invalid OverTLS endpoint")
    if ":" in domain:
        ipaddress.IPv6Address(domain)
    elif not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
        raise ValueError("invalid OverTLS TLS name")
    remarks = config.get("remarks", label)
    if not isinstance(remarks, str):
        raise ValueError("invalid OverTLS remarks")
    timeout = config.get("test_timeout_secs")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout < 1 << 64):
        raise ValueError("invalid OverTLS test timeout")
    # Validate trust and identity before considering any JSON-only setting.
    # A malformed CA/UUID must not become a representability-only fallback.
    certificate = client.get("cafile")
    certificate_path = False
    if certificate is not None:
        if not isinstance(certificate, str) or not certificate:
            raise ValueError("invalid selected OverTLS certificate")
        if len(certificate.encode("utf-8")) > 65536 or "PRIVATE KEY" in certificate or "\x00" in certificate:
            raise ValueError("invalid selected OverTLS certificate")
        if certificate.startswith("-----BEGIN CERTIFICATE-----"):
            try:
                ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=certificate)
            except (ssl.SSLError, ValueError) as exc:
                raise ValueError("invalid selected OverTLS certificate") from exc
        elif "-----" in certificate or "\n" in certificate or "\r" in certificate:
            raise ValueError("invalid selected OverTLS certificate")
        else:
            certificate_path = True
    client_id = client.get("client_id")
    if client_id is not None:
        if not isinstance(client_id, str):
            raise ValueError("invalid OverTLS client identity")
        client_id = str(uuid.UUID(client_id))
    if is_ipv6:
        raise OverTLSJSONRequired("IPv6 endpoints require the OverTLS JSON file; the upstream URL parser cannot retain IPv6")
    if host.lower() == "router.invalid":
        raise OverTLSJSONRequired("Set this node's reachable endpoint before using an OverTLS URL; retain the JSON file for setup")
    top_fields = {"method", "password", "remarks", "tunnel_path", "client_settings"}
    if set(config) - top_fields or isinstance(path, list):
        raise OverTLSJSONRequired("Additional top-level settings or multiple tunnel paths require the complete OverTLS JSON file")
    representable = {"disable_tls", "dangerous_mode", "server_host", "server_port", "server_domain", "cafile",
                     "client_id", "listen_host", "listen_port"}
    if (set(client) - representable or client.get("listen_host", "127.0.0.1") != "127.0.0.1"
            or client.get("listen_port", 1080) != 1080):
        raise OverTLSJSONRequired("Additional listener/client settings require the complete OverTLS JSON file")
    if certificate_path:
        raise OverTLSJSONRequired("A selected certificate file path requires the complete OverTLS JSON file and that certificate")
    query = {"remarks": b64url_encode(remarks.encode("utf-8")), "ot_enable": "1",
             "ot_domain": b64url_encode(domain.encode("utf-8")), "ot_path": b64url_encode(path.encode("utf-8"))}
    if certificate is not None:
        query["ot_cert"] = b64url_encode(certificate.encode("utf-8"))
    query["dangerous_mode"] = "false"
    if client_id is not None:
        query["client_id"] = client_id
    password = b64url_encode(config.get("password", "").encode("utf-8"))
    inner = f"{host}:{port}:origin:none:plain:{password}/?" + urllib.parse.urlencode(query)
    return "ssr://" + b64url_encode(inner.encode("utf-8"))


def validate_hysteria2_uri(uri: str) -> dict:
    if not isinstance(uri, str) or any(ord(char) <= 32 or ord(char) == 127 for char in uri):
        raise ValueError("invalid Hysteria2 whitespace/control character")
    parts = urllib.parse.urlsplit(uri)
    if (parts.scheme not in ("hysteria2", "hy2") or not parts.hostname or not parts.port
            or not parts.username or parts.netloc.count("@") != 1):
        raise ValueError("invalid Hysteria2 URI")
    if parts.path not in ("", "/") or any(char in parts.hostname for char in "%@/?#[]\\<>\"{}|^`"):
        raise ValueError("invalid Hysteria2 endpoint/path")
    if ":" in parts.hostname:
        ipaddress.IPv6Address(parts.hostname)
    for value in (parts.username, parts.password, parts.query, parts.fragment):
        if value is not None:
            _uri_decode(value)
    query = urllib.parse.parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
    allowed = {"sni", "insecure", "pinSHA256", "obfs", "obfs-password"}
    if set(query) - allowed or any(len(values) != 1 or not values[0] for values in query.values()):
        raise ValueError("ambiguous or unsupported Hysteria2 URI parameter")
    if "insecure" in query and query["insecure"][0] not in ("0", "1", "true", "false"):
        raise ValueError("invalid Hysteria2 insecure parameter")
    if "pinSHA256" in query and not re.fullmatch(r"[a-fA-F0-9]{64}", query["pinSHA256"][0].replace(":", "")):
        raise ValueError("invalid Hysteria2 certificate fingerprint")
    if "sni" in query and any(char.isspace() or char in "\x00/@?#\\" for char in query["sni"][0]):
        raise ValueError("invalid Hysteria2 TLS name")
    if ("obfs" in query) != ("obfs-password" in query) or query.get("obfs", ["salamander"])[0] != "salamander":
        raise ValueError("invalid Hysteria2 Salamander parameters")
    password = _uri_decode(parts.username)
    if parts.password is not None:
        password += ":" + _uri_decode(parts.password)
    return {
        "password": password,
        "host": parts.hostname,
        "port": parts.port,
        "query": query,
        "label": _uri_decode(parts.fragment),
    }


class Hysteria2JSONRequired(ValueError):
    """A valid native setting cannot be represented by the named desktop profile."""


def hysteria2_certificate(pem: str) -> list[bytes]:
    if not isinstance(pem, str) or not 1 <= len(pem.encode("utf-8")) <= 1 << 20:
        raise ValueError("Hysteria2 requires a bounded selected PEM certificate")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", pem)
    remainder = re.sub(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", "", pem)
    if not blocks or len(blocks) > 16 or remainder.strip():
        raise ValueError("Hysteria2 certificate contains missing or non-certificate material")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=pem)
        return [ssl.PEM_cert_to_DER_cert(block) for block in blocks]
    except (ValueError, ssl.SSLError) as exc:
        raise ValueError("invalid selected Hysteria2 certificate") from exc


def hysteria2_config(text: str) -> tuple[dict, dict]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Hysteria2 JSON contains a duplicated field")
            result[key] = value
        return result
    config = json.loads(text, object_pairs_hook=unique)
    if not isinstance(config, dict) or not isinstance(config.get("outbounds"), list):
        raise ValueError("Hysteria2 download requires a complete sing-box configuration")
    proxies = [item for item in config["outbounds"] if isinstance(item, dict) and item.get("tag") == "proxy"]
    if len(proxies) != 1 or proxies[0].get("type") != "hysteria2":
        raise ValueError("Hysteria2 requires one unambiguous selected proxy outbound")
    proxy = proxies[0]
    tls = proxy.get("tls")
    if not isinstance(tls, dict) or tls.get("enabled") is not True or tls.get("insecure", False) is not False:
        raise ValueError("Hysteria2 import requires enabled TLS with certificate verification")
    if not isinstance(tls.get("server_name"), str) or not tls["server_name"]:
        raise ValueError("Hysteria2 requires its selected TLS server name")
    return config, proxy


def hysteria2_official_profile(config: dict, server_pin: str, home_dns: dict) -> tuple[dict, str]:
    # This named app-proxy export is additional to the complete native TUN
    # configuration. Do not silently discard selected outbound/TLS options.
    _, proxy = hysteria2_config(json.dumps(config))
    tls, obfs = proxy["tls"], proxy.get("obfs")
    certificate = tls.get("certificate")
    if isinstance(certificate, list) and all(isinstance(line, str) for line in certificate):
        certificate = "\n".join(certificate)
    hysteria2_certificate(certificate)
    if tls.get("certificate_path"):
        raise ValueError("Hysteria2 download still refers to an external certificate path")
    if not isinstance(server_pin, str) or not re.fullmatch(r"[a-f0-9]{64}", server_pin):
        raise ValueError("Hysteria2 download lacks its captured server certificate fingerprint")
    host, port, password = proxy.get("server"), proxy.get("server_port"), proxy.get("password")
    if (not isinstance(host, str) or not host or host != host.strip() or type(port) is not int
            or not 1 <= port <= 65535 or not isinstance(password, str) or not password
            or any(ord(char) < 32 or ord(char) == 127 for char in password)):
        raise ValueError("invalid selected Hysteria2 endpoint or password")
    if (not isinstance(obfs, dict) or obfs.get("type") != "salamander"
            or not isinstance(obfs.get("password"), str) or not obfs["password"]):
        raise ValueError("Hysteria2 requires the selected Salamander secret")
    # Validate trust/identity before deciding that optional settings need the
    # native JSON. Invalid material is never a representability fallback.
    query = {"sni": tls["server_name"], "insecure": "0", "pinSHA256": server_pin,
             "obfs": "salamander", "obfs-password": obfs["password"]}
    uri = ("hysteria2://" + urllib.parse.quote(password, safe="") + "@" + _hostport(host, port)
           + "/?" + urllib.parse.urlencode(query) + "#Router%20VPN%20Hysteria2")
    validate_hysteria2_uri(uri)
    if (set(proxy) - {"type", "tag", "server", "server_port", "password", "obfs", "tls"}
            or set(tls) - {"enabled", "server_name", "insecure", "certificate"}
            or set(obfs) - {"type", "password"}):
        raise Hysteria2JSONRequired("Additional selected transport/TLS settings require the complete sing-box JSON")
    if not isinstance(home_dns, dict) or home_dns.get("protocol") != "udp" or home_dns.get("port") != 53:
        raise ValueError("Hysteria2 requires the explicitly captured home UDP DNS policy")
    try:
        resolver = ipaddress.ip_address(home_dns.get("host", ""))
    except ValueError as exc:
        raise ValueError("Hysteria2 Home DNS must be an explicit literal IP") from exc
    if resolver.is_unspecified or resolver.is_multicast or resolver.is_link_local or "%" in str(resolver):
        raise ValueError("Hysteria2 Home DNS must be an unscoped unicast IP")
    expected_dns = {"servers": [{"type": "udp", "tag": "home-dns", "server": str(resolver),
                                "server_port": 53, "detour": "proxy"}], "final": "home-dns"}
    if config.get("dns") != expected_dns:
        raise Hysteria2JSONRequired("The selected DNS policy requires the complete sing-box JSON")
    remote = _hostport(str(resolver), 53)
    return ({"server": uri, "tls": {"ca": "router-vpn-hysteria2-ca.pem", "insecure": False},
             "socks5": {"listen": "127.0.0.1:1080"},
             "tcpForwarding": [{"listen": "127.0.0.1:1053", "remote": remote}],
             "udpForwarding": [{"listen": "127.0.0.1:1053", "remote": remote, "timeout": "30s"}]}, certificate)


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
