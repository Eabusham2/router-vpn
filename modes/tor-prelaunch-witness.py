#!/usr/bin/env python3
"""Validate a captured Unix Tor launch and record an owned prelaunch failure.

The --validate path runs before protection and writes no receipt. Only the
wrapper's EXIT trap requests a failure witness. A successful exec replaces
that shell and its trap, including when the native process later fails. The
witness is not a native drain receipt and grants no deletion or firewall authority.
"""
from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys


INPUTS = {
    "tor-profile.json": "HOMEVPN_TOR_PROFILE_SHA256",
    "tor-capture.json": "HOMEVPN_TOR_CAPTURE_SHA256",
    "torrc": "HOMEVPN_TOR_TORRC_SHA256",
    "tor-defaults": "HOMEVPN_TOR_DEFAULTS_SHA256",
    "sing-box.json": "HOMEVPN_TOR_CONFIG_SHA256",
}
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
DIR_FLAGS = FILE_FLAGS | getattr(os, "O_DIRECTORY", 0)


def private_verifier():
    helper = Path(__file__).with_name("cleanup-private-runtime.py")
    if helper.is_symlink() or not helper.is_file():
        raise ValueError("private directory verifier is unavailable")
    spec = importlib.util.spec_from_file_location("routervpn_private_verifier", helper)
    verifier = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(verifier)
    return verifier


def exact_json(raw: bytes):
    def object_value(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate captured JSON member")
            value[key] = item
        return value

    def invalid_constant(_):
        raise ValueError("non-finite captured JSON value")

    return json.loads(raw, object_pairs_hook=object_value, parse_constant=invalid_constant)


def physical_address(value):
    if type(value) is not str:
        raise ValueError("physical address is not a string")
    address = ipaddress.ip_address(value)
    if (str(address) != value or "%" in value or address.is_unspecified or address.is_loopback
            or address.is_multicast or address.is_link_local
            or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None
            or isinstance(address, ipaddress.IPv4Address) and (address.packed[0] == 0 or address.packed[0] >= 224)):
        raise ValueError("physical address is not a canonical unicast literal")
    return value


def physical_tuples(value):
    if type(value) is not list or not 1 <= len(value) <= 16:
        raise ValueError("physical tuple bound is invalid")
    seen = set()
    result = []
    for item in value:
        if (type(item) is not dict or set(item) != {"host", "port", "network"}
                or type(item["port"]) is not int or not 1 <= item["port"] <= 65535
                or type(item["network"]) is not str or item["network"] not in {"tcp", "udp"}):
            raise ValueError("physical tuple has unowned or untyped fields")
        host = physical_address(item["host"])
        key = (host, item["port"], item["network"])
        if key in seen:
            raise ValueError("duplicate physical tuple")
        seen.add(key)
        result.append({"host": host, "port": item["port"], "network": item["network"]})
    return result


def direct_obfs4_tuples(profile):
    """Reconstruct fixed Direct sockets from hashed source, never child output."""
    external = profile["external"]
    config = external.get("tor_bridge")
    if external["protocol"] != "tor-bridge" or type(config) is not dict:
        return None
    lines = config.get("bridges")
    if type(lines) is not list or not 1 <= len(lines) <= 8:
        raise ValueError("Direct bridge source exceeds its captured bound")
    if config.get("transport") not in {"obfs4", "custom"}:
        return None
    result, seen_lines, seen_tuples = [], set(), set()
    for line in lines:
        if type(line) is not str or len(line) > 8192 or any(c in line for c in "\r\n\x00"):
            raise ValueError("Direct bridge source is not a bounded normalized line")
        words = line.split()
        if not words or words[0] != "obfs4":
            return None
        if (len(words) < 4 or " ".join(words) != line or line in seen_lines
                or not re.fullmatch(r"[0-9A-F]{40}", words[2])):
            raise ValueError("Direct obfs4 source lost its exact normalized identity")
        match = re.fullmatch(r"(\[[0-9a-f:]+\]|[0-9.]+):([1-9][0-9]{0,4})", words[1])
        if match is None:
            raise ValueError("Direct obfs4 source lost its literal socket")
        host = physical_address(match[1].strip("[]"))
        address, port = ipaddress.ip_address(host), int(match[2])
        private = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
        if port > 65535 or any(address in ipaddress.ip_network(prefix) for prefix in private):
            raise ValueError("Direct obfs4 source is not a public literal socket")
        seen_lines.add(line)
        key = (host, port)
        if key not in seen_tuples:
            seen_tuples.add(key)
            result.append({"host": host, "port": port, "network": "tcp"})
    return result


def validate_launch(target: str, bridge_endpoint: str | None = None, tor_binary: str | None = None) -> None:
    """Bind the pre-protection environment to the hashed native capture."""
    session = os.environ.get("HOMEVPN_TOR_SESSION", "")
    source = os.environ.get("HOMEVPN_TOR_SOURCE_SHA256", "")
    physical = os.environ.get("HOMEVPN_PROFILE_ID", "")
    policy = os.environ.get("HOMEVPN_POLICY_PROFILE_ID", "")
    broker_marker = os.environ.get("HOMEVPN_TOR_PHYSICAL_BROKER", "")
    if broker_marker not in {"", "1"}:
        raise ValueError("invalid native physical broker marker")
    socket_broker = broker_marker == "1"
    if (not re.fullmatch(r"[a-f0-9]{32}", session) or not re.fullmatch(r"[a-f0-9]{64}", source)
            or os.environ.get("HOMEVPN_STANDARD_ENGINE") != "native"
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", physical)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", policy)):
        raise ValueError("native launch identity is incomplete")
    verifier = private_verifier()
    root = os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client")
    directory = verifier.verify_directory(root, target)
    relative = directory.relative_to(verifier.lexical(root) / "run")
    if len(relative.parts) != 2 or relative.parts[0] != "tor-bridge":
        raise ValueError("native launch has another private directory")
    before = directory.lstat()
    if before.st_mode & 0o077:
        raise ValueError("native launch directory is not private")
    descriptor = verifier.open_directory(directory, before, "Tor launch capture")
    try:
        inputs = {}
        for name, variable in INPUTS.items():
            expected = os.environ.get(variable, "")
            raw = regular_at(descriptor, name, 8 << 20 if name == "tor-capture.json" else 4 << 20)
            if not re.fullmatch(r"[a-f0-9]{64}", expected) or hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError("private launch input differs from its captured digest")
            inputs[name] = raw
        profile = exact_json(inputs["tor-profile.json"])
        capture = exact_json(inputs["tor-capture.json"])
        graph = exact_json(inputs["sing-box.json"])
        if type(profile) is not dict or type(capture) is not dict or type(graph) is not dict:
            raise ValueError("native launch inputs require exact JSON objects")
        external = profile.get("external")
        if type(external) is not dict or external.get("protocol") not in {"tor", "tor-bridge"}:
            raise ValueError("native Tor launch lost its exact selected protocol")
        protocol = external["protocol"]
        if protocol == "tor" and external.get("tor_bridge") is not None:
            raise ValueError("plain Tor cannot discard a captured bridge selection")
        required = {"schema", "session_id", "isolation_secret", "target_os", "tor_binary"}
        via_entry = "predecessor" in capture
        server = capture.get("schema") == 2
        if (set(capture) != required | ({"predecessor"} if via_entry else set())
                or type(capture.get("schema")) is not int or capture["schema"] not in {1, 2}
                or capture.get("session_id") != session or profile.get("id") != policy
                or type(capture.get("isolation_secret")) is not str
                or not re.fullmatch(r"[a-f0-9]{64}", capture["isolation_secret"])
                or capture.get("target_os") != ("darwin" if sys.platform == "darwin" else "linux")
                or type(capture.get("tor_binary")) is not str
                or tor_binary is not None and capture["tor_binary"] != tor_binary):
            raise ValueError("private capture belongs to another launch owner")
        if server:
            if (not via_entry or capture["tor_binary"] or os.environ.get("HOMEVPN_TOR_BINARY_SHA256")
                    or profile.get("multihop_execution") != "server"
                    or inputs["torrc"] != b"\n" or inputs["tor-defaults"] != b"\n"):
                raise ValueError("Server Tor acquired a local child or lost its explicit captured execution")
        elif (not os.path.isabs(capture["tor_binary"])
              or not re.fullmatch(r"[a-f0-9]{64}", os.environ.get("HOMEVPN_TOR_BINARY_SHA256", ""))):
            raise ValueError("Local Tor lost its captured executable identity")
        endpoint = os.environ.get("HOMEVPN_ENDPOINT", "")
        if socket_broker:
            if (sys.platform not in {"linux", "darwin"} or via_entry or server or physical != policy
                    or profile.get("node_kind") != "external"
                    or profile.get("multihop_enabled", False) is not False
                    or profile.get("kill_switch_policy") not in {"on-connect", "always"}
                    or type(profile.get("kill_switch", False)) is not bool
                    or endpoint or bridge_endpoint not in {None, ""}):
                raise ValueError("physical broker lost its captured protected direct Unix source")
        elif not via_entry and protocol == "tor":
            if (endpoint or bridge_endpoint not in {None, ""}
                    or profile.get("kill_switch_policy") != "off"
                    or profile.get("kill_switch", False) is not False):
                raise ValueError("direct plain Tor requires explicit Off protection and no invented guard endpoint")
        else:
            endpoint = physical_address(endpoint)
        if via_entry:
            entry = capture["predecessor"]
            if type(entry) is not dict or type(entry.get("schema")) is not int or entry["schema"] not in {1, 2}:
                raise ValueError("predecessor has no supported captured proof schema")
            external_entry = entry["schema"] == 2
            entry_fields = {"schema", "entry_mode", "profile", "config", "assets_sha256"}
            if external_entry:
                entry_fields |= {"entry_kind", "source_config"}
            if (set(entry) != entry_fields
                    or type(entry.get("entry_mode")) is not str or not re.fullmatch(r"[a-z0-9-]{1,32}", entry["entry_mode"])
                    or type(entry.get("assets_sha256")) is not str or not re.fullmatch(r"[a-f0-9]{64}", entry["assets_sha256"])
                    or type(entry.get("profile")) is not dict or type(entry.get("config")) is not dict
                    or entry["profile"].get("id") != physical
                    or physical == policy or profile.get("multihop_enabled") is not True
                    or profile.get("multihop_entry_id") != physical or profile.get("multihop_exit_id") != policy
                    or profile.get("multihop_entry_mode") != entry["entry_mode"]
                    or profile.get("multihop_exit_mode") != protocol
                    or profile.get("multihop_execution", "") not in ({"server"} if server else {"", "local"})
                    or os.environ.get("HOMEVPN_EXTERNAL_SESSION") != session):
                raise ValueError("predecessor differs from the captured execution")
            if external_entry:
                external = entry["profile"].get("external")
                if (server or entry["entry_kind"] != "external-public-ip" or type(entry["source_config"]) is not dict
                        or not entry["source_config"] or entry["profile"].get("node_kind") != "external"
                        or type(external) is not dict or external.get("protocol") != entry["entry_mode"]
                        or entry["entry_mode"] not in {"wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"}
                        or any(entry["profile"].get(key) not in {None, ""} for key in ("node_proof_id", "router_api", "api_token"))):
                    raise ValueError("ordinary predecessor borrowed another proof authority or lost its original graph")
                physical_address(external.get("expected_public_ip"))
            elif entry["profile"].get("node_kind") != "router-vpn":
                raise ValueError("Router proof schema cannot admit an ordinary predecessor")
        elif (len(inputs["tor-capture.json"]) > 16 << 10 or physical != policy
              or profile.get("multihop_enabled", False) is not False
              or bridge_endpoint is not None and endpoint != bridge_endpoint):
            raise ValueError("direct Tor acquired an unowned physical predecessor")
        direct = None if via_entry else direct_obfs4_tuples(profile)
        if not via_entry and protocol == "tor-bridge":
            kill = profile.get("kill_switch_policy", "")
            flag = profile.get("kill_switch", False)
            if type(kill) is not str or kill not in {"", "off", "on-connect", "always"} or type(flag) is not bool:
                raise ValueError("Direct Tor protection lost its captured type")
            if (kill in {"on-connect", "always"} or not kill and flag) and direct is None and not socket_broker:
                raise ValueError("dynamic Direct Tor cannot acquire strict physical authority")
        if socket_broker:
            if (direct is not None or "desktop_physical_egress" in profile
                    or os.environ.get("HOMEVPN_NATIVE_ENDPOINTS_JSON") or os.environ.get("HOMEVPN_NATIVE_EGRESS_JSON")
                    or os.environ.get("HOMEVPN_EXTERNAL_SESSION")):
                raise ValueError("dynamic physical broker cannot acquire a destination-wide exemption")
        elif via_entry or direct is not None:
            address_raw = os.environ.get("HOMEVPN_NATIVE_ENDPOINTS_JSON", "")
            egress_raw = os.environ.get("HOMEVPN_NATIVE_EGRESS_JSON", "")
            if (os.environ.get("HOMEVPN_EXTERNAL_SESSION") != session
                    or len(address_raw) > 1024 or len(egress_raw) > 4096):
                raise ValueError("physical environment exceeds its bound")
            addresses = exact_json(address_raw.encode())
            if (type(addresses) is not list or not 1 <= len(addresses) <= 16
                    or json.dumps(addresses, separators=(",", ":")) != address_raw
                    or addresses[0] != endpoint or len(set(addresses)) != len(addresses)):
                raise ValueError("physical endpoint list changed its captured owner")
            for address in addresses:
                physical_address(address)
            egress = physical_tuples(exact_json(egress_raw.encode()))
            if (json.dumps(egress, separators=(",", ":")) != egress_raw
                    or {item["host"] for item in egress} != set(addresses)):
                raise ValueError("physical tuples do not cover the exact captured endpoints")
            # This projection was derived by the shared complete-graph compiler
            # and is inside the checked profile digest. Native reconstruction
            # independently compares it with the same predecessor graph.
            projected = physical_tuples(profile.get("desktop_physical_egress"))
            if projected != egress:
                raise ValueError("physical tuples differ from the captured graph projection")
            if direct is not None and (egress != direct or addresses != list(dict.fromkeys(row["host"] for row in direct))):
                raise ValueError("Direct obfs4 tuples differ from the complete captured bridge source")
        elif ("desktop_physical_egress" in profile
              or os.environ.get("HOMEVPN_NATIVE_ENDPOINTS_JSON") or os.environ.get("HOMEVPN_NATIVE_EGRESS_JSON")
              or os.environ.get("HOMEVPN_EXTERNAL_SESSION")):
            raise ValueError("direct Tor acquired an unowned physical predecessor")
        services = graph.get("services")
        if type(services) is not list:
            raise ValueError("native graph lacks its captured network owner")
        owners = [item for item in services if type(item) is dict and item.get("type") == "routervpn-desktop-tor-network"]
        if (len(owners) != 1 or owners[0].get("tag") != "routervpn-tor-physical"
                or owners[0].get("session_id") != session or owners[0].get("source_sha256") != source):
            raise ValueError("native graph network identity changed")
        if (owners[0].get("physical_broker", False) is not socket_broker):
            raise ValueError("native graph physical factory does not match its captured protection")
        if socket_broker:
            physical_outbounds = [item for item in graph.get("outbounds", [])
                                  if type(item) is dict and item.get("type") == "routervpn-desktop-tor-physical"]
            expected_physical = {"type": "routervpn-desktop-tor-physical", "tag": "routervpn-tor-physical-egress",
                                 "session_id": session, "source_sha256": source}
            if physical_outbounds != [expected_physical]:
                raise ValueError("native physical outbound has another source or authority")
            dns = graph.get("dns")
            servers = dns.get("servers") if type(dns) is dict else None
            bootstrap = ([item for item in servers if type(item) is dict and item.get("tag") == "routervpn-tor-bootstrap"]
                         if type(servers) is list else [])
            if len(bootstrap) != 1 or bootstrap[0].get("detour") != expected_physical["tag"]:
                raise ValueError("selected bootstrap DNS bypassed its physical socket owner")
        if verifier.verify_directory(root, target) != directory or not os.path.samestat(before, directory.lstat()):
            raise ValueError("private launch directory changed during capture")
    finally:
        os.close(descriptor)


def regular_at(directory: int, name: str, bound: int) -> bytes:
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or not 0 < before.st_size <= bound:
        raise ValueError("private input type or size changed")
    descriptor = os.open(name, FILE_FLAGS, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        if not os.path.samestat(before, opened):
            raise ValueError("private input owner changed")
        chunks = []
        count = 0
        while count <= bound:
            block = os.read(descriptor, min(65536, bound + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (count != before.st_size or not os.path.samestat(before, after)
                or not os.path.samestat(before, current) or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns or not stat.S_ISREG(current.st_mode)):
            raise ValueError("private input changed during capture")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_witness(target: str) -> None:
    validate_launch(target)
    session = os.environ.get("HOMEVPN_TOR_SESSION", "")
    source = os.environ.get("HOMEVPN_TOR_SOURCE_SHA256", "")
    if (not re.fullmatch(r"[a-f0-9]{32}", session)
            or not re.fullmatch(r"[a-f0-9]{64}", source)
            or os.environ.get("HOMEVPN_STANDARD_ENGINE") != "native"):
        raise ValueError("missing captured native identity")
    for variable in INPUTS.values():
        if not re.fullmatch(r"[a-f0-9]{64}", os.environ.get(variable, "")):
            raise ValueError("missing captured private digest")
    verifier = private_verifier()
    root = os.environ.get("HOMEVPN_ROOT", "/opt/router-vpn-client")
    directory = verifier.verify_directory(root, target)
    relative = directory.relative_to(verifier.lexical(root) / "run")
    if len(relative.parts) != 2 or relative.parts[0] != "tor-bridge":
        raise ValueError("no captured Tor session directory")
    expected = directory.lstat()
    if expected.st_mode & 0o077:
        raise ValueError("private session permissions changed")
    descriptor = verifier.open_directory(directory, expected, "Tor prelaunch workspace")
    try:
        names = set(os.listdir(descriptor))
        if names - set(INPUTS) - {"tor-data", "stop.json"} or not (set(INPUTS) | {"tor-data"}) <= names:
            raise ValueError("native admission or foreign files already exist")
        for name, variable in INPUTS.items():
            bound = 8 << 20 if name == "tor-capture.json" else 4 << 20
            if hashlib.sha256(regular_at(descriptor, name, bound)).hexdigest() != os.environ[variable]:
                raise ValueError("private input digest changed")
        data_info = os.stat("tor-data", dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(data_info.st_mode) or data_info.st_mode & 0o077:
            raise ValueError("private Tor data owner changed")
        data = os.open("tor-data", DIR_FLAGS, dir_fd=descriptor)
        try:
            if not os.path.samestat(data_info, os.fstat(data)) or os.listdir(data):
                raise ValueError("native Tor data has already been used")
        finally:
            os.close(data)
        if "stop.json" in names:
            stop = json.loads(regular_at(descriptor, "stop.json", 4096))
            if (stop.get("schema") != 1 or stop.get("session_id") != session
                    or stop.get("source_sha256") != source or stop.get("closed", False)):
                raise ValueError("stop request belongs to another owner")
        if verifier.verify_directory(root, target) != directory or not os.path.samestat(expected, directory.lstat()):
            raise ValueError("private workspace changed before witness")
        record = json.dumps({"schema": 1, "session_id": session, "source_sha256": source,
                             "config_sha256": os.environ["HOMEVPN_TOR_CONFIG_SHA256"],
                             "no_native_process": True}, separators=(",", ":")).encode("ascii")
        output = os.open("prelaunch-failed.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=descriptor)
        try:
            while record:
                count = os.write(output, record)
                if count <= 0:
                    raise OSError("prelaunch witness write did not progress")
                record = record[count:]
            os.fsync(output)
        finally:
            os.close(output)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "--validate":
            validate_launch(sys.argv[2], sys.argv[3], sys.argv[4])
        elif len(sys.argv) == 2:
            write_witness(sys.argv[1])
        else:
            raise ValueError("expected one captured runtime")
    except Exception:
        # Do not print private profiles, transports, paths, or captured values.
        print("Tor prelaunch witness could not be safely recorded.", file=sys.stderr)
        sys.exit(1)
