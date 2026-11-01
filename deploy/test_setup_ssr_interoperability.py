#!/usr/bin/env python3
"""Consume actual Methods downloads with the unchanged pinned Mihomo client.

The fixture proves TCP/UDP payloads, selected home-DNS receipts, wrong-secret
rejection and independent hostname bootstrap in a disconnected namespace.
It does not establish a full-device tunnel, device DNS or off-LAN acceptance.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading

import test_aux_interoperability as aux
from fetch_mihomo_test_client import PINS, VERSION
from test_setup_overtls_interoperability import call, downloaded_config

RESOLVERS = {"selected": "127.0.0.53", "wrong": "127.0.0.54", "bootstrap": "127.0.0.55"}
BOOTSTRAP_NAME = "owned-ssr-node.router-vpn.test"


def question(name, kind):
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return secrets.token_bytes(2) + struct.pack("!5H", 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", kind, 1)


def parse_question(packet):
    if len(packet) < 17 or struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("owned DNS query must contain one complete question")
    offset, labels = 12, []
    while offset < len(packet) and packet[offset]:
        length = packet[offset]
        if not 1 <= length <= 63 or offset + 1 + length >= len(packet):
            raise ValueError("invalid owned DNS label")
        labels.append(packet[offset + 1:offset + 1 + length].decode("ascii"))
        offset += 1 + length
    if offset + 5 > len(packet):
        raise ValueError("incomplete owned DNS question")
    kind, category = struct.unpack_from("!HH", packet, offset + 1)
    if kind not in (1, 28) or category != 1:
        raise ValueError("owned DNS fixture requires A/AAAA questions")
    return ".".join(labels).lower(), kind, offset + 5


def answer(query):
    name, kind, end = parse_question(query)
    # The hostname bootstrap resolves the IPv4-only generated SSR listener.
    # Application DNS receives both A and AAAA answers from either resolver;
    # identical answers cannot substitute for captured-resolver receipts.
    empty = name == BOOTSTRAP_NAME and kind == 28
    header = query[:2] + struct.pack("!5H", 0x8180, 1, 0 if empty else 1, 0, 0)
    result = header + query[12:end]
    if not empty:
        data = ipaddress.ip_address("127.0.0.1" if kind == 1 else "::1").packed
        result += b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(data)) + data
    return result


class DNSPeers:
    def __init__(self):
        self.stop, self.lock = threading.Event(), threading.Lock()
        self.sockets, self.threads, self.received, self.errors = {}, [], {}, []
        try:
            for name, host in RESOLVERS.items():
                connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sockets[name] = connection
                connection.bind((host, 53))
                connection.settimeout(0.1)
        except BaseException:
            self.close()
            raise

    def start(self):
        for name, connection in self.sockets.items():
            thread = threading.Thread(target=self.serve, args=(name, connection))
            self.threads.append(thread)
            thread.start()

    def serve(self, resolver, connection):
        while not self.stop.is_set():
            try:
                query, sender = connection.recvfrom(4096)
                name, kind, _ = parse_question(query)
                response = answer(query)
                with self.lock:
                    self.received.setdefault((name, kind), {key: 0 for key in RESOLVERS})[resolver] += 1
                connection.sendto(response, sender)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop.is_set():
                    with self.lock:
                        self.errors.append(str(exc))
                return
            except Exception as exc:
                with self.lock:
                    self.errors.append(str(exc))
                return

    def counts(self, query):
        name, kind, _ = parse_question(query)
        with self.lock:
            if self.errors:
                raise AssertionError("owned DNS peer error: " + self.errors[0])
            return dict(self.received.get((name, kind), {key: 0 for key in RESOLVERS}))

    def close(self):
        self.stop.set()
        for connection in self.sockets.values():
            connection.close()
        for thread in self.threads:
            thread.join(3)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("owned DNS workers did not join")


def query_local_dns(query):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(3)
        connection.sendto(query, (aux.HOST, 1053))
        response, sender = connection.recvfrom(4096)
        if sender != (aux.HOST, 1053):
            raise AssertionError("DNS response came from a different local owner")
        return response


def valid_answer(query, response):
    if len(response) < 4:
        return False
    # Mihomo marks its local response authoritative. Retain exact transaction,
    # question, class, answer address and all remaining flags/bytes; only that
    # documented observed local AA-bit normalization is immaterial here.
    flags = struct.unpack_from("!H", response, 2)[0] & ~0x0400
    return response[:2] + struct.pack("!H", flags) + response[4:] == answer(query)


def selected_dns(peers, query, resolver, response):
    counts = peers.counts(query)
    if (not valid_answer(query, response) or counts[resolver] < 1
            or any(counts[key] for key in RESOLVERS if key != resolver)):
        raise AssertionError("valid DNS bytes did not prove the captured resolver: " + repr(counts)
                             + "; response=" + response.hex() + "; expected=" + answer(query).hex())


def run(args):
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/self/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise RuntimeError("SSR import gate requires an owned disconnected namespace")
    nameservers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines()
                   if line.startswith("nameserver ")]
    if nameservers != [RESOLVERS["bootstrap"]]:
        raise RuntimeError("SSR hostname bootstrap must use only the fixture-owned system resolver")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)
    dns_peers = DNSPeers()
    try:
        from run_aux_interoperability import drop_setup_capabilities
        drop_setup_capabilities()
        status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        if any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")) or status["NoNewPrivs"].strip() != "1":
            raise RuntimeError("SSR import protocol runtime retained setup capabilities")
        dns_peers.start()
        execute(args, dns_peers)
    finally:
        dns_peers.close()


def execute(args, dns_peers):
    paths = {name: getattr(args, name.replace("-", "_")).resolve() for name in ("ssr-server", "mihomo", "node")}
    hashes = {}
    for name, path in paths.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("actual SSR import binary missing: " + name)
        with path.open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    receipt = json.loads(paths["mihomo"].with_suffix(".json").read_text())
    if receipt.get("architecture") not in PINS:
        raise ValueError("unrecognized unchanged client receipt architecture")
    archive_name, archive_hash, _ = PINS[receipt["architecture"]]
    if (receipt.get("binary_sha256") != hashes["mihomo"] or receipt.get("archive_sha256") != archive_hash
            or receipt.get("upstream_modified") is not False or receipt.get("version") != VERSION
            or receipt.get("archive_url") != "https://github.com/MetaCubeX/mihomo/releases/download/v" + VERSION + "/" + archive_name):
        raise ValueError("unchanged client receipt differs from the pinned released binary")
    if ("v" + VERSION) not in call([paths["mihomo"], "-v"]).split():
        raise ValueError("actual unchanged SSR client version differs")
    expected = os.environ.get("ROUTERVPN_SSR_SERVER_SHA256", "")
    if os.environ.get("ROUTERVPN_REQUIRE_PRODUCTION_HASHES") == "1" and not expected:
        raise ValueError("SSR import lacks finalized server identity")
    if expected and expected != hashes["ssr-server"]:
        raise ValueError("SSR import server differs from the finalized image")
    cases, denied_payloads, dns_expectations = [], [], []
    with tempfile.TemporaryDirectory(prefix="routervpn-ssr-import-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        servers, peers = aux.Children(root), aux.PayloadPeers(host=aux.HOST)
        try:
            for endpoint_kind, endpoint in (("literal-ipv4", aux.HOST), ("hostname", BOOTSTRAP_NAME)):
                directory = root / endpoint_kind
                directory.mkdir(mode=0o700)
                settings = directory / "config/tls/settings.env"
                settings.parent.mkdir(parents=True, mode=0o700)
                settings.write_text("TLS_NAME='" + aux.TLS_NAME + "'\n")
                settings.chmod(0o600)
                (directory / "client-bundle/generated").mkdir(parents=True, mode=0o700)
                server_port = aux.port()
                call([sys.executable, args.source / "server/scripts/generate-aux-proxies.py", directory,
                      endpoint, "14443", server_port])
                generated = directory / "client-bundle/generated/shadowsocksr/ssr-client.json"
                original_text, original = generated.read_text(), json.loads(generated.read_text())
                server = json.loads((directory / "config/aux/ssr-server.json").read_text())
                server["server_settings"]["listen_address"] = aux.HOST
                aux.private_json(directory / "server.json", server)
                servers.start(endpoint_kind + "-server", [paths["ssr-server"], "-c", directory / "server.json"], server_port)
                for attempt, variant in enumerate(("valid", "wrong-password", "valid", "wrong-resolver")):
                    selected = copy.deepcopy(original)
                    if variant == "wrong-password":
                        selected["password"] = secrets.token_urlsafe(32)
                    aux.private_json(generated, selected)
                    resolver = RESOLVERS["wrong" if variant == "wrong-resolver" else "selected"]
                    call([sys.executable, args.source / "server/scripts/generate-setup-assets.py", directory, endpoint, resolver])
                    call([sys.executable, args.source / "server/scripts/normalize-setup-imports.py", directory])
                    bundle = directory / "client-bundle"
                    data = json.loads((bundle / "setup-assets.json").read_text())
                    if data["homeDNS"] != {"protocol": "udp", "host": resolver, "port": 53}:
                        raise AssertionError("finalization's explicit home-DNS argument was not captured")
                    method = next(item for item in data["methods"] if item["id"] == "shadowsocksr")
                    if json.loads(method["config"]) != selected or method["qrPayload"] != method["url"]:
                        raise AssertionError("compatible profile replaced the existing native SSR import")
                    html = (bundle / "router-vpn-device-setup.html").read_text()
                    if "onclick=\"downloadMethodConfig('compatible')\"" not in html:
                        raise AssertionError("named compatible-profile download has no actual page action")
                    download = downloaded_config(paths["node"], html, method, "compatible")
                    if download["filename"] != "router-vpn-shadowsocksr-mihomo.json":
                        raise AssertionError("wrong compatible SSR download filename")
                    profile = json.loads(download["content"])
                    proxy = profile["proxies"][0]
                    if (proxy["server"], proxy["port"], proxy["password"], proxy["cipher"], proxy["protocol"], proxy["obfs"],
                            proxy["protocol-param"], proxy["obfs-param"]) != (
                            endpoint, server_port, selected["password"], selected["method"], selected["protocol"], selected["obfs"],
                            selected["protocol_param"], selected["obfs_param"]):
                        raise AssertionError("downloaded profile changed selected node/credentials/protocol parameters")
                    if profile["dns"]["nameserver"] != ["udp://" + resolver + ":53#RouterVPN-SSR"] or profile["dns"]["fallback"] != []:
                        raise AssertionError("downloaded profile changed the captured home resolver")
                    owned = directory / str(attempt)
                    owned.mkdir(mode=0o700)
                    config = owned / download["filename"]
                    config.write_text(download["content"])
                    config.chmod(0o600)
                    state = owned / "state"
                    state.mkdir(mode=0o700)
                    clients = aux.Children(owned)
                    try:
                        # No config mutation: the exact download binds 1080
                        # and 1053 in this namespace. Owners run sequentially.
                        call([paths["mihomo"], "-t", "-d", state, "-f", config])
                        clients.start("unchanged-client", [paths["mihomo"], "-d", state, "-f", config], 1080)
                        if variant != "wrong-resolver":
                            for network in ("tcp", "udp"):
                                payload = aux.verify_delivery(clients, peers, 1080, network, variant == "valid")
                                if variant != "valid":
                                    denied_payloads.append(payload)
                        for kind in (1, 28):
                            query = question(secrets.token_hex(16) + ".router-vpn-ssr.test", kind)
                            try:
                                response = query_local_dns(query)
                            except OSError:
                                response = b""
                            if variant == "wrong-password":
                                if valid_answer(query, response) or any(dns_peers.counts(query).values()):
                                    raise AssertionError("selected DNS bypassed SSR credential authentication")
                                dns_expectations.append((query, None))
                            elif variant == "wrong-resolver":
                                selected_dns(dns_peers, query, "wrong", response)
                                try:
                                    selected_dns(dns_peers, query, "selected", response)
                                except AssertionError:
                                    pass
                                else:
                                    raise AssertionError("identical wrong-resolver answer passed captured-DNS proof")
                                dns_expectations.append((query, "wrong"))
                            else:
                                selected_dns(dns_peers, query, "selected", response)
                                dns_expectations.append((query, "selected"))
                        clients.current()
                    except BaseException:
                        print(clients.diagnostics(), file=sys.stderr)
                        raise
                    finally:
                        clients.close()
                    cases.append(endpoint_kind + "/final-download/" + variant)
                    print("PASS unchanged SSR Methods client:", cases[-1], flush=True)
                generated.write_text(original_text)
            servers.current()
        except BaseException:
            print(servers.diagnostics(), file=sys.stderr)
            raise
        finally:
            try:
                servers.close()
            finally:
                peers.close()
        if any(peers.count(payload) for payload in denied_payloads):
            raise AssertionError("late rejected SSR payload reached its independent peer")
    for query, resolver in dns_expectations:
        counts = dns_peers.counts(query)
        if (resolver is None and any(counts.values())) or (resolver is not None and
                (counts[resolver] < 1 or any(counts[key] for key in RESOLVERS if key != resolver))):
            raise AssertionError("late DNS query changed captured resolver evidence")
    bootstrap_counts = [dns_peers.counts(question(BOOTSTRAP_NAME, kind)) for kind in (1, 28)]
    if not any(item["bootstrap"] for item in bootstrap_counts) or any(item["selected"] or item["wrong"] for item in bootstrap_counts):
        raise AssertionError("node hostname resolution entered a home-DNS bootstrap loop or used the wrong resolver")
    print(json.dumps({"schema": 1, "cases": cases, "binary_sha256": hashes, "client": receipt,
                      "dns_query_attempts": len(dns_expectations), "hostname_bootstrap": "owned-system-resolver-only",
                      "final_download_bytes": "consumed-unmodified", "children": "owned-parent-processes-joined",
                      "payload_workers": "joined", "finalized_production_binary_match": bool(expected),
                      "device_DNS_full_device_off_LAN_and_physical_acceptance": "separate-required-gates"}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    for name in ("ssr-server", "mihomo", "node"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("bounded SSR import fixture expired")))
    signal.alarm(180)
    try:
        run(args)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
