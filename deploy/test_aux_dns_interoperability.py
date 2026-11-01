#!/usr/bin/env python3
"""Prove selected private DNS over actual OverTLS, entirely in an owned namespace.

The sockets bearing public resolver addresses are local canaries on disconnected
loopback. No query can leave this fixture. This is UDP DNS forwarding evidence,
not real AdGuard deployment or physical-device acceptance.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading

import test_aux_interoperability as aux

RESOLVERS = {
    "selected4": "10.203.0.53", "wrong4": "10.203.0.54", "canary4": "8.8.8.8",
    "selected6": "fd42:7276:706e::53", "wrong6": "fd42:7276:706e::54", "canary6": "2001:4860:4860::8888",
}


def check_namespace():
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/self/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise RuntimeError("DNS fixture requires an owned namespace containing only disconnected loopback")


def prepare(args):
    check_namespace()
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)
    subprocess.run(["ip", "address", "add", aux.PEER_HOST + "/32", "dev", "lo"], check=True, timeout=5)
    sockets, descriptors = [], {}
    for name, host in RESOLVERS.items():
        address = ipaddress.ip_address(host)
        command = ["ip", "address", "add", host + ("/32" if address.version == 4 else "/128"), "dev", "lo"]
        if address.version == 6:
            command.append("nodad")
        subprocess.run(command, check=True, timeout=5)
        family = socket.AF_INET if address.version == 4 else socket.AF_INET6
        connection = socket.socket(family, socket.SOCK_DGRAM)
        connection.bind((host, 53))
        connection.set_inheritable(True)
        sockets.append(connection)
        descriptors[name] = connection.fileno()
    # Binding 53 uses setup-only NET_BIND_SERVICE. All DNS and protocol runtime
    # processes execute after capabilities have been dropped, with owned sockets
    # inherited only by this parent; Popen closes them for native children.
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "DNS fixture could not prevent privilege restoration")
    header, data = Header(0x20080522, 0), (Data * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "DNS fixture could not drop setup capabilities")
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))
    os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:],
                            "--prepared", "--dns-fds", json.dumps(descriptors, sort_keys=True)])


def question(kind):
    labels = [secrets.token_hex(16), "router-vpn-dns", "test"]
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return secrets.token_bytes(2) + struct.pack("!5H", 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", kind, 1)


def answer(query):
    if len(query) < 17 or struct.unpack("!5H", query[2:12]) != (0x0100, 1, 0, 0, 0):
        raise ValueError("independent DNS peer received an invalid query header")
    offset = 12
    while offset < len(query) and query[offset]:
        length = query[offset]
        if length > 63 or offset + 1 + length >= len(query):
            raise ValueError("independent DNS peer received invalid query labels")
        offset += 1 + length
    if offset + 5 != len(query):
        raise ValueError("independent DNS peer received incomplete or trailing query bytes")
    kind, category = struct.unpack("!HH", query[offset + 1:])
    if category != 1 or kind not in (1, 28):
        raise ValueError("DNS fixture requires real IN A or AAAA queries")
    data = ipaddress.ip_address("203.0.113.42" if kind == 1 else "2001:db8::42").packed
    return (query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + query[12:]
            + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 30, len(data)) + data)


class DNSPeers:
    def __init__(self, descriptors):
        if set(descriptors) != set(RESOLVERS) or len(set(descriptors.values())) != len(RESOLVERS):
            raise ValueError("DNS fixture did not inherit exactly its six owned resolver sockets")
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.received, self.errors, self.sockets, self.threads = {}, [], {}, []
        try:
            for name, host in RESOLVERS.items():
                fd = descriptors[name]
                if not isinstance(fd, int) or not 3 <= fd <= 1024:
                    raise ValueError("invalid owned DNS descriptor")
                connection = socket.socket(socket.AF_INET if name.endswith("4") else socket.AF_INET6,
                                           socket.SOCK_DGRAM, fileno=fd)
                self.sockets[name] = connection
                connection.set_inheritable(False)
                if connection.getsockname()[:2] != (host, 53) or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM:
                    raise ValueError("DNS descriptor does not own its captured resolver address and UDP port")
                connection.settimeout(0.1)
            for name, connection in self.sockets.items():
                thread = threading.Thread(target=self.serve, args=(name, connection))
                thread.start()
                self.threads.append(thread)
        except BaseException:
            self.close()
            raise

    def serve(self, name, connection):
        while not self.stop.is_set():
            try:
                query, sender = connection.recvfrom(4096)
                response = answer(query)
                with self.lock:
                    values = self.received.setdefault(query, {key: 0 for key in RESOLVERS})
                    values[name] += 1
                # Deliberately identical answers at every resolver prove why
                # a valid answer alone is insufficient selected-DNS evidence.
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
        with self.lock:
            if self.errors:
                raise AssertionError("independent DNS peer error: " + self.errors[0])
            return dict(self.received.get(query, {key: 0 for key in RESOLVERS}))

    def close(self):
        self.stop.set()
        for connection in self.sockets.values():
            connection.close()
        for thread in self.threads:
            thread.join(2)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("owned DNS peer threads did not join")


def query_dns(client, destination, query):
    with socket.create_connection((aux.HOST, client), timeout=aux.IO_LIMIT) as control:
        control.settimeout(aux.IO_LIMIT)
        control.sendall(b"\x05\x01\x00")
        if aux.exact(control, 2) != b"\x05\x00":
            raise ValueError("OverTLS client did not select its generated local SOCKS method")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as packet:
            packet.bind((aux.HOST, 0))
            packet.settimeout(aux.IO_LIMIT)
            control.sendall(b"\x05\x03\x00" + aux.socks_address(packet.getsockname()))
            host, port = aux.reply(control)
            if host == "0.0.0.0":
                host = aux.HOST
            if not ipaddress.ip_address(host).is_loopback or not 1 <= port <= 65535:
                raise ValueError("DNS query was assigned an unowned SOCKS relay")
            header = b"\x00\x00\x00" + aux.socks_address(destination)
            packet.sendto(header + query, (host, port))
            response, sender = packet.recvfrom(4096)
            if sender != (host, port) or response[:len(header)] != header or response[len(header):] != answer(query):
                raise ValueError("DNS response did not preserve the exact resolver address, query identity and answer")
            return response[len(header):]


def selected_proof(peers, query, selected, response):
    expected = {name: int(name == selected) for name in RESOLVERS}
    if response != answer(query) or peers.counts(query) != expected:
        raise AssertionError("DNS answer is not evidence from the captured selected resolver")


def execute(args):
    check_namespace()
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")) or status["NoNewPrivs"].strip() != "1":
        raise RuntimeError("DNS protocol runtime still has setup capabilities or permits privilege restoration")
    paths = {name: getattr(args, name.replace("-", "_")).resolve() for name in
             ("overtls-server", "overtls-client", "overtls-stock-server", "caddy", "openssl")}
    hashes = {}
    for name, path in paths.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("missing actual DNS interoperability binary: " + name)
        with path.open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    expected_server = os.environ.get("ROUTERVPN_OVERTLS_SERVER_SHA256", "")
    expected_caddy = os.environ.get("ROUTERVPN_CADDY_SHA256", "")
    if os.environ.get("ROUTERVPN_REQUIRE_PRODUCTION_HASHES") == "1" and not expected_server:
        raise ValueError("DNS fixture lacks finalized production OverTLS binary identity")
    for name, expected in (("overtls-server", expected_server), ("caddy", expected_caddy)):
        if expected and hashes[name] != expected:
            raise ValueError("DNS fixture binary differs from finalized production image: " + name)
    for name in ("overtls-server", "overtls-client", "overtls-stock-server"):
        version = subprocess.check_output([str(paths[name]), "--version"], text=True, timeout=5)
        if "0.3.12" not in version.split():
            raise ValueError("DNS fixture requires the exact pinned OverTLS version")
    peers, private, private_denied = None, {}, {}
    expectations, cases = {}, []
    with tempfile.TemporaryDirectory(prefix="routervpn-aux-dns-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        children = aux.Children(directory)
        try:
            peers = DNSPeers(json.loads(args.dns_fds))
            for family in ("4", "6"):
                private[family] = aux.PayloadPeers(host=RESOLVERS["selected" + family])
            ports = {name: aux.port() for name in ("backend", "overtls", "stock-backend", "stock-overtls", "ssr")}
            if len(set(ports.values())) != len(ports):
                raise RuntimeError("DNS fixture listener allocation collided")
            settings = directory / "config/tls/settings.env"
            settings.parent.mkdir(parents=True, mode=0o700)
            settings.write_text("TLS_NAME='" + aux.TLS_NAME + "'\n")
            settings.chmod(0o600)
            (directory / "client-bundle/generated").mkdir(parents=True, mode=0o700)
            subprocess.run([sys.executable, str(args.source / "server/scripts/generate-aux-proxies.py"),
                            str(directory), aux.HOST, str(ports["overtls"]), str(ports["ssr"])],
                           check=True, timeout=15, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=dict(os.environ, OVERTLS_INTERNAL_PORT=str(ports["backend"])))
            generated = directory / "client-bundle/generated/overtls/overtls-client.json"
            original = json.loads(generated.read_text())
            if original["client_settings"]["disable_tls"] is not False or original["client_settings"]["dangerous_mode"] is not False:
                raise AssertionError("generated DNS path lost selected verified TLS")
            aux.certificates(directory, paths["openssl"])
            original["client_settings"]["cafile"] = str(directory / "ca.crt")
            server = json.loads((directory / "config/aux/overtls-server.json").read_text())
            clients = {}
            for kind in ("selected", "stock"):
                root = directory if kind == "selected" else directory / "stock"
                if root != directory:
                    root.mkdir(mode=0o700)
                    for name in ("server.key", "server.crt"):
                        shutil.copy2(directory / name, root / name)
                local = {"backend": ports["backend" if kind == "selected" else "stock-backend"],
                         "overtls": ports["overtls" if kind == "selected" else "stock-overtls"]}
                value = copy.deepcopy(server)
                value["server_settings"]["listen_port"] = local["backend"]
                aux.private_json(root / "server.json", value)
                binary = paths["overtls-server" if kind == "selected" else "overtls-stock-server"]
                children.start(kind + "-server", [binary, "-r", "server", "-c", root / "server.json"], local["backend"])
                config = aux.caddy_configuration(args.source, root, local, original["tunnel_path"])
                children.start(kind + "-caddy", [paths["caddy"], "run", "--config", config, "--adapter", "caddyfile"], local["overtls"])
                client = copy.deepcopy(original)
                listen = aux.port()
                client["client_settings"].update(server_port=local["overtls"], listen_port=listen)
                aux.private_json(root / "client.json", client)
                children.start(kind + "-client", [paths["overtls-client"], "-r", "client", "-c", root / "client.json"], listen)
                clients[kind] = listen
            untrusted = copy.deepcopy(original)
            clients["untrusted"] = aux.port()
            untrusted["client_settings"].update(listen_port=clients["untrusted"], cafile=str(directory / "other-ca.crt"))
            aux.private_json(directory / "untrusted.json", untrusted)
            children.start("untrusted-client", [paths["overtls-client"], "-r", "client", "-c", directory / "untrusted.json"], clients["untrusted"])

            def expect(query, name):
                counts = {key: int(key == name) for key in RESOLVERS}
                if peers.counts(query) != counts:
                    raise AssertionError("DNS query reached a substituted, duplicate or missing resolver: " + repr(peers.counts(query)))
                expectations[query] = counts

            def selected(family, kind):
                query = question(kind)
                response = query_dns(clients["selected"], (RESOLVERS["selected" + family], 53), query)
                selected_proof(peers, query, "selected" + family, response)
                expect(query, "selected" + family)

            for family in ("4", "6"):
                for kind in (1, 28):
                    selected(family, kind)
                    cases.append("ipv" + family + "/selected/" + ("A" if kind == 1 else "AAAA"))
                query = question(1)
                response = query_dns(clients["selected"], (RESOLVERS["wrong" + family], 53), query)
                try:
                    selected_proof(peers, query, "selected" + family, response)
                except AssertionError:
                    expect(query, "wrong" + family)
                else:
                    raise AssertionError("an identical answer from the wrong resolver satisfied selected-DNS proof")
                cases.append("ipv" + family + "/wrong-resolver-proof-rejected")
                selected(family, 1)

                query = question(1)
                try:
                    response = query_dns(clients["stock"], (RESOLVERS["selected" + family], 53), query)
                except OSError:
                    response = b""
                try:
                    selected_proof(peers, query, "selected" + family, response)
                except AssertionError:
                    expect(query, "canary" + family)
                else:
                    raise AssertionError("original upstream public-DNS substitution passed selected-policy proof")
                cases.append("ipv" + family + "/stock-substitution-caught-by-owned-canary")

                query = question(28)
                try:
                    query_dns(clients["untrusted"], (RESOLVERS["selected" + family], 53), query)
                except OSError:
                    expect(query, None)
                else:
                    raise AssertionError("DNS query bypassed selected TLS trust")
                cases.append("ipv" + family + "/untrusted-TLS-rejected")
                selected(family, 28)

                # Calibrate the independent private TCP peer directly before
                # and after proving the actual TLS path still refuses it.
                for before in (True, False):
                    payload = secrets.token_bytes(aux.PAYLOAD_SIZE)
                    with socket.create_connection(private[family].tcp.getsockname()[:2], timeout=aux.IO_LIMIT) as connection:
                        connection.sendall(payload)
                        if aux.exact(connection, len(payload)) != payload or private[family].count(payload) != 1:
                            raise AssertionError("private TCP peer calibration failed")
                    if before:
                        private_denied[family] = aux.verify_delivery(children, private[family], clients["selected"], "tcp", False)
                cases.append("ipv" + family + "/ordinary-private-TCP-still-rejected")
                children.current()
                print("PASS actual DNS selected receipts and rejection controls: IPv" + family, flush=True)
        except BaseException:
            print(children.diagnostics(), file=sys.stderr)
            raise
        finally:
            try:
                children.close()
            finally:
                try:
                    if peers is not None:
                        peers.close()
                finally:
                    for value in private.values():
                        value.close()
        for query, expected in expectations.items():
            if peers.counts(query) != expected:
                raise AssertionError("DNS receipt ownership changed during teardown")
        for family, payload in private_denied.items():
            if private[family].count(payload) != 0:
                raise AssertionError("private TCP payload arrived during teardown")
        totals = {name: sum(peers.counts(query)[name] for query in expectations) for name in RESOLVERS}
        print(json.dumps({"schema": 1, "cases": cases, "actual_dns_query_attempts": len(expectations),
                          "received_dns_queries": sum(totals.values()), "independent_resolver_receipts": totals,
                          "query_types": ["A", "AAAA"], "resolver_transports": ["UDP/IPv4", "UDP/IPv6"],
                          "tls": "verified-native-caddy", "selected_resolver_receipts": "exact",
                          "wrong_resolver_identical_answer": "rejected", "upstream_substitution": "caught-in-owned-namespace",
                          "ordinary_private_TCP": "still-rejected", "children": "owned-parent-processes-joined",
                          "DNS_peer_threads": "joined", "binary_sha256": hashes,
                          "finalized_production_binary_matches": sorted(name for name, expected in
                              (("overtls-server", expected_server), ("caddy", expected_caddy)) if expected),
                          "real_AdGuard_deployment_and_device_acceptance": "separate-required-gates"}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=aux.ROOT)
    for name in ("overtls-server", "overtls-client", "overtls-stock-server", "caddy", "openssl"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--prepared", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dns-fds", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.prepared:
        prepare(args)
    def expired(_signum, _frame):
        raise TimeoutError("DNS interoperability exceeded its 180-second aggregate")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    try:
        execute(args)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
