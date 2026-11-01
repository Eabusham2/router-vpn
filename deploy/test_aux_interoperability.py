#!/usr/bin/env python3
"""Exercise generated auxiliary profiles with real, separate protocol clients.

This fixture owns listeners on an isolated loopback interface, disposable
credentials/certificates, and its child process groups. Its payload peer uses a
reserved documentation address on that same interface: OverTLS correctly
rejects TCP destinations in 127/8. CI runs with Docker networking disabled and
drops the setup capability before starting this fixture. It does not establish
physical-device or off-LAN interoperability.
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
import time
from string import Template

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
PEER_HOST = "192.0.2.1"
TLS_NAME = "router-vpn-interop.test"
PAYLOAD_SIZE = 512
IO_LIMIT = 2.0


class UDPEnvelopeError(ValueError):
    def __init__(self, expected_local_address):
        super().__init__("UDP reply carries the local application address instead of the remote payload peer"
                         if expected_local_address else "UDP reply carries an unexpected remote address")
        self.expected_local_address = expected_local_address


def exact(connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise OSError("peer closed before the complete payload")
        result.extend(chunk)
    return bytes(result)


def private_json(path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    path.chmod(0o600)


def port():
    with socket.socket() as reservation:
        reservation.bind((HOST, 0))
        return reservation.getsockname()[1]


class Children:
    def __init__(self, directory):
        self.directory = directory
        self.children = []

    def start(self, name, command, listen):
        log = (self.directory / (name + ".log")).open("wb")
        environment = dict(os.environ, XDG_CONFIG_HOME=str(self.directory / "xdg-config"),
                           XDG_DATA_HOME=str(self.directory / "xdg-data"))
        try:
            child = subprocess.Popen([str(x) for x in command], stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True,
                                     cwd=self.directory, stdin=subprocess.DEVNULL, env=environment)
        finally:
            log.close()
        self.children.append((name, child))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError(name + " exited before its owned listener: " + str(child.returncode))
            try:
                with socket.create_connection((HOST, listen), timeout=0.1):
                    return child
            except OSError:
                time.sleep(0.02)
        raise TimeoutError(name + " did not open its loopback listener")

    def current(self):
        if any(child.poll() is not None for _, child in self.children):
            raise RuntimeError("an original auxiliary child exited during interoperability")

    def close(self):
        failures = []
        for name, child in reversed(self.children):
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    failures.append(name)
        if failures:
            raise RuntimeError("owned auxiliary parent processes did not join: " + ", ".join(failures))

    def diagnostics(self):
        # Bounded logs contain only this fixture's disposable state.
        reports = []
        for name, _ in self.children:
            with (self.directory / (name + ".log")).open("rb") as log:
                log.seek(0, os.SEEK_END)
                log.seek(max(0, log.tell() - 4096))
                reports.append(name + ":\n" + log.read(4096).decode(errors="replace"))
        return "\n".join(reports)


class PayloadPeers:
    """Independent receipt counters make missing echoes insufficient rejection."""
    def __init__(self):
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.received = {}
        self.errors = []
        self.connections = set()
        self.workers = []
        self.tcp = socket.socket()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp.bind((PEER_HOST, 0))
        self.udp.bind((PEER_HOST, 0))
        self.tcp.listen(8)
        self.tcp.settimeout(0.1)
        self.udp.settimeout(0.1)
        self.threads = [threading.Thread(target=self.accept), threading.Thread(target=self.packets)]
        for thread in self.threads:
            thread.start()

    def record(self, payload):
        if len(payload) != PAYLOAD_SIZE:
            raise ValueError("independent peer received an incomplete payload")
        with self.lock:
            self.received[payload] = self.received.get(payload, 0) + 1

    def count(self, payload):
        with self.lock:
            if self.errors:
                raise RuntimeError("independent payload peer failed: " + self.errors[0])
            return self.received.get(payload, 0)

    def connection(self, connection):
        payload = bytearray()
        try:
            connection.settimeout(3)
            while len(payload) < PAYLOAD_SIZE:
                chunk = connection.recv(PAYLOAD_SIZE - len(payload))
                if not chunk:
                    raise OSError("peer closed before complete payload")
                payload.extend(chunk)
            self.record(bytes(payload))
            connection.sendall(payload)
        except OSError:
            # Empty handshakes may close; partial payload delivery is a failure,
            # never evidence that invalid credentials were safely rejected.
            if payload:
                with self.lock:
                    self.errors.append("independent TCP peer received only a partial payload")
        except Exception as exc:
            with self.lock:
                self.errors.append(str(exc))
        finally:
            with self.lock:
                self.connections.discard(connection)
            connection.close()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                if len(self.workers) >= 64:
                    self.errors.append("unbounded peer connection count")
                    connection.close()
                    return
                self.connections.add(connection)
                worker = threading.Thread(target=self.connection, args=(connection,))
                self.workers.append(worker)
            worker.start()

    def packets(self):
        while not self.stop.is_set():
            try:
                payload, address = self.udp.recvfrom(PAYLOAD_SIZE + 1)
                self.record(payload)
                self.udp.sendto(payload, address)
            except socket.timeout:
                continue
            except OSError:
                return
            except Exception as exc:
                with self.lock:
                    self.errors.append(str(exc))
                return

    def close(self):
        self.stop.set()
        self.tcp.close()
        self.udp.close()
        for thread in self.threads:
            thread.join(2)
        with self.lock:
            for connection in self.connections:
                connection.close()
            workers = list(self.workers)
        for thread in workers:
            thread.join(4)
        if any(thread.is_alive() for thread in self.threads + workers):
            raise RuntimeError("independent payload peers did not join")


def socks_address(address):
    return b"\x01" + socket.inet_aton(address[0]) + struct.pack("!H", address[1])


def reply(connection):
    header = exact(connection, 4)
    if header[0] != 5 or header[2] != 0 or header[3] not in (1, 3, 4):
        raise ValueError("client returned malformed SOCKS5 framing")
    if header[1] != 0:
        raise OSError("native protocol client rejected the requested route")
    if header[3] == 1:
        host = socket.inet_ntop(socket.AF_INET, exact(connection, 4))
    elif header[3] == 4:
        host = socket.inet_ntop(socket.AF_INET6, exact(connection, 16))
    else:
        host = exact(connection, exact(connection, 1)[0]).decode("ascii")
    return host, struct.unpack("!H", exact(connection, 2))[0]


def exchange(client_port, peers, network, payload):
    with socket.create_connection((HOST, client_port), timeout=IO_LIMIT) as control:
        control.settimeout(IO_LIMIT)
        control.sendall(b"\x05\x01\x00")
        if exact(control, 2) != b"\x05\x00":
            raise ValueError("native client did not select the generated unauthenticated local SOCKS method")
        if network == "tcp":
            control.sendall(b"\x05\x01\x00" + socks_address(peers.tcp.getsockname()))
            reply(control)
            control.sendall(payload)
            if exact(control, len(payload)) != payload:
                raise ValueError("real TCP payload changed through the auxiliary path")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as packet:
                packet.bind((HOST, 0))
                packet.settimeout(IO_LIMIT)
                control.sendall(b"\x05\x03\x00" + socks_address(packet.getsockname()))
                host, relay_port = reply(control)
                if host == "0.0.0.0":
                    host = HOST
                if not ipaddress.ip_address(host).is_loopback or not 1 <= relay_port <= 65535:
                    raise ValueError("native client returned an unowned UDP relay")
                header = b"\x00\x00\x00" + socks_address(peers.udp.getsockname())
                packet.sendto(header + payload, (host, relay_port))
                response, sender = packet.recvfrom(len(header) + len(payload) + 1)
                if sender != (host, relay_port) or len(response) != len(header) + len(payload) or response[len(header):] != payload:
                    raise ValueError("real UDP payload or relay sender changed")
                if response[:len(header)] != header:
                    local_header = b"\x00\x00\x00" + socks_address(packet.getsockname())
                    raise UDPEnvelopeError(response[:len(header)] == local_header)


def verify_delivery(children, peers, client_port, network, accepted):
    children.current()
    payload = secrets.token_bytes(PAYLOAD_SIZE)
    failure = None
    try:
        exchange(client_port, peers, network, payload)
    except OSError as exc:
        failure = exc
    children.current()
    # The original independent peer records complete payload before echoing.
    delivered = peers.count(payload)
    if accepted:
        if failure is not None or delivered != 1:
            raise AssertionError(f"real {network} delivery failed: {failure}; independent receipts={delivered}")
    elif failure is None or delivered != 0:
        raise AssertionError(f"invalid credentials/policy delivered {network} payload; independent receipts={delivered}")
    return payload


def certificates(directory, openssl):
    def run(*arguments):
        result = subprocess.run([str(openssl), *map(str, arguments)], cwd=directory,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15)
        if result.returncode:
            raise RuntimeError("disposable certificate generation failed: " + result.stderr[-1024:].decode(errors="replace"))
    for name in ("ca", "other-ca"):
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-keyout", name + ".key", "-out", name + ".crt", "-days", "1",
            "-subj", "/CN=Router VPN disposable interoperability " + name)
    run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=" + TLS_NAME)
    (directory / "server.ext").write_text("subjectAltName=DNS:" + TLS_NAME + "\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n")
    run("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "server.crt", "-days", "1", "-extfile", "server.ext")
    for path in directory.glob("*.key"):
        path.chmod(0o600)


def caddy_configuration(source, directory, ports, tunnel_path):
    # Run the actual shipping OverTLS stanza. Only fixture bind/certificate/root
    # paths differ; matcher and reverse-proxy routing are not a test imitation.
    entry = (source / "server/naive/entrypoint.sh").read_text()
    marker = "cat >>/tmp/Caddyfile <<EOF\n"
    if entry.count(marker) != 1:
        raise ValueError("shipping OverTLS TLS stanza changed")
    stanza = entry.split(marker, 1)[1].split("\nEOF", 1)[0]
    stanza = Template(stanza).substitute(TLS_NAME=TLS_NAME, OVERTLS_PORT=ports["overtls"],
                                        OVERTLS_INTERNAL_PORT=ports["backend"], OVERTLS_PATH=tunnel_path)
    site = f"https://{TLS_NAME}:{ports['overtls']} {{"
    if stanza.count(site) != 1 or stanza.count("root * /srv") != 1:
        raise ValueError("shipping OverTLS TLS site lost its captured fixture boundary")
    stanza = stanza.replace(site, site + "\n  bind 127.0.0.1\n  tls " + json.dumps(str(directory / "server.crt")) + " " + json.dumps(str(directory / "server.key")))
    stanza = stanza.replace("root * /srv", "root * " + json.dumps(str(directory / "www")))
    (directory / "www").mkdir()
    config = directory / "Caddyfile"
    config.write_text("{\n  admin off\n  auto_https off\n}\n" + stanza + "\n")
    return config


def execute(source, overtls_server, overtls_client, ssr_server, ssr_client, ssr_stock_client, caddy, openssl):
    for binary in (overtls_server, overtls_client, ssr_server, ssr_client, ssr_stock_client, caddy, openssl):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("required actual interoperability binary is unavailable: " + str(binary))
    for binary in (overtls_server, overtls_client):
        version = subprocess.check_output([str(binary), "--version"], timeout=5, text=True)
        if "0.3.12" not in version.split():
            raise ValueError("interoperability requires the pinned OverTLS version")
    binary_hashes = {}
    for name, binary in (("overtls-server", overtls_server), ("overtls-reference-client", overtls_client),
                         ("ssr-server", ssr_server), ("ssr-reference-client", ssr_client),
                         ("ssr-stock-client", ssr_stock_client), ("caddy", caddy)):
        with binary.open("rb") as stream:
            binary_hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    expected_images = {name: os.environ.get(variable, "") for name, variable in (
        ("overtls-server", "ROUTERVPN_OVERTLS_SERVER_SHA256"),
        ("ssr-server", "ROUTERVPN_SSR_SERVER_SHA256"), ("caddy", "ROUTERVPN_CADDY_SHA256"))}
    if os.environ.get("ROUTERVPN_REQUIRE_PRODUCTION_HASHES") == "1" and not all(expected_images[name] for name in ("ssr-server", "overtls-server")):
        raise ValueError("container fixture requires finalized production auxiliary binary identities")
    for name, expected in expected_images.items():
        if expected and binary_hashes[name] != expected:
            raise ValueError(name + " does not match the finalized production image binary")
    if (source / "server/naive/Dockerfile").read_text().splitlines()[0] != "FROM pocat/naiveproxy:v2.11.4-uot":
        raise ValueError("fixture Caddy image must track the production Naive image")
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/self/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise ValueError("interoperability requires a disposable namespace containing only loopback")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")) or status["NoNewPrivs"].strip() != "1":
        raise ValueError("fixture runtime must have no effective, permitted, inheritable or ambient capabilities, with no_new_privs")
    with tempfile.TemporaryDirectory(prefix="routervpn-aux-interop-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        children, peers = Children(directory), PayloadPeers()
        try:
            ports = {name: port() for name in ("overtls", "backend", "ssr")}
            if len(set(ports.values())) != len(ports):
                raise RuntimeError("fixture port allocation collided")
            settings = directory / "config/tls/settings.env"
            settings.parent.mkdir(parents=True, mode=0o700)
            settings.write_text("TLS_NAME='" + TLS_NAME + "'\n")
            settings.chmod(0o600)
            (directory / "client-bundle/generated").mkdir(parents=True, mode=0o700)
            environment = dict(os.environ, OVERTLS_INTERNAL_PORT=str(ports["backend"]))
            subprocess.run([sys.executable, str(source / "server/scripts/generate-aux-proxies.py"),
                            str(directory), HOST, str(ports["overtls"]), str(ports["ssr"])],
                           check=True, env=environment, timeout=15, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            generated = directory / "client-bundle/generated"
            ot = json.loads((generated / "overtls/overtls-client.json").read_text())
            ssr = json.loads((generated / "shadowsocksr/ssr-client.json").read_text())
            server = json.loads((directory / "config/aux/ssr-server.json").read_text())
            server["server_settings"]["listen_address"] = HOST
            private_json(directory / "ssr-server.json", server)
            certificates(directory, openssl)
            children.start("ssr-server", [ssr_server, "-c", directory / "ssr-server.json"], ports["ssr"])
            children.start("overtls-server", [overtls_server, "-r", "server", "-c", directory / "config/aux/overtls-server.json"], ports["backend"])
            caddy_config = caddy_configuration(source, directory, ports, ot["tunnel_path"])
            children.start("caddy", [caddy, "run", "--config", caddy_config, "--adapter", "caddyfile"], ports["overtls"])
            ot["client_settings"]["cafile"] = str(directory / "ca.crt")
            if ot["client_settings"]["dangerous_mode"] is not False or ot["client_settings"]["disable_tls"] is not False:
                raise AssertionError("generated OverTLS lost verified TLS")
            negatives = {"ssr": ("password",), "overtls": ("path", "tls-name", "tls-root")}
            cases, denied_payloads, stock_controls = [], [], []
            for protocol, original in (("ssr", ssr), ("overtls", ot)):
                clients = {}
                for variant in ("valid", *negatives[protocol]):
                    value = copy.deepcopy(original)
                    listen = port()
                    value["client_settings"]["listen_port"] = listen
                    if variant == "password":
                        value["password"] = secrets.token_urlsafe(32)
                    elif variant == "path":
                        value["tunnel_path"] = "/unselected-" + secrets.token_hex(16) + "/"
                    elif variant == "tls-name":
                        value["client_settings"]["server_domain"] = "different.router-vpn-interop.test"
                    elif variant == "tls-root":
                        value["client_settings"]["cafile"] = str(directory / "other-ca.crt")
                    name = protocol + "-" + variant
                    config = directory / (name + ".json")
                    private_json(config, value)
                    command = [ssr_client, "-c", config] if protocol == "ssr" else [overtls_client, "-r", "client", "-c", config]
                    children.start(name, command, listen)
                    clients[variant] = listen
                for network in ("tcp", "udp"):
                    for variant in negatives[protocol]:
                        verify_delivery(children, peers, clients["valid"], network, True)
                        denied = verify_delivery(children, peers, clients[variant], network, False)
                        denied_payloads.append(denied)
                        verify_delivery(children, peers, clients["valid"], network, True)
                        if peers.count(denied) != 0:
                            raise AssertionError("late invalid payload reached the independent peer")
                        cases.append(protocol + "/" + network + "/" + variant)
                        print("PASS actual auxiliary payload and independent rejection:", cases[-1], flush=True)
                # Keep the exact unmodified-client defect executable. A passing
                # reference client must never silently be called stock-client
                # compatibility, and a weakened envelope gate must fail here.
                stock = copy.deepcopy(original)
                stock_port = port()
                stock["client_settings"]["listen_port"] = stock_port
                stock_path = directory / (protocol + "-stock.json")
                private_json(stock_path, stock)
                stock_command = [ssr_stock_client, "-c", stock_path] if protocol == "ssr" else [overtls_server, "-r", "client", "-c", stock_path]
                children.start(protocol + "-stock-client", stock_command, stock_port)
                payload = secrets.token_bytes(PAYLOAD_SIZE)
                try:
                    exchange(stock_port, peers, "udp", payload)
                except UDPEnvelopeError as exc:
                    if not exc.expected_local_address or peers.count(payload) != 1:
                        raise AssertionError("stock-client control did not reproduce its exact returned-address defect") from exc
                else:
                    raise AssertionError("pinned unmodified client unexpectedly bypassed the strict UDP envelope control")
                children.current()
                stock_controls.append(protocol + "/udp/local-address-envelope-rejected")
                print("PASS known stock-client UDP defect rejected:", stock_controls[-1], flush=True)
            children.current()
            if any(peers.count(payload) for payload in denied_payloads):
                raise AssertionError("a delayed invalid payload reached the independent peer")
        except BaseException:
            print(children.diagnostics(), file=sys.stderr)
            raise
        finally:
            try:
                children.close()
            finally:
                peers.close()
        # Include receipts/errors observed while the original servers and peer
        # workers joined, before emitting the final successful receipt.
        if any(peers.count(payload) for payload in denied_payloads):
            raise AssertionError("an invalid payload arrived during owned teardown")
        print(json.dumps({"schema": 1, "cases": cases, "actual_tcp_udp": True,
                          "tls": "verified-native-caddy", "children": "owned-parent-processes-joined",
                          "binary_sha256": binary_hashes,
                          "finalized_production_binary_matches": sorted(name for name, expected in expected_images.items() if expected),
                          "reference_client_udp_envelopes": "explicit-pinned-corrections-see-server/aux-proxies/patches",
                          "stock_client_negative_controls": stock_controls,
                          "unmodified_upstream_udp_clients": "known-returned-address-defects-not-accepted",
                          "off_lan_and_device_acceptance": "separate-required-gates"}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    for name in ("overtls-server", "overtls-client", "ssr-server", "ssr-client", "ssr-stock-client", "caddy", "openssl"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    def expired(_signal, _frame):
        raise TimeoutError("auxiliary interoperability exceeded its 180-second aggregate")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    try:
        execute(args.source.resolve(), args.overtls_server.resolve(), args.overtls_client.resolve(), args.ssr_server.resolve(),
                args.ssr_client.resolve(), args.ssr_stock_client.resolve(), args.caddy.resolve(), args.openssl.resolve())
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
