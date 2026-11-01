#!/usr/bin/env python3
"""Use actual final manual SOCKS downloads with unchanged curl and sing-box.

The shipping finalization metadata blocks, private transaction, Setup Center
generation/normalization and download handler execute in a disconnected owned
namespace. HTTP payload and independent DNS receipts prove the selected server
and resolver, not physical LAN/VPN reachability or all-device DNS acceptance.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.parse

import test_aux_interoperability as aux
from run_aux_interoperability import drop_setup_capabilities
from test_setup_overtls_interoperability import call, downloaded_config

RESOLVERS = {"selected": "127.0.0.53", "wrong": "127.0.0.54", "system": "127.0.0.55"}


def parse_question(packet):
    if len(packet) < 17 or struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("owned DNS request must contain one complete question")
    offset, labels = 12, []
    while offset < len(packet) and packet[offset]:
        length = packet[offset]
        if not 1 <= length <= 63 or offset + length + 1 >= len(packet):
            raise ValueError("invalid owned DNS question label")
        labels.append(packet[offset + 1:offset + 1 + length].decode("ascii"))
        offset += length + 1
    if offset + 5 > len(packet):
        raise ValueError("incomplete owned DNS question")
    kind, category = struct.unpack_from("!HH", packet, offset + 1)
    if kind not in (1, 28) or category != 1:
        raise ValueError("owned DNS proof requires IN A/AAAA")
    return ".".join(labels).lower(), kind, offset + 5


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
                name, kind, end = parse_question(query)
                denied = name.startswith("no-answer-")
                response = query[:2] + struct.pack("!5H", 0x8183 if denied else 0x8180, 1, 0 if denied else 1, 0, 0) + query[12:end]
                if not denied:
                    address = ipaddress.ip_address("127.0.0.1" if kind == 1 else "::1").packed
                    response += b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(address)) + address
                with self.lock:
                    self.received.setdefault(name, {key: {1: 0, 28: 0} for key in RESOLVERS})[resolver][kind] += 1
                connection.sendto(response, sender)
            except socket.timeout:
                continue
            except OSError as error:
                if not self.stop.is_set():
                    with self.lock:
                        self.errors.append(str(error))
                return
            except Exception as error:
                with self.lock:
                    self.errors.append(str(error))
                return

    def counts(self, name):
        with self.lock:
            if self.errors:
                raise AssertionError("owned DNS responder failed: " + self.errors[0])
            return copy.deepcopy(self.received.get(name, {key: {1: 0, 28: 0} for key in RESOLVERS}))

    def close(self):
        self.stop.set()
        for connection in self.sockets.values():
            connection.close()
        for thread in self.threads:
            thread.join(3)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("owned SOCKS DNS workers did not join")


class HTTPPeers:
    def __init__(self):
        self.stop, self.lock = threading.Event(), threading.Lock()
        self.sockets, self.threads, self.received, self.errors = [], [], {}, []
        self.port = aux.port()
        try:
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                listener = socket.socket(family, socket.SOCK_STREAM)
                self.sockets.append(listener)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((host, self.port))
                listener.listen(8)
                listener.settimeout(0.1)
                thread = threading.Thread(target=self.serve, args=(listener,))
                self.threads.append(thread)
                thread.start()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def body(path):
        return hashlib.sha256(path.encode("ascii")).digest() * 16

    def serve(self, listener):
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    header = b""
                    while b"\r\n\r\n" not in header:
                        part = connection.recv(1024)
                        if not part or len(header) + len(part) > 8192:
                            raise ValueError("owned HTTP client did not send a bounded complete request")
                        header += part
                    method, path, version = header.split(b"\r\n", 1)[0].decode("ascii").split(" ")
                    if method != "GET" or version != "HTTP/1.1" or not path.startswith("/"):
                        raise ValueError("unexpected owned HTTP request")
                    with self.lock:
                        self.received[path] = self.received.get(path, 0) + 1
                    body = self.body(path)
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\nConnection: close\r\n\r\n" + body)
            except socket.timeout:
                continue
            except OSError as error:
                if not self.stop.is_set():
                    with self.lock:
                        self.errors.append(str(error))
                return
            except Exception as error:
                with self.lock:
                    self.errors.append(str(error))
                return

    def count(self, path):
        with self.lock:
            if self.errors:
                raise AssertionError("owned HTTP peer failed: " + self.errors[0])
            return self.received.get(path, 0)

    def close(self):
        self.stop.set()
        for listener in self.sockets:
            listener.close()
        for thread in self.threads:
            thread.join(3)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("owned HTTP workers did not join")


def finalize_metadata(source, root, script):
    program = (source / "server/finalize" / script).read_text()
    marker = 'python3 - "$BASE" "$ADGUARD4" "$META_TMP" <<\'PY\'\n'
    if program.count(marker) != 1:
        raise AssertionError("shipping private finalization metadata block changed")
    body = program.split(marker, 1)[1].split("\nPY\n", 1)[0]
    stage = root / "metadata-stage"
    stage.mkdir(mode=0o700)
    call([sys.executable, "-", root, RESOLVERS["selected"], stage], source=body)
    call([sys.executable, source / "server/scripts/atomic-private-batch.py",
          str(root / "config/socks5.json") + "=" + str(stage / "socks5.json"),
          str(root / "client-bundle/routers.json") + "=" + str(stage / "routers.json")])
    config = json.loads((root / "config/socks5.json").read_text())
    if "users" in config["inbounds"][0] or config["dns"]["servers"][0]["server"] != RESOLVERS["selected"]:
        raise AssertionError("actual finalization did not preserve no-auth and explicit Home AdGuard")
    return hashlib.sha256(body.encode()).hexdigest()


def manual_fields(content):
    fields = {}
    names = {"SOCKS5 host", "Port", "TLS", "Authentication", "Username", "Password"}
    for line in content.splitlines():
        name, separator, value = line.partition(": ")
        if separator and name in names:
            if name in fields:
                raise AssertionError("ambiguous duplicated downloaded SOCKS field")
            fields[name] = value
    required = {"SOCKS5 host", "Port", "TLS", "Authentication"}
    if not required <= fields.keys() or not fields["TLS"].startswith("off "):
        raise AssertionError("downloaded manual SOCKS fields are incomplete")
    host = fields["SOCKS5 host"]
    if not ipaddress.ip_address(host).is_loopback:
        raise AssertionError("fixture method escaped its owned loopback")
    port = int(fields["Port"])
    if not 1 <= port <= 65535:
        raise AssertionError("invalid downloaded SOCKS listener port")
    authentication = fields["Authentication"]
    if authentication == "none":
        if "Username" in fields or "Password" in fields:
            raise AssertionError("no-auth manual method includes credentials")
    elif authentication != "username/password" or not {"Username", "Password"} <= fields.keys():
        raise AssertionError("unsupported downloaded SOCKS authentication")
    return fields


def request(curl, fields, http, *, local_dns=False, no_answer=False):
    token = secrets.token_hex(16)
    name = ("no-answer-" if no_answer else "") + token + ".router-vpn-socks.test"
    path = "/" + token
    host = fields["SOCKS5 host"]
    endpoint = ("[" + host + "]" if ":" in host else host) + ":" + fields["Port"]
    authority = endpoint
    if fields["Authentication"] == "username/password":
        authority = urllib.parse.quote(fields["Username"], safe="") + ":" + urllib.parse.quote(fields["Password"], safe="") + "@" + endpoint
    proxy = ("socks5://" if local_dns else "socks5h://") + authority
    command = [curl, "-q", "--silent", "--show-error", "--fail", "--http1.1", "--noproxy", "",
               "--connect-timeout", "2", "--max-time", "4", "--proxy", proxy]
    command.append("http://" + name + ":" + str(http.port) + path)
    result = subprocess.run([str(item) for item in command], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
    return {"name": name, "path": path, "result": result}


def payload_receipt(http, record, accepted):
    result, path = record["result"], record["path"]
    if accepted:
        if result.returncode or result.stdout != http.body(path) or http.count(path) != 1:
            raise AssertionError("unchanged curl did not deliver exact independent HTTP bytes: " + result.stderr[-1024:].decode(errors="replace"))
    elif result.returncode == 0 or result.stdout or http.count(path):
        raise AssertionError("invalid SOCKS endpoint/auth/DNS answer delivered HTTP payload")


def resolver_receipt(peers, record, selected):
    counts = peers.counts(record["name"])
    if selected is None:
        if any(sum(value.values()) for value in counts.values()):
            raise AssertionError("unconnected/rejected SOCKS request reached a DNS resolver")
        return counts
    if (any(counts[selected][kind] < 1 for kind in (1, 28))
            or any(sum(counts[name].values()) for name in RESOLVERS if name != selected)):
        raise AssertionError("HTTP success did not prove selected A/AAAA resolver ownership: " + repr(counts))
    return counts


def execute(args, dns):
    paths = {name: getattr(args, name.replace("-", "_")).resolve() for name in ("sing-box", "curl", "node")}
    hashes = {}
    for name, path in paths.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("missing actual private SOCKS interoperability binary: " + name)
        with path.open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    if not call([paths["sing-box"], "version"]).startswith("sing-box version 1.13.12\n"):
        raise ValueError("private SOCKS gate requires the pinned production server")
    client_version = call([paths["curl"], "--version"]).splitlines()[0]
    if not client_version.startswith("curl "):
        raise ValueError("missing unchanged independent curl client")
    expected = os.environ.get("ROUTERVPN_SINGBOX_SHA256", "")
    if os.environ.get("ROUTERVPN_REQUIRE_PRODUCTION_HASHES") == "1" and not expected:
        raise ValueError("private SOCKS gate lacks production image binary identity")
    if expected and expected != hashes["sing-box"]:
        raise ValueError("private SOCKS server differs from the finalized production image")
    template = json.loads((args.source / "configs/router/socks5.json.example").read_text())
    cases, receipts, blocks, denied = [], [], {}, []
    with tempfile.TemporaryDirectory(prefix="routervpn-private-socks-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        http = HTTPPeers()
        try:
            scenarios = (("default", "::", 1080, "finalize.sh", False),
                         ("saved-ipv4", "127.0.0.1", 19080, "finalize.sh", False),
                         ("saved-ipv6", "::1", 19081, "upgrade-safe.sh", False),
                         ("existing-auth", "127.0.0.1", 19082, "finalize.sh", True))
            for label, listen, port, script, authentication in scenarios:
                root = directory / label
                (root / "config").mkdir(parents=True, mode=0o700)
                (root / "client-bundle").mkdir(mode=0o700)
                config = copy.deepcopy(template)
                config["inbounds"][0].update(listen=listen, listen_port=port)
                config["dns"]["servers"][0]["server"] = RESOLVERS["wrong"]
                source_path = root / "config/socks5.json"
                aux.private_json(source_path, config)
                aux.private_json(root / "client-bundle/routers.json", {"profiles": [{"id": "owned", "socks_port": port}]})
                blocks[script] = finalize_metadata(args.source, root, script)
                config = json.loads(source_path.read_text())
                if authentication:
                    # The no-auth finalizers remain unchanged. This additional
                    # case describes a pre-existing explicit server credential;
                    # the Methods exporter must not strip or replace it.
                    config["inbounds"][0]["users"] = [{"username": "owned:user @/+\u00b5", "password": "__DATA__ __SOCKS__ :@/?+&<> \u03c0"}]
                    aux.private_json(source_path, config)
                server_bytes = source_path.read_bytes()
                call([sys.executable, args.source / "server/scripts/generate-setup-assets.py", root,
                      "router.invalid", RESOLVERS["selected"]])
                call([sys.executable, args.source / "server/scripts/normalize-setup-imports.py", root])
                data = json.loads((root / "client-bundle/setup-assets.json").read_text())
                method = next(item for item in data["methods"] if item["id"] == "socks5")
                if method["qrSupported"] or method["qrPayload"] or method["url"] or method["endpointScope"] != "tunnel-private-only":
                    raise AssertionError("private manual SOCKS method became a public/QR import")
                page = (root / "client-bundle/router-vpn-device-setup.html").read_text()
                page_data = json.loads(page.split("const DATA=", 1)[1].split(";const $=", 1)[0])
                page_method = next(item for item in page_data["methods"] if item["id"] == "socks5")
                if page_method != method:
                    raise AssertionError("final published page changed selected SOCKS source fields")
                download = downloaded_config(paths["node"], page, page_method)
                if download["filename"] != "router-vpn-socks5.txt":
                    raise AssertionError("manual SOCKS download lost its actual text filename")
                fields = manual_fields(download["content"])
                selected_host = RESOLVERS["selected"] if listen == "::" else listen
                if fields["SOCKS5 host"] != selected_host or int(fields["Port"]) != port:
                    raise AssertionError("final downloaded SOCKS instructions changed the finalized listener")
                if authentication and (fields["Username"], fields["Password"]) != tuple(config["inbounds"][0]["users"][0][key] for key in ("username", "password")):
                    raise AssertionError("final download changed selected server credentials")
                children = aux.Children(root)
                try:
                    children.start(label, [paths["sing-box"], "run", "-c", source_path], port, host=selected_host)
                    valid = request(paths["curl"], fields, http)
                    payload_receipt(http, valid, True)
                    receipts.append(resolver_receipt(dns, valid, "selected"))
                    cases.append(label + "/final-download-http-and-selected-A-AAAA")
                    failed = request(paths["curl"], fields, http, no_answer=True)
                    payload_receipt(http, failed, False)
                    receipts.append(resolver_receipt(dns, failed, "selected"))
                    denied.append(failed["path"])
                    cases.append(label + "/selected-NXDOMAIN-rejects-HTTP")
                    if authentication:
                        wrong = dict(fields, Password="different-owned-password")
                        failure = request(paths["curl"], wrong, http)
                        payload_receipt(http, failure, False)
                        resolver_receipt(dns, failure, None)
                        denied.append(failure["path"])
                        cases.append(label + "/wrong-credential-rejected")
                        again = request(paths["curl"], fields, http)
                        payload_receipt(http, again, True)
                        receipts.append(resolver_receipt(dns, again, "selected"))
                    if label == "saved-ipv4":
                        with socket.socket() as reservation:
                            reservation.bind((selected_host, 0))
                            wrong = dict(fields, Port=str(reservation.getsockname()[1]))
                            failure = request(paths["curl"], wrong, http)
                        payload_receipt(http, failure, False)
                        resolver_receipt(dns, failure, None)
                        denied.append(failure["path"])
                        cases.append(label + "/wrong-downloaded-port-rejected")
                        bypass = request(paths["curl"], fields, http, local_dns=True)
                        payload_receipt(http, bypass, True)
                        receipts.append(resolver_receipt(dns, bypass, "system"))
                        try:
                            resolver_receipt(dns, bypass, "selected")
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError("local DNS bypass passed the selected-resolver proof")
                        cases.append(label + "/local-DNS-bypass-rejected-by-receipt")
                    children.current()
                except BaseException:
                    print(children.diagnostics(), file=sys.stderr)
                    raise
                finally:
                    children.close()
                if label == "saved-ipv4":
                    wrong_config = copy.deepcopy(config)
                    wrong_config["dns"]["servers"][0]["server"] = RESOLVERS["wrong"]
                    wrong_path = root / "wrong-resolver-control.json"
                    aux.private_json(wrong_path, wrong_config)
                    control = aux.Children(root)
                    try:
                        control.start("wrong-resolver", [paths["sing-box"], "run", "-c", wrong_path], port, host=selected_host)
                        wrong_answer = request(paths["curl"], fields, http)
                        payload_receipt(http, wrong_answer, True)
                        receipts.append(resolver_receipt(dns, wrong_answer, "wrong"))
                        try:
                            resolver_receipt(dns, wrong_answer, "selected")
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError("identical DNS/HTTP response from wrong resolver passed ownership proof")
                        cases.append(label + "/wrong-resolver-identical-answer-rejected-by-receipt")
                    finally:
                        control.close()
                if source_path.read_bytes() != server_bytes:
                    raise AssertionError("private Methods export or traffic mutated the selected server")
                print("PASS actual private SOCKS manual download:", label, flush=True)
        finally:
            http.close()
        if any(http.count(path) for path in denied):
            raise AssertionError("rejected private SOCKS request delivered a late HTTP payload")
    print(json.dumps({"schema": 1, "cases": cases, "dns_receipts": receipts,
                      "finalization_metadata_block_sha256": blocks,
                      "final_generator_normalizer_and_text_download_handler": "executed",
                      "independent_client": "unchanged-distribution-curl", "client_version": client_version,
                      "binary_sha256": hashes, "finalized_production_binary_match": bool(expected),
                      "endpoint_bootstrap": "literal-private-IP; no DNS bootstrap required",
                      "children": "owned-parent-processes-joined", "peer_workers": "joined",
                      "physical_LAN_VPN_device_DNS_and_off_LAN_acceptance": "separate-required-gates"}, sort_keys=True))


def run(args):
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/self/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise RuntimeError("private SOCKS gate requires a disconnected owned loopback namespace")
    nameservers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines() if line.startswith("nameserver ")]
    if nameservers != [RESOLVERS["system"]]:
        raise RuntimeError("DNS bypass control requires only the owned system resolver")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)
    dns = DNSPeers()
    try:
        drop_setup_capabilities()
        status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        if any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")) or status["NoNewPrivs"].strip() != "1":
            raise RuntimeError("private SOCKS runtime retained setup privileges")
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 << 20, 4 << 20))
        dns.start()
        execute(args, dns)
    finally:
        dns.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/src"))
    for name in ("sing-box", "curl", "node"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    def expired(_signal, _frame):
        raise TimeoutError("private SOCKS gate exceeded its 180-second aggregate")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    try:
        run(args)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
