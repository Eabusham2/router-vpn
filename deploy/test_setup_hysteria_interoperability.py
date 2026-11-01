#!/usr/bin/env python3
"""Execute final Hysteria downloads with unchanged official and production binaries.

All TLS identities, app payloads and DNS peers belong to a disconnected owned
namespace. This gate proves desktop app-proxy imports and selected resolver
receipts; physical TUN, device, signing and off-LAN acceptance remain separate.
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
import urllib.parse

import test_aux_interoperability as aux
from fetch_hysteria_test_client import COMMIT, PINS, VERSION
from run_aux_interoperability import drop_setup_capabilities
from test_setup_overtls_interoperability import call, downloaded_config
from test_setup_socks_interoperability import HTTPPeers, RESOLVERS, parse_question, request, payload_receipt


class DNSPeers:
    """Independent TCP/UDP receipts; all resolvers return the same valid answer."""
    def __init__(self):
        self.stop, self.lock = threading.Event(), threading.Lock()
        self.sockets, self.threads, self.received, self.errors = [], [], {}, []
        try:
            for name, host in RESOLVERS.items():
                for network in ("tcp", "udp"):
                    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM)
                    self.sockets.append((name, network, connection))
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    connection.bind((host, 53))
                    if network == "tcp":
                        connection.listen(8)
                    connection.settimeout(0.1)
        except BaseException:
            self.close()
            raise

    def start(self):
        for name, network, connection in self.sockets:
            thread = threading.Thread(target=self.serve, args=(name, network, connection))
            self.threads.append(thread)
            thread.start()

    def answer(self, resolver, network, query):
        name, kind, end = parse_question(query)
        address = ipaddress.ip_address("127.0.0.1" if kind == 1 else "::1").packed
        response = (query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + query[12:end]
                    + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(address)) + address)
        with self.lock:
            entry = self.received.setdefault(name, {key: {"tcp": {1: 0, 28: 0}, "udp": {1: 0, 28: 0}} for key in RESOLVERS})
            entry[resolver][network][kind] += 1
        return response

    def serve(self, resolver, network, connection):
        while not self.stop.is_set():
            try:
                if network == "udp":
                    query, sender = connection.recvfrom(4096)
                    connection.sendto(self.answer(resolver, network, query), sender)
                else:
                    peer, _ = connection.accept()
                    with peer:
                        peer.settimeout(2)
                        length = struct.unpack("!H", aux.exact(peer, 2))[0]
                        if not 17 <= length <= 4096:
                            raise ValueError("invalid bounded DNS query size")
                        response = self.answer(resolver, network, aux.exact(peer, length))
                        peer.sendall(struct.pack("!H", len(response)) + response)
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
                raise AssertionError("owned Hysteria DNS peer failed: " + self.errors[0])
            return copy.deepcopy(self.received.get(name, {key: {"tcp": {1: 0, 28: 0}, "udp": {1: 0, 28: 0}} for key in RESOLVERS}))

    def close(self):
        self.stop.set()
        for _, _, connection in self.sockets:
            connection.close()
        for thread in self.threads:
            thread.join(3)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("owned Hysteria DNS workers did not join")


def receipt(peers, name, selected, *, kinds=(1, 28), network=None):
    counts = peers.counts(name)
    if selected is None:
        if any(sum(values.values()) for protocols in counts.values() for values in protocols.values()):
            raise AssertionError("unexpected resolver query for a rejected/literal endpoint")
    else:
        protocols = (network,) if network else ("tcp", "udp")
        if (any(sum(counts[selected][protocol][kind] for protocol in protocols) < 1 for kind in kinds)
                or any(sum(values.values()) for resolver, networks in counts.items() if resolver != selected for values in networks.values())):
            raise AssertionError("successful answer did not prove the selected Hysteria resolver: " + repr(counts))
    return counts


def dns_query(peers, network, kind, selected):
    name = secrets.token_hex(16) + ".hysteria-dns.test"
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00" + struct.pack("!HH", kind, 1)
    query = secrets.token_bytes(2) + struct.pack("!5H", 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM) as stream:
        stream.settimeout(3)
        stream.connect(("127.0.0.1", 1053))
        if network == "tcp":
            stream.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", aux.exact(stream, 2))[0]
            if not 17 <= length <= 4096:
                raise AssertionError("native forwarding returned an oversized DNS response")
            answer = aux.exact(stream, length)
        else:
            stream.send(query)
            answer = stream.recv(4096)
    expected_ip = ipaddress.ip_address("127.0.0.1" if kind == 1 else "::1").packed
    expected = (query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + question
                + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(expected_ip)) + expected_ip)
    if answer != expected:
        raise AssertionError("unchanged native Hysteria forwarding changed the exact DNS answer")
    result = receipt(peers, name, selected, kinds=(kind,), network=network)
    return name, result


def imported_method(paths, source, root, endpoint):
    for script in ("generate-setup-assets.py", "normalize-setup-imports.py"):
        command = [sys.executable, source / "server/scripts" / script, root]
        if script == "generate-setup-assets.py":
            # An unrelated metadata endpoint must not replace this profile's
            # captured server address. The generator source remains authoritative.
            command.extend(["unselected-metadata.invalid", RESOLVERS["selected"]])
        call(command)
    html = (root / "client-bundle/router-vpn-device-setup.html").read_text()
    published = json.loads((root / "client-bundle/setup-assets.json").read_text())
    embedded = json.loads(html.split("const DATA=", 1)[1].split(";const $=", 1)[0])
    method = next(value for value in embedded["methods"] if value["id"] == "hysteria2")
    if method != next(value for value in published["methods"] if value["id"] == "hysteria2"):
        raise AssertionError("final Hysteria page differs from published private metadata")
    if method["url"] or method["qrPayload"] or method["qrSupported"] or method["qrPngBase64"]:
        raise AssertionError("a CA-dependent method was published as a self-contained URI/QR")
    outputs = {}
    for variant in ("native", "compatible", "certificate"):
        download = downloaded_config(paths["node"], html, method, variant)
        path = root / download["filename"]
        path.write_text(download["content"])
        path.chmod(0o600)
        outputs[variant] = path
    original = json.loads((root / "client-bundle/generated/hysteria2/sing-box.json").read_text())
    native = json.loads(outputs["native"].read_text())
    selected = next(value for value in native["outbounds"] if value.get("tag") == "proxy")
    expected = copy.deepcopy(original)
    expected_proxy = next(value for value in expected["outbounds"] if value.get("tag") == "proxy")
    expected_proxy["tls"].pop("certificate_path")
    expected_proxy["tls"]["certificate"] = [outputs["certificate"].read_text()]
    if native != expected or selected["server"] != endpoint or selected["tls"].get("insecure", False) is not False:
        raise AssertionError("final native Hysteria download changed selected policy, identity or trust")
    call([paths["sing-box"], "check", "-c", outputs["native"]])
    official = json.loads(outputs["compatible"].read_text())
    uri = urllib.parse.urlsplit(official["server"])
    params = urllib.parse.parse_qs(uri.query)
    if (uri.hostname != endpoint or uri.port != selected["server_port"]
            or urllib.parse.unquote(uri.username) != selected["password"]
            or params["sni"] != [selected["tls"]["server_name"]] or params["insecure"] != ["0"]
            or params["obfs-password"] != [selected["obfs"]["password"]] or params["pinSHA256"] != [method["hysteria2ServerPin"]]
            or official["tls"] != {"ca": outputs["certificate"].name, "insecure": False}):
        raise AssertionError("official Hysteria download changed the complete selected transport identity")
    for key in ("tcpForwarding", "udpForwarding"):
        if official[key][0]["remote"] != RESOLVERS["selected"] + ":53":
            raise AssertionError("official Hysteria download substituted the captured Home AdGuard")
    return outputs, official


def command(paths, profile):
    return [paths["hysteria"], "--disable-update-check", "client", "-c", profile]


def rejected_client(paths, root, label, profile, expected_error):
    path = root / (label + ".json")
    aux.private_json(path, profile)
    owned = aux.Children(root)
    log_path = root / (label + ".log")
    try:
        with log_path.open("wb") as log:
            child = subprocess.Popen([str(item) for item in command(paths, path)], cwd=root, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        owned.children.append((label, child))
        try:
            code = child.wait(timeout=16)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError("invalid Hysteria profile did not produce its bounded expected rejection: " + label) from exc
        evidence = log_path.read_text(errors="replace").lower()
        if code == 0 or not any(marker in evidence for marker in expected_error):
            raise AssertionError("Hysteria failed for a different reason than the negative control: " + label + "\n" + evidence[-2048:])
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", 1080)) == 0:
                raise AssertionError("rejected official profile left its app proxy active")
    finally:
        owned.close()


def execute(args, dns):
    paths = {name: getattr(args, name.replace("-", "_")).resolve() for name in ("sing-box", "hysteria", "curl", "node")}
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
    if hashes["hysteria"] not in {value[0] for value in PINS.values()}:
        raise ValueError("Hysteria client differs from the unchanged checksum-pinned official release")
    version = call([paths["hysteria"], "version"])
    if "v" + VERSION not in version or COMMIT not in version:
        raise ValueError("official Hysteria version/source identity changed")
    if not call([paths["sing-box"], "version"]).startswith("sing-box version 1.13.12\n"):
        raise ValueError("Hysteria import gate requires the pinned production server")
    expected_hash = os.environ.get("ROUTERVPN_SINGBOX_SHA256", "")
    if os.environ.get("ROUTERVPN_REQUIRE_PRODUCTION_HASHES") == "1" and not expected_hash:
        raise ValueError("Hysteria import gate lacks finalized production binary identity")
    if expected_hash and expected_hash != hashes["sing-box"]:
        raise ValueError("Hysteria import gate uses a different production server binary")
    if args.source.resolve() != Path("/src"):
        raise ValueError("run the shipping transport generator from its read-only /src mount")
    os.environ["PATH"] = str(paths["sing-box"].parent) + os.pathsep + os.environ.get("PATH", "")
    cases, receipts = [], []
    with tempfile.TemporaryDirectory(prefix="routervpn-hysteria-import-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        http = HTTPPeers()
        try:
            for family, endpoint in (("ipv4", "127.0.0.1"), ("ipv6", "::1"),
                                     ("hostname", "node-" + secrets.token_hex(12) + ".hysteria-bootstrap.test")):
                root = directory / family
                root.mkdir(mode=0o700)
                hy_port, ss_port = aux.port(), aux.port()
                if hy_port == ss_port:
                    raise RuntimeError("owned Hysteria transport ports collided")
                call(["bash", args.source / "server/scripts/generate-transports.sh", root, endpoint,
                      RESOLVERS["selected"], "24443", hy_port, ss_port], timeout=60)
                source_path = root / "client-bundle/generated/hysteria2/sing-box.json"
                original = json.loads(source_path.read_text())
                server = json.loads((root / "config/transports/server.json").read_text())
                proxy = next(value for value in original["outbounds"] if value.get("tag") == "proxy")
                inbound = next(value for value in server["inbounds"] if value.get("type") == "hysteria2")
                # Disposable selected credentials deliberately exercise the
                # native URI parser; the client/server binaries remain unchanged.
                proxy["password"] = inbound["users"][0]["password"] = "owned:@/?+#%&=\u03c0" + secrets.token_hex(12)
                proxy["obfs"]["password"] = inbound["obfs"]["password"] = "separate-obfs:@/?+\u03bc" + secrets.token_hex(12)
                aux.private_json(source_path, original)
                source_bytes = source_path.read_bytes()
                outputs, profile = imported_method(paths, args.source, root, endpoint)
                if server.get("dns") != {"servers": [{"type": "udp", "tag": "home-dns", "server": RESOLVERS["selected"],
                                                      "server_port": 53}], "final": "home-dns"} or server["route"].get("default_domain_resolver") != "home-dns":
                    raise AssertionError("generated transport server omitted the selected Home AdGuard resolver")
                inbound["tls"].update(certificate_path=str(root / "config/transports/cert.pem"),
                                      key_path=str(root / "config/transports/key.pem"))
                server_path = root / "owned-server.json"
                aux.private_json(server_path, server)
                servers, peers = aux.Children(root), aux.PayloadPeers(host="::1" if family == "ipv6" else "127.0.0.1")
                try:
                    servers.start("production-transport", [paths["sing-box"], "run", "-c", server_path], ss_port)

                    def positive(label, selected_profile=None, selected_resolver="selected"):
                        native_path = outputs["compatible"]
                        if selected_profile is not None:
                            native_path = root / (label + ".json")
                            aux.private_json(native_path, selected_profile)
                        clients = aux.Children(root)
                        try:
                            clients.start(label, command(paths, native_path), 1080)
                            for network in ("tcp", "udp"):
                                aux.verify_delivery(clients, peers, 1080, network, True)
                            for network in ("tcp", "udp"):
                                for kind in (1, 28):
                                    name, proof = dns_query(dns, network, kind, selected_resolver)
                                    receipts.append(proof)
                                    if selected_resolver != "selected":
                                        try:
                                            receipt(dns, name, "selected", kinds=(kind,), network=network)
                                        except AssertionError:
                                            pass
                                        else:
                                            raise AssertionError("wrong resolver's identical answer passed selected receipt")
                            record = request(paths["curl"], {"SOCKS5 host": "127.0.0.1", "Port": "1080", "Authentication": "none"}, http)
                            payload_receipt(http, record, True)
                            receipts.append(receipt(dns, record["name"], "selected"))
                            clients.current()
                        except BaseException:
                            print(clients.diagnostics(), file=sys.stderr)
                            raise
                        finally:
                            clients.close()

                    positive("final-download")
                    cases.append(family + "/final-download/TCP-UDP-payloads-and-TCP-UDP-A-AAAA-selected-DNS")
                    if family == "hostname":
                        receipts.append(receipt(dns, endpoint, "system"))
                        cases.append("hostname/endpoint-bootstrap-separate-from-routed-DNS")
                    else:
                        receipt(dns, endpoint, None)
                    if family == "ipv4":
                        # Correct CA + selected leaf pin is necessary. A pin
                        # alone cannot replace normal PKI in the official client.
                        other = root / "other-ca.pem"
                        call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                              "-subj", "/CN=other.test", "-keyout", root / "other-key.pem", "-out", other])
                        variants = (("missing-ca", "ca", "absent.pem", ("no such file",)),
                                    ("wrong-ca", "ca", other.name, ("unknown authority",)),
                                    ("uri-without-selected-ca", "remove-ca", None, ("unknown authority",)),
                                    ("wrong-sni", "sni", "wrong-router.example", ("certificate is valid for", "not valid for")),
                                    ("wrong-pin", "pinSHA256", "00" * 32, ("no certificate matches the pinned hash",)),
                                    ("wrong-password", "password", "unselected-auth", ("authentication error", "auth error",)),
                                    ("wrong-salamander", "obfs-password", "unselected-obfs", ("timeout",)))
                        for label, field, value, error in variants:
                            bad = copy.deepcopy(profile)
                            if field == "ca":
                                bad["tls"]["ca"] = value
                            elif field == "remove-ca":
                                bad["tls"].pop("ca")
                            else:
                                uri = urllib.parse.urlsplit(bad["server"])
                                query = urllib.parse.parse_qs(uri.query)
                                authority = uri.netloc
                                if field == "password":
                                    authority = urllib.parse.quote(value, safe="") + "@" + uri.netloc.split("@", 1)[1]
                                else:
                                    query[field] = [value]
                                bad["server"] = urllib.parse.urlunsplit((uri.scheme, authority, uri.path,
                                                                          urllib.parse.urlencode(query, doseq=True), uri.fragment))
                            rejected_client(paths, root, label, bad, error)
                            cases.append(label + "/unchanged-client-rejection")
                        positive("after-negative-controls")
                        wrong = copy.deepcopy(profile)
                        for key in ("tcpForwarding", "udpForwarding"):
                            wrong[key][0]["remote"] = RESOLVERS["wrong"] + ":53"
                        positive("wrong-forward-resolver", wrong, "wrong")
                        cases.append("wrong-forward-resolver/identical-answer-rejected-by-independent-receipt")
                    if source_path.read_bytes() != source_bytes:
                        raise AssertionError("Methods publication or native test mutated the selected generated profile")
                    servers.current()
                except BaseException:
                    print(servers.diagnostics(), file=sys.stderr)
                    raise
                finally:
                    servers.close()
                    peers.close()
                if family == "ipv4":
                    # A wrong default resolver still returns the same valid
                    # HTTP payload. Its receipt must fail the selected policy.
                    wrong_server = copy.deepcopy(server)
                    wrong_server["dns"]["servers"][0]["server"] = RESOLVERS["wrong"]
                    wrong_path = root / "wrong-server-dns.json"
                    aux.private_json(wrong_path, wrong_server)
                    controls = aux.Children(root)
                    try:
                        controls.start("wrong-server-dns", [paths["sing-box"], "run", "-c", wrong_path], ss_port)
                        controls.start("wrong-server-official-client", command(paths, outputs["compatible"]), 1080)
                        record = request(paths["curl"], {"SOCKS5 host": "127.0.0.1", "Port": "1080", "Authentication": "none"}, http)
                        payload_receipt(http, record, True)
                        receipts.append(receipt(dns, record["name"], "wrong"))
                        try:
                            receipt(dns, record["name"], "selected")
                        except AssertionError:
                            pass
                        else:
                            raise AssertionError("wrong transport resolver's identical payload passed selected receipt")
                        cases.append("wrong-server-resolver/identical-HTTP-answer-rejected-by-independent-receipt")
                    finally:
                        controls.close()
                print("PASS final official Hysteria imports:", family, flush=True)
        finally:
            http.close()
    print(json.dumps({"schema": 1, "cases": cases, "dns_receipts": receipts,
                      "unchanged_official_client": "Hysteria " + VERSION, "client_source_commit": COMMIT,
                      "binary_sha256": hashes, "finalized_production_binary_match": bool(expected_hash),
                      "final_generator_normalizer_and_three_download_handlers": "executed-with-real-Blob",
                      "native_sing_box_complete_config": "actual-config-check; physical-TUN-separate",
                      "children": "owned-parent-processes-joined", "peer_workers": "joined",
                      "endpoint_bootstrap": "owned-system-DNS; selected-resolver-proof-for-routed-traffic-separate",
                      "physical_TUN_device_DNS_signing_and_off_LAN_acceptance": "separate-required-gates"}, sort_keys=True))


def run(args):
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/self/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise RuntimeError("Hysteria import gate requires a disconnected owned namespace")
    nameservers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines() if line.startswith("nameserver ")]
    if nameservers != [RESOLVERS["system"]]:
        raise RuntimeError("Hysteria bootstrap control requires only the owned system resolver")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)
    dns = DNSPeers()
    try:
        drop_setup_capabilities()
        status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        if any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")) or status["NoNewPrivs"].strip() != "1":
            raise RuntimeError("Hysteria runtime retained setup privileges")
        dns.start()
        execute(args, dns)
    finally:
        dns.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/src"))
    for name in ("sing-box", "hysteria", "curl", "node"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    def expired(_signal, _frame):
        raise TimeoutError("Hysteria import gate exceeded its 180-second aggregate")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    try:
        run(args)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
