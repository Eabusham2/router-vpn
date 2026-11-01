#!/usr/bin/env python3
"""Import final Setup Center SIP002 URLs with unmodified native clients.

The real transport generator, Setup Center generator and final normalization
run in a disconnected namespace. An unchanged shadowsocks-rust client consumes
the resulting URL directly and transfers TCP/UDP payloads through the pinned
production sing-box server. This does not establish physical-client acceptance.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile

import test_aux_interoperability as aux


def call(command, *, timeout=30):
    result = subprocess.run([str(value) for value in command], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError("owned import command failed: " + result.stderr[-2048:].decode(errors="replace"))
    return result.stdout.decode("utf-8")


def run(args):
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/self/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise RuntimeError("native import test requires a disconnected owned loopback namespace")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")) or status["NoNewPrivs"].strip() != "1":
        raise RuntimeError("native import test requires zero runtime capabilities and no privilege gains")
    paths = {name: getattr(args, name.replace("-", "_")).resolve() for name in ("sing-box", "sslocal", "ssurl")}
    hashes = {}
    for name, path in paths.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("missing actual import interoperability binary: " + name)
        with path.open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    if not call([paths["sing-box"], "version"]).startswith("sing-box version 1.13.12\n"):
        raise ValueError("import test requires the pinned production sing-box version")
    for name in ("sslocal", "ssurl"):
        if "1.24.0" not in call([paths[name], "--version"]).split():
            raise ValueError("import test requires the pinned unmodified independent client")
    expected_server = os.environ.get("ROUTERVPN_SINGBOX_SHA256", "")
    if os.environ.get("ROUTERVPN_REQUIRE_PRODUCTION_HASHES") == "1" and not expected_server:
        raise ValueError("native import test lacks finalized production server identity")
    if expected_server and hashes["sing-box"] != expected_server:
        raise ValueError("native import server does not match the production image")
    # generate-transports.sh intentionally uses the shipping /src helpers.
    if args.source.resolve() != Path("/src") or paths["sing-box"].name != "sing-box":
        raise ValueError("run the unchanged shipping generator from its read-only /src mount")
    os.environ["PATH"] = str(paths["sing-box"].parent) + os.pathsep + os.environ.get("PATH", "")
    spec = importlib.util.spec_from_file_location("actual_setup_normalizer", args.source / "server/scripts/normalize-setup-imports.py")
    normalizer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(normalizer)
    with tempfile.TemporaryDirectory(prefix="routervpn-method-import-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        children, peers = aux.Children(directory), aux.PayloadPeers(host=aux.HOST)
        denied_payloads, cases, imports = [], [], []
        try:
            for family, endpoint in (("4", "127.0.0.1"), ("6", "::1")):
                root = directory / ("ipv" + family)
                root.mkdir(mode=0o700)
                ss_port, hy_port = aux.port(), aux.port()
                if ss_port == hy_port:
                    raise RuntimeError("owned transport ports collided")
                call(["bash", args.source / "server/scripts/generate-transports.sh", root,
                      endpoint, "127.0.0.1", "24443", hy_port, ss_port], timeout=60)
                call([sys.executable, args.source / "server/scripts/generate-setup-assets.py", root, endpoint, "127.0.0.1"])
                call([sys.executable, args.source / "server/scripts/normalize-setup-imports.py", root])
                assets = json.loads((root / "client-bundle/setup-assets.json").read_text())
                method = next(value for value in assets["methods"] if value["id"] == "shadowsocks")
                uri = method["url"]
                if assets["methodContractVersion"] != 2 or method["qrPayload"] != uri or not method["qrSupported"]:
                    raise AssertionError("final normalized Methods import lost its exact URI/QR payload")
                html = (root / "client-bundle/router-vpn-device-setup.html").read_text()
                if uri not in html:
                    raise AssertionError("corrected final URI did not reach the actual published Methods page")
                if not uri.startswith("ss://2022-blake3-aes-256-gcm:"):
                    raise AssertionError("final AEAD-2022 import still uses forbidden Base64URL userinfo")
                original = json.loads((root / "client-bundle/generated/shadowsocks/sing-box.json").read_text())
                proxy = next(value for value in original["outbounds"] if value["tag"] == "proxy")
                parsed = normalizer.imports.parse_sip002(uri)
                if (parsed["method"], parsed["password"], ipaddress.ip_address(parsed["host"]), parsed["port"]) != (
                        proxy["method"], proxy["password"], ipaddress.ip_address(endpoint), ss_port):
                    raise AssertionError("final import changed the selected endpoint or credential identity")
                # The unchanged upstream utility parses the delivered URL and
                # independently regenerates its canonical URI from JSON5.
                decoded = root / "independent-import.json"
                decoded.write_text(call([paths["ssurl"], "--decode", uri]))
                decoded.chmod(0o600)
                if call([paths["ssurl"], "--encode", decoded]).strip() != uri:
                    raise AssertionError("final Methods URI differs from the unchanged native client's canonical import")
                imports.append("ipv" + family + "/final-normalized-native-import")

                server = json.loads((root / "config/transports/server.json").read_text())
                for inbound in server["inbounds"]:
                    tls = inbound.get("tls", {})
                    if tls.get("enabled"):
                        tls["certificate_path"] = str(root / "config/transports/cert.pem")
                        tls["key_path"] = str(root / "config/transports/key.pem")
                # Only certificate mount paths differ in this owned namespace;
                # real generated ciphers, keys, endpoints and inbounds remain.
                server_path = root / "owned-server.json"
                aux.private_json(server_path, server)
                children.start("sing-box-ipv" + family, [paths["sing-box"], "run", "-c", server_path], ss_port)
                clients = {}
                for variant in ("valid", "wrong-key"):
                    value = copy.deepcopy(method)
                    if variant == "wrong-key":
                        wrong = copy.deepcopy(original)
                        bad_proxy = next(item for item in wrong["outbounds"] if item["tag"] == "proxy")
                        bad_proxy["password"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
                        if bad_proxy["password"] == proxy["password"]:
                            raise AssertionError("wrong-key control accidentally reused the selected key")
                        value["config"] = json.dumps(wrong)
                        normalizer.normalize_method(value, endpoint)
                    listen = aux.port()
                    children.start("sslocal-ipv" + family + "-" + variant,
                                   [paths["sslocal"], "--server-url", value["url"],
                                    "--local-addr", "127.0.0.1:" + str(listen), "-U", "--worker-threads", "2"], listen)
                    clients[variant] = listen
                for network in ("tcp", "udp"):
                    aux.verify_delivery(children, peers, clients["valid"], network, True)
                    denied_payloads.append(aux.verify_delivery(children, peers, clients["wrong-key"], network, False))
                    aux.verify_delivery(children, peers, clients["valid"], network, True)
                    cases.append("ipv" + family + "/" + network + "/real-import-and-wrong-key-rejection")
                    print("PASS unchanged-client final Methods import:", cases[-1], flush=True)
            children.current()
        except BaseException:
            print(children.diagnostics(), file=sys.stderr)
            raise
        finally:
            try:
                children.close()
            finally:
                peers.close()
        if any(peers.count(payload) for payload in denied_payloads):
            raise AssertionError("invalid imported key delivered a late payload")
        print(json.dumps({"schema": 1, "cases": cases, "imports": imports,
                          "final_generator_and_normalizer": "executed", "independent_client": "unchanged-shadowsocks-rust-1.24.0",
                          "source_crate_sha256": "ffb45881cb155d64015a93b36278f4ee1e06d0c444857c3591715ba2bb87b355",
                          "source_crate_commit": "bb276eda014a4717b1315e90462aeeda13e8ff5b",
                          "binary_sha256": hashes, "finalized_production_binary_match": bool(expected_server),
                          "children": "owned-parent-processes-joined", "peer_workers": "joined",
                          "physical_QR_off_LAN_and_device_acceptance": "separate-required-gates"}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/src"))
    for name in ("sing-box", "sslocal", "ssurl"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    def expired(_signum, _frame):
        raise TimeoutError("native Methods import exceeded its 180-second aggregate")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    try:
        run(args)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
