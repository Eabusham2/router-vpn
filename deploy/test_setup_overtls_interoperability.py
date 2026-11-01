#!/usr/bin/env python3
"""Consume final OverTLS Methods links/downloads with the unchanged client.

TCP acceptance is separate from the stock client's retained UDP envelope
defect. All peers, TLS authorities and private imports are disposable, inside
an owned disconnected namespace; the production TLS matcher remains intact.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile

import test_aux_interoperability as aux


def call(command, *, source=None, timeout=30):
    result = subprocess.run([str(value) for value in command], input=source, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError("owned import command failed: " + result.stderr[-2048:])
    return result.stdout


def downloaded_config(node, html, method, variant="native"):
    """Execute the final page's real handler, with an owned DOM boundary.

    Node supplies the actual Blob implementation. The adapter records the
    selected download's bytes/name and checks object URL revocation; it does
    not claim a physical browser/QR acceptance run.
    """
    marker, end = "function downloadMethodConfig(variant='native'){", "\nfunction renderMethod(){"
    if html.count(marker) != 1 or html.count(end) != 1:
        raise AssertionError("final Methods download handler changed")
    script = marker + html.split(marker, 1)[1].split(end, 1)[0]
    fixture = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
(async()=>{
 let current=input.method.id,blob,anchor,attached=false,clicked=false,removed=false,revoked=false;
 const context={Blob,availableMethods:[input.method],$:()=>({value:current}),setTimeout:fn=>fn(),
  URL:{createObjectURL:value=>{assert(!blob);blob=value;return 'blob:owned-method-config'},revokeObjectURL:value=>{assert.equal(value,'blob:owned-method-config');revoked=true}},
  document:{createElement:tag=>{assert.equal(tag,'a');anchor={click(){assert(attached);clicked=true},remove(){removed=true}};return anchor},body:{appendChild:value=>{assert.equal(value,anchor);attached=true}}}};
 context.variant=input.variant;
 vm.runInNewContext(input.script+'\ndownloadMethodConfig(variant);',context,{timeout:1000});
 const selected=input.variant==='compatible'?input.method.compatibleConfig:input.variant==='certificate'?input.method.certificateConfig:{filename:input.method.configFilename,content:input.method.config};
 assert(clicked&&removed&&revoked);assert.equal(anchor.download,selected.filename);
 assert.equal(blob.type,selected.filename.endsWith('.json')?'application/json;charset=utf-8':'text/plain;charset=utf-8');
 const content=await blob.text();assert.equal(content,selected.content);
 for(const invalid of ['missing-selection','../../private.json']){
  if(invalid==='missing-selection')current='different-method';else{current=input.method.id;if(input.variant==='compatible')input.method.compatibleConfig.filename=invalid;else if(input.variant==='certificate')input.method.certificateConfig.filename=invalid;else input.method.configFilename=invalid}
  assert.throws(()=>vm.runInNewContext('downloadMethodConfig(variant);',context,{timeout:1000}),/No valid selected method config/);
 }
 process.stdout.write(JSON.stringify({content,filename:anchor.download}));
})().catch(error=>{console.error(error);process.exitCode=1});
'''
    return json.loads(call([node, "-e", fixture], source=json.dumps({"method": method, "script": script, "variant": variant})))


def run(args):
    if args.prepare_network:
        from run_aux_interoperability import prepare_namespace
        prepare_namespace()
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/self/net/dev").read_text().splitlines()[2:]}
    if interfaces != {"lo"}:
        raise RuntimeError("OverTLS import test requires an owned disconnected namespace")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")) or status["NoNewPrivs"].strip() != "1":
        raise RuntimeError("OverTLS import runtime requires zero capabilities and no_new_privs")
    paths = {name: getattr(args, name.replace("-", "_")).resolve()
             for name in ("overtls-server", "overtls-client", "caddy", "openssl", "node")}
    hashes = {}
    for name, path in paths.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("actual import binary is missing: " + name)
        with path.open("rb") as stream:
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    for name in ("overtls-server", "overtls-client"):
        version = call([paths[name], "--version"])
        if "0.3.12" not in version.split():
            raise ValueError("OverTLS import test requires the pinned 0.3.12 source")
    for name, variable in (("overtls-server", "ROUTERVPN_OVERTLS_SERVER_SHA256"), ("caddy", "ROUTERVPN_CADDY_SHA256")):
        expected = os.environ.get(variable, "")
        if os.environ.get("ROUTERVPN_REQUIRE_PRODUCTION_HASHES") == "1" and not expected:
            raise ValueError("missing finalized production binary identity: " + name)
        if expected and hashes[name] != expected:
            raise ValueError("import test uses a different finalized production binary: " + name)
    spec = importlib.util.spec_from_file_location("overtls_methods_normalizer", args.source / "server/scripts/normalize-setup-imports.py")
    normalizer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(normalizer)
    cases, defects, denied = [], [], []
    with tempfile.TemporaryDirectory(prefix="routervpn-overtls-import-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        children, peers = aux.Children(root), aux.PayloadPeers()
        try:
            for family, endpoint in (("ipv4", "127.0.0.1"), ("ipv6", "::1")):
                directory = root / family
                directory.mkdir(mode=0o700)
                ports = {name: aux.port() for name in ("overtls", "backend", "ssr")}
                if len(set(ports.values())) != len(ports):
                    raise RuntimeError("owned ports collided")
                settings = directory / "config/tls/settings.env"
                settings.parent.mkdir(parents=True, mode=0o700)
                settings.write_text("TLS_NAME='" + aux.TLS_NAME + "'\n")
                settings.chmod(0o600)
                (directory / "client-bundle/generated").mkdir(parents=True, mode=0o700)
                environment = dict(os.environ, OVERTLS_INTERNAL_PORT=str(ports["backend"]))
                subprocess.run([sys.executable, str(args.source / "server/scripts/generate-aux-proxies.py"),
                                str(directory), endpoint, str(ports["overtls"]), str(ports["ssr"])],
                               check=True, env=environment, timeout=20, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                generated_path = directory / "client-bundle/generated/overtls/overtls-client.json"
                original = json.loads(generated_path.read_text())
                aux.certificates(directory, paths["openssl"])
                # The only generated private setting adapted here is this
                # fixture's selected root certificate, before final publishing.
                original["client_settings"]["cafile"] = (directory / "ca.crt").read_text()
                aux.private_json(generated_path, original)
                for command in ("generate-setup-assets.py", "normalize-setup-imports.py"):
                    arguments = [sys.executable, args.source / "server/scripts" / command, directory]
                    if command == "generate-setup-assets.py":
                        arguments.extend([endpoint, "127.0.0.1"])
                    call(arguments)
                bundle = directory / "client-bundle"
                data = json.loads((bundle / "setup-assets.json").read_text())
                method = next(value for value in data["methods"] if value["id"] == "overtls")
                html = (bundle / "router-vpn-device-setup.html").read_text()
                download = downloaded_config(paths["node"], html, method)
                if download["filename"] != "router-vpn-overtls.json":
                    raise AssertionError("downloaded private method has the wrong filename")
                selected = json.loads(download["content"])
                if selected["client_settings"] != original["client_settings"] or selected["tunnel_path"] != original["tunnel_path"]:
                    raise AssertionError("final method download changed selected endpoint, TLS or path identity")
                if selected["client_settings"]["dangerous_mode"] is not False or selected["client_settings"]["disable_tls"] is not False:
                    raise AssertionError("final OverTLS import weakened TLS verification")
                downloaded = directory / download["filename"]
                downloaded.write_text(download["content"])
                downloaded.chmod(0o600)
                if family == "ipv4":
                    if not method["url"] or method["qrPayload"] != method["url"] or not method["qrSupported"]:
                        raise AssertionError("real native OverTLS URI/QR missing from final Methods")
                    if call([paths["overtls-client"], "-c", downloaded, "--generate-url"]).strip() != method["url"]:
                        raise AssertionError("published OverTLS link differs from unchanged native canonical import")
                elif method["url"] or method["qrPayload"] or method["qrSupported"]:
                    raise AssertionError("upstream-incompatible IPv6 OverTLS URL was published")
                children.start(family + "-server", [paths["overtls-server"], "-r", "server", "-c",
                                                    directory / "config/aux/overtls-server.json"], ports["backend"])
                caddy_config = aux.caddy_configuration(args.source, directory, ports, original["tunnel_path"])
                # Both addresses belong only to this owned loopback namespace.
                caddy_config.write_text(caddy_config.read_text().replace("bind 127.0.0.1\n", "bind 127.0.0.1 ::1\n"))
                children.start(family + "-caddy", [paths["caddy"], "run", "--config", caddy_config, "--adapter", "caddyfile"], ports["overtls"])
                for import_kind in (("json", "uri") if family == "ipv4" else ("json",)):
                    clients = {}
                    for variant in ("valid", "wrong-path", "wrong-tls-name", "wrong-ca"):
                        value = copy.deepcopy(method)
                        config = json.loads(value["config"])
                        if variant == "wrong-path":
                            config["tunnel_path"] = "/wrong-" + secrets.token_hex(16) + "/"
                        elif variant == "wrong-tls-name":
                            config["client_settings"]["server_domain"] = "unselected.example"
                        elif variant == "wrong-ca":
                            config["client_settings"]["cafile"] = (directory / "other-ca.crt").read_text()
                        value["config"] = json.dumps(config)
                        normalizer.normalize_method(value, endpoint)
                        listen = aux.port()
                        command = [paths["overtls-client"], "-r", "client", "-l", "127.0.0.1:" + str(listen), "--pool-max-size", "16"]
                        if import_kind == "uri":
                            command.extend(["-u", value["url"]])
                        else:
                            path = directory / (import_kind + "-" + variant + ".json")
                            if variant == "valid":
                                path = downloaded
                            else:
                                path.write_text(downloaded_config(paths["node"], html, value)["content"])
                                path.chmod(0o600)
                            command.extend(["-c", path])
                        children.start("-".join((family, import_kind, variant)), command, listen)
                        clients[variant] = listen
                    for variant in ("wrong-path", "wrong-tls-name", "wrong-ca"):
                        aux.verify_delivery(children, peers, clients["valid"], "tcp", True)
                        denied.append(aux.verify_delivery(children, peers, clients[variant], "tcp", False))
                        aux.verify_delivery(children, peers, clients["valid"], "tcp", True)
                        cases.append("/".join((family, import_kind, "tcp", variant)))
                        print("PASS final unchanged OverTLS import:", cases[-1], flush=True)
                    # Do not disguise the upstream UDP reply defect as a
                    # successful full-method test or use a patched client here.
                    payload = secrets.token_bytes(aux.PAYLOAD_SIZE)
                    try:
                        aux.exchange(clients["valid"], peers, "udp", payload)
                    except aux.UDPEnvelopeError as exc:
                        if not exc.expected_local_address or peers.count(payload) != 1:
                            raise AssertionError("unchanged client UDP control differed from its exact defect") from exc
                        defects.append(family + "/" + import_kind + "/stock-UDP-address-defect")
                    else:
                        raise AssertionError("stock UDP defect changed; reassess the recorded client limitation")
            children.current()
        except BaseException:
            print(children.diagnostics(), file=sys.stderr)
            raise
        finally:
            try:
                children.close()
            finally:
                peers.close()
        if any(peers.count(payload) for payload in denied):
            raise AssertionError("late forbidden import payload reached the independent peer")
    print(json.dumps({"schema": 1, "cases": cases, "retained_upstream_defects": defects,
                      "unchanged_client": "overtls-0.3.12", "source_commit": "59eba9b327e1a256712cc7ac426d2d084d825a0d",
                      "binary_sha256": hashes, "generator_and_final_normalizer": "executed",
                      "download_handler": "executed-with-owned-DOM-and-real-Blob",
                      "children": "owned-parent-processes-joined", "peer_workers": "joined",
                      "finalized_production_binary_match": bool(os.environ.get("ROUTERVPN_OVERTLS_SERVER_SHA256")
                                                               and os.environ.get("ROUTERVPN_CADDY_SHA256")),
                      "physical_QR_off_LAN_and_device_acceptance": "separate-required-gates"}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    for name in ("overtls-server", "overtls-client", "caddy", "openssl", "node"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--prepare-network", action="store_true")
    args = parser.parse_args()
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("bounded OverTLS import fixture expired")))
    signal.alarm(180)
    try:
        run(args)
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
