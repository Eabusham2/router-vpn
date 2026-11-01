#!/usr/bin/env python3
"""Complete selected Hysteria trust/identity must survive final Methods exports."""
from __future__ import annotations
import copy
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = spec_from_file_location("actual_hysteria_normalizer", HERE / "normalize-setup-imports.py")
normalizer = module_from_spec(spec)
spec.loader.exec_module(normalizer)
imports = normalizer.imports
HOME = {"protocol": "udp", "host": "192.168.50.133", "port": 53}


def private(path, text):
    path.write_text(text)
    path.chmod(0o600)


def generation(root, expected=True):
    result = subprocess.run([sys.executable, HERE / "generate-setup-assets.py", root,
                             "unselected-metadata.example", HOME["host"]],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if (result.returncode == 0) != expected:
        raise AssertionError("unexpected Hysteria generation result: " + result.stderr.decode(errors="replace")[-1024:])
    if expected:
        subprocess.run([sys.executable, HERE / "normalize-setup-imports.py", root],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)


def main():
    with tempfile.TemporaryDirectory(prefix="router-vpn-hysteria-method-") as temporary:
        root = Path(temporary)
        generated = root / "client-bundle/generated/hysteria2"
        generated.mkdir(parents=True, mode=0o700)
        certificate = generated / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2",
                        "-subj", "/CN=selected-tls.example", "-addext", "subjectAltName=DNS:selected-tls.example",
                        "-keyout", root / "owned-key.pem", "-out", certificate],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        certificate.chmod(0o600)
        pem = certificate.read_text()
        pin = hashlib.sha256(imports.hysteria2_certificate(pem)[0]).hexdigest()
        config = {"log": {"level": "warn"},
                  "dns": {"servers": [{"type": "udp", "tag": "home-dns", "server": HOME["host"],
                                        "server_port": 53, "detour": "proxy"}], "final": "home-dns"},
                  "inbounds": [{"type": "tun", "mtu": 1360, "auto_route": True, "strict_route": True}],
                  "outbounds": [{"type": "hysteria2", "tag": "proxy", "server": "selected-endpoint.example", "server_port": 18443,
                                 "password": "__DATA__ :@/?+#%&= \u03c0", "obfs": {"type": "salamander", "password": "different-obfs: @/#%+\u03bc"},
                                 "tls": {"enabled": True, "server_name": "selected-tls.example", "certificate_path": "cert.pem"}},
                                {"type": "direct", "tag": "direct"}],
                  "route": {"final": "proxy", "auto_detect_interface": True}}
        source = generated / "sing-box.json"
        private(source, json.dumps(config))
        original = source.read_bytes()
        generation(root)
        output = root / "client-bundle/setup-assets.json"
        page = root / "client-bundle/router-vpn-device-setup.html"
        data = json.loads(output.read_text())
        method = next(value for value in data["methods"] if value["id"] == "hysteria2")
        embedded = json.loads(page.read_text().split("const DATA=", 1)[1].split(";const $=", 1)[0])
        assert next(value for value in embedded["methods"] if value["id"] == "hysteria2") == method
        selected = json.loads(method["config"])
        expected = copy.deepcopy(config)
        expected["outbounds"][0]["tls"].pop("certificate_path")
        expected["outbounds"][0]["tls"]["certificate"] = [pem]
        assert selected == expected and source.read_bytes() == original and certificate.read_text() == pem
        assert method["configFilename"] == "router-vpn-hysteria2.json" and method["hysteria2ServerPin"] == pin
        assert not method["url"] and not method["qrSupported"] and not method["qrPayload"] and not method["qrPngBase64"]
        assert method["available"] and method["methodLane"] == "universal" and method["importType"] == "hysteria2-config-with-ca"
        alternate = method["compatibleConfig"]
        assert alternate["filename"] == "router-vpn-hysteria2-official.json"
        official = json.loads(alternate["content"])
        parsed = imports.validate_hysteria2_uri(official["server"])
        assert parsed["host"] == config["outbounds"][0]["server"] and parsed["port"] == 18443
        assert parsed["password"] == config["outbounds"][0]["password"]
        assert parsed["query"] == {"sni": ["selected-tls.example"], "insecure": ["0"], "pinSHA256": [pin],
                                    "obfs": ["salamander"], "obfs-password": [config["outbounds"][0]["obfs"]["password"]]}
        assert official["tls"] == {"ca": "router-vpn-hysteria2-ca.pem", "insecure": False}
        assert method["certificateConfig"]["content"] == pem and method["certificateConfig"]["filename"] == official["tls"]["ca"]
        assert official["socks5"] == {"listen": "127.0.0.1:1080"}
        for key in ("tcpForwarding", "udpForwarding"):
            assert official[key][0]["listen"] == "127.0.0.1:1053" and official[key][0]["remote"] == HOME["host"] + ":53"
        before_normalize = copy.deepcopy(method)
        normalizer.normalize_method(method, "different.example", HOME)
        assert method == before_normalize, "normalization must be idempotent"
        assert method["compatibleConfig"] == alternate
        for endpoint in ("2001:db8::123", "127.0.0.1"):
            changed = copy.deepcopy(expected)
            changed["outbounds"][0]["server"] = endpoint
            exported, ca = imports.hysteria2_official_profile(changed, pin, HOME)
            assert imports.validate_hysteria2_uri(exported["server"])["host"] == endpoint and ca == pem
        ipv6_dns = {"protocol": "udp", "host": "fd42::53", "port": 53}
        changed = copy.deepcopy(expected)
        changed["dns"]["servers"][0]["server"] = ipv6_dns["host"]
        exported, _ = imports.hysteria2_official_profile(changed, pin, ipv6_dns)
        assert exported["tcpForwarding"][0]["remote"] == "[fd42::53]:53"

        # Native-only options remain intact, but cannot silently vanish into
        # a plausible named-client export. Invalid trust must still reject.
        native_only = copy.deepcopy(method)
        extended = copy.deepcopy(expected)
        extended["outbounds"][0]["tls"]["alpn"] = ["h3"]
        native_only["config"] = json.dumps(extended)
        normalizer.normalize_method(native_only, "different.example", HOME)
        assert json.loads(native_only["config"]) == extended and not native_only.get("compatibleConfig")
        for invalid in ({"insecure": True}, {"insecure": "false"}, {"enabled": False},
                        {"certificate": ["malformed"]}, {"certificate": [pem + "PRIVATE DATA"]},
                        {"certificate_path": "missing.pem"}):
            changed = copy.deepcopy(extended)
            changed["outbounds"][0]["tls"].update(invalid)
            try:
                imports.hysteria2_official_profile(changed, pin, HOME)
            except ValueError as error:
                assert not isinstance(error, imports.Hysteria2JSONRequired), "invalid trust cannot be a native-only fallback"
            else:
                raise AssertionError("invalid selected Hysteria trust accepted")
        for bad in ("hysteria2://secret@example.com:8443/?sni=one&sni=two", "hysteria2://secret@example.com:8443/?insecure=perhaps",
                    "hysteria2://secret@example.com:8443/?pinSHA256=bad", "hysteria2://secret@example.com:8443/?obfs=salamander",
                    "hysteria2://secret@example.com:8443/?sni=%ZZ", "hysteria2://secret@example.com:8443/path",
                    "hysteria2://secret@example.com:8443/?sni=a%0ab", "hysteria2://secret@example.com:8443/?unknown=x",
                    "hysteria2://secret@example.com:8443/#bad%FF", "hysteria2://s@different@example.com:8443/"):
            try:
                imports.validate_hysteria2_uri(bad)
            except ValueError:
                pass
            else:
                raise AssertionError("ambiguous or malformed Hysteria URI accepted")
        assert imports.validate_hysteria2_uri("hysteria2://user:pass%3Aword@example.com:8443/")["password"] == "user:pass:word"

        saved_output, saved_page = output.read_bytes(), page.read_bytes()
        for invalid in ({"server_port": True}, {"server_port": "8443"}, {"server_port": 0},
                        {"server": "ambiguous@host"}, {"password": ""}, {"obfs": {"type": "salamander", "password": ""}},
                        {"tls": {"enabled": True, "server_name": "other\nname", "certificate_path": "cert.pem"}}):
            changed = copy.deepcopy(config)
            changed["outbounds"][0].update(invalid)
            private(source, json.dumps(changed))
            captured = source.read_bytes()
            generation(root, expected=False)
            assert source.read_bytes() == captured and output.read_bytes() == saved_output and page.read_bytes() == saved_page
        private(source, original.decode())
        for invalid_pem in ("not a certificate", pem + "\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"):
            private(certificate, invalid_pem)
            generation(root, expected=False)
            assert certificate.read_text() == invalid_pem and source.read_bytes() == original
            assert output.read_bytes() == saved_output and page.read_bytes() == saved_page
        private(certificate, pem)
        for mode in (0o644, 0o400):
            certificate.chmod(mode)
            generation(root, expected=False)
            assert output.read_bytes() == saved_output and page.read_bytes() == saved_page
        certificate.chmod(0o600)
        alternate_certificate = root / "selected-public-cert.pem"
        private(alternate_certificate, pem)
        certificate.unlink()
        certificate.symlink_to(alternate_certificate)
        generation(root, expected=False)
        assert output.read_bytes() == saved_output and page.read_bytes() == saved_page
        certificate.unlink()
        private(certificate, pem)
        source.write_text('{"outbounds":[],"outbounds":[]}')
        generation(root, expected=False)
        assert output.read_bytes() == saved_output and page.read_bytes() == saved_page
        private(source, original.decode())
        certificate.unlink()
        generation(root, expected=False)
        assert output.read_bytes() == saved_output and page.read_bytes() == saved_page
    print("Complete Hysteria Methods trust, URI identity and publication preservation: OK")


if __name__ == "__main__":
    main()
