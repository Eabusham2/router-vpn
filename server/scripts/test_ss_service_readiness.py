#!/usr/bin/env python3
"""Exercise SS upgrade admission against actual generator and finalizer code."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CHECK = HERE / "verify-ss-service.py"
CAP = runpy.run_path(str(HERE / "ss_service_capability.py"))
DECLARATION = "config/transports/ss-service.json"
SERVER = "config/transports/server.json"
CLIENT = "client-bundle/generated/shadowsocks/sing-box.json"
SECRET = "config/transports/generated-secrets.json"


class SSServiceReadiness(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="routervpn-ss-upgrade-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name) / "state"
        self.key = base64.b64encode(b"s" * 32).decode()
        self.hy_password = "original-hysteria-password"
        self.generate("vpn.example")
        self.put("config/xray/server.json", {"inbounds": [
            {"tag": "reality-in", "port": 24443},
            {"tag": "pq-reality-in", "port": 10443},
        ]})
        self.put("config/xray/generated-secrets.json", {"identity": "existing"})
        for mode, port in (("reality-vision", 24443), ("reality-pq-vision", 10443)):
            self.put(f"client-bundle/generated/{mode}/xray.json", {
                "outbounds": [{"tag": "proxy", "settings": {"vnext": [{"port": port}]}}],
            })
            self.put(f"client-bundle/generated/{mode}/sing-box.json", {})
        self.put("config/.core-transports-xray-v2", b"core-transports-xray-v2\n")

    def put(self, relative, value):
        body = value if isinstance(value, bytes) else CAP["encoded"](value)
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o600)

    def value(self, relative):
        return json.loads((self.base / relative).read_bytes())

    def snapshot(self):
        return {str(path.relative_to(self.base)): (path.read_bytes(), path.stat().st_mode)
                for path in self.base.rglob("*") if path.is_file() and not path.is_symlink()}

    def environment(self, image=None):
        result = dict(os.environ)
        result.pop("SING_BOX_IMAGE", None)
        if image is not None:
            result["SING_BOX_IMAGE"] = image
        return result

    def generate(self, endpoint, image=None, *, preserve=False):
        # Execute the unchanged shipping Python generator body and private batch
        # publisher. No fake network check or successful listener is substituted.
        source = (HERE / "generate-transports.sh").read_text()
        self.assertIn("\numask 077\n", source)
        body = source[source.index('python3 - "$GEN_TMP"'):].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        body = body.replace('"/src/server/scripts/ss_service_capability.py"', repr(str(HERE / "ss_service_capability.py")))
        body = body.replace('"/src/server/portainer-current.yaml"', repr(str(ROOT / "server/portainer-current.yaml")))
        key, hy_password = self.key, self.hy_password
        if preserve:
            saved = runpy.run_path(str(HERE / "preserve-generated-state.py"))["transports"](self.base)
            key, hy_password = saved["SS_KEY"], saved["HY2_PASSWORD"]
        with tempfile.TemporaryDirectory(dir=self.temporary.name) as generated:
            result = subprocess.run(
                [sys.executable, "-c", body, generated, endpoint, "192.168.50.133",
                 "8443", "8388", key, hy_password, "router-vpn.home", image or CAP["IMAGE"]],
                capture_output=True, timeout=15, **({"umask": 0o077} if os.name != "nt" else {}),
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            files = {SERVER: "server.json", CLIENT: "shadowsocks.json", SECRET: "generated-secrets.json",
                     DECLARATION: "ss-service.json",
                     "client-bundle/generated/hysteria2/sing-box.json": "hysteria2.json"}
            result = subprocess.run(
                [sys.executable, str(HERE / "atomic-private-batch.py"),
                 *[str(self.base / dest) + "=" + str(Path(generated) / src) for dest, src in files.items()]],
                capture_output=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def verify(self, endpoint="vpn.example", image=None):
        before = self.snapshot()
        result = subprocess.run([sys.executable, str(CHECK), str(self.base), endpoint],
                                env=self.environment(image), capture_output=True, text=True, timeout=15)
        self.assertEqual(self.snapshot(), before, "readiness check changed private state")
        self.assertNotIn(self.key, result.stdout + result.stderr)
        self.assertNotIn(self.hy_password, result.stdout + result.stderr)
        return result

    def core(self, endpoint="vpn.example", image=None, *, omit_ss_gate=False):
        # Run the actual shipping shell definitions, stopping before any rebuild
        # or external process. Only the immutable /src source location is mapped.
        source = (ROOT / "server/finalize/ensure-profile-engines.sh").read_text()
        source = source[:source.index("\nadvanced_credentials_ready(){")]
        source = source.replace("/src/", str(ROOT) + "/")
        if omit_ss_gate:
            line = '  python3 ' + str(CHECK) + ' "$BASE" "$ENDPOINT"\n'
            self.assertEqual(source.count(line), 1)
            source = source.replace(line, "  return 0\n")
        source += '\nif core_ready; then printf "ready\\n"; else printf "regenerate\\n"; fi\n'
        result = subprocess.run(["bash", "-c", source, "ss-readiness", str(self.base), endpoint],
                                env=self.environment(image), capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_current_generation_is_read_only_and_ready(self):
        self.assertEqual(self.verify().returncode, 0)
        self.assertEqual(self.core(), "ready")
        self.assertEqual(self.verify(image="").returncode, 0)

    def test_old_marker_does_not_bypass_missing_declaration(self):
        (self.base / DECLARATION).unlink()
        self.assertNotEqual(self.verify().returncode, 0)
        self.assertEqual(self.core(), "regenerate")
        self.assertEqual(self.core(omit_ss_gate=True), "ready", "causal old gate no longer admits fixture")
        before = self.snapshot()
        self.generate("vpn.example", preserve=True)
        self.assertEqual(self.core(), "ready")
        after = self.snapshot()
        self.assertEqual({name: after[name] for name in before}, before)

    def test_endpoint_migration_preserves_credentials_and_dns(self):
        credentials = (self.base / SECRET).read_bytes()
        original = self.value(CLIENT)
        self.assertEqual(self.core("new-vpn.example"), "regenerate")
        self.assertEqual(self.core("new-vpn.example", omit_ss_gate=True), "ready")
        self.generate("new-vpn.example", preserve=True)
        self.assertEqual(self.core("new-vpn.example"), "ready")
        self.assertEqual((self.base / SECRET).read_bytes(), credentials)
        changed = self.value(CLIENT)
        original["outbounds"][0]["server"] = "new-vpn.example"
        self.assertEqual(changed, original)
        self.assertNotIn("udp_over_tcp", changed["outbounds"][0])
        self.assertEqual(changed["dns"]["servers"][0]["server"], "192.168.50.133")

    def test_reality_failure_is_not_masked_by_current_ss(self):
        value = self.value("config/xray/server.json")
        value["inbounds"][0]["port"] = 443
        self.put("config/xray/server.json", value)
        self.assertEqual(self.verify().returncode, 0)
        self.assertEqual(self.core(), "regenerate")

    def test_declaration_shape_hashes_and_current_image_are_required(self):
        original = self.value(DECLARATION)
        for fault in ("missing-field", "extra", "schema-bool", "schema-old", "server-hash",
                      "source-hash", "generator-image", "configured-image", "not-object"):
            with self.subTest(fault=fault):
                value = dict(original)
                if fault == "missing-field": value.pop("server_sha256")
                elif fault == "extra": value["ready"] = True
                elif fault == "schema-bool": value["schema"] = True
                elif fault == "schema-old": value["schema"] = 0
                elif fault == "server-hash": value["server_sha256"] = "0" * 64
                elif fault == "source-hash": value["source_sha256"] = "0" * 64
                elif fault == "generator-image": value["generator_image"] = "foreign.example/ss:old"
                elif fault == "configured-image": value["configured_image"] = "foreign.example/ss:old"
                else: value = []
                self.put(DECLARATION, value)
                self.assertNotEqual(self.verify().returncode, 0)
        self.put(DECLARATION, original)
        self.assertEqual(self.verify().returncode, 0)

    def test_source_drift_rejects_stale_and_recomputed_mixed_generations(self):
        original = (self.base / CLIENT).read_bytes()
        declaration = (self.base / DECLARATION).read_bytes()
        for field, value in (("password", "foreign-credential"), ("server_port", 8389),
                             ("method", "aes-256-gcm"), ("server", "foreign.example")):
            with self.subTest(field=field):
                altered = json.loads(original)
                altered["outbounds"][0][field] = value
                self.put(CLIENT, altered)
                self.assertNotEqual(self.verify().returncode, 0)
                # Matching superficial hashes cannot make differing server and
                # client identities a valid generation, or adopt another node.
                claim = json.loads(declaration)
                claim["source_sha256"] = CAP["digest"]((self.base / CLIENT).read_bytes())
                self.put(DECLARATION, claim)
                self.assertNotEqual(self.verify().returncode, 0)
                self.put(DECLARATION, declaration)
        self.put(CLIENT, original)
        self.assertEqual(self.verify().returncode, 0)

    def test_explicit_unsupported_image_is_current_but_grants_no_capability(self):
        image = "foreign.example/ss:old"
        self.assertEqual(self.core(image=image), "regenerate")
        self.generate("vpn.example", image, preserve=True)
        self.assertEqual(self.core(image=image), "ready")
        self.assertNotEqual(self.verify().returncode, 0)
        self.assertIsNone(CAP["capture"](self.value(DECLARATION), (self.base / SERVER).read_bytes(),
                                        (self.base / CLIENT).read_bytes(), "a" * 64, "vpn.example"))

    def test_unconfigured_placeholder_remains_current_without_uot_authority(self):
        self.generate("router.invalid", preserve=True)
        self.assertEqual(self.core("router.invalid"), "ready")
        self.assertIsNone(CAP["capture"](self.value(DECLARATION), (self.base / SERVER).read_bytes(),
                                        (self.base / CLIENT).read_bytes(), "a" * 64, ""))

    @unittest.skipIf(os.name == "nt", "POSIX private state gate")
    def test_private_permissions_and_symlinks_are_refused(self):
        for relative in (DECLARATION, SERVER, CLIENT):
            with self.subTest(relative=relative):
                path = self.base / relative
                body = path.read_bytes()
                path.chmod(0o644)
                self.assertNotEqual(self.verify().returncode, 0)
                path.chmod(0o600)
                outside = Path(self.temporary.name) / "outside.json"
                outside.write_bytes(body)
                outside.chmod(0o600)
                path.unlink()
                path.symlink_to(outside)
                self.assertNotEqual(self.verify().returncode, 0)
                self.assertEqual(outside.read_bytes(), body)
                path.unlink()
                self.put(relative, body)
        self.assertEqual(self.verify().returncode, 0)

    def test_malformed_and_oversized_private_data_remains_unchanged(self):
        for body in (b"{invalid", b"\xff", b" " * ((4 << 20) + 1)):
            with self.subTest(size=len(body)):
                self.put(DECLARATION, body)
                self.assertNotEqual(self.verify().returncode, 0)


if __name__ == "__main__":
    unittest.main()
