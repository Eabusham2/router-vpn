#!/usr/bin/env python3
"""Exercise REALITY port readiness, stale-profile detection, and migration contract."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "server/scripts/verify-reality-port.py"


class PortMigration(unittest.TestCase):
    def put(self, root: Path, rel: str, value: dict):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)

    def fixture(self, root: Path, standard=24443, pq=10443):
        self.put(root, "config/xray/server.json", {"inbounds": [
            {"tag": "reality-in", "port": standard},
            {"tag": "pq-reality-in", "port": pq},
            {"tag": "max-xhttp-in", "port": 11443},
        ]})
        for mode, port in (("reality-vision", standard), ("reality-pq-vision", pq)):
            self.put(root, f"client-bundle/generated/{mode}/xray.json", {
                "outbounds": [{"tag": "proxy", "settings": {"vnext": [{
                    "address": "192.0.2.1", "port": port,
                }]}}],
            })

    def verify(self, root: Path, standard=24443, pq=10443):
        return subprocess.run(
            [sys.executable, str(CHECK), str(root), str(standard), str(pq)],
            capture_output=True, text=True, check=False,
        )

    def test_new_port(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            result = self.verify(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_old_port_preserved_until_opt_in(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root, standard=443)
            self.assertEqual(self.verify(root, standard=443).returncode, 0)
            self.assertNotEqual(self.verify(root, standard=24443).returncode, 0)

    def test_stale_client_and_server_rejected(self):
        for stale in ("server", "client"):
            with self.subTest(stale=stale), TemporaryDirectory() as temp:
                root = Path(temp)
                self.fixture(root)
                rel = ("config/xray/server.json" if stale == "server"
                       else "client-bundle/generated/reality-vision/xray.json")
                value = json.loads((root / rel).read_text())
                if stale == "server":
                    next(i for i in value["inbounds"] if i["tag"] == "reality-in")["port"] = 443
                else:
                    value["outbounds"][0]["settings"]["vnext"][0]["port"] = 443
                self.put(root, rel, value)
                self.assertNotEqual(self.verify(root).returncode, 0)

    def test_duplicate_inbound_and_wrong_file_permissions_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root)
            path = root / "config/xray/server.json"
            value = json.loads(path.read_text())
            value["inbounds"].append({"tag": "reality-in", "port": 24443})
            self.put(root, "config/xray/server.json", value)
            self.assertNotEqual(self.verify(root).returncode, 0)
            self.fixture(root)
            path.chmod(0o644)
            self.assertNotEqual(self.verify(root).returncode, 0)

    def test_non_443_default_and_upgrade_contract(self):
        for rel, marker in (
            ("server/finalize/finalize.sh", "REALITY_PORT=${REALITY_PORT:-24443}"),
            ("server/finalize/upgrade-safe.sh", "REALITY_PORT=${REALITY_PORT:-24443}"),
            ("server/init/noninteractive.sh", "REALITY_PORT=${REALITY_PORT:-24443}"),
            ("server/scripts/apply-runtime.sh", "REALITY_PORT=${REALITY_PORT:-24443}"),
            ("router/asus-merlin-router-vpn-forwards.sh", "REALITY_PORT=${REALITY_PORT:-24443}"),
            ("server/scripts/generate-xray-pq.sh", "REALITY_PORT=${6:-24443}"),
            ("server/scripts/generate-transports.sh", "REALITY_PORT=${4:-24443}"),
            ("server/finalize/ensure-profile-engines.sh", "REALITY_PORT=${6:-24443}"),
        ):
            with self.subTest(rel=rel):
                self.assertIn(marker, (ROOT / rel).read_text())
        compose = (ROOT / "server/portainer-current.yaml").read_text()
        self.assertEqual(compose.count("REALITY_PORT: ${REALITY_PORT:-24443}"), 2)
        self.assertEqual(compose.count("REALITY_PORT_MIGRATE_TO: ${REALITY_PORT_MIGRATE_TO:-}"), 1)
        upgrade = (ROOT / "server/finalize/upgrade-safe.sh").read_text()
        self.assertIn("REQUESTED_REALITY_PORT_MIGRATION=${REALITY_PORT_MIGRATE_TO:-}", upgrade)
        self.assertLess(
            upgrade.index('eval "$(python3 /src/server/finalize/detect-settings.py "$BASE")"'),
            upgrade.index("REALITY_PORT=$REQUESTED_REALITY_PORT_MIGRATION"),
        )
        ensure = (ROOT / "server/finalize/ensure-profile-engines.sh").read_text()
        self.assertIn("verify-reality-port.py", ensure)
        transports = (ROOT / "server/scripts/generate-transports.sh").read_text()
        self.assertNotIn('rm -rf "$BASE/client-bundle/generated/reality-vision"', transports)


if __name__ == "__main__":
    unittest.main()
