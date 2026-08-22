#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = HERE / "setup-center-product-server.py"
spec = importlib.util.spec_from_file_location("setup_center_product_server_test", MODULE)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class SetupCenterReleaseTests(unittest.TestCase):
    def test_wrapper_preserves_authenticated_ai_surface(self):
        self.assertTrue(issubclass(mod.Handler, mod._ai.Handler))
        self.assertTrue(issubclass(mod.Server, mod._ai.Server))
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn('urlparse(self.path).path == "/api/release-status"', source)
        self.assertIn("self._require_auth()", source)
        self.assertIn("_release.release_status", source)

    def test_release_panel_injected_once(self):
        h = object.__new__(mod.Handler)
        base = '<html><body><div id="tabs"></div><div id="wizard" class="overlay"></div></body></html>'
        rendered = h._inject_product_ui(base)
        self.assertIn('data-tab="release-status"', rendered)
        self.assertEqual(rendered.count('data-tab="release-status"'), 1)
        again = h._inject_product_ui(rendered)
        self.assertEqual(again.count('data-tab="release-status"'), 1)

    def test_exact_sha_status_is_read_only(self):
        old = os.environ.get("ROUTER_VPN_GITHUB_SHA")
        try:
            os.environ["ROUTER_VPN_GITHUB_SHA"] = "a" * 40
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                (base / "config").mkdir()
                status = mod._release.release_status(base)
            self.assertTrue(status["exact_sha"])
            self.assertEqual(status["deployed_sha"], "a" * 40)
            self.assertEqual(status["production_model"], "exact-sha-image-only")
            self.assertFalse(status["self_update_available"])
            joined = " ".join(status["recovery"]["safe_sequence"] + status["protected_invariants"]).lower()
            self.assertIn("portainer", joined)
            self.assertNotIn("docker.sock", joined)
            destructive_global_prune = "docker system " + "prune -a"
            self.assertNotIn(destructive_global_prune, joined)
        finally:
            if old is None:
                os.environ.pop("ROUTER_VPN_GITHUB_SHA", None)
            else:
                os.environ["ROUTER_VPN_GITHUB_SHA"] = old

    def test_production_and_launcher_use_product_wrapper(self):
        server_dir = HERE.parent
        compose = (server_dir / "portainer-current.yaml").read_text(encoding="utf-8")
        launcher = (HERE / "run-setup-center.sh").read_text(encoding="utf-8")
        marker = "/src/server/scripts/setup-center-product-server.py"
        self.assertIn(marker, compose)
        self.assertIn(marker, launcher)
        self.assertNotIn("build:", compose)
        self.assertIn("/opt/router-vpn:/opt/router-vpn:ro", compose)


if __name__ == "__main__":
    unittest.main()
