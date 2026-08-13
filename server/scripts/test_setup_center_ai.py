#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = HERE / "setup-center-ai-server.py"
spec = importlib.util.spec_from_file_location("setup_center_ai_server_test", MODULE)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class SetupCenterAIIntegrationTests(unittest.TestCase):
    def test_wrapper_preserves_core_handler_and_server(self):
        self.assertTrue(issubclass(mod.Handler, mod._core.Handler))
        self.assertTrue(issubclass(mod.Server, mod._core.Server))

    def test_ai_ui_is_same_origin_and_contains_no_provider_secret(self):
        panel = mod.AI_PANEL
        self.assertIn("/api/ai-help/status", panel)
        self.assertIn("/api/ai-help", panel)
        self.assertIn("credentials:'same-origin'", panel)
        self.assertIn("maxlength=\"4000\"", panel)
        self.assertNotIn("Authorization", panel)
        self.assertNotIn("openai-api.key", panel)
        self.assertNotIn("sk-", panel)
        self.assertNotIn("api.openai.com", panel)

    def test_ai_panel_is_injected_through_existing_setup_center_ui(self):
        handler = object.__new__(mod.Handler)
        rendered = handler._inject_admin_ui("<html><body><main>Setup</main></body></html>")
        self.assertIn("id=\"rvpn-ai-help\"", rendered)
        self.assertIn("Router VPN Setup Center", rendered)
        self.assertEqual(rendered.count("id=\"rvpn-ai-help\""), 1)
        rendered_again = handler._inject_admin_ui(rendered)
        self.assertEqual(rendered_again.count("id=\"rvpn-ai-help\""), 1)

    def test_routes_require_existing_setup_center_auth_boundary(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn('if urlparse(self.path).path == "/api/ai-help/status":', source)
        self.assertIn('if urlparse(self.path).path != "/api/ai-help":', source)
        self.assertGreaterEqual(source.count("self._require_auth()"), 2)
        self.assertIn("16 * 1024", source)
        self.assertIn("Transfer-Encoding", source)
        self.assertIn("Never return provider/key internals", source)

    def test_server_provider_is_disabled_until_model_and_private_key_are_configured(self):
        old = os.environ.pop("ROUTER_VPN_AI_MODEL", None)
        try:
            provider = mod._ai.AIHelpProvider(model="", key_file="/definitely/missing")
            status = provider.status()
            self.assertFalse(status["available"])
            self.assertEqual(status["provider"], "openai")
        finally:
            if old is not None:
                os.environ["ROUTER_VPN_AI_MODEL"] = old


if __name__ == "__main__":
    unittest.main()
