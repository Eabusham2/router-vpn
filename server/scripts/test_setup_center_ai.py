#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, os, sys, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent; MODULE=HERE/"setup-center-ai-server.py"; spec=importlib.util.spec_from_file_location("setup_center_ai_server_test",MODULE); mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; sys.modules[spec.name]=mod; spec.loader.exec_module(mod)

class SetupCenterAIIntegrationTests(unittest.TestCase):
    def test_wrapper_preserves_core(self):
        self.assertTrue(issubclass(mod.Handler,mod._core.Handler)); self.assertTrue(issubclass(mod.Server,mod._core.Server))
    def test_ai_ui_same_origin_no_secret(self):
        p=mod.AI_PANEL
        for m in ("/api/ai-help/status","/api/ai-help","credentials:'same-origin'",'maxlength="4000"'): self.assertIn(m,p)
        for m in ("Authorization","openai-api.key","sk-","api.openai.com"): self.assertNotIn(m,p)
    def test_ai_guide_and_device_ux_each_injected_once(self):
        h=object.__new__(mod.Handler); rendered=h._inject_admin_ui("<html><body><main>Setup</main></body></html>")
        for marker in ('id="rvpn-ai-help"','id="rvpn-guide-open"','id="rvpn-device-download"'):
            self.assertIn(marker,rendered); self.assertEqual(rendered.count(marker),1)
        self.assertIn("Router VPN Setup Center",rendered); self.assertIn("routervpn.setup-guide.v1",rendered); self.assertIn("Download for this device",rendered)
        again=h._inject_admin_ui(rendered)
        for marker in ('id="rvpn-ai-help"','id="rvpn-guide-open"','id="rvpn-device-download"'): self.assertEqual(again.count(marker),1)
    def test_routes_reuse_auth_boundary(self):
        s=MODULE.read_text(encoding="utf-8"); self.assertIn('urlparse(self.path).path == "/api/ai-help/status"',s); self.assertIn('urlparse(self.path).path != "/api/ai-help"',s); self.assertGreaterEqual(s.count("self._require_auth()"),2); self.assertIn("16 * 1024",s); self.assertIn("Transfer-Encoding",s); self.assertIn("Never return provider/key internals",s)
    def test_disabled_until_private_config(self):
        old=os.environ.pop("ROUTER_VPN_AI_MODEL",None)
        try:
            provider=mod._ai.AIHelpProvider(model="",key_file="/definitely/missing"); self.assertFalse(provider.status()["available"])
        finally:
            if old is not None: os.environ["ROUTER_VPN_AI_MODEL"]=old

if __name__=="__main__": unittest.main()
