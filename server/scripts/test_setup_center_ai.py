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
        for m in ("Authorization","openai-api.key","ai-api.key","ai-base-url","sk-","api.openai.com"): self.assertNotIn(m,p)
    def test_ai_guide_and_device_ux_each_injected_once(self):
        h=object.__new__(mod.Handler)
        base='<html><body><div id="tabs"></div><div id="wizard" class="overlay"></div></body></html>'
        rendered=h._inject_product_ui(base)
        for marker in ('id="routerVpnServerAdminScript"','id="rvpn-ai-help"','id="rvpn-guide-open"','id="rvpn-device-download"'):
            self.assertIn(marker,rendered); self.assertEqual(rendered.count(marker),1)
        self.assertIn("routervpn.setup-guide.v1",rendered); self.assertIn("Download for this device",rendered)
        again=h._inject_product_ui(rendered)
        for marker in ('id="routerVpnServerAdminScript"','id="rvpn-ai-help"','id="rvpn-guide-open"','id="rvpn-device-download"'): self.assertEqual(again.count(marker),1)
    def test_routes_reuse_auth_boundary(self):
        s=MODULE.read_text(encoding="utf-8")
        self.assertIn('urlparse(self.path).path == "/api/ai-help/status"',s)
        self.assertIn('urlparse(self.path).path != "/api/ai-help"',s)
        self.assertGreaterEqual(s.count("self._require_auth()"),2)
        self.assertIn("16 * 1024",s)
        self.assertIn("Transfer-Encoding",s)
        # The browser gets only AIHelpProvider.status()/ask() results. Private
        # provider configuration stays encapsulated in the provider instance;
        # Setup Center must never read or return its key/base-url file fields.
        for forbidden in ("key_file", "provider_file", "model_file", "base_url_file", "DEFAULT_KEY_FILE", "DEFAULT_BASE_URL_FILE"):
            self.assertNotIn("self.server.ai_provider." + forbidden, s)
        self.assertIn("self.server.ai_provider.status()", s)
        self.assertIn("self.server.ai_provider.ask(", s)
    def test_real_setup_html_path_uses_product_injector(self):
        s=MODULE.read_text(encoding="utf-8"); self.assertIn("def _serve_setup_html",s); self.assertIn("self._inject_product_ui",s); self.assertIn("_core._inject_admin_ui(text)",s)
    def test_disabled_until_private_config(self):
        old=os.environ.pop("ROUTER_VPN_AI_MODEL",None)
        try:
            provider=mod._ai.AIHelpProvider(model="",key_file="/definitely/missing"); self.assertFalse(provider.status()["available"])
        finally:
            if old is not None: os.environ["ROUTER_VPN_AI_MODEL"]=old

if __name__=="__main__": unittest.main()
