#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("setup_center_ux_patch_test", HERE / "setup_center_ux_patch.py")
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class SetupCenterUXPatchTests(unittest.TestCase):
    def setUp(self): self.patch = mod.UX_PATCH

    def test_download_for_this_device_uses_existing_published_links(self):
        for marker in (
            'id="rvpn-device-download"',
            "Download for this device",
            "document.querySelectorAll('a[href]')",
            "family='android'",
            "family='ios'",
            "family='windows'",
            "family='macos'",
            "family='linux'",
            "arm64|aarch64",
            "getHighEntropyValues",
            "architecture",
            "CPU architecture is not safely exposed",
            "will not guess the wrong architecture",
            "native|router vpn app|installer",
        ):
            self.assertIn(marker, self.patch)
        # Progressive enhancement chooses from already-published same-origin
        # Setup Center anchors; it does not invent a floating external URL.
        self.assertNotIn("api.github.com", self.patch)
        self.assertNotIn("github.com/", self.patch)
        self.assertNotIn("window.open('http", self.patch)

    def test_retained_package_can_be_retried_or_deleted_for_30_minutes(self):
        for marker in (
            "function terminal(j){return ['failed','cancelled','expired']",
            "function retained(j)",
            "Temporary package deletes in",
            "Download again",
            "Delete now",
            "downloadExisting(active)",
            "retained_until",
            "expires_in_seconds",
            "same 30-minute retained job policy",
            "direct_href:safeSameOriginPath(lastRequest&&lastRequest.directHref,'/')",
            "lastRequest={name:active.name,directHref:direct||''}",
        ):
            self.assertIn(marker, self.patch)
        # A completed or interrupted download remains a retained package rather
        # than being converted into a new build request by the Retry button.
        self.assertIn("if(retained(active)){downloadExisting(active);return}", self.patch)
        self.assertIn("Deleting temporary package now", self.patch)

    def test_no_servers_found_keeps_requested_methods_open_and_actionable(self):
        for marker in (
            "'socks5'",
            "'overtls'",
            "'over tls'",
            "'shadowsocks'",
            "text.includes('no servers found')",
            "container.open=true",
            "routerVpnNoServers",
            "The method stays open",
            "will not substitute a different protocol and call it ready",
        ):
            self.assertIn(marker, self.patch)


if __name__ == "__main__": unittest.main()
