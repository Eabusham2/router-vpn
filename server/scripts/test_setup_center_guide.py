#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("setup_center_guide_test", HERE / "setup_center_guide.py")
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class SetupCenterGuideTests(unittest.TestCase):
    def setUp(self):
        self.guide = mod.GUIDE_PANEL

    def test_first_run_persistence_completion_resume_and_independent_access(self):
        for marker in (
            'id="rvpn-guide-open"',
            'id="rvpn-full-guide"',
            "routervpn.setup-guide.v1",
            "localStorage.getItem(KEY)",
            "localStorage.setItem(KEY",
            "if(!state.completed)setTimeout(show,250)",
            "Close & resume later",
            "Restart guide",
            "Finish setup guide",
            "state.completed=true",
        ):
            self.assertIn(marker, self.guide)

    def test_zero_knowledge_install_from_zero_and_linking_is_separate_data_operation(self):
        for marker in (
            "What gets installed — and what does not",
            "Installing an app does not link it to your home",
            "install the app once and can add more routers without reinstalling",
            "Deploy the home node from zero",
            "server/portainer-current.yaml",
            "ASUS router forwarding",
            "Link after install",
            "one-time LAN pairing",
            "router-vpn-bundle.json",
        ):
            self.assertIn(marker, self.guide)

    def test_method_hierarchy_is_explicit_and_capability_honest(self):
        ordered = [
            "1 — Simple / native method",
            "2 — Router VPN app",
            "3 — Universal third-party",
            "4 — Manual / custom",
        ]
        positions = [self.guide.index(x) for x in ordered]
        self.assertEqual(positions, sorted(positions))
        for marker in (
            "Use only when the generated format is verified with the named external app",
            "Unavailable or unproven lanes must stay grey/unavailable",
            "Manual Connect still requires health proof and rollback on failure",
        ):
            self.assertIn(marker, self.guide)

    def test_guide_covers_daily_connection_dns_lan_killswitch_multihop_forwarding_and_recovery(self):
        for marker in (
            "AUTO",
            "SMART AUTO",
            "WireGuard/AmneziaWG",
            "Home AdGuard",
            "fastest measured home-exit public DNS",
            "home-LAN access",
            "MTU/Jumbo",
            "kill-switch policy",
            "multihop",
            "Connected Clients",
            "public-exit proof",
            "Emergency Stop/rollback",
            "boot/always, connected, reconnecting, manual disconnect and failure states",
        ):
            self.assertIn(marker, self.guide)

    def test_safety_and_distribution_guidance_are_explicit(self):
        for marker in (
            "Never WAN-expose Setup Center 8786",
            "SOCKS5 1080",
            "loopback OverTLS 14444",
            "Direct public IP works",
            "DDNS is optional",
            "Open Anyway",
            "Never globally disable Gatekeeper",
            "Signed/notarized distribution remains the long-term target",
        ):
            self.assertIn(marker, self.guide)


if __name__ == "__main__":
    unittest.main()
