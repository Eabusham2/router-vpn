#!/usr/bin/env python3
"""Focused regression tests for recovered-map-first-ui-contract-audit.py."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

AUDIT_PATH = Path(__file__).with_name("recovered-map-first-ui-contract-audit.py")
SPEC = importlib.util.spec_from_file_location("recovered_map_first_ui_contract_audit", AUDIT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {AUDIT_PATH}")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class RecoveredMapFirstAuditTests(unittest.TestCase):
    def test_contains_any_is_case_insensitive(self) -> None:
        self.assertTrue(AUDIT.contains_any("SMART AUTO", ("smart auto",)))
        self.assertTrue(AUDIT.contains_any("KillSwitch", ("killswitch",)))
        self.assertFalse(AUDIT.contains_any("Disconnected", ("fastest",)))

    def test_shipping_closure_follows_named_sources_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            launcher = root / "launcher.sh"
            included = root / "unified.inc"
            orphan = root / "orphan.inc"
            launcher.write_text('source "unified.inc"\n', encoding="utf-8")
            included.write_text("SMART AUTO\nConnect\n", encoding="utf-8")
            orphan.write_text("CUSTOM\n", encoding="utf-8")
            platform = AUDIT.Platform(
                "Fixture",
                (str(root),),
                ("launcher.sh",),
                ("native",),
            )
            closure, scope = AUDIT.shipping_closure(platform, [launcher, included, orphan])
            self.assertEqual({launcher, included}, set(closure))
            self.assertIn("SMART AUTO", scope)
            self.assertNotIn("CUSTOM", scope)

    def test_orphan_source_cannot_satisfy_shipping_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            launcher = root / "launcher.sh"
            orphan = root / "feature.inc"
            launcher.write_text("native shell\n", encoding="utf-8")
            orphan.write_text("SMART AUTO\n", encoding="utf-8")
            platform = AUDIT.Platform(
                "Fixture",
                (str(root),),
                ("launcher.sh",),
                ("native",),
            )
            _, scope = AUDIT.shipping_closure(platform, [launcher, orphan])
            failures: list[str] = []
            AUDIT.require_group(failures, platform, scope, "SMART AUTO", ("smart auto",))
            self.assertEqual(
                ["Fixture: shipping closure missing SMART AUTO"],
                failures,
            )

    def test_retired_product_patterns_are_bounded_words(self) -> None:
        labels = {label for label, _ in AUDIT.RETIRED_SHIPPING_PATTERNS}
        self.assertEqual(
            {"Electron", "WebView final product", "WSL dataplane/UI", "PWA final product"},
            labels,
        )
        for _, pattern in AUDIT.RETIRED_SHIPPING_PATTERNS:
            self.assertIsNone(pattern.search("browserless native implementation"))


if __name__ == "__main__":
    unittest.main()
