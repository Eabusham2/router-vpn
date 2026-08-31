#!/usr/bin/env python3
"""Focused regression tests for recovered-native-ui-contract-audit.py."""

from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path

AUDIT = runpy.run_path(str(Path(__file__).with_name("recovered-native-ui-contract-audit.py")))
contains_any = AUDIT["contains_any"]
entrypoints = AUDIT["entrypoints"]
require_group = AUDIT["require_group"]
platforms = AUDIT["PLATFORMS"]


class RecoveredNativeUiContractTests(unittest.TestCase):
    def test_contains_any_is_case_insensitive(self) -> None:
        self.assertTrue(contains_any("SMART AUTO", ("smart auto",)))
        self.assertTrue(contains_any("KillSwitch", ("killswitch",)))
        self.assertFalse(contains_any("Disconnected", ("fastest",)))

    def test_entrypoints_are_exact_filename_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "ProductActivity.java"
            decoy = root / "OldProductActivity.java"
            real.write_text("native", encoding="utf-8")
            decoy.write_text("legacy", encoding="utf-8")
            selected = entrypoints([real, decoy], ("productactivity.java",))
            self.assertEqual([real], selected)

    def test_missing_group_fails_closed(self) -> None:
        failures: list[str] = []
        require_group(failures, "Fixture", "Connect DNS", "SMART AUTO", ("smart auto",))
        self.assertEqual(
            ["Fixture: missing recovered UI contract: SMART AUTO"],
            failures,
        )

    def test_any_real_alias_satisfies_group(self) -> None:
        failures: list[str] = []
        require_group(
            failures,
            "Fixture",
            "current path RTT",
            "live latency",
            ("latency", "rtt"),
        )
        self.assertEqual([], failures)

    def test_mobile_platform_roots_are_native_projects(self) -> None:
        self.assertEqual(("android",), platforms["Android"][0])
        self.assertEqual(("ios/RouterVPN",), platforms["iOS/iPadOS"][0])

    def test_mobile_entrypoints_are_real_native_sources(self) -> None:
        self.assertEqual(
            ("productactivity.java", "androidmanifest.xml"),
            platforms["Android"][1],
        )
        self.assertEqual(
            ("iosunifiedproductview.swift", "packettunnelprovider.swift"),
            platforms["iOS/iPadOS"][1],
        )


if __name__ == "__main__":
    unittest.main()
