#!/usr/bin/env python3
"""Check that first-launch diagnostics preserve the actual launch contract."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("first_ui_diagnostic", ROOT / "deploy/diagnose_windows_ui_startup.py")
DIAGNOSTIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTIC)


class FirstLaunchDiagnostic(unittest.TestCase):
    def test_instrumentation_only_adds_fixed_timing_lines(self):
        copies = DIAGNOSTIC.instrumented_scripts()
        self.assertEqual(len(copies), 3)
        stages = set()
        for name, raw in copies.items():
            lines = raw.splitlines(keepends=True)
            original = (ROOT / name).read_bytes()
            kept = []
            for line in lines:
                if DIAGNOSTIC.PREFIX.encode() in line:
                    self.assertTrue(line.lstrip().startswith(b"[Console]::Error.WriteLine('"))
                    self.assertTrue(line.rstrip().endswith(b"[DateTime]::UtcNow.Ticks)"))
                    stages.add(line.decode().split(DIAGNOSTIC.PREFIX + " ", 1)[1].split(" ticks=", 1)[0])
                else:
                    kept.append(line)
            self.assertEqual(b"".join(kept), original)
        self.assertTrue({"app-script-entered", "tray-script-entered", "module-entered", "initialize-entered",
                         "framework-http-begin", "framework-http-complete", "transport-compile-begin",
                         "transport-compile-complete", "pipe-connect-begin", "pipe-connect-complete"}.issubset(stages))

    def test_changed_initializer_fails_instead_of_tracing_another_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("App.ps1", "Tray.ps1", "ControllerTransport.psm1"):
                relative = "client/RouterVPN-Windows-" + name
                target = root / relative
                target.parent.mkdir(exist_ok=True)
                raw = (ROOT / relative).read_bytes()
                if name.endswith("psm1"):
                    raw = raw.replace(b"        Add-Type @Compile", b"        Add-Type @DifferentCompile")
                target.write_bytes(raw)
            with patch.object(DIAGNOSTIC, "ROOT", root), self.assertRaisesRegex(ValueError, "exact production boundary"):
                DIAGNOSTIC.instrumented_scripts()

    def test_marker_cannot_include_arguments_or_dynamic_input(self):
        for value in ("", "private path", "stage'", "stage\n", "$env:PATH", "123"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                DIAGNOSTIC.marker(value)


if __name__ == "__main__":
    unittest.main()
