#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from profile_id import validate_profile_id  # noqa: E402

VALID = ["router", "home-1", "node_2", "a.b-c_d"]
INVALID = ["", ".", "..", "a..b", "../x", "x/..", "a/b", r"a\b", "bad space", "x$y", "a" * 65]
CRITICAL_SHELL = ["run-mode.sh", "run-all.sh", "run-max.sh", "run-combined.sh", "run-xhttp.sh", "check-mode.sh", "check-combined.sh"]


class ProfileIdSafety(unittest.TestCase):
    def shell_validate(self, value: str) -> subprocess.CompletedProcess[str]:
        script = f'. {str(HERE / "profile-id.sh")!r}; homevpn_profile_id'
        env = os.environ.copy()
        env["HOMEVPN_PROFILE_ID"] = value
        return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True, check=False)

    def test_valid_python_and_shell(self) -> None:
        for value in VALID:
            with self.subTest(value=value):
                self.assertEqual(validate_profile_id(value), value)
                proc = self.shell_validate(value)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(proc.stdout.strip(), value)

    def test_invalid_python_and_shell_fail_closed(self) -> None:
        for value in INVALID:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_profile_id(value, default="")
                proc = self.shell_validate(value)
                self.assertNotEqual(proc.returncode, 0, f"unsafe shell profile id accepted: {value!r}")

    def test_runtime_entrypoints_use_shared_validator(self) -> None:
        for name in CRITICAL_SHELL:
            with self.subTest(name=name):
                text = (HERE / name).read_text(encoding="utf-8")
                self.assertIn("profile-id.sh", text)
                self.assertIn("homevpn_profile_id", text)
                self.assertNotIn("tr -cd 'A-Za-z0-9_.-'", text)


if __name__ == "__main__":
    unittest.main()
