#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from profile_id import validate_profile_id  # noqa: E402

VALID = ["router", "home-1", "node_2", "a.b-c_d"]
INVALID = ["", ".", "..", "a..b", "../x", "x/..", "a/b", r"a\b", "bad space", "x$y", "%2e%2e", "%2fetc", "%5c..", "%252e%252e", "a" * 65]
CRITICAL_SHELL = ["run-mode.sh", "run-all.sh", "run-max.sh", "run-combined.sh", "run-xhttp.sh", "check-mode.sh", "check-combined.sh"]
PYTHON_CONSUMERS = ["dns-policy.py", "mtu-policy.py", "kill-switch.py", "multihop.py", "orchestrate.py"]


def load_script(name: str):
    path = HERE / name
    module_name = "profile_safety_" + name.replace("-", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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

    def test_python_consumers_use_shared_validator(self) -> None:
        for name in PYTHON_CONSUMERS:
            with self.subTest(name=name):
                text = (HERE / name).read_text(encoding="utf-8")
                self.assertIn("from profile_id import", text)

    def test_mtu_consumer_rejects_traversal(self) -> None:
        mtu = load_script("mtu-policy.py")
        old = os.environ.get("HOMEVPN_PROFILE_ID")
        try:
            os.environ["HOMEVPN_PROFILE_ID"] = ".."
            with self.assertRaises(SystemExit):
                mtu.profile_id()
        finally:
            if old is None:
                os.environ.pop("HOMEVPN_PROFILE_ID", None)
            else:
                os.environ["HOMEVPN_PROFILE_ID"] = old

    def test_kill_switch_consumer_rejects_traversal(self) -> None:
        kill_switch = load_script("kill-switch.py")
        with self.assertRaises(RuntimeError):
            kill_switch.validate_profile_id("..", "test profile")
        with self.assertRaises(RuntimeError):
            kill_switch.validate_profile_id("a/../b", "test profile")

    def test_multihop_consumer_rejects_traversal(self) -> None:
        multihop = load_script("multihop.py")
        with self.assertRaises(RuntimeError):
            multihop.valid_id("..", "entry id")
        with self.assertRaises(RuntimeError):
            multihop.valid_id(r"a\b", "entry id")

    def test_dns_policy_rejects_traversal_before_profile_lookup(self) -> None:
        env = os.environ.copy()
        env["HOMEVPN_PROFILE_ID"] = "../escape"
        proc = subprocess.run([sys.executable, str(HERE / "dns-policy.py"), "json"], env=env, text=True, capture_output=True, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("invalid Router VPN profile id", proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main()
