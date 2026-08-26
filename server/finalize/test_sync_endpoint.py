#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("sync-endpoint.py")
spec = importlib.util.spec_from_file_location("router_vpn_sync_endpoint", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
assert spec.loader is not None
spec.loader.exec_module(module)


class EndpointSyncTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="router-vpn-sync-endpoint-")
        self.base = Path(self.temp.name)
        self.wg = self.base / "client-bundle" / "generated" / "wg" / "wg.conf"
        self.awg = self.base / "client-bundle" / "generated" / "awg2-fast" / "awg.conf"
        self.routers_path = self.base / "client-bundle" / "routers.json"
        for path in (self.wg, self.awg, self.routers_path):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.wg.write_text("[Peer]\nEndpoint = old.example:51820\n")
        self.awg.write_text("[Peer]\nEndpoint = old.example:51822\n")
        original = {
            "schema_version": 4,
            "selected_id": "home",
            "profiles": [
                {"id": "home", "node_kind": "router-vpn", "endpoint": "old.example"},
                {"id": "other-router", "node_kind": "router-vpn", "endpoint": "other.example"},
                {
                    "id": "external-exit",
                    "node_kind": "external",
                    "endpoint": "exit.example",
                    "external": {"shadowsocks": {"server": "ss.example", "port": 8388}},
                },
            ],
        }
        self.routers_path.write_text(json.dumps(original) + "\n")
        self.before = {path: path.read_bytes() for path in (self.wg, self.awg, self.routers_path)}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_owned_endpoint_update_is_atomic_private_and_narrow(self) -> None:
        patched = module.sync(self.base, "203.0.113.9")
        self.assertEqual(patched, 2)
        self.assertIn("Endpoint = 203.0.113.9:51820", self.wg.read_text())
        self.assertIn("Endpoint = 203.0.113.9:51822", self.awg.read_text())
        updated = json.loads(self.routers_path.read_text())
        profiles = {profile["id"]: profile for profile in updated["profiles"]}
        self.assertEqual(profiles["home"]["endpoint"], "203.0.113.9")
        self.assertEqual(profiles["other-router"]["endpoint"], "other.example")
        self.assertEqual(profiles["external-exit"]["endpoint"], "exit.example")
        self.assertEqual(profiles["external-exit"]["external"]["shadowsocks"]["server"], "ss.example")
        for path in (self.wg, self.awg, self.routers_path):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_legacy_broad_mode_is_hardened_before_read(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX mode contract")
        os.chmod(self.wg, 0o644)
        before = self.wg.read_bytes()
        self.assertEqual(module.read_owned_file(self.wg), before)
        self.assertEqual(self.wg.stat().st_mode & 0o777, 0o600)

    def test_late_adoption_failure_restores_every_changed_file(self) -> None:
        real_replace = os.replace
        calls = 0
        failed = False

        def fail_second_adoption(src, dst):
            nonlocal calls, failed
            calls += 1
            if calls == 2 and not failed:
                failed = True
                raise OSError("injected adoption failure")
            return real_replace(src, dst)

        with mock.patch.object(module.os, "replace", side_effect=fail_second_adoption):
            with self.assertRaisesRegex(RuntimeError, "prior files were restored"):
                module.sync(self.base, "203.0.113.9")

        for path, before in self.before.items():
            self.assertEqual(path.read_bytes(), before, str(path))

    def test_symlink_owned_target_is_rejected_before_mutation(self) -> None:
        real = self.wg.with_name("real.conf")
        self.wg.replace(real)
        self.wg.symlink_to(real)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            module.sync(self.base, "203.0.113.9")
        self.assertEqual(self.awg.read_bytes(), self.before[self.awg])
        self.assertEqual(self.routers_path.read_bytes(), self.before[self.routers_path])

    def test_symlink_owned_parent_is_rejected_before_mutation(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX symlink parent contract")
        real_dir = self.wg.parent.with_name("wg-real")
        self.wg.parent.replace(real_dir)
        self.wg.parent.symlink_to(real_dir, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            module.sync(self.base, "203.0.113.9")
        self.assertEqual((real_dir / "wg.conf").read_bytes(), self.before[self.wg])
        self.assertEqual(self.awg.read_bytes(), self.before[self.awg])
        self.assertEqual(self.routers_path.read_bytes(), self.before[self.routers_path])

    def test_nested_symlink_owned_ancestor_is_rejected_before_mutation(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX symlink ancestor contract")
        root = self.base.parent
        real_base = root / (self.base.name + "-real")
        self.base.rename(real_base)
        self.base.symlink_to(real_base, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "path component"):
            module.sync(self.base, "203.0.113.9")
        self.assertEqual((real_base / "client-bundle/generated/wg/wg.conf").read_bytes(), self.before[self.wg])
        # Restore lexical base for TemporaryDirectory cleanup.
        self.base.unlink()
        real_base.rename(self.base)

    def test_owned_file_identity_change_during_open_is_rejected(self) -> None:
        real_fstat = module.os.fstat
        replacement = self.wg.with_name("replacement.conf")
        replacement.write_text("[Peer]\nEndpoint = attacker.example:51820\n")
        changed = False

        def swap_after_open(fd):
            nonlocal changed
            info = real_fstat(fd)
            if not changed:
                changed = True
                os.replace(replacement, self.wg)
            return info

        with mock.patch.object(module.os, "fstat", side_effect=swap_after_open):
            with self.assertRaisesRegex(RuntimeError, "changed during open"):
                module.read_owned_file(self.wg)

    def test_owned_file_identity_change_during_read_is_rejected(self) -> None:
        replacement = self.wg.with_name("replacement.conf")
        replacement.write_text("[Peer]\nEndpoint = newer.example:51820\n")
        real_read = module.os.read
        changed = False

        def swap_after_bytes(fd, size):
            nonlocal changed
            chunk = real_read(fd, size)
            if chunk and not changed:
                changed = True
                os.replace(replacement, self.wg)
            return chunk

        with mock.patch.object(module.os, "read", side_effect=swap_after_bytes):
            with self.assertRaisesRegex(RuntimeError, "changed during read"):
                module.read_owned_file(self.wg)
        self.assertIn("newer.example", self.wg.read_text())

    def test_duplicate_owned_home_profiles_fail_closed(self) -> None:
        data = json.loads(self.routers_path.read_text())
        data["profiles"].append({"id": "home", "node_kind": "router-vpn", "endpoint": "duplicate.example"})
        self.routers_path.write_text(json.dumps(data) + "\n")
        with self.assertRaisesRegex(RuntimeError, "multiple owned home"):
            module.sync(self.base, "203.0.113.9")
        self.assertEqual(self.wg.read_bytes(), self.before[self.wg])
        self.assertEqual(self.awg.read_bytes(), self.before[self.awg])


if __name__ == "__main__":
    unittest.main(verbosity=2)
