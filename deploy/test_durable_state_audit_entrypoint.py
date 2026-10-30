#!/usr/bin/env python3
"""Exercise the public audit entrypoint and its actual Android source guards.

The source-guard negatives below evaluate the real contract's require/forbid
calls against shipping Java with deliberate defects. They do not claim Android
device execution; the full audit still runs its unchanged platform contracts.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "deploy/durable-state-transaction-audit.py"
CONTRACT = ROOT / "deploy/durable-state-transaction-audit-v1.py"
ANDROID = "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java"
ANDROID_TEST = "android/test_android_connection_profiles_contract.py"


def run_entrypoint() -> None:
    exec(
        compile(ENTRYPOINT.read_text(encoding="utf-8"), str(ENTRYPOINT), "exec"),
        {"__name__": "__main__", "__file__": str(ENTRYPOINT)},
    )


class DurableStateEntrypointTests(unittest.TestCase):
    def test_public_entrypoint_reaches_the_current_complete_contract(self):
        # Restoring the old wrapper fails before delegation: its Android,
        # MTU and native-child textual substitutions no longer match v1.
        with mock.patch("runpy.run_path") as run:
            run_entrypoint()
        run.assert_called_once_with(str(CONTRACT), run_name="__main__")

    def test_contract_failure_is_not_hidden_by_entrypoint(self):
        with mock.patch("runpy.run_path", side_effect=SystemExit(23)):
            with self.assertRaises(SystemExit) as result:
                run_entrypoint()
        self.assertEqual(result.exception.code, 23)


class AndroidDurabilitySourceTests(unittest.TestCase):
    def setUp(self):
        self.tree = ast.parse(CONTRACT.read_text(encoding="utf-8"))
        self.source = (ROOT / ANDROID).read_text(encoding="utf-8")
        self.functions = [
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name in ("require", "forbid")
        ]
        self.checks = [
            node
            for node in self.tree.body
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in ("require", "forbid")
            and node.value.args
            and isinstance(node.value.args[0], ast.Constant)
            and node.value.args[0].value == ANDROID
        ]
        self.assertEqual({node.name for node in self.functions}, {"require", "forbid"})
        self.assertEqual(
            {node.value.func.id for node in self.checks}, {"require", "forbid"}
        )

    def audit_source(self, source: str) -> list[str]:
        def read(path: str) -> str:
            self.assertEqual(path, ANDROID)
            return source

        scope = {"text": read, "errors": []}
        module = ast.Module(body=self.functions + self.checks, type_ignores=[])
        exec(compile(module, str(CONTRACT), "exec"), scope)
        return scope["errors"]

    def test_current_profile_migration_passes_actual_source_guards(self):
        self.assertEqual(self.audit_source(self.source), [])

    def test_private_read_write_cleanup_and_rollback_bypasses_are_rejected(self):
        for before, after in (
            ("AndroidPrivateFileStore.read(source, MAX_STORE)", "unsafeRead(source)"),
            ("AndroidPrivateFileStore.write(file, raw, MAX_STORE)", "unsafeWrite(file, raw)"),
            ("AndroidPrivateFileStore.remove(legacyFile, MAX_STORE)", "unsafeRemove(legacyFile)"),
            ("nodes.restoreSelection(originalSelection)", "forgetSelection()"),
            ("nodes.importBundle(originalBundle)", "forgetRollback()"),
        ):
            with self.subTest(removed=before):
                self.assertIn(before, self.source)
                errors = self.audit_source(self.source.replace(before, after))
                self.assertTrue(any(before in error for error in errors), errors)

    def test_direct_filesystem_writer_is_rejected(self):
        broken = self.source + "\nclass UnsafeWriter { FileOutputStream output; }\n"
        errors = self.audit_source(broken)
        self.assertTrue(any("FileOutputStream" in error for error in errors), errors)

    def test_full_gate_keeps_the_current_android_profile_contract(self):
        tests = [
            node.args[0].value
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "run_test"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
        ]
        self.assertEqual(tests.count(ANDROID_TEST), 1)
        self.assertNotIn(
            "android/test_android_connection_profile_store_contract.py", tests
        )


if __name__ == "__main__":
    unittest.main()
