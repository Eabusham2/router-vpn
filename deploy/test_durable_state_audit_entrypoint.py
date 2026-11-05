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
NODE_STORE = "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java"
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
        self.sources = {path: (ROOT / path).read_text(encoding="utf-8") for path in (ANDROID, NODE_STORE)}
        self.source = self.sources[ANDROID]
        self.functions = [
            node
            for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name in ("require", "forbid", "require_order")
        ]
        self.checks = [
            node
            for node in self.tree.body
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in ("require", "forbid", "require_order")
            and node.value.args
            and isinstance(node.value.args[0], ast.Constant)
            and node.value.args[0].value in (ANDROID, NODE_STORE)
        ]
        self.assertEqual({node.name for node in self.functions}, {"require", "forbid", "require_order"})
        self.assertEqual(
            {node.value.func.id for node in self.checks}, {"require", "forbid", "require_order"}
        )

    def audit_source(self, source: str, path: str = ANDROID) -> list[str]:
        sources = dict(self.sources, **{path: source})
        def read(path: str) -> str:
            self.assertIn(path, sources)
            return sources[path]

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
            ("nodes.applyProfileBundle(update.id,update.original,updatedBundle)", "nodes.importBundle(updatedBundle)"),
            ("nodes.restoreProfileBundle(update.id,update.original,update.updated)", "nodes.importBundle(update.original)"),
            ("nodes.restoreProfileSelection(originalSelection,attemptedSelections)", "nodes.restoreSelection(originalSelection)"),
        ):
            with self.subTest(removed=before):
                self.assertIn(before, self.source)
                errors = self.audit_source(self.source.replace(before, after))
                self.assertTrue(any(before in error for error in errors), errors)

    def test_native_store_exact_source_and_selection_guards_are_required(self):
        source = self.sources[NODE_STORE]
        for before, after in (
            ("synchronized (STORE_LOCK)", "if (true)"),
            ("if (!java.util.Arrays.equals(snapshotOptional(nodeFile(id)), original))", "if (false)"),
            ("if (!id.equals(deriveId(new JSONObject(new String(updated, StandardCharsets.UTF_8)), updated)))", "if (false)"),
            ("if (!java.util.Arrays.equals(current, published))", "if (false)"),
            ("if (!owned) throw", "if (false) throw"),
            ("left.id.equals(right.id) && java.util.Arrays.equals(left.activeBundle, right.activeBundle)", "left.id.equals(right.id)"),
        ):
            with self.subTest(removed=before):
                self.assertIn(before, source)
                self.assertTrue(self.audit_source(source.replace(before, after), NODE_STORE))

    def test_ownership_checks_cannot_move_after_their_publication(self):
        for path, start, end, write, anchor in (
            (NODE_STORE, "synchronized Node applyProfileBundle(", "synchronized List<Node> list()",
             "return importBundle(updated);", "if (!java.util.Arrays.equals(snapshotOptional(nodeFile(id)), original))"),
            (NODE_STORE, "synchronized void restoreProfileBundle(", "synchronized void restoreProfileSelection(",
             "atomicWrite(target, original);", "byte[] current = snapshotOptional(target);"),
            (NODE_STORE, "synchronized void restoreProfileSelection(", "private static boolean sameSelection(",
             "rollbackSelection(activeBundleFile(), original.activeBundle, original.id);", "SelectionSnapshot current = snapshotSelection();"),
            (ANDROID, "synchronized Record load(String id)", "synchronized void delete(String id)",
             "nodes.restoreProfileSelection(originalSelection,attemptedSelections)", "nodes.restoreProfileBundle(update.id,update.original,update.updated)"),
        ):
            with self.subTest(publication=write):
                source = self.sources[path]
                first = source.index(start); last = source.index(end, first)
                scope = source[first:last]
                self.assertEqual(scope.count(write), 1)
                changed = scope.replace(write, "").replace(anchor, write + "\n" + anchor, 1)
                errors = self.audit_source(source[:first] + changed + source[last:], path)
                self.assertTrue(any("misordered" in error for error in errors), errors)

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
