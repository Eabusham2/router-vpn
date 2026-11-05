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
PRODUCT = "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java"
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
        self.sources = {path: (ROOT / path).read_text(encoding="utf-8") for path in (ANDROID, NODE_STORE, PRODUCT)}
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
            and node.value.args[0].value in (ANDROID, NODE_STORE, PRODUCT)
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

    def test_preference_owner_and_shared_monitor_bypasses_are_rejected(self):
        for before, after in (
            ("synchronized(prefs()) {\n        try{", "{\n        try{"),
            ("if(!preferenceUpdate.original.equals(snapshotPreferences()))", "if(false)"),
            ("if(!ownsPreferences(preferenceUpdate))", "if(false)"),
            ("if(ownsPreferences(preferenceUpdate))", "if(true)"),
            ("if(!update.original.equals(snapshotPreferences()))", "if(false)"),
            ("update.attempted=true;", ""),
            ("if(!update.next.equals(snapshotPreferences()))", "if(false)"),
            ("return update.original.equals(current)||(update.attempted&&update.next.equals(current))", "return true"),
            ("if(!ownsPreferences(update))", "if(false)"),
            ("if(update.attempted&&!update.original.equals(snapshotPreferences()))restorePreferences(update.original)", "restorePreferences(update.original)"),
            ("synchronized(preferences){editor.apply();}", "editor.apply();"),
            ("this.original=new LinkedHashMap<>(original);this.next=new LinkedHashMap<>(next)", "this.original=original;this.next=next"),
        ):
            with self.subTest(removed=before):
                self.assertIn(before,self.source)
                self.assertTrue(self.audit_source(self.source.replace(before,after)))

    def test_other_profile_publishers_keep_captured_preference_transaction(self):
        for start,end in (
            ("synchronized void selectExternalPath(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String entryMode,String execution)","synchronized void selectOrdinaryTorPath("),
            ("synchronized void selectOrdinaryTorPath(","synchronized ExternalSelection currentExternalPath("),
            ("synchronized void selectMeasuredExternal(","private static final class NodeUpdate"),
        ):
            for before,after in (("publishPreferences(preferenceUpdate)","restorePreferences(next)"),("rollbackPreferences(preferenceUpdate)","restorePreferences(original)")):
                with self.subTest(method=start,bypass=before):
                    first=self.source.index(start);last=self.source.index(end,first)
                    scope=self.source[first:last];self.assertIn(before,scope)
                    self.assertTrue(self.audit_source(self.source[:first]+scope.replace(before,after)+self.source[last:]))

    def test_preference_publication_and_rollback_cannot_precede_ownership(self):
        for start,end,write,anchor in (
            ("private void publishPreferences(","private boolean ownsPreferences(",
             "restorePreferences(update.next);","if(!update.original.equals(snapshotPreferences()))"),
            ("private void rollbackPreferences(","private void restorePreferences(",
             "if(update.attempted&&!update.original.equals(snapshotPreferences()))restorePreferences(update.original);","if(!ownsPreferences(update))"),
            ("synchronized Record load(String id)","synchronized void delete(String id)",
             "publishPreferences(preferenceUpdate);","if(!preferenceUpdate.original.equals(snapshotPreferences()))"),
            ("synchronized void selectImportedRouterPath(AndroidStandardExitStore.Entry first,AndroidNodeStore.Node last,String mode,String expectedFinal)","static final class ExternalSelection",
             "nodes.select(last.id);","if(!preferenceUpdate.original.equals(snapshotPreferences()))"),
        ):
            with self.subTest(publication=write):
                first=self.source.index(start);last=self.source.index(end,first)
                scope=self.source[first:last];self.assertEqual(scope.count(write),1)
                changed=scope.replace(write,"").replace(anchor,write+"\n"+anchor,1)
                errors=self.audit_source(self.source[:first]+changed+self.source[last:])
                self.assertTrue(any("misordered" in error for error in errors),errors)

    def test_product_refresh_must_reread_selection_under_the_original_monitor(self):
        source=self.sources[PRODUCT];first=source.index("private void refreshNodes()");last=source.index("private void refreshMap()",first)
        scope=source[first:last]
        for before,after in (
            ("synchronized(prefs())", "if(true)"),
            ('selectedId=prefs().getString(SELECTED_ID,nodeStore.activeId())', 'selectedId=cachedSelection'),
            ("if(selectedId.isEmpty()&&!items.isEmpty()&&!mutationBusy())", "if(!items.isEmpty())"),
            ("AndroidConnectionProfileStore.applySelection(prefs(),prefs().edit()", "unsafeApply(prefs().edit()"),
        ):
            with self.subTest(bypass=before):
                self.assertIn(before,scope)
                self.assertTrue(self.audit_source(source[:first]+scope.replace(before,after)+source[last:],PRODUCT))
        read='selectedId=prefs().getString(SELECTED_ID,nodeStore.activeId());'
        changed=scope.replace(read,"").replace("synchronized(prefs())",read+"synchronized(prefs())",1)
        self.assertTrue(self.audit_source(source[:first]+changed+source[last:],PRODUCT))

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
