#!/usr/bin/env python3
"""Exercise the real persistence audit against broken DNS transactions."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DNSPersistenceAuditTests(unittest.TestCase):
    def setUp(self):
        audit = ROOT / "deploy/profile-persistence-error-audit.py"
        tree = ast.parse(audit.read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "dns_policy_transaction_errors"]
        self.assertEqual(len(functions), 1)
        # The checked predicate must still run in the real release audit.
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and isinstance(node.func.value, ast.Name) and node.func.value.id == "errors"
                            and node.func.attr == "extend" and len(node.args) == 1
                            and isinstance(node.args[0], ast.Call)
                            and isinstance(node.args[0].func, ast.Name)
                            and node.args[0].func.id == "dns_policy_transaction_errors"
                            for node in ast.walk(tree)))
        scope = {"re": re}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(audit), "exec"), scope)
        self.check = scope["dns_policy_transaction_errors"]
        self.source = (ROOT / "cmd/client/dns_policy_api.go").read_text(encoding="utf-8")

    def test_shipping_current_object_transaction_passes(self):
        self.assertEqual(self.check(self.source), [])

    def test_removed_ownership_and_rollback_guards_fail(self):
        mutations = (
            ("a.beginMutationOperation(r)", "beginUnownedEdit(r)"),
            ("profile, entry, ok := a.dnsPolicySelectionLocked()", "profile, entry, ok := unrelatedSelection()"),
            ("request.ProfileToken != token", "false"),
            ("current.ID != profile.ID", "false"),
            ("dnsPolicySelectionToken(current, currentEntry) != token", "false"),
            ("profileSettingsBusy(a.state.Connected, a.state.Phase)", "false"),
            ("r.Context().Err() != nil", "false"),
            ("currentUpdate := cloneRouterProfile(current)", "currentUpdate := cloneRouterProfile(profile)"),
            ("copyDNSPolicy(&currentUpdate, updated)", "currentUpdate = updated"),
            ("a.profiles.Profiles[i].ID != current.ID", "false"),
            ("err = a.persistProfilesLocked()", "_ = a.persistProfilesLocked()"),
            ("a.profiles.Profiles[i] = current\n", "a.profiles.Profiles[i] = profile\n"),
            ("a.profiles.Profiles[i] = current\n", "// rollback removed\n"),
            ("http.StatusInternalServerError", "http.StatusOK"),
            ("writeDNSPolicy(w, currentUpdate, currentEntry)", "writeDNSPolicy(w, updated, entry)"),
        )
        for before, after in mutations:
            with self.subTest(removed=before):
                self.assertIn(before, self.source)
                broken = self.source.replace(before, after)
                # Historical variable names or comments cannot repair a
                # missing transaction in the actual handler.
                broken += "\n// oldProfile persistProfilesLocked " + before + "\n"
                self.assertTrue(self.check(broken), "Broken DNS transaction passed the actual release audit")

    def test_old_variable_names_alone_do_not_prove_persistence(self):
        self.assertTrue(self.check("// oldProfile persistProfilesLocked\n"))


if __name__ == "__main__":
    unittest.main()
