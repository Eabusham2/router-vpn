#!/usr/bin/env python3
"""Reject broken shipping Tor proof ownership and editor mutation coverage."""
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

AUDIT = runpy.run_path(str(Path(__file__).with_name("tor-circumvention-audit.py")))
CHECK = AUDIT["need_android_tor_editor_controls"]
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT/"android/test_android_tor_form.py").read_text(encoding="utf-8")
MAINTENANCE_CHECK = AUDIT["need_desktop_tor_maintenance"]
COMMAND = "mobile/desktop/external_tor.go.tmpl"
WORKER = "mobile/desktop/external_tor_transition.go.tmpl"
NATIVE = "mobile/desktop/external_tor_native.go.tmpl"
PATH = "mobile/desktop/mtu_tor.go.tmpl"
FIXTURES = "mobile/desktop/external_tor_transition_test.go.tmpl"
MAINTENANCE_SOURCE = {path: (ROOT/path).read_text(encoding="utf-8")
                      for path in (COMMAND, WORKER, NATIVE, PATH, FIXTURES)}


class TorEditorAuditTests(unittest.TestCase):
    def errors(self, source):
        errors = []
        with patch.dict(CHECK.__globals__, {"read": lambda _: source, "errors": errors}):
            CHECK("fixture.py")
        return errors

    def test_current_policy_and_visibility_mutations_are_executed(self):
        self.assertEqual([], self.errors(SOURCE))

    def test_cosmetic_test_count_text_is_not_an_authoritative_gate(self):
        self.assertEqual([], self.errors(SOURCE.replace("all five original-source negative controls rejected", "all editor mutation controls rejected")))

    def test_each_control_is_required_and_comments_cannot_replace_it(self):
        for label in ("rewritten-policy", "ipv6-default", "lan-default", "dns-precedence", "hidden-mode-list"):
            with self.subTest(label=label):
                changed = SOURCE.replace('("'+label+'",', '("removed",')
                self.assertTrue(self.errors(changed + '\n# ("'+label+'",\n'))

    def test_ignored_or_unrelated_mutation_failure_is_rejected(self):
        for guard in ("False", "failure not in rejected.stderr", "rejected.returncode == 0"):
            with self.subTest(guard=guard):
                self.assertTrue(self.errors(SOURCE.replace("rejected.returncode == 0 or failure not in rejected.stderr", guard)))


class TorMaintenanceAuditTests(unittest.TestCase):
    def errors(self, changed=None):
        sources = dict(MAINTENANCE_SOURCE)
        sources.update(changed or {})
        errors = []
        with patch.dict(MAINTENANCE_CHECK.__globals__, {"read": sources.__getitem__, "errors": errors}):
            MAINTENANCE_CHECK()
        return errors

    def reject(self, path, original, replacement):
        source = MAINTENANCE_SOURCE[path]
        self.assertEqual(1, source.count(original), "mutation must target the actual shipping code exactly once")
        errors = self.errors({path: source.replace(original, replacement)})
        self.assertTrue(errors, "broken shipping maintenance must fail its source contract")
        self.assertTrue(all("desktop Tor retained maintenance/proof ownership:" in error for error in errors))

    def test_actual_retained_worker_and_native_proof_chain_pass(self):
        self.assertEqual([], self.errors())

    def test_whitespace_and_nonsemantic_comments_do_not_change_ownership(self):
        changed = {path: source.replace("\n", "\r\n").replace("owner.VerifyCurrentPath(verify)",
                   "owner /* braces } { */ . VerifyCurrentPath ( verify )")
                   for path, source in MAINTENANCE_SOURCE.items()}
        self.assertEqual([], self.errors(changed))

    def test_proof_bypass_cannot_be_replaced_by_comment_or_string(self):
        self.reject(WORKER, "err := owner.VerifyCurrentPath(verify)",
                    'err := func() error { return nil }()\n'
                    '\t\t// owner.VerifyCurrentPath(verify)\n'
                    '\t\t_ = "owner.VerifyCurrentPath(verify) { }"')

    def test_verification_keeps_captured_deadline_and_rejects_failure(self):
        for original, replacement in (
            ("context.WithTimeout(ctx, mobiletor.DesktopBridgeHeartbeatMaxAge)", "context.WithCancel(ctx)"),
            ("context.WithTimeout(ctx, mobiletor.DesktopBridgeHeartbeatMaxAge)",
             "context.WithTimeout(context.Background(), mobiletor.DesktopBridgeHeartbeatMaxAge)"),
            ("if err != nil || ctx.Err() != nil || !owner.Healthy() || files.current() != nil || routerVPNTorRefreshReadback(owner, &result.proof) != nil {",
             "_ = err\n\t\tif ctx.Err() != nil || !owner.Healthy() || files.current() != nil || routerVPNTorRefreshReadback(owner, &result.proof) != nil {"),
        ):
            with self.subTest(replacement=replacement):
                self.reject(WORKER, original, replacement)

    def test_command_requires_one_owned_worker_with_captured_version(self):
        for original, replacement in (
            ("if maintenance == nil {", "if true {"),
            ("ctx, cancel := context.WithCancel(parent)", "ctx, cancel := context.WithCancel(context.Background())"),
            ("version: proofVersion, proof: receipt", "version: 0, proof: receipt"),
            ("heartbeat: transitionDone == nil && time.Since(heartbeat)", "heartbeat: time.Since(heartbeat)"),
            ("completed <- routerVPNTorMaintain(ctx, owner, files, dnsFiles, mtuFiles, pathFiles, captured)", "completed <- captured"),
        ):
            with self.subTest(original=original):
                self.reject(COMMAND, original, replacement)

    def test_adoption_rejects_stale_or_failed_result_before_publishing(self):
        for original, replacement in (
            ("if result.version != proofVersion {\n\t\t\t\tbreak\n\t\t\t}",
             "if result.version != proofVersion { /* break */ }"),
            ("if result.err != nil {\n\t\t\t\tfailure, stopping = routerVPNTorFailure, true\n\t\t\t\tbreak\n\t\t\t}",
             "if result.err != nil { /* failure deliberately ignored */ }"),
        ):
            with self.subTest(original=original):
                self.reject(COMMAND, original, replacement)
        original = "if result.heartbeat {\n\t\t\t\treceipt = result.proof"
        self.reject(COMMAND, original, "if result.heartbeat {\n\t\t\t\treceipt = receipt")

    def test_teardown_cancels_and_joins_actual_worker_before_native_close(self):
        for original, replacement in (
            ("if cancelMaintenance != nil {\n\t\tcancelMaintenance()\n\t}", "if cancelMaintenance != nil { /* cancelMaintenance() */ }"),
            ("if maintenance != nil {\n\t\t<-maintenance\n\t}", "if maintenance != nil { /* <-maintenance */ }"),
        ):
            with self.subTest(original=original):
                self.reject(COMMAND, original, replacement)

    def test_transition_cannot_extend_expired_or_different_proof(self):
        for original, replacement in (
            ("value.ExpiresAt > now.UnixMilli()", "value.ExpiresAt >= 0"),
            ("value.ExpiresAt-value.StartedAt <= mobiletor.DesktopBridgeMTUTransitionLimit.Milliseconds()", "value.ExpiresAt-value.StartedAt >= 0"),
            ("proof.HeartbeatAt == value.FromHeartbeatAt", "proof.HeartbeatAt != 0"),
            ("*proof.MTUReadback == value.From", "proof.MTUReadback != nil"),
        ):
            with self.subTest(original=original):
                self.reject(WORKER, original, replacement)

    def test_native_adapter_and_fresh_path_keep_actual_selected_path_proof(self):
        self.reject(NATIVE, "tor.VerifyCurrentPath(ctx)", "func() error { return nil }()")
        self.reject(PATH, "mtu.owner.VerifyExternal(ctx, state) != nil", "false")

    def test_real_slow_control_and_transition_regressions_remain_required(self):
        for name in ("TestRouterVPNDesktopTorMTUTransitionRejectsForeignExpiredAndReplacedAdmission",
                     "TestRouterVPNDesktopTorMTUTransitionKeepsControlResponsiveAndJoinsSlowReader",
                     "TestRouterVPNDesktopTorMTUTransitionWaitsForActualCompletionBeforeHeartbeat",
                     "TestRouterVPNDesktopTorHeartbeatAllowsOwnedSlowControlWithoutInventingFreshness"):
            with self.subTest(name=name):
                self.reject(FIXTURES, "func " + name + "(", "func Removed" + name + "(")


if __name__ == "__main__":
    unittest.main()
