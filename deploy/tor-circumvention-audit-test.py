#!/usr/bin/env python3
"""Reject broken Tor proof, durable-choice ownership and editor coverage."""
from pathlib import Path
from contextlib import redirect_stdout
import io
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
CHOICE_CHECK = AUDIT["need_desktop_tor_choice"]
ROUTE = "cmd/client/tor_bridge_routes.go"
CHOICE = "cmd/client/desktop_tor_persistence.go"
CHOICE_SOURCE = {path: (ROOT/path).read_text(encoding="utf-8") for path in (ROUTE, CHOICE)}


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


class TorChoiceAuditTests(unittest.TestCase):
    def errors(self, changed=None):
        sources = dict(CHOICE_SOURCE)
        sources.update(changed or {})
        errors = []
        with patch.dict(CHOICE_CHECK.__globals__, {"read": sources.__getitem__, "errors": errors}):
            CHOICE_CHECK()
        return errors

    def rejects(self, changed):
        errors = self.errors(changed)
        self.assertTrue(errors, "broken shipping persistence must fail its source contract")
        self.assertTrue(all("desktop Tor durable choice/adoption ownership:" in error for error in errors))

    def reject(self, path, original, replacement):
        source = CHOICE_SOURCE[path]
        self.assertEqual(1, source.count(original), "mutation must target the actual shipping code exactly once")
        self.rejects({path: source.replace(original, replacement)})

    def move_before(self, path, moved, target):
        source = CHOICE_SOURCE[path]
        self.assertEqual(1, source.count(moved))
        self.assertEqual(1, source.count(target))
        self.rejects({path: source.replace(moved, "").replace(target, moved + target)})

    def test_actual_route_save_binding_and_fresh_adoption_pass(self):
        self.assertEqual([], self.errors())
        self.assertNotIn("a.persistProfilesLocked()", CHOICE_SOURCE[ROUTE])

    def test_shipping_audit_actually_invokes_the_durable_choice_contract(self):
        original_read = Path.read_text
        broken = CHOICE_SOURCE[CHOICE].replace("a.persistProfilesLocked()", "skipDurableWrite()")

        def read(path, *args, **kwargs):
            return broken if path == ROOT/CHOICE else original_read(path, *args, **kwargs)

        output = io.StringIO()
        with patch.object(Path, "read_text", read), redirect_stdout(output):
            with self.assertRaises(SystemExit) as failure:
                runpy.run_path(str(Path(__file__).with_name("tor-circumvention-audit.py")))
        self.assertEqual(1, failure.exception.code)
        self.assertIn("desktop Tor durable choice/adoption ownership:", output.getvalue())

    def test_whitespace_and_nonsemantic_comments_are_allowed(self):
        changed = {path: source.replace("\n", "\r\n").replace("a.persistProfilesLocked()",
                   "a /* braces } { */ . persistProfilesLocked ( )")
                   for path, source in CHOICE_SOURCE.items()}
        self.assertEqual([], self.errors(changed))

    def test_missing_or_unrelated_source_function_cannot_supply_the_contract(self):
        for path in CHOICE_SOURCE:
            with self.subTest(path=path):
                self.rejects({path: ""})
        self.reject(CHOICE, "func (a *app) commitDesktopTorChoice(",
                    "func (a *app) unrelatedChoice(")
        self.reject(ROUTE, "func (a *app) torBridgeConnectSelectionOwned(",
                    "func (a *app) unrelatedRoute(")

    def test_actual_route_calls_cannot_be_replaced_by_comments_or_strings(self):
        for original in (
            "saved, saveErr := a.commitDesktopTorChoice(selection, prelaunch.workspace, q, startup, operation, selected, actualIP)",
            "retainedProof, err = saved.adopt(a)",
        ):
            with self.subTest(original=original):
                self.reject(ROUTE, original, '// ' + original + '\n\t_ = "' + original + ' { }"')
        self.reject(CHOICE, "if err := a.persistProfilesLocked(); err != nil {",
                    'if err := func() error { return nil }(); err != nil {\n'
                    '\t\t// a.persistProfilesLocked()\n\t\t_ = "a.persistProfilesLocked() { }"')

    def test_route_requires_captured_arguments_and_rejects_failed_save_or_adoption(self):
        for original, replacement in (
            ("a.commitDesktopTorChoice(selection, prelaunch.workspace, q, startup, operation, selected, actualIP)",
             "a.commitDesktopTorChoice(selection, prelaunch.workspace, q, startup, operation, selected, profile.PublicIP)"),
            ("if saveErr != nil {", "if false {"),
            ("retainedProof, err = saved.adopt(a)\n\tif err != nil {",
             "retainedProof, err = saved.adopt(a)\n\tif false {"),
        ):
            with self.subTest(original=original):
                self.reject(ROUTE, original, replacement)
        self.move_before(ROUTE, "\tretainedProof, err = saved.adopt(a)\n",
                         "\tsaved, saveErr := a.commitDesktopTorChoice(")

    def test_captured_owner_source_request_and_startup_are_admitted_before_save(self):
        source = CHOICE_SOURCE[CHOICE]
        admission = next(line for line in source.splitlines()
                         if line.startswith("\tif desktopTorOperationCurrentLocked(a, operation, selected) != nil ||"))
        for guard in ("desktopTorOperationCurrentLocked(a, operation, selected) != nil",
                      "registered != launch", "!desktopTorChoiceRuntimeCurrentLocked(a, launch)",
                      "launch.tor.committedChoice.Load() != nil", "selection.currentLocked(a) != nil",
                      "a.validateExternalProfileExpectedProfilesLocked(q, selection.profile) != nil",
                      "startup != nil && startup.currentLocked(a) != nil"):
            with self.subTest(guard=guard):
                self.assertIn(guard, admission)
                self.reject(CHOICE, admission, admission.replace(guard, "false"))
        self.reject(CHOICE, "if err := selection.current(a); err != nil {\n\t\treturn nil, err\n\t}",
                    "_ = selection.current(a)")

    def test_last_source_and_operation_checks_cannot_move_after_disk_write(self):
        final_guard = "\tif err := desktopTorOperationCurrentLocked(a, operation, selected); err != nil {\n\t\treturn nil, err\n\t}\n"
        self.move_before(CHOICE, final_guard, "\tchoice := &desktopTorCommittedChoice{")
        self.reject(CHOICE, "if err != nil || selection.predecessor != nil && source != selection.predecessor.assetsSHA256 {",
                    "if err != nil {")

    def test_save_failure_keeps_real_rollback_and_returns_before_binding(self):
        for original, replacement in (
            ("a.rollbackProfilesLocked(previous)", "/* a.rollbackProfilesLocked(previous) */"),
            ('return nil, fmt.Errorf("%w: %v", errDesktopTorChoiceSave, err)',
             '_ = fmt.Errorf("%w: %v", errDesktopTorChoiceSave, err)'),
        ):
            with self.subTest(original=original):
                self.reject(CHOICE, original, replacement)
        binding = next(line for line in CHOICE_SOURCE[CHOICE].splitlines(keepends=True)
                       if line.startswith("\tchoice := &desktopTorCommittedChoice{")) + "\tlaunch.tor.committedChoice.Store(choice)\n"
        self.move_before(CHOICE, binding, "\tif err := a.persistProfilesLocked(); err != nil {")

    def test_atomic_saved_token_is_bound_to_exact_native_identity(self):
        for original, replacement in (
            ("launch.tor.committedChoice.Store(choice)", "/* launch.tor.committedChoice.Store(choice) */"),
            ("sessionID: launch.tor.expected.SessionID", 'sessionID: "replacement"'),
            ("choice.sourceSHA256 != owner.expected.SourceSHA256", "false"),
            ("return choice.profileToken", "return owner.profileToken"),
        ):
            with self.subTest(original=original):
                self.reject(CHOICE, original, replacement)

    def test_saved_choice_needs_real_proof_before_startup_and_after_startup(self):
        for original in ("_, err := a.readDesktopTorProof(saved.launch)",
                         "proof, err := a.readDesktopTorProof(saved.launch)"):
            with self.subTest(original=original):
                self.reject(CHOICE, original, '// ' + original + '\n\t_ = "' + original + '"')
        proof = "\tproof, err := a.readDesktopTorProof(saved.launch)\n\tif err != nil {\n\t\treturn desktopTorProof{}, err\n\t}\n"
        self.move_before(CHOICE, proof, "\tif err := a.saveStartupSelection(saved.startup); err != nil {")
        self.reject(CHOICE, proof, proof.replace("return desktopTorProof{}, err", "_ = err"))

    def test_startup_and_final_admission_failures_cannot_be_ignored(self):
        for original, replacement in (
            ('return desktopTorProof{}, fmt.Errorf("proved Tor Startup Last record could not be saved: %w", err)',
             '_ = fmt.Errorf("proved Tor Startup Last record could not be saved: %w", err)'),
            ("if err := saved.currentLocked(a); err != nil {\n\t\treturn desktopTorProof{}, err\n\t}",
             "_ = saved.currentLocked(a)"),
        ):
            with self.subTest(original=original):
                self.reject(CHOICE, original, replacement)
        self.move_before(CHOICE, '\ta.state.Connected, a.state.Phase, a.state.LastError = true, "connected", ""\n',
                         "\tif err := saved.currentLocked(a); err != nil {\n\t\treturn desktopTorProof{}, err\n\t}")

    def test_post_save_failure_cannot_claim_rollback_of_committed_choice(self):
        self.reject(CHOICE, "proof, err := a.readDesktopTorProof(saved.launch)",
                    "a.rollbackProfilesLocked(a.profiles)\n\tproof, err := a.readDesktopTorProof(saved.launch)")
        self.reject(ROUTE, "retainedProof, err = saved.adopt(a)\n\tif err != nil {",
                    "retainedProof, err = saved.adopt(a)\n\tif err != nil {\n\t\ta.rollbackProfilesLocked(a.profiles)")


IMPORT_CHECK = AUDIT["need_desktop_tor_import"]
IMPORT = "cmd/client/tor_bridge_import.go"
IMPORT_SOURCE_DECODER = "cmd/client/tor_bridge_import_source.go"
APPEND_IMPORT = "cmd/client/external_profile_import.go"
IMPORT_SOURCE = {path: (ROOT/path).read_text(encoding="utf-8")
                 for path in (IMPORT, IMPORT_SOURCE_DECODER, APPEND_IMPORT)}


class TorCapturedImportAuditTests(unittest.TestCase):
    def errors(self, changed=None):
        sources = dict(IMPORT_SOURCE)
        sources.update(changed or {})
        errors = []
        with patch.dict(IMPORT_CHECK.__globals__, {"read": sources.__getitem__, "errors": errors}):
            IMPORT_CHECK()
        return errors

    def reject(self, path, original, replacement):
        source = IMPORT_SOURCE[path]
        self.assertEqual(1, source.count(original), "mutation must target actual shipping code once")
        errors = self.errors({path: source.replace(original, replacement)})
        self.assertTrue(errors, "unsafe captured bridge import must fail its shipping contract")
        self.assertTrue(all("desktop Tor captured bridge update ownership:" in error for error in errors))

    def test_actual_captured_update_chain_passes(self):
        self.assertEqual([], self.errors())

    def test_nonsemantic_comments_and_whitespace_do_not_replace_guards(self):
        changed = {path: source.replace("\n", "\r\n").replace("a.persistProfilesLocked()",
                   "a /* { } */ . persistProfilesLocked ( )") for path, source in IMPORT_SOURCE.items()}
        self.assertEqual([], self.errors(changed))

    def test_shipping_audit_invokes_actual_import_contract(self):
        original_read = Path.read_text
        broken = IMPORT_SOURCE[IMPORT].replace("a.validateExternalProfileExpectedProfilesLocked(expected, existing)", "skipSourceGuard(expected, existing)")
        def read(path, *args, **kwargs):
            return broken if path == ROOT/IMPORT else original_read(path, *args, **kwargs)
        output = io.StringIO()
        with patch.object(Path, "read_text", read), redirect_stdout(output):
            with self.assertRaises(SystemExit) as failure:
                runpy.run_path(str(Path(__file__).with_name("tor-circumvention-audit.py")))
        self.assertEqual(1, failure.exception.code)
        self.assertIn("desktop Tor captured bridge update ownership:", output.getvalue())

    def test_route_and_policy_calls_cannot_be_replaced_by_comments_or_strings(self):
        for original in (
            "handled, err := a.updateExistingTorBridgeProfile(r, &profile, updateIntent, q.expectedProfiles())",
            "merged := preserveTorBridgeEditSettings(existing, *profile, intent)",
            "policy, err := normalizeTorBridgeImportPolicy(merged)",
            "if _, err := standardExitFromExternalProfile(policy); err != nil {",
        ):
            with self.subTest(original=original):
                self.reject(IMPORT, original, '// '+original+'\n\t_ = "'+original+'"')

    def test_every_saved_graph_field_and_protection_are_preserved(self):
        for field in ("MultihopEnabled", "MultihopEntryID", "MultihopExitID", "MultihopEntryMode", "MultihopExecution"):
            original = f"next.{field} = existing.{field}"
            with self.subTest(field=field):
                self.reject(IMPORT, original, '// '+original)
        self.reject(IMPORT, "next.KillSwitchPolicy = existing.KillSwitchPolicy", "/* protection reset */")

    def test_direct_dynamic_strict_admission_still_requires_a_real_saved_path(self):
        self.reject(IMPORT, 'if requestedKill != "off" && !strictLiteralObfs4 && !profile.MultihopEnabled {',
                    'if requestedKill != "off" && !strictLiteralObfs4 && false {')
        self.reject(IMPORT, "if supported, reason := externalDevicePolicySupportForPath(merged, entry); !supported {", "if supported, reason := true, \"\"; !supported {")
        self.reject(IMPORT, "if err := validateExternalDeviceSettingsForPath(merged, entry); err != nil {", "if err := error(nil); err != nil {")
        self.reject(IMPORT, "if matches != 1 {", "if matches < 1 {")

    def test_source_revision_and_identity_guards_must_precede_adoption(self):
        for original, replacement in (
            ("if err := a.validateExternalProfileExpectedProfilesLocked(expected, existing); err != nil {", "if err := error(nil); err != nil {"),
            ("return false, errExternalProfileSelectionChanged", "return false, nil"),
            ("if index >= 0 {", "if false {"),
            ("release, guardErr := a.beginMutationOperation(r)", "release, guardErr := func() {}, error(nil)"),
            ("defer a.mu.Unlock()", "/* no captured transaction */"),
        ):
            with self.subTest(original=original):
                self.reject(IMPORT, original, replacement)
        source = IMPORT_SOURCE[IMPORT]
        guard = "\tif err := a.validateExternalProfileExpectedProfilesLocked(expected, existing); err != nil {\n\t\treturn false, err\n\t}\n"
        marker = "\ta.profiles.Profiles[index] = merged\n"
        self.assertEqual(1, source.count(guard))
        changed = source.replace(guard, "").replace(marker, marker+guard)
        self.assertTrue(self.errors({IMPORT: changed}), "source check after private mutation cannot pass")

    def test_malformed_source_json_cannot_silently_downgrade(self):
        for original, replacement in (
            ("fields, err := externalConnectJSONObject(data)", "fields, err := map[string]json.RawMessage{}, error(nil)"),
            ("json.Unmarshal(expectationJSON, &capture)", "json.Unmarshal([]byte(`{}`), &capture)"),
            ("decoder.DisallowUnknownFields()", "/* unknown path controls accepted */"),
            ("if name != canonical && strings.EqualFold(name, canonical) {", "if false {"),
        ):
            with self.subTest(original=original):
                self.reject(IMPORT_SOURCE_DECODER, original, replacement)

    def test_real_cancellation_and_persistence_rollback_remain_required(self):
        source = IMPORT_SOURCE[IMPORT]
        guard = '\tif r.Context().Err() != nil {\n\t\treturn false, errors.New("Tor bridge update was cancelled")\n\t}\n'
        self.assertEqual(2, source.count(guard))
        for index in (0, 1):
            parts = source.split(guard)
            parts[index] += '/* cancellation ignored */\n' + parts.pop(index+1)
            self.assertTrue(self.errors({IMPORT: guard.join(parts)}))
        self.reject(APPEND_IMPORT, "if r.Context().Err() != nil {", "if false {")
        self.reject(IMPORT, "a.rollbackProfilesLocked(previousStore)", "/* rollback omitted */")


if __name__ == "__main__":
    unittest.main()
