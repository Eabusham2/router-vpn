#!/usr/bin/env python3
"""Keep PowerShell negative verdicts tied to the exact behavioral failure."""
import importlib.util
import contextlib
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name("test_desktop_connection_profile_modes.py")
SPEC = importlib.util.spec_from_file_location("profile_modes", PATH)
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)
WITNESS = "Setup action discarded its original source inventory"
# Exact diagnostic from Actions job130897310958, with only Actions timestamps
# removed (the subprocess output consumed by run() never contains timestamps).
# https://github.com/Eabusham2/router-vpn/actions/runs/43130513238/job/130897310958
WRAPPED = (
    '\x1b[31;1mException: \x1b[0mD:\\a\\router-vpn\\router-vpn\\client\\test-windows-connection-profile-modes.ps1:16\x1b[0m\n'
    '\x1b[31;1m\x1b[0m\x1b[36;1mLine |\x1b[0m\n'
    "\x1b[31;1m\x1b[0m\x1b[36;1m\x1b[36;1m  16 | \x1b[0m … ){$script:Count++;if(-not$Value){\x1b[36;1mthrow ('PROFILE-CHECK: '+$Message)\x1b[0m}}\x1b[0m\n"
    '\x1b[31;1m\x1b[0m\x1b[36;1m\x1b[36;1m\x1b[0m\x1b[36;1m\x1b[0m\x1b[36;1m     | \x1b[31;1m                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\x1b[0m\n'
    '\x1b[31;1m\x1b[0m\x1b[36;1m\x1b[36;1m\x1b[0m\x1b[36;1m\x1b[0m\x1b[36;1m\x1b[31;1m\x1b[31;1m\x1b[36;1m     | \x1b[31;1mPROFILE-CHECK: Actual Add callback failed: Add failed: PROFILE-CHECK: Setup action discarded its original source\x1b[0m\n'
    '\x1b[31;1m\x1b[0m\x1b[36;1m\x1b[36;1m\x1b[0m\x1b[36;1m\x1b[0m\x1b[36;1m\x1b[31;1m\x1b[31;1m\x1b[36;1m\x1b[31;1m\x1b[36;1m     | \x1b[31;1minventory\x1b[0m\n'
    '\n'
)

class PowerShellDiagnosticVerdict(unittest.TestCase):
    def classify(self, output, code=1):
        result = subprocess.CompletedProcess(["captured-pwsh"], code, "", output)
        with patch.object(G.subprocess, "run", return_value=result):
            G.run(["captured-pwsh"], negative=True, witness=WITNESS)

    def test_actual_wrapped_ansi_failure_keeps_exact_cause(self):
        self.assertNotIn(WITNESS, " ".join(WRAPPED.split()))
        self.classify(WRAPPED)

    def test_plain_and_unstyled_wrapped_diagnostics_remain_supported(self):
        self.classify("PROFILE-CHECK: " + WITNESS)
        self.classify("     | PROFILE-CHECK: Setup action discarded its original source\r\n     | inventory\r\n")

    def test_different_behavioral_cause_is_not_accepted(self):
        with self.assertRaisesRegex(RuntimeError, "Negative did not fail"):
            self.classify(WRAPPED.replace("discarded", "retained"))

    def test_missing_word_is_not_reconstructed(self):
        with self.assertRaisesRegex(RuntimeError, "Negative did not fail"):
            self.classify(WRAPPED.replace("inventory", ""))

    def test_inline_pipe_is_not_erased_from_message(self):
        with self.assertRaisesRegex(RuntimeError, "Negative did not fail"):
            self.classify("PROFILE-CHECK: Setup action discarded its original source | inventory")

    def test_generic_error_with_matching_words_is_not_a_behavioral_assertion(self):
        with self.assertRaisesRegex(RuntimeError, "Negative did not fail"):
            self.classify(WRAPPED.replace("PROFILE-CHECK:", "RuntimeError:"))

    def test_success_cannot_supply_a_negative_verdict(self):
        with self.assertRaisesRegex(RuntimeError, "Negative did not fail"):
            self.classify(WRAPPED, code=0)

    def test_only_the_original_assertion_exit_one_is_accepted(self):
        for code in (2, 124, 125, -4, -6, -9, -11, 3221225477):
            with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, "Negative did not fail"):
                self.classify(WRAPPED, code=code)

    def test_late_crash_cannot_borrow_an_earlier_assertion(self):
        for crash in ("panic: late native failure", "fatal error: late runtime failure",
                      "Fatal: native cleanup failed", "Segmentation fault",
                      "*** Signal 4: Backtracing", "SIGSEGV", "SIGABRT", "SIGBUS"):
            with self.subTest(crash=crash), self.assertRaisesRegex(RuntimeError, "Negative did not fail"):
                self.classify(WRAPPED + "\n" + crash, code=1)

    def test_timeout_preserves_original_exception_and_bound(self):
        command = ["captured-pwsh"]
        expired = subprocess.TimeoutExpired(command, 90, output="PROFILE-CHECK: " + WITNESS)
        with patch.object(G.subprocess, "run", side_effect=expired) as original, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                G.run(command, negative=True, witness=WITNESS)
        self.assertIs(caught.exception, expired)
        original.assert_called_once_with(command, cwd=G.ROOT, text=True,
                                         capture_output=True, timeout=90)

    def test_timeout_keeps_native_milestones_and_errors_without_accepting_them(self):
        for binary in (False, True):
            with self.subTest(binary=binary):
                milestone = "Profile fixture stage: callbacks-extracted; checks=0\n"
                diagnostic = "PROFILE-CHECK: " + WITNESS
                expired = subprocess.TimeoutExpired(["captured-pwsh"], 90,
                    output=milestone.encode() if binary else milestone,
                    stderr=diagnostic.encode() if binary else diagnostic)
                output = io.StringIO()
                with patch.object(G.subprocess, "run", side_effect=expired), contextlib.redirect_stdout(output):
                    with self.assertRaises(subprocess.TimeoutExpired) as caught:
                        G.run(["captured-pwsh"], negative=True, witness=WITNESS,
                              observation="profile:shipping")
                self.assertIs(caught.exception, expired)
                self.assertIn("timed out: profile:shipping", output.getvalue())
                self.assertIn(milestone, output.getvalue())
                self.assertIn(diagnostic, output.getvalue())

    def test_timeout_without_output_remains_a_failed_native_child(self):
        expired = subprocess.TimeoutExpired(["captured-pwsh"], 90)
        output = io.StringIO()
        with patch.object(G.subprocess, "run", side_effect=expired), contextlib.redirect_stdout(output):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                G.run(["captured-pwsh"], observation="profile:shipping")
        self.assertIs(caught.exception, expired)
        self.assertIn("timed out: profile:shipping", output.getvalue())
        self.assertNotIn("finished:", output.getvalue())

class OrderedEditorPartition(unittest.TestCase):
    def test_exact_inventory_refuses_missing_extra_duplicate_or_changed_witness(self):
        source = (G.ROOT / "client/test-windows-ordered-editor.ps1").read_text()
        self.assertEqual(G.windows_editor_inventory(source), G.WINDOWS_EDITOR_CONTROLS)
        name, witness = next(iter(G.WINDOWS_EDITOR_CONTROLS.items()))
        literal = "'" + name + "'='" + witness + "'"
        for replacement in ("", literal + ";" + literal, "'foreign'='foreign'", literal.replace(witness, "different")):
            with self.subTest(replacement=replacement), self.assertRaises(RuntimeError):
                G.windows_editor_inventory(source.replace(literal, replacement, 1))

    def test_required_baseline_and_every_causal_are_called_once(self):
        with patch.object(G, "run") as run:
            G.windows_editor("captured-pwsh")
        calls = run.call_args_list
        self.assertEqual(len(calls), 1 + len(G.WINDOWS_EDITOR_CONTROLS))
        self.assertIn("-PositiveOnly", calls[0].args[0])
        self.assertNotIn("negative", calls[0].kwargs)
        for call, (name, witness) in zip(calls[1:], G.WINDOWS_EDITOR_CONTROLS.items()):
            self.assertEqual(call.args[0][-2:], ["-NegativeControl", name])
            self.assertTrue(call.kwargs["negative"])
            self.assertEqual(call.kwargs["marker"], "ORDERED-EDITOR:")
            self.assertEqual(call.kwargs["witness"], witness)

    def test_required_windows_entrypoint_keeps_complete_editor_partition(self):
        with patch.object(G, "run") as run, contextlib.redirect_stdout(io.StringIO()):
            G.windows("captured-pwsh")
        editor = [c for c in run.call_args_list if "test-windows-ordered-editor.ps1" in " ".join(c.args[0])]
        self.assertEqual(len(editor), 1 + len(G.WINDOWS_EDITOR_CONTROLS))
        self.assertIn("-PositiveOnly", editor[0].args[0])
        self.assertEqual([c.args[0][-1] for c in editor[1:]], list(G.WINDOWS_EDITOR_CONTROLS))
        self.assertEqual(len(run.call_args_list) - len(editor), 22)

    def test_ordered_marker_exit_and_intended_cause_are_required(self):
        witness = next(iter(G.WINDOWS_EDITOR_CONTROLS.values()))
        for code, output, accepted in ((1, "ORDERED-EDITOR: " + witness, True),
                (0, "ORDERED-EDITOR: " + witness, False), (1, "PROFILE-CHECK: " + witness, False),
                (1, "ORDERED-EDITOR: unrelated", False), (1, "fatal error: ORDERED-EDITOR: " + witness, False)):
            with self.subTest(code=code, output=output):
                result = subprocess.CompletedProcess(["pwsh"], code, output, "")
                with patch.object(G.subprocess, "run", return_value=result) as run:
                    if accepted:
                        G.run(["pwsh"], negative=True, marker="ORDERED-EDITOR:", witness=witness)
                    else:
                        with self.assertRaises(RuntimeError):
                            G.run(["pwsh"], negative=True, marker="ORDERED-EDITOR:", witness=witness)
                    self.assertEqual(run.call_args.kwargs["timeout"], 90)

if __name__ == "__main__":
    unittest.main()
