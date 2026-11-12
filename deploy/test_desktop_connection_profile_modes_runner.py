#!/usr/bin/env python3
"""Keep PowerShell negative verdicts tied to the exact behavioral failure."""
import importlib.util
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

if __name__ == "__main__":
    unittest.main()
