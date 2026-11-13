#!/usr/bin/env python3
"""Refusal tests for native desktop editor observations."""
from pathlib import Path
import importlib.util
import sys
import unittest

spec = importlib.util.spec_from_file_location("desktop_editor_gate", Path(__file__).with_name("validate-desktop-socks-editor.py"))
D = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = D
spec.loader.exec_module(D)


def complete(target):
    if target == "linux/amd64":
        return ("Shipping GTK ordered editor + Add/Load/Update/Connect: 123 checks PASS; real callbacks/persistence, doubled controller boundary.\n" +
                "".join("GTK ordered causal control " + name + ": rejected\n" for name in D.LINUX_CONTROLS)).encode()
    return ("Actual WPF profile Add/Load/Update and main Connect callbacks: 123 checks PASS\n" +
            "WPF pair and ordered capture, setup ownership/response, load/Connect, capability and startup deadline negatives: 19 rejected\n" +
            "".join("Actual ordered editor causal control " + name + ": rejected\n" for name in sorted(D.WINDOWS_CONTROLS)) +
            "Actual ordered node editor callbacks: 123 checks PASS; WPF=True\n").encode()


class DesktopEditorVerdicts(unittest.TestCase):
    def test_exact_native_hosts(self):
        for target, (system, machines) in D.TARGETS.items():
            for machine in machines:
                self.assertEqual(D.require_host(target, system, machine), system)
            for wrong in (("Darwin", "arm64"), (system, "foreign"), ("Linux" if system == "Windows" else "Windows", machines[0])):
                with self.subTest(target=target, wrong=wrong), self.assertRaises(ValueError):
                    D.require_host(target, *wrong)

    def test_complete_original_and_new_inventories(self):
        self.assertEqual(len(D.WINDOWS_CONTROLS), 8)
        self.assertEqual(len(D.LINUX_CONTROLS), 11)
        self.assertIn("socks-mode", D.WINDOWS_CONTROLS)
        self.assertEqual(D.LINUX_CONTROLS[0], "socks-mode")
        for target in D.TARGETS:
            self.assertTrue(D.verdict(complete(target), target, 0, False, True)["accepted"])

    def test_failed_exit_timeout_and_unjoined_never_pass(self):
        for target in D.TARGETS:
            for code, timeout, joined in ((1, False, True), (-9, False, True), (124, True, True), (0, True, True), (0, False, False)):
                self.assertFalse(D.verdict(complete(target), target, code, timeout, joined)["accepted"])

    def test_each_missing_or_duplicate_control_is_refused(self):
        for target in D.TARGETS:
            raw = complete(target)
            controls = [line for line in raw.splitlines(keepends=True) if b"causal control" in line]
            for control in controls:
                for changed in (raw.replace(control, b"", 1), raw + control):
                    self.assertFalse(D.verdict(changed, target, 0, False, True)["accepted"])

    def test_wrong_summary_widget_boundary_and_late_error_are_refused(self):
        for target in D.TARGETS:
            raw = complete(target)
            variants = [raw.replace(b"123 checks", b"0 checks", 1), raw + b"Traceback failure\n", raw + b"ERROR original child failed\n"]
            if target.startswith("windows"):
                variants += [raw.replace(b"WPF=True", b"WPF=False"), raw.replace(b"19 rejected", b"18 rejected"),
                             raw + b"Actual WPF profile Add/Load/Update and main Connect callbacks: 123 checks PASS\n"]
            else:
                variants += [raw + b"Gtk-WARNING: original widget failed\n",
                             raw.replace(b"Shipping GTK ordered editor + Add/Load/Update/Connect", b"Shipping ordered source model/serialization/persistence")]
            for changed in variants:
                self.assertFalse(D.verdict(changed, target, 0, False, True)["accepted"])

    def test_windows_forwarded_line_boundaries_preserve_exact_results(self):
        raw = complete("windows/amd64")
        for ending in (b"\n", b"\r\n", b"\r\r\n"):
            self.assertTrue(D.verdict(raw.replace(b"\n", ending), "windows/amd64", 0, False, True)["accepted"])

    def test_linux_causal_control_order_is_preserved(self):
        raw = complete("linux/amd64").splitlines(keepends=True)
        raw[-1], raw[-2] = raw[-2], raw[-1]
        self.assertFalse(D.verdict(b"".join(raw), "linux/amd64", 0, False, True)["accepted"])


    def test_windows_suite_budget_covers_each_original_bounded_command(self):
        source = (D.ROOT / "deploy/test_desktop_connection_profile_modes.py").read_text(encoding="utf-8")
        self.assertEqual(D.windows_suite_budget(source), 1890)
        self.assertEqual(D.windows_suite_budget(source), (20 + 1) * 90)
        self.assertIn('execute("gtk-profiles", command, 900)', Path(D.__file__).read_text(encoding="utf-8"))

    def test_windows_suite_budget_refuses_changed_child_or_case_inventory(self):
        source = (D.ROOT / "deploy/test_desktop_connection_profile_modes.py").read_text(encoding="utf-8")
        changes = (
            source.replace("timeout=90", "timeout=91", 1),
            source.replace("timeout=90", "timeout=None", 1),
            source.replace('"shipping", "capture-two-modes", ', '"shipping", ', 1),
            source.replace('"shipping", "capture-two-modes", ', '"shipping", "shipping", "capture-two-modes", ', 1),
            source.replace('    run(editor', '    run(editor)\n    run(editor', 1),
            source.replace('def windows(shell):', 'def omitted_windows(shell):', 1),
        )
        for changed in changes:
            self.assertNotEqual(source, changed)
            with self.assertRaises(ValueError):
                D.windows_suite_budget(changed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
