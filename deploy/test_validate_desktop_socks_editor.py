#!/usr/bin/env python3
"""Refusal tests for native desktop editor observations."""
from pathlib import Path
import ast
import importlib.util
import sys
import re
import unittest

spec = importlib.util.spec_from_file_location("desktop_editor_gate", Path(__file__).with_name("validate-desktop-socks-editor.py"))
D = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = D
spec.loader.exec_module(D)


def complete(target):
    if target == "linux/amd64":
        return ("Shipping GTK ordered editor + Add/Load/Update/Connect: 123 checks PASS; real callbacks/persistence, doubled controller boundary.\n" +
                "".join("GTK ordered causal control " + name + ": rejected\n" for name in D.LINUX_CONTROLS)).encode()
    return ("".join("Actual WPF profile Add/Load/Update and main Connect callbacks: 123 checks PASS\n" +
                    receipt + "\n" for receipt in D.WINDOWS_PROFILE_RECEIPTS) +
            "WPF pair and ordered capture, setup ownership/response, load/Connect, capability and startup deadline negatives: 21 rejected\n" +
            "".join("Actual ordered editor causal control " + name + ": rejected\n" for name in sorted(D.WINDOWS_CONTROLS)) +
            "".join("Actual ordered node editor callbacks (" + group + "): 123 checks PASS; WPF=True\n" for group in D.WINDOWS_EDITOR_GROUPS)).encode()


class DesktopEditorVerdicts(unittest.TestCase):
    def test_exact_native_hosts(self):
        for target, (system, machines) in D.TARGETS.items():
            for machine in machines:
                self.assertEqual(D.require_host(target, system, machine), system)
            for wrong in (("Darwin", "arm64"), (system, "foreign"), ("Linux" if system == "Windows" else "Windows", machines[0])):
                with self.subTest(target=target, wrong=wrong), self.assertRaises(ValueError):
                    D.require_host(target, *wrong)

    def test_complete_original_and_new_inventories(self):
        self.assertEqual(len(D.WINDOWS_CONTROLS), 33)
        self.assertEqual(len(D.LINUX_CONTROLS), 40)
        self.assertIn("socks-mode", D.WINDOWS_CONTROLS)
        self.assertEqual(D.LINUX_CONTROLS[10:15], ("socks-execution-global", "socks-execution-capability", "socks-execution-entry-layer", "socks-execution-final-layer", "socks-execution-layer"))
        for target in D.TARGETS:
            self.assertTrue(D.verdict(complete(target), target, 0, False, True)["accepted"])

    def test_linux_inventory_matches_the_actual_native_fixture(self):
        source = (D.ROOT / "client/linux/test-ordered-nodes-v1.py").read_text(encoding="utf-8")
        inventories = [node.value for node in ast.walk(ast.parse(source))
                       if isinstance(node, ast.Assign) and isinstance(node.value, ast.List)
                       and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                       and node.targets[0].id == "controls"]
        self.assertEqual(len(inventories), 1)
        actual = tuple(ast.literal_eval(row.elts[0]) for row in inventories[0].elts)
        self.assertEqual(actual, D.LINUX_CONTROLS)

    def test_windows_inventory_matches_actual_powershell_and_each_new_guard_is_required(self):
        source = (D.ROOT / "client/test-windows-ordered-editor.ps1").read_text(encoding="utf-8")
        blocks = re.findall(r"\$controls=@\{([^}]+)\}", source)
        self.assertEqual(len(blocks), 1)
        pairs = re.findall(r"'([^']+)'='([^']+)'", blocks[0])
        self.assertEqual(len(pairs), len(D.WINDOWS_CONTROLS))
        self.assertEqual(len(dict(pairs)), len(pairs))
        self.assertEqual(dict(pairs), D.WINDOWS_EDITOR_WITNESSES)
        self.assertEqual(D.LINUX_CONTROLS[7:9], ("connect-execution-old-trio", "connect-execution-prefix-layer"))
        suite = (D.ROOT / "deploy/test_desktop_connection_profile_modes.py").read_text(encoding="utf-8")
        row = "'connect-execution-prefix-layer': 'CONNECT execution admitted a malformed paired prefix layer',"
        self.assertEqual(suite.count(row), 1)
        for replacement in ("", row + row, row.replace("malformed paired prefix layer", "unrelated error")):
            with self.assertRaises(ValueError):
                D.windows_suite_budget(suite.replace(row, replacement, 1))

    def test_hostname_controls_remain_exact_in_both_required_inventories(self):
        self.assertEqual(D.LINUX_CONTROLS[-4:-1], ("hostname-minimum", "hostname-capability", "hostname-conflict"))
        suite = (D.ROOT / "deploy/test_desktop_connection_profile_modes.py").read_text(encoding="utf-8")
        for name in ("hostname-minimum", "hostname-conflict", "hostname-capability"):
            row = repr(name) + ": " + repr(D.WINDOWS_EDITOR_WITNESSES[name]) + ","
            self.assertEqual(suite.count(row), 1)
            for replacement in ("", row + row, row.replace(D.WINDOWS_EDITOR_WITNESSES[name], "unrelated failure")):
                with self.assertRaises(ValueError):
                    D.windows_suite_budget(suite.replace(row, replacement, 1))

    def test_published_openvpn_controls_are_exact_and_required(self):
        names = ("openvpn-execution-global", "openvpn-execution-capability", "openvpn-execution-final-layer")
        self.assertEqual(D.LINUX_CONTROLS[4:7], names)
        self.assertEqual(set(name for name in D.WINDOWS_CONTROLS if name.startswith("openvpn-")), set(names))
        suite = (D.ROOT / "deploy/test_desktop_connection_profile_modes.py").read_text(encoding="utf-8")
        for name in names:
            row = repr(name) + ": " + repr(D.WINDOWS_EDITOR_WITNESSES[name]) + ","
            self.assertEqual(suite.count(row), 1)
            for replacement in ("", row + row, row.replace(D.WINDOWS_EDITOR_WITNESSES[name], "unrelated failure")):
                with self.subTest(control=name, replacement=replacement), self.assertRaises(ValueError):
                    D.windows_suite_budget(suite.replace(row, replacement, 1))

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
                variants += [raw.replace(b"WPF=True", b"WPF=False"), raw.replace(b"21 rejected", b"19 rejected"),
                             raw + b"Actual WPF profile Add/Load/Update and main Connect callbacks: 123 checks PASS\n"]
            else:
                variants += [raw + b"Gtk-WARNING: original widget failed\n",
                             raw.replace(b"Shipping GTK ordered editor + Add/Load/Update/Connect", b"Shipping ordered source model/serialization/persistence")]
            for changed in variants:
                self.assertFalse(D.verdict(changed, target, 0, False, True)["accepted"])

    def test_windows_shipping_groups_are_all_required_once(self):
        raw = complete("windows/amd64")
        for group in D.WINDOWS_EDITOR_GROUPS:
            line = next(row for row in raw.splitlines(keepends=True)
                        if ("callbacks (" + group + "):").encode() in row)
            for changed in (raw.replace(line, b""), raw + line, raw.replace(line, line.replace(b"123 checks", b"0 checks"))):
                self.assertFalse(D.verdict(changed, "windows/amd64", 0, False, True)["accepted"])

    def test_windows_forwarded_line_boundaries_preserve_exact_results(self):
        raw = complete("windows/amd64")
        for ending in (b"\n", b"\r\n", b"\r\r\n"):
            self.assertTrue(D.verdict(raw.replace(b"\n", ending), "windows/amd64", 0, False, True)["accepted"])

    def test_linux_causal_control_order_is_preserved(self):
        raw = complete("linux/amd64").splitlines(keepends=True)
        raw[-1], raw[-2] = raw[-2], raw[-1]
        self.assertFalse(D.verdict(b"".join(raw), "linux/amd64", 0, False, True)["accepted"])


    def test_hysteria_control_is_additive_and_required(self):
        self.assertEqual(D.LINUX_CONTROLS[-1], "hysteria-execution-global")
        self.assertEqual(D.WINDOWS_EDITOR_WITNESSES["hysteria-execution-global"], "Hysteria execution borrowed unrelated global capability")
        for target in ("windows/amd64", "linux/amd64"):
            raw = complete(target)
            self.assertFalse(D.verdict(raw.replace(b"hysteria-execution-global", b"omitted-hysteria"), target, 0, False, True)["accepted"])

    def test_windows_profile_receipts_require_all_completed_cases_in_the_original_groups(self):
        raw = complete("windows/amd64")
        for receipt in D.WINDOWS_PROFILE_RECEIPTS:
            line = (receipt + "\n").encode()
            for changed in (raw.replace(line, b""), raw + line, raw.replace(line, line.replace(b"ordered=", b"ordered=99,"))):
                self.assertFalse(D.verdict(changed, "windows/amd64", 0, False, True)["accepted"])

    def test_windows_suite_budget_covers_each_original_bounded_command(self):
        source = (D.ROOT / "deploy/test_desktop_connection_profile_modes.py").read_text(encoding="utf-8")
        self.assertEqual(D.windows_suite_budget(source), 6030)
        self.assertEqual(D.windows_suite_budget(source), (1 + 6 + 21 + 6 + 33) * 90)
        self.assertIn('execute("gtk-profiles", command, 900)', Path(D.__file__).read_text(encoding="utf-8"))

    def test_windows_suite_budget_refuses_changed_child_or_case_inventory(self):
        source = (D.ROOT / "deploy/test_desktop_connection_profile_modes.py").read_text(encoding="utf-8")
        changes = (
            source.replace("timeout=90", "timeout=91", 1),
            source.replace("timeout=90", "timeout=None", 1),
            source.replace('    "capture-two-modes":', '    "missing-control":', 1),
            source.replace('    "pair-local":', '    "pair-local": (), "pair-local":', 1),
            source.replace('for group, cases in WINDOWS_PROFILE_GROUPS.items():', 'for group, cases in {}.items():', 1),
            source.replace('["-TransactionOnly"]', '["-Mutation", "shipping"]', 1),
            source.replace('    windows_editor(shell)', '    windows_editor(shell)\n    windows_editor(shell)', 1),
            source.replace('def windows_editor(shell):', 'def omitted_windows_editor(shell):', 1),
            source.replace("'socks-execution-global': 'SOCKS execution borrowed unrelated global capability',", '', 1),
            source.replace("'SOCKS execution borrowed unrelated global capability'", "'unrelated failure'", 1),
            source.replace('def windows(shell):', 'def omitted_windows(shell):', 1),
        )
        for changed in changes:
            self.assertNotEqual(source, changed)
            with self.assertRaises(ValueError):
                D.windows_suite_budget(changed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
