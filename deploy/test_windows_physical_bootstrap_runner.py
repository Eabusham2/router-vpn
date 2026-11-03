#!/usr/bin/env python3
"""Exercise bootstrap source ownership and explicit prospective overlay bounds."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("windows_bootstrap_runner_test", ROOT / "deploy/test_windows_physical_bootstrap.py")
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)
spec = importlib.util.spec_from_file_location("windows_external_runner_test", ROOT / "deploy/test_windows_external_physical.py")
EXTERNAL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(EXTERNAL)


class ExternalOutputBoundary(unittest.TestCase):
    def report(self, status, output):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n")
        self.addCleanup(stream.close)
        with contextlib.redirect_stdout(stream):
            EXTERNAL.report_baseline("command", ("NativeComposition",), status, output)
        return raw.getvalue()

    def test_redirected_cp1252_preserves_exact_utf8_native_output(self):
        output = "native path \u2192 Caf\u00e9/\u6771\u4eac\n--- PASS: NativeComposition (0.01s)\n"
        self.assertEqual(self.report(0, output), output.encode("utf-8"))

    def test_encoding_never_turns_failed_or_incomplete_native_output_into_success(self):
        success = "native path \u2192 selected exit\n--- PASS: NativeComposition (0.01s)\n"
        for status, output in ((1, success), (0, "native path \u2192 selected exit\n"),
                               (0, success + "--- SKIP: AnotherCase (0.01s)\n"),
                               (0, success + "WARNING: DATA RACE\n")):
            with self.subTest(status=status, output=output):
                raw = io.BytesIO()
                with io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n") as stream:
                    with contextlib.redirect_stdout(stream), self.assertRaisesRegex(ValueError, "did not prove its native composition"):
                        EXTERNAL.report_baseline("command", ("NativeComposition",), status, output)
                    self.assertEqual(raw.getvalue(), output.encode("utf-8"))


class ExternalRetainedJournalInventory(unittest.TestCase):
    def test_latency_observer_requires_every_exact_boundary_verdict(self):
        self.assertEqual(len(EXTERNAL.LATENCY_OBSERVATION_CASES), 13)
        runs = EXTERNAL.baseline_runs("box", "unused", ())
        selected = [(name, required) for name, _, required in runs if set(required) & set(EXTERNAL.LATENCY_OBSERVATION_CASES)]
        self.assertEqual(selected, [("box", EXTERNAL.LATENCY_OBSERVATION_CASES)])
        required = EXTERNAL.LATENCY_OBSERVATION_CASES
        complete = "".join("--- PASS: " + name + " (0.01s)\n" for name in required)
        with contextlib.redirect_stdout(io.StringIO()):
            EXTERNAL.report_baseline("latency-observation", required, 0, complete)
        for name in required:
            line = "--- PASS: " + name + " (0.01s)\n"
            for changed in (complete.replace(line, ""), complete + line, complete.replace(line, "prefix " + line)):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                    EXTERNAL.report_baseline("latency-observation", required, 0, changed)

    def test_every_new_journal_root_is_mandatory(self):
        expected_command = tuple("TestRouterVPNDesktopExternalPhysicalCommandJournal" + name for name in (
            "BeforePrivateInputs", "PublicRequiresCompleteCapture", "WindowsHasNoFileFallback", "RetainedPipeline",
            "PartialRetirementRequiresJoin", "AdmissionCloseJoinsCallback", "TransferInput", "RetirementReceipt",
            "LegacyUnprotectedPolicy", "LegacyUnprotectedPublicStop", "ParserOwnedFlags"))
        expected_factory = (
            "TestRouterVPNExternalPhysicalJournalAdmissionCapturesDurableBarrier",
            "TestRouterVPNExternalPhysicalRetirementKeepsExactJoinedSource",
            "TestRouterVPNExternalPhysicalWindowsRetirementKeepsOriginalPredecessor",
        )
        self.assertEqual(EXTERNAL.JOURNAL_COMMAND_CASES, expected_command)
        self.assertEqual(EXTERNAL.JOURNAL_FACTORY_CASES, expected_factory)
        for required in (expected_command, expected_factory):
            complete = "".join("--- PASS: " + name + " (0.01s)\n" for name in required)
            with contextlib.redirect_stdout(io.StringIO()):
                EXTERNAL.report_baseline("journal", required, 0, complete)
            for name in required:
                with self.subTest(missing=name), contextlib.redirect_stdout(io.StringIO()):
                    incomplete = complete.replace("--- PASS: " + name + " (0.01s)\n", "")
                    with self.assertRaisesRegex(ValueError, "did not prove its native composition"):
                        EXTERNAL.report_baseline("journal", required, 0, incomplete)



    def test_actual_dispatch_retains_journal_requirements_and_source_recheck(self):
        with tempfile.TemporaryDirectory(prefix="windows-external-dispatch-") as temporary:
            core = Path(temporary).resolve()
            calls = []
            observed = {}
            names = set()
            for path in (ROOT / "mobile/desktop").glob("*.go.tmpl"):
                names.update(re.findall(r"^func (Test\w+)\(", path.read_text(), re.MULTILINE))
            # A parent/root PASS never substitutes for its exact native child
            # verdicts at this explicit process boundary.
            names.update(EXTERNAL.HYSTERIA2_BOX_CASES)
            names.update(EXTERNAL.HYSTERIA2_LAYER_BOX_CASES)
            names.update(EXTERNAL.HYSTERIA2_FACTORY_CASES)
            names.update(EXTERNAL.SOCKS_BOX_CASES)
            names.update(EXTERNAL.SOCKS_FACTORY_CASES)
            names.update(EXTERNAL.PACKET_BOX_CASES)
            names.update(EXTERNAL.STREAM_BOX_CASES)
            names.update(EXTERNAL.LATENCY_OBSERVATION_CASES)
            names.update(EXTERNAL.PACKET_FACTORY_CASES)
            names.update(EXTERNAL.PACKET_COMMANDS)
            names.update(EXTERNAL.OPENVPN_COMMAND_CASES)
            names.update(EXTERNAL.OPENVPN_FACTORY_CASES)
            names.update("TestRouterVPNDesktopExternalPhysicalIntegration/latency50/" + leaf for leaf in EXTERNAL.LATENCY_BOUNDARIES)
            parent = "TestRouterVPNDesktopExternalPhysicalIntegration"
            names.update(parent + "/" + leaf for leaf in ("delayed-accept-retains-prior-grant", "network-reset-during-mtu", "network-reset-after-native-publication", "network-reset-during-real-proof"))

            def run(command, **kwargs):
                calls.append(tuple(str(value) for value in command))
                self.assertEqual(kwargs["cwd"], core)
                if str(command[0]) == "owned-go":
                    self.assertIn("-mod=readonly", command)
                    self.assertIn("-race", command)
                    self.assertIn("-ldflags=-checklinkname=0", command)
                    binary = Path(command[command.index("-o") + 1])
                    binary.write_bytes(b"explicit native compiler model")
                    return 0, ""
                selection = next(str(value).removeprefix("-test.run=") for value in command if str(value).startswith("-test.run="))
                def selected(name):
                    return all(re.search(pattern, part) for pattern, part in zip(selection.split("/"), name.split("/")))
                output = "".join("--- PASS: " + name + " (0.01s)\n" for name in sorted(names) if selected(name))
                return 0, output

            actual_report = EXTERNAL.report_baseline
            def report(name, required, status, output):
                observed[name] = required
                return actual_report(name, required, status, output)

            # Only the external runner's source/compiler/OS boundaries are
            # modeled. Its complete dispatch, mandatory verdict checks, image
            # identity checks and final source recheck execute unchanged.
            with patch.object(EXTERNAL.platform, "system", return_value="Windows"), \
                 patch.object(EXTERNAL, "checked_sources", return_value=(core, {"original": "captured"})) as sources, \
                 patch.object(EXTERNAL.IDENTITY, "selected_compiler", return_value=("owned-go", {}, "amd64")), \
                 patch.object(EXTERNAL.IDENTITY, "run", side_effect=run), \
                 patch.object(EXTERNAL, "mutants", return_value=()), \
                 patch.object(EXTERNAL, "report_baseline", side_effect=report), \
                 contextlib.redirect_stdout(io.StringIO()):
                EXTERNAL.execute(core)
            self.assertEqual(sources.call_count, 2)
            self.assertTrue({"command", "box", "factory"}.issubset(observed))
            self.assertTrue(set(EXTERNAL.JOURNAL_COMMAND_CASES).issubset(observed["command"]))
            self.assertTrue(set(EXTERNAL.JOURNAL_FACTORY_CASES).issubset(observed["factory"]))
            self.assertIn(EXTERNAL.HYSTERIA2_COMMAND, observed["command"])
            self.assertTrue(set(EXTERNAL.HYSTERIA2_BOX_CASES).issubset(set().union(*(set(required) for name, required in observed.items() if name.startswith("box")))))
            self.assertTrue(set(EXTERNAL.HYSTERIA2_FACTORY_CASES).issubset(observed["factory"]))
            self.assertEqual(len(calls), 28)



class ExternalHysteria2Inventory(unittest.TestCase):
    def test_layered_encrypted_inventory_is_complete_and_partitioned_once(self):
        expected = tuple(case.replace("hysteria2", mode) for mode in ("hysteria2-aes", "hysteria2-aes-xor") for case in EXTERNAL.HYSTERIA2_BOX_CASES) + (
            "TestRouterVPNDesktopExternalPhysicalIntegration/hysteria2-aes/reject/layer-key",
            "TestRouterVPNDesktopExternalPhysicalIntegration/hysteria2-aes-xor/reject/layer-key",
            "TestRouterVPNDesktopExternalPhysicalIntegration/hysteria2-aes-xor/reject/whitening")
        self.assertEqual(EXTERNAL.HYSTERIA2_LAYER_BOX_CASES, expected)
        self.assertEqual(len(expected), 33)
        runs = EXTERNAL.baseline_runs("box", "original", expected)
        self.assertCountEqual([case for _, _, required in runs for case in required if case in expected], expected)
        output = "".join("--- PASS: " + case + " (0.01s)\n" for case in expected)
        for case in expected:
            with self.subTest(missing=case), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                EXTERNAL.report_baseline("hy2-layer", expected, 0, output.replace("--- PASS: " + case + " (0.01s)\n", ""))

    def test_actual_encrypted_udp_mtu_latency_and_negative_leaves_are_required(self):
        self.assertEqual(EXTERNAL.HYSTERIA2_COMMAND,
                         "TestRouterVPNDesktopExternalPhysicalCommandHysteria2SupportedTargets")
        expected_box = tuple("TestRouterVPNDesktopExternalPhysicalIntegration/" + leaf for leaf in (
            "hysteria2/proof-and-mtu", "hysteria2/reject/dns", "hysteria2/reject/exit", "hysteria2/reject/credential",
            "hysteria2/reject/tls-name", "hysteria2/reject/tls-root", "hysteria2/reject/lower-denied",
            "hysteria2/reject/peer-tls-name", "hysteria2/reject/truncated", "hysteria2/cancelled-proof",
            "latency50/hysteria2", "latency50/hysteria2/source", "latency50/hysteria2/capture",
            "latency50/hysteria2/session", "latency50/hysteria2/current"))
        expected_factory = ("TestRouterVPNExternalPhysicalStartupSocketPhase/hysteria2",
                            "TestRouterVPNExternalPhysicalActualBytesAndCapturedTuple/hysteria2-udp")
        self.assertEqual(EXTERNAL.HYSTERIA2_BOX_CASES, expected_box)
        self.assertEqual(EXTERNAL.HYSTERIA2_FACTORY_CASES, expected_factory)
        for required in ((EXTERNAL.HYSTERIA2_COMMAND,), expected_box, expected_factory):
            output = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            with contextlib.redirect_stdout(io.StringIO()):
                EXTERNAL.report_baseline("hysteria2", required, 0, output)
            for case in required:
                with self.subTest(missing=case), contextlib.redirect_stdout(io.StringIO()):
                    without = output.replace("--- PASS: " + case + " (0.01s)\n", "")
                    with self.assertRaisesRegex(ValueError, "did not prove its native composition"):
                        EXTERNAL.report_baseline("hysteria2", required, 0, without)


class BootstrapOverlayBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="windows-bootstrap-source-")
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.root, self.core = self.workspace / "repository", self.workspace / "native"
        copies = GATE.PREP.pt_copies()
        for package in ("common", "mobiletor"):
            incoming = ROOT / "internal" / package
            copied = self.root / "internal" / package
            copied.mkdir(parents=True)
            destination = self.core / "routervpn" / package
            destination.mkdir(parents=True)
            for source in incoming.glob("*.go"):
                raw = source.read_bytes()
                (copied / source.name).write_bytes(raw)
                (destination / source.name).write_bytes(GATE.PREP.relocated_shared_source(raw))
        for relative, raw in copies.items():
            target = self.core / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        resources = self.root / "deploy/fixtures/windows-physical-bootstrap"
        shutil.copytree(GATE.RESOURCES, resources)
        registry = self.core / "include/registry.go"
        registry.parent.mkdir()
        registry.write_bytes(GATE.PREP.pt_registry_source('''package include
import (
\t"github.com/sagernet/sing-box/service/resolved"
)
func ServiceRegistry() *service.Registry {
\tresolved.RegisterService(registry)
}
func OutboundRegistry() *outbound.Registry {
\tsocks.RegisterOutbound(registry)
}
func DNSTransportRegistry() *dns.TransportRegistry {
\ttransport.RegisterTCP(registry)
}
'''))
        self.addCleanup(patch.stopall)
        patch.object(GATE, "ROOT", self.root).start()
        patch.object(GATE, "RESOURCES", resources).start()
        patch.object(GATE.IDENTITY, "ROOT", self.root).start()
        patch.object(GATE.PREP, "pt_copies", return_value=copies).start()
        # This unit boundary supplies an already selected pinned directory.
        # The actual Windows gate independently checks the Git commit.
        patch.object(GATE.PREP, "checked_vendor", side_effect=lambda path: Path(path).resolve()).start()

    def test_exact_prepared_sources_and_test_resources_are_read_only(self):
        source, before = GATE.sources(self.core)
        self.assertEqual(source, self.core)
        self.assertIn("routervpn/desktoppt/tor_physical_windows.go", before)
        self.assertIn("routervpn/mobiletor/desktop_bridge.go", before)
        self.assertIn("fixture/kernel_observer.go", before)
        self.assertTrue(all("\\" not in name for name in before))
        work = self.workspace / "overlay"
        work.mkdir()
        selected = json.loads(GATE.overlay(source, work, True).read_text())["Replace"]
        self.assertEqual(len(selected), 8)
        for path in selected.values():
            self.assertTrue(Path(path).is_relative_to(work))
        self.assertEqual(GATE.sources(source)[1], before)
        self.assertFalse((source / "routervpn_windows_physical_composition_test.go").exists())

    def test_changed_compiler_factory_and_socket_copies_are_rejected(self):
        for relative in ("routervpn/mobiletor/desktop_bridge.go", "routervpn/desktoppt/tor_physical_windows.go",
                         "routervpn/mobiletor/desktop_socket_windows_policy.go"):
            with self.subTest(relative=relative):
                path = self.core / relative
                before = path.read_bytes()
                try:
                    path.write_bytes(before + b"// altered copied source\n")
                    with self.assertRaises(ValueError):
                        GATE.sources(self.core)
                finally:
                    path.write_bytes(before)
        GATE.sources(self.core)

    def test_changed_native_registration_is_rejected(self):
        path = self.core / "include/registry.go"
        path.write_text(path.read_text().replace("routervpndesktoppt.RegisterPhysicalOutbound(registry)", "other.RegisterPhysicalOutbound(registry)"))
        with self.assertRaises(ValueError):
            GATE.sources(self.core)

    def test_ordinary_mode_never_overlays_os_admission(self):
        work = self.workspace / "ordinary"
        work.mkdir()
        selected = json.loads(GATE.overlay(self.core, work, False).read_text())["Replace"]
        self.assertEqual(len(selected), 5)
        for path in ("routervpn/mobiletor/desktop_bridge.go", "routervpn/mobiletor/desktop_physical_policy.go",
                     "routervpn_desktop_tor_box_physical.go"):
            self.assertNotIn(str(self.core / path), selected)

    def test_overlay_refuses_existing_foreign_test_source(self):
        path = self.core / "routervpn_windows_physical_composition_test.go"
        path.write_text("// another owner's test file\n")
        work = self.workspace / "foreign"
        work.mkdir()
        with self.assertRaisesRegex(ValueError, "Unowned bootstrap test"):
            GATE.overlay(self.core, work, True)
        self.assertEqual(path.read_text(), "// another owner's test file\n")

    def test_fixture_tag_cannot_enter_an_ordinary_binary(self):
        path = GATE.RESOURCES / "kernel_observer.go"
        path.write_bytes(path.read_bytes().replace(b"windows && routervpn_windows_physical_composition", b"windows"))
        with self.assertRaisesRegex(ValueError, "compile-time test tag"):
            GATE.sources(self.core)

    def test_static_os_change_preserves_other_platform_boundary(self):
        paths = ("routervpn/mobiletor/desktop_bridge.go", "routervpn/mobiletor/desktop_physical_policy.go",
                 "routervpn_desktop_tor_box_physical.go")
        original = [self.core.joinpath(path).read_text() for path in paths]
        bridge, policy, box = GATE.prospective_admission(*original)
        self.assertIn('return targetOS == "linux" || targetOS == "windows"', policy)
        self.assertNotIn('targetOS == "darwin"', policy)
        self.assertIn("DesktopPhysicalBrokerSupported(targetOS)", bridge)
        self.assertIn("mobiletor.DesktopPhysicalBrokerSupported(runtime.GOOS)", box)
        for current in ('targetOS == "linux"', 'targetOS == "linux" || targetOS == "darwin"'):
            with self.subTest(current=current):
                shared = policy.replace('targetOS == "linux" || targetOS == "windows"', current)
                _, changed, _ = GATE.prospective_admission(bridge, shared, box)
                self.assertIn("return " + current + ' || targetOS == "windows"', changed)
        unsafe = policy.replace('return targetOS == "linux" || targetOS == "windows"', 'return true')
        with self.assertRaisesRegex(ValueError, "predicate changed"):
            GATE.prospective_admission(bridge, unsafe, box)


class ExternalPacketInventory(unittest.TestCase):
    def test_baseline_rejects_prefixed_duplicate_or_failed_verdicts(self):
        required = ("TestActual/owned",)
        valid = "    --- PASS: TestActual/owned (0.01s)\n"
        with contextlib.redirect_stdout(io.StringIO()):
            EXTERNAL.report_baseline("owned", required, 0, valid)
        for invalid in (valid + valid, "diagnostic " + valid.strip() + "\n", valid.rstrip() + " trailing\n",
                        *(valid + marker for marker in ("--- FAIL: TestOther", "--- SKIP: TestOther", "DATA RACE", "panic: timed out", "fatal error: broken", "[build failed]"))):
            with self.subTest(output=invalid), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):
                    EXTERNAL.report_baseline("owned", required, 0, invalid)

    def test_openvpn_commands_and_eager_phase_require_each_original_remote_case(self):
        self.assertEqual(len(EXTERNAL.OPENVPN_COMMAND_CASES), 37)
        self.assertEqual(len(EXTERNAL.OPENVPN_FACTORY_CASES), 3)
        for required in (EXTERNAL.OPENVPN_COMMAND_CASES, EXTERNAL.OPENVPN_FACTORY_CASES):
            output = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            for case in required:
                with self.subTest(missing=case), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(ValueError):
                        EXTERNAL.report_baseline("openvpn", required, 0, output.replace("--- PASS: " + case + " (0.01s)\n", ""))

    def test_packet_guards_and_all_encrypted_verdicts_are_required(self):
        self.assertEqual(len(EXTERNAL.PACKET_FACTORY_CASES), 6)
        self.assertEqual(len(EXTERNAL.PACKET_BOX_CASES), 47)
        for required in (EXTERNAL.PACKET_COMMANDS, EXTERNAL.PACKET_BOX_CASES, EXTERNAL.PACKET_FACTORY_CASES):
            output = "".join("--- PASS: " + case + " (0.01s)\n" for case in required)
            for case in required:
                with self.subTest(missing=case), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(ValueError):
                        EXTERNAL.report_baseline("packet", required, 0, output.replace("--- PASS: " + case + " (0.01s)\n", ""))
        all_cases = EXTERNAL.HYSTERIA2_BOX_CASES + EXTERNAL.HYSTERIA2_LAYER_BOX_CASES + EXTERNAL.SOCKS_BOX_CASES + EXTERNAL.PACKET_BOX_CASES
        runs = EXTERNAL.baseline_runs("box", "original", ("TestRouterVPNDesktopExternalPhysicalBoxRequiresPreparedStartedOwner", *all_cases))
        actual = [case for _, _, required in runs for case in required if case in all_cases]
        self.assertCountEqual(actual, all_cases)
        self.assertEqual(EXTERNAL.LATENCY_BOUNDARIES, ("latency-dns", "latency-tls", "latency-partial", "cancel", "network", "native-owner"))
        self.assertTrue(set("TestRouterVPNDesktopExternalPhysicalIntegration/latency50/" + leaf for leaf in EXTERNAL.LATENCY_BOUNDARIES).issubset(set(case for _, _, required in runs for case in required)))
        for name, selection, required in runs:
            self.assertTrue(required)
            if name != "box":
                self.assertTrue(selection.startswith("^TestRouterVPNDesktopExternalPhysicalIntegration$/"))


if __name__ == "__main__":
    unittest.main()
