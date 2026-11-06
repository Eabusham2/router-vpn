#!/usr/bin/env python3
"""Check privileged routing execution retains its exact native fixture owner."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("desktop_node_routing_gate", ROOT / "deploy/test_desktop_node_physical.py")
NODE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NODE)


class ExactPerformanceMutationBoundary(unittest.TestCase):
    def test_actual_legacy_methods_do_not_mutate_contextual_siblings(self):
        cases = (
            ("mobile/performance/service.go.tmpl",
             "func (s *Service) resolve(tag string, seen map[string]bool) (adapter.Outbound, string, error) {",
             "func (s *Service) resolveContext(",
             "if composite, ok := out.(*routervpncomposite.Outbound); ok {",
             "if composite, ok := out.(*routervpncomposite.Outbound); false && ok {"),
            ("mobile/performance/service.go.tmpl",
             "func (s *Service) resolve(tag string, seen map[string]bool) (adapter.Outbound, string, error) {",
             "func (s *Service) resolveContext(", "switch out.Type() {",
             'switch out.Type() {\n\tcase "routervpn-composite":\n\t\treturn out, identity, nil'),
            ("mobile/composite/outbound.go.tmpl",
             "func (h *Outbound) RouterVPNPerformanceIdentity() string {",
             "func (h *Outbound) RouterVPNPerformanceIdentityContext(",
             "|| currentTCP != tcp ||", "|| false && currentTCP != tcp ||"),
            ("mobile/composite/outbound.go.tmpl",
             "func (h *Outbound) RouterVPNPerformanceIdentity() string {",
             "func (h *Outbound) RouterVPNPerformanceIdentityContext(",
             "|| currentUDP != udp {", "|| false && currentUDP != udp {"),
        )
        for name, signature, sibling, before, after in cases:
            with self.subTest(source=name, mutation=before):
                path = ROOT / name
                original = path.read_text()
                self.assertEqual(original.count(before), 2)
                changed = NODE.mutation_in_function(original, signature, before, after)
                boundary = original.index(sibling)
                self.assertEqual(changed[changed.index(sibling):], original[boundary:])
                self.assertEqual(changed, original.replace(before, after, 1))
                self.assertEqual(path.read_text(), original)

    def test_missing_duplicate_and_wrong_method_fail_closed(self):
        signature = "func (s *Service) selected() {"
        raw = "package sample\n\n" + signature + "\n unique()\n}\nfunc sibling() {\n unique()\n}\n"
        for value, target, before in (
            (raw, signature.replace("selected", "missing"), "unique()"),
            (raw + "\n" + signature + "\n unique()\n}\n", signature, "unique()"),
            (raw.replace(" unique()", " unique(); unique()", 1), signature, "unique()"),
            (raw.replace(" unique()", " absent()", 1), signature, "unique()"),
        ):
            with self.subTest(source=value, target=target):
                with self.assertRaises(ValueError):
                    NODE.mutation_in_function(value, target, before, "broken()")

    def test_unix_interface_control_preserves_contextual_observer(self):
        original = (ROOT / "mobile/desktop/node_physical_linux.go.tmpl").read_text()
        before = "return actual != nil && actual.Index == index"
        after = "return actual != nil && (actual.Index == index || actual.Index != index)"
        self.assertEqual(original.count("actual.Index == index"), 2)
        changed = NODE.BOOT.IDENTITY.replace_once(original, before, after)
        marker = "physicalCurrentContext := func("
        self.assertEqual(changed[changed.index(marker):], original[original.index(marker):])
        with self.assertRaises(ValueError):
            NODE.BOOT.IDENTITY.replace_once(original + "\n" + before, before, after)


class NativeStartupTransportVerdicts(unittest.TestCase):
    def test_original_supervised_startup_transport_is_required(self):
        self.assertEqual({key: len(value) for key, value in NODE.STARTUP_TRANSPORT_VERDICTS.items()}, {"native-startup-transport": 17, "native-startup-codec": 10})
        for family, names in NODE.STARTUP_TRANSPORT_VERDICTS.items():
            suite = (family, "actual-generated-package", "original-startup", tuple(name for name in names if "/" not in name))
            lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
            baseline = Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                baseline.execute.return_value = (0, "".join(lines))
                NODE.execute_baseline_suite(baseline, suite)
                for line in lines:
                    for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line):
                        baseline.execute.return_value = (0, changed)
                        with self.assertRaises(ValueError):
                            NODE.execute_baseline_suite(baseline, suite)


class TorRegistrationContextVerdicts(unittest.TestCase):
    def test_every_original_registration_verdict_is_required(self):
        self.assertEqual({key: len(value) for key, value in NODE.TOR_REGISTRATION_VERDICTS.items()}, {"tor-registration-owner": 6, "tor-registration-policy": 3, "tor-registration-box": 4})
        for family, names in NODE.TOR_REGISTRATION_VERDICTS.items():
            suite = (family, "actual-generated-package", "original-registration", tuple(name for name in names if "/" not in name))
            lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
            baseline = Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                baseline.execute.return_value = (0, "".join(lines))
                NODE.execute_baseline_suite(baseline, suite)
                for line in lines:
                    for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line):
                        baseline.execute.return_value = (0, changed)
                        with self.assertRaises(ValueError):
                            NODE.execute_baseline_suite(baseline, suite)


class NativeStartupContextVerdicts(unittest.TestCase):
    def test_original_startup_deadlines_are_required(self):
        self.assertEqual({key:len(value) for key,value in NODE.STARTUP_CONTEXT_VERDICTS.items()}, {"native-startup-inbound":4, "native-startup-box":6, "native-startup-command":4})
        for family,names in NODE.STARTUP_CONTEXT_VERDICTS.items():
            suite=(family,"actual-generated-package","original-startup",tuple(name for name in names if "/" not in name))
            lines=[line for name in names for line in ("=== RUN   "+name+"\n","--- PASS: "+name+" (0.01s)\n")]
            baseline=Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                baseline.execute.return_value=(0,"".join(lines)); NODE.execute_baseline_suite(baseline,suite)
                for line in lines:
                    for changed in ("".join(lines).replace(line,"",1),"".join(lines)+line):
                        baseline.execute.return_value=(0,changed)
                        with self.assertRaises(ValueError): NODE.execute_baseline_suite(baseline,suite)


class NativeLifecycleAdmissionVerdicts(unittest.TestCase):
    def test_original_admission_and_completed_cleanup_are_required(self):
        names = NODE.NATIVE_LIFECYCLE_ADMISSION_VERDICTS
        self.assertEqual(len(names), 15)
        output = "".join("=== RUN   " + name + "\n--- PASS: " + name + " (0.01s)\n" for name in names)
        NODE.require_native_verdicts(output, names, "lifecycle admission")
        for name in names:
            with self.subTest(missing=name):
                with self.assertRaises(ValueError):
                    NODE.require_native_verdicts(output.replace("--- PASS: " + name + " (0.01s)\n", "", 1), names, "lifecycle admission")
        with self.assertRaises(ValueError):
            NODE.require_native_verdicts(output+output, names, "lifecycle admission")


class LinuxLayeredEntryVerdicts(unittest.TestCase):
    def test_generated_original_entry_runs_and_passes_exactly_once(self):
        suite = NODE.LINUX_LAYERED_ENTRY_SUITE
        self.assertEqual(len(suite[3]), 3)
        output = ''.join('=== RUN   ' + name + '\n--- PASS: ' + name + ' (0.01s)\n' for name in suite[3])
        baseline = Mock()
        with contextlib.redirect_stdout(io.StringIO()):
            baseline.execute.return_value = (0, output)
            NODE.execute_baseline_suite(baseline, suite)
            baseline.execute.assert_called_once_with(*suite[:3], 90)
            for line in output.splitlines(True):
                for changed in (output.replace(line, '', 1), output + line, output.replace(line, line.replace('Root', 'ForeignRoot'), 1)):
                    baseline.execute.return_value = (0, changed)
                    with self.assertRaises(ValueError):
                        NODE.execute_baseline_suite(baseline, suite)
            for marker in ('--- SKIP:', '--- FAIL:', 'DATA RACE', 'panic:'):
                baseline.execute.return_value = (0, output + marker + ' foreign\n')
                with self.assertRaises(ValueError):
                    NODE.execute_baseline_suite(baseline, suite)


class LinuxSSEntryVerdicts(unittest.TestCase):
    def test_original_physical_and_actual_cipher_verdicts_are_mandatory(self):
        for suite, count in ((NODE.LINUX_SS_ENTRY_SUITE, 4), (NODE.SS_ENTRY_REFERENCE_SUITE, 17),
                             (NODE.LINUX_SS_CONNECT_SUITE, 3), (NODE.SS_CONNECT_REFERENCE_SUITE, 15)):
            self.assertEqual(len(suite[3]), count)
            output = ''.join('=== RUN   ' + name + '\n--- PASS: ' + name + ' (0.01s)\n' for name in suite[3])
            baseline = Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                baseline.execute.return_value = (0, output)
                NODE.execute_baseline_suite(baseline, suite)
                baseline.execute.assert_called_once_with(*suite[:3], 90)
                for line in output.splitlines(True):
                    for changed in (output.replace(line, '', 1), output + line, output.replace(line, line.replace('TestRouterVPN', 'TestForeignVPN'), 1)):
                        baseline.execute.return_value = (0, changed)
                        with self.subTest(suite=suite[0], verdict=line.strip()), self.assertRaises(ValueError):
                            NODE.execute_baseline_suite(baseline, suite)
                for marker in ('--- SKIP:', '--- FAIL:', 'DATA RACE', 'panic:'):
                    baseline.execute.return_value = (0, output + marker + ' foreign\n')
                    with self.assertRaises(ValueError):
                        NODE.execute_baseline_suite(baseline, suite)


class StandardServiceMTUVerdicts(unittest.TestCase):
    def test_actual_standard_reader_verdict_cannot_be_omitted_or_substituted(self):
        for suite, expected in ((NODE.STANDARD_MTU_SUITE, 9), (NODE.STANDARD_MTU_RETIRE_SUITE, 3),
                                (NODE.STANDARD_PARENT_SUITE, 6), (NODE.STANDARD_PARENT_NATIVE_SUITE, 2)):
            names = suite[3]
            self.assertEqual(len(names), expected)
            output = "".join("=== RUN   " + name + "\n--- PASS: " + name + " (0.01s)\n" for name in names)
            baseline = Mock()
            baseline.execute.return_value = (0, output)
            with contextlib.redirect_stdout(io.StringIO()):
                NODE.execute_baseline_suite(baseline, suite)
                baseline.execute.assert_called_once_with(*suite[:3], 90)
                for name in names:
                    for changed in (output.replace("--- PASS: " + name + " (0.01s)\n", "", 1),
                                    output + "--- PASS: " + name + " (0.01s)\n",
                                    output.replace(name, name + "Foreign"),
                                    output.replace("--- PASS: " + name, "--- SKIP: " + name),
                                    output.replace("--- PASS: " + name, "--- FAIL: " + name)):
                        baseline.execute.return_value = (0, changed)
                        with self.subTest(name=name, changed=changed), self.assertRaises(ValueError):
                            NODE.execute_baseline_suite(baseline, suite)


    def test_actual_claim_failure_requires_native_cleanup_and_child_join(self):
        suite = NODE.STANDARD_MTU_NATIVE_SUITE
        self.assertEqual(len(suite[3]), 3)
        output = "".join("=== RUN   " + name + "\n--- PASS: " + name + " (0.01s)\n" for name in suite[3])
        baseline = Mock()
        with contextlib.redirect_stdout(io.StringIO()):
            baseline.execute.return_value = (0, output)
            NODE.execute_baseline_suite(baseline, suite)
            baseline.execute.assert_called_once_with(*suite[:3], 90)
            for name in suite[3]:
                for changed in (output.replace("--- PASS: " + name + " (0.01s)\n", "", 1),
                                output + "--- PASS: " + name + " (0.01s)\n",
                                output.replace(name, name + "Foreign"),
                                output.replace("--- PASS: " + name, "--- SKIP: " + name),
                                output.replace("--- PASS: " + name, "--- FAIL: " + name)):
                    baseline.execute.return_value = (0, changed)
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        NODE.execute_baseline_suite(baseline, suite)


class NativeAddressRetirementVerdicts(unittest.TestCase):
    def test_partial_and_foreign_address_verdicts_cannot_be_omitted(self):
        names = NODE.NATIVE_ADDRESS_RETIREMENT_VERDICTS
        self.assertEqual(len(names), 67)
        output = "".join("=== RUN   " + name + "\n--- PASS: " + name + " (0.01s)\n" for name in names)
        NODE.require_native_verdicts(output, names, "partial addresses")
        for name in names:
            with self.subTest(missing=name):
                with self.assertRaises(ValueError):
                    NODE.require_native_verdicts(output.replace("--- PASS: " + name + " (0.01s)\n", "", 1), names, "partial addresses")
        with self.assertRaises(ValueError):
            NODE.require_native_verdicts(output+output, names, "partial addresses")


class NativeRetirementVerdicts(unittest.TestCase):
    def test_every_real_tun_leaf_is_required_exactly_once(self):
        root = "TestRouterVPNNativeLinuxRoutingRetirementNamespace"
        suite = ("native-routing-receipt", "github.com/sagernet/sing-tun", "^TestRouterVPNNativeLinuxRouting", (root,))
        lines = ["--- PASS: " + root + " (1s)\n"] + ["    --- PASS: " + root + "/" + case + " (0.1s)\n" for case in NODE.NATIVE_RETIREMENT_CASES]
        lines += ["--- PASS: TestRouterVPNNativeLinuxRoutingDNSAddressBoundary" + ("/" + case if case else "") + " (0.01s)\n" for case in ("", *NODE.NATIVE_DNS_CASES)]
        self.assertEqual(len(NODE.NATIVE_CLOSED_EVENT_VERDICTS), 13)
        lines += [line for name in NODE.NATIVE_CLOSED_EVENT_VERDICTS for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
        baseline = Mock()
        baseline.execute.return_value = (0, "".join(lines))
        with contextlib.redirect_stdout(io.StringIO()):
            NODE.execute_baseline_suite(baseline, suite)
            baseline.execute.assert_called_once_with(*suite[:3], 90)
            for line in lines[1:]:
                for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line,
                                "".join(lines).replace(line, line.replace("\n", "-unselected\n") if line.startswith("=== RUN") else line.replace(" (", "-unselected ("), 1)):
                    with self.subTest(line=line, changed=changed):
                        baseline.execute.return_value = (0, changed)
                        with self.assertRaisesRegex(ValueError, "actual original-TUN retirement leaf|captured DNS address verdict|closed-event diagnostic verdict"):
                            NODE.execute_baseline_suite(baseline, suite)


class NativeObservationVerdicts(unittest.TestCase):
    def test_actual_heartbeat_caller_budget_and_original_stop(self):
        subprocess.run([sys.executable, str(ROOT/'deploy/test_node_heartbeat_context.py')], check=True, timeout=190)

    def test_bounded_native_observations_require_each_selected_verdict(self):
        identity = "TestRouterVPNNativeIdentityObservationPreservesHealthyOwner"
        command = ["TestRouterVPNDesktopNetworkProjectionContextPreservesObservationErrors",
                   "TestRouterVPNDesktopNativeNetworkProjectionCancelsHeldOwnerLock",
                   "TestRouterVPNDesktopStopInterruptsOriginalNetworkObserver"]
        tor = "TestRouterVPNDesktopTorObservationRevokesWithoutJoiningCleanup"
        lease = "TestOpenVPNLeaseObservationKeepsGenuineFailureAlongsideCancellation"
        suites = [
            (("external-lease-observation", "./experimental/libbox/routervpn/mobilemultihop", "^" + lease + "$", (lease,)),
             [lease, lease + "/OK", lease + "/Service_Unavailable"]),
            (("native-identity-context", ".", "^" + identity + "$", (identity,)),
             [identity] + [identity + "/" + leaf for leaf in ("engine-lock", "physical-read", "genuine-replacement", "mixed-loss-cancel", "held-cleanup")]),
            (("command-observation-context", "./cmd/sing-box", "original-context-selector", tuple(command)),
             command + [command[0] + "/" + leaf for leaf in ("cancelled", "deadline", "unavailable", "identity", "success")] +
             [parent + "/" + leaf for parent in command[1:] for leaf in ("external", "tor")]),
            (("tor-observation-context", ".", "^" + tor + "$", (tor,)), [tor]),
        ]
        socket = ["TestDesktopBrokerContextExpiryDoesNotRetireOriginal", "TestDesktopBrokerContextRequiresExplicitObserver",
                  "TestDesktopBrokerConfirmedLossSurvivesRacedCallerCancellation", "TestServerTorCurrentContextExpiresWithoutRetiringLease",
                  "TestServerTorCurrentContextKeepsCancellationSeparateFromIdentityLoss", "TestServerTorConfirmedLossSurvivesRacedCallerCancellation",
                  "TestObservationCancellationCannotHideConfirmedOwnerLoss", "TestObservationExpiryRequiresOriginalCaller",
                  "TestPaddingNativeReceiptContextPreservesOwnerOnObserverExpiry"]
        suites.append((("owned-socket-observation-context", "./routervpn/mobiletor", "original-socket-selector", tuple(socket)),
                       socket + [socket[-1] + "/" + leaf for leaf in ("lease-lock", "owner-observation", "proof-observation", "success")]))
        for manager in ("inbound", "outbound", "endpoint", "service", "dns"):
            names = ["TestRouterVPNManagerObservationRetainsCaller"]
            if manager == "inbound":
                names += ["TestRouterVPNManagerInventoryRetainsCaller"]
            suites.append((("manager-context-" + manager, "./adapter/" + manager, "original-manager-selector", tuple(names)), names))
        for suite, names in suites:
            lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
            baseline = Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                baseline.execute.return_value = (0, "".join(lines))
                NODE.execute_baseline_suite(baseline, suite)
                for line in lines:
                    for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line,
                                    "".join(lines).replace(line, line.replace("Test", "ForeignTest", 1), 1)):
                        with self.subTest(suite=suite[0], line=line):
                            baseline.execute.return_value = (0, changed)
                            with self.assertRaisesRegex(ValueError, "omitted"):
                                NODE.execute_baseline_suite(baseline, suite)


class NativeMTUOperationVerdicts(unittest.TestCase):
    def test_each_original_operation_and_cleanup_verdict_is_required(self):
        expected = {
            "mtu-operation-context": 15, "mtu-owner-context": 7,
            "mtu-manager-context": 4, "mtu-cleanup-context": 4, "mtu-startup-context": 1, "mtu-finalization-context": 5,
        }
        self.assertEqual(set(expected), set(NODE.MTU_CONTEXT_VERDICTS))
        for family, count in expected.items():
            names = NODE.MTU_CONTEXT_VERDICTS[family]
            self.assertEqual(len(names), count)
            self.assertEqual(len(set(names)), count)
            suite = (family, "exact-generated-package", "original-context-selector", tuple(name for name in names if "/" not in name))
            lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
            baseline = Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                baseline.execute.return_value = (0, "".join(lines))
                NODE.execute_baseline_suite(baseline, suite)
                for line in lines:
                    for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line,
                                    "".join(lines).replace(line, line.replace("Test", "ForeignTest", 1), 1)):
                        with self.subTest(family=family, verdict=line):
                            baseline.execute.return_value = (0, changed)
                            with self.assertRaisesRegex(ValueError, "omitted"):
                                NODE.execute_baseline_suite(baseline, suite)


class NativePhysicalMutationVerdicts(unittest.TestCase):
    def test_physical_mutation_context_requires_every_original_verdict(self):
        parent = "TestRouterVPNPhysicalTunnelOriginalMutationContext"
        names = [parent] + [parent + "/" + family + "/" + phase + "/" + operation
            for family in ("tor", "external") for phase in ("admission", "acknowledgement", "native-failure") for operation in ("bind", "retire")]
        suite = ("physical-mutation-context", "./routervpn/desktoppt", "^" + parent + "$", (parent,))
        lines = [line for test in names for line in ("=== RUN   " + test + "\n", "--- PASS: " + test + " (0.01s)\n")]
        baseline = Mock()
        with contextlib.redirect_stdout(io.StringIO()):
            baseline.execute.return_value = (0, "".join(lines))
            NODE.execute_baseline_suite(baseline, suite)
            for line in lines:
                for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line,
                                "".join(lines).replace(line, line.replace("Test", "ForeignTest", 1), 1)):
                    with self.subTest(line=line):
                        baseline.execute.return_value = (0, changed)
                        with self.assertRaisesRegex(ValueError, "omitted"):
                            NODE.execute_baseline_suite(baseline, suite)


class NativeMTUVerdicts(unittest.TestCase):
    def test_mtu_command_context_requires_every_original_verdict(self):
        parents = ["TestRouterVPNDesktopMTUCallerContextWaits", "TestRouterVPNDesktopMTUMailboxKeepsOriginalDeadline",
                   "TestRouterVPNDesktopMTUCacheExpiredSaveIsNotACommit", "TestRouterVPNDesktopMTURestoreContextCancelsAndReprovesOriginal"]
        names = parents + [parents[0] + "/" + case for case in ("start", "record", "commit", "cancel", "cache")]
        names += [parents[1] + "/" + case for case in ("accepted-worker", "already-expired")]
        suite = ("mtu-command-context", "./cmd/sing-box", "exact-context-selector", tuple(parents))
        lines = [line for test in names for line in ("=== RUN   " + test + "\n", "--- PASS: " + test + " (0.01s)\n")]
        baseline = Mock()
        with contextlib.redirect_stdout(io.StringIO()):
            baseline.execute.return_value = (0, "".join(lines))
            NODE.execute_baseline_suite(baseline, suite)
            for line in lines:
                for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line,
                                "".join(lines).replace(line, line.replace("Test", "ForeignTest", 1), 1)):
                    with self.subTest(line=line):
                        baseline.execute.return_value = (0, changed)
                        with self.assertRaisesRegex(ValueError, "omitted"):
                            NODE.execute_baseline_suite(baseline, suite)

    def test_actual_tor_lease_release_ignores_held_owner_and_rejects_old_lock(self):
        spec = importlib.util.spec_from_file_location("tor_lease_control", ROOT / "deploy/test_tor_mtu_release.py")
        control = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(control)
        control.execute()

    def test_tor_release_and_complete_heartbeat_require_each_original_verdict(self):
        release = "TestRouterVPNDesktopTorMTUReleaseWithHeldOwner"
        heartbeat = "TestRouterVPNDesktopTorMTUHeartbeatAdoptsCompleteReceipt"
        for suite, names in (
            (("tor-mtu-release", ".", "^" + release + "$", (release,)),
             [release, release + "/ordinary", release + "/inherited-measurement"]),
            (("tor-mtu-heartbeat", "./cmd/sing-box", "^TestRouterVPNDesktopTorMTUHeartbeat", (heartbeat,)),
             ["TestRouterVPNDesktopTorMTUHeartbeatRejectsRegressedOrUnregisteredReadback", heartbeat] +
             [heartbeat + "/previous-" + prior + "/" + outcome for prior in ("false", "true")
              for outcome in ("network-failure", "cancel-after-readback", "cancel-after-network", "network-name", "network-index", "network-mtu", "revision-changed", "cancel-after-recheck", "success")]),
        ):
            lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
            baseline = Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                baseline.execute.return_value = (0, "".join(lines))
                NODE.execute_baseline_suite(baseline, suite)
                for line in lines:
                    for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line,
                                    "".join(lines).replace(line, line.replace("TestRouterVPN", "TestForeign"), 1)):
                        with self.subTest(suite=suite[0], line=line, changed=changed):
                            baseline.execute.return_value = (0, changed)
                            with self.assertRaisesRegex(ValueError, "omitted"):
                                NODE.execute_baseline_suite(baseline, suite)

    def test_original_network_context_parent_and_each_leaf_are_required(self):
        suite = ("network-context", "./protocol/tun", "^TestRouterVPNDesktopNetwork", NODE.NETWORK_CONTEXT_TESTS)
        names = NODE.NETWORK_CONTEXT_TESTS + NODE.NETWORK_CONTEXT_LEAVES
        lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
        baseline = Mock()
        with contextlib.redirect_stdout(io.StringIO()):
            baseline.execute.return_value = (0, "".join(lines))
            NODE.execute_baseline_suite(baseline, suite)
            for line in lines:
                for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line):
                    baseline.execute.return_value = (0, changed)
                    with self.subTest(line=line), self.assertRaisesRegex(ValueError, "omitted"):
                        NODE.execute_baseline_suite(baseline, suite)

    def test_owned_transaction_and_every_native_leaf_are_mandatory(self):
        suites = (("native-mtu-transaction", ".", "^TestRouterVPNNativeLinuxMTUTransactionNamespace$", (NODE.NATIVE_MTU_TEST,)),
                  ("mtu-transaction-model", "./adapter/inbound", "^TestRouterVPNTun", NODE.NATIVE_MTU_MODEL_TESTS),
                  ("mtu-startup-budget", "./protocol/tun", "^TestRouterVPNMTUStartupReceiptKeepsOriginalOperation$", ("TestRouterVPNMTUStartupReceiptKeepsOriginalOperation",)))
        for suite in suites:
            if suite[0] == "mtu-startup-budget":
                names = ["TestRouterVPNMTUStartupReceiptKeepsOriginalOperation"]
            elif suite[0] == "native-mtu-transaction":
                names = [NODE.NATIVE_MTU_TEST] + [NODE.NATIVE_MTU_TEST + "/" + case for case in NODE.NATIVE_MTU_CASES]
            else:
                names = list(NODE.NATIVE_MTU_MODEL_TESTS) + ["TestRouterVPNTunTransactionRetainsOriginalAndPartialCandidateEvidence/" + case for case in ("candidate", "rollback")] + ["TestRouterVPNTunFullSearchRetainsEveryOriginalAttempt/" + case for case in ("full-search-and-winner", "failed-candidate-and-original-restore", "cancel-after-provisional-winner")]
            lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
            baseline = Mock()
            with contextlib.redirect_stdout(io.StringIO()):
                baseline.execute.return_value = (0, "".join(lines))
                NODE.execute_baseline_suite(baseline, suite)
                baseline.execute.assert_called_once_with(*suite[:3], 90)
                for line in lines:
                    for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line, "".join(lines).replace(line, line.replace(" (", "-unselected ("), 1)):
                        if changed == "".join(lines):
                            continue
                        with self.subTest(suite=suite[0], line=line, changed=changed):
                            baseline.execute.return_value = (0, changed)
                            with self.assertRaisesRegex(ValueError, "omitted"):
                                NODE.execute_baseline_suite(baseline, suite)


class NativeResolverVerdicts(unittest.TestCase):
    def test_every_original_resolver_verdict_is_required_exactly_once(self):
        suite = ("native-resolver-lifetime", "github.com/sagernet/sing-tun", "^TestRouterVPNNativeLinuxResolver", NODE.NATIVE_RESOLVER_TESTS)
        names = list(NODE.NATIVE_RESOLVER_TESTS) + ["TestRouterVPNNativeLinuxResolver" + root + "/" + leaf
                for root, leaves in NODE.NATIVE_RESOLVER_LEAVES.items() for leaf in leaves]
        lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
        baseline = Mock()
        baseline.execute.return_value = (0, "".join(lines))
        with contextlib.redirect_stdout(io.StringIO()):
            NODE.execute_baseline_suite(baseline, suite)
            baseline.execute.assert_called_once_with(*suite[:3], 90)
            for line in lines:
                for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line,
                                *(["".join(lines).replace(line, line.replace("NamedBusNamespace", "NamedBusNamespaceUnselected"), 1)]
                                  if "NamedBusNamespace" in line else [])):
                    with self.subTest(line=line, changed=changed):
                        baseline.execute.return_value = (0, changed)
                        with self.assertRaisesRegex(ValueError, "omitted"):
                            NODE.execute_baseline_suite(baseline, suite)


class NativeDBusVerdicts(unittest.TestCase):
    def test_every_original_descriptor_verdict_is_required_exactly_once(self):
        suite = ("native-dbus-rights", "github.com/godbus/dbus/v5", "^TestRouterVPNDBus", NODE.NATIVE_DBUS_TESTS)
        names = list(NODE.NATIVE_DBUS_TESTS) + [NODE.NATIVE_DBUS_TESTS[0] + "/" + case for case in NODE.NATIVE_DBUS_CASES]
        lines = [line for name in names for line in ("=== RUN   " + name + "\n", "--- PASS: " + name + " (0.01s)\n")]
        baseline = Mock()
        with contextlib.redirect_stdout(io.StringIO()):
            baseline.execute.return_value = (0, "".join(lines))
            NODE.execute_baseline_suite(baseline, suite)
            baseline.execute.assert_called_once_with(*suite[:3], 90)
            invalid = [changed for line in lines for changed in ("".join(lines).replace(line, "", 1), "".join(lines) + line)]
            invalid += ["".join(lines) + suffix for suffix in (
                "=== RUN   TestRouterVPNDBusForeign\n--- PASS: TestRouterVPNDBusForeign (0.01s)\n",
                "--- FAIL: TestRouterVPNDBusReceivedRightsRetireOnError (0.01s)\n",
                "--- SKIP: foreign (0.01s)\n", "DATA RACE\n", "panic: unexpected wire error\n")]
            for output in invalid:
                with self.subTest(output=output):
                    baseline.execute.return_value = (0, output)
                    with self.assertRaisesRegex(ValueError, "omitted"):
                        NODE.execute_baseline_suite(baseline, suite)



class RoutingNamespaceLauncher(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="node-routing-private-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.binary = self.work / "original.test"
        self.binary.write_bytes(b"exact compiled routing fixture")
        self.binary.chmod(0o755)
        self.staged = []
        self.source = Path("/original-source")
        self.env = {"GOOS": "linux", "EXACT_COMPILER_ENV": "captured",
                    "ROUTERVPN_NATIVE_ROUTING_RECEIPT_CHILD": "1",
                    "ROUTERVPN_NATIVE_ROUTING_RETIREMENT_CASE": "foreign-case",
                    "ROUTERVPN_NATIVE_RESOLVER_NAMED_CASE": "foreign-endpoint",
                    "ROUTERVPN_NATIVE_MTU_TRANSACTION_CASE": "foreign-mtu",
                    "ROUTERVPN_STANDARD_MTU_CLAIM_FAILURE": "foreign-claim",
                    "ROUTERVPN_ROUTING_PARENT_NET": "foreign-network",
                    "ROUTERVPN_ROUTING_PARENT_USER": "foreign-user"}
        self.native = Mock()
        self.native.privilege_tool.return_value = "/usr/bin/sudo"
        self.native.run.return_value = "actual native fixture output\n"

        def observe(command, **options):
            offset = 3 if options["sudo"] is not None else 0
            image = Path(command[offset])
            self.staged.append(image)
            self.assertNotEqual(image, self.binary)
            self.assertEqual(image.read_bytes(), self.binary.read_bytes())
            self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(image.parent.stat().st_mode), 0o711)
            self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)
            return self.native.run.return_value

        self.native.run.side_effect = observe
        self.system = patch.object(NODE.platform, "system", return_value="Linux")
        self.loader = patch.object(NODE, "namespace_runner", return_value=self.native)
        self.system.start()
        self.loader.start()
        self.addCleanup(self.loader.stop)
        self.addCleanup(self.system.stop)

    def invoke(self):
        return NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env, duration=90)

    def test_only_exact_compiled_fixture_uses_trusted_privilege_and_join_owner(self):
        original = dict(self.env)
        self.assertEqual(self.invoke(), (0, "actual native fixture output\n"))
        self.native.privilege_tool.assert_called_once_with()
        self.native.run.assert_called_once_with(
            ["/usr/bin/sudo", "-n", "--", str(self.staged[0]),
             "-test.run=^TestRouterVPNNativeLinuxRouting", "-test.count=1", "-test.timeout=90s", "-test.v"],
            cwd=self.source, env={"GOOS": "linux", "EXACT_COMPILER_ENV": "captured"}, timeout=105, sudo="/usr/bin/sudo")
        self.assertEqual(self.env, original)
        self.assertFalse(self.staged[0].parent.exists())
        self.assertTrue(self.binary.exists())

    def test_resolver_uses_only_its_fixed_privileged_selector(self):
        self.assertEqual(NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env, duration=90,
                         selector="^TestRouterVPNNativeLinuxResolver"), (0, "actual native fixture output\n"))
        args, options = self.native.run.call_args
        self.assertIn("-test.run=^TestRouterVPNNativeLinuxResolver", args[0])
        self.assertEqual(options["timeout"], 105)
        self.native.run.reset_mock()
        with self.assertRaisesRegex(ValueError, "another fixture selector"):
            NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env, duration=90,
                                           selector="^TestRouterVPNNativeLinuxResolver|Other")
        self.native.run.assert_not_called()

    def test_mtu_executes_only_its_exact_original_native_selector(self):
        selector = "^TestRouterVPNNativeLinuxMTUTransactionNamespace$"
        self.assertEqual(NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env, duration=90, selector=selector), (0, "actual native fixture output\n"))
        args, options = self.native.run.call_args
        self.assertIn("-test.run=" + selector, args[0])
        self.assertNotIn("ROUTERVPN_NATIVE_MTU_TRANSACTION_CASE", options["env"])
        self.native.run.reset_mock()
        with self.assertRaisesRegex(ValueError, "another fixture selector"):
            NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env, duration=90, selector=selector + "|Other")
        self.native.run.assert_not_called()

    def test_root_keeps_the_same_fixture_and_owned_timeout_without_sudo(self):
        self.native.privilege_tool.return_value = None
        self.invoke()
        args, options = self.native.run.call_args
        self.assertEqual(args[0][0], str(self.staged[0]))
        self.assertFalse(self.staged[0].parent.exists())
        self.assertIsNone(options["sudo"])
        self.assertEqual(options["timeout"], 105)

    def test_standard_cleanup_uses_only_original_retirement_selector(self):
        selector = NODE.STANDARD_MTU_RETIRE_SUITE[2]
        self.assertEqual(NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env,
                         duration=90, selector=selector), (0, "actual native fixture output\n"))
        command, options = self.native.run.call_args
        self.assertIn("-test.run=" + selector, command[0])
        self.assertEqual(options["timeout"], 105)
        self.native.run.reset_mock()
        for changed in (selector + "|Other", NODE.STANDARD_MTU_SUITE[2]):
            with self.assertRaisesRegex(ValueError, "another fixture selector"):
                NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env,
                                               duration=90, selector=changed)
        self.native.run.assert_not_called()

    def test_parent_lifetime_uses_only_each_exact_privileged_selector(self):
        for suite in (NODE.STANDARD_MTU_NATIVE_SUITE, NODE.STANDARD_PARENT_SUITE, NODE.STANDARD_PARENT_NATIVE_SUITE):
            selector = suite[2]
            self.assertEqual(NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env,
                             duration=90, selector=selector), (0, "actual native fixture output\n"))
            command, options = self.native.run.call_args
            self.assertIn("-test.run=" + selector, command[0])
            self.assertEqual(options["timeout"], 105)
            self.assertNotIn("ROUTERVPN_STANDARD_MTU_CLAIM_FAILURE", options["env"])
            self.native.run.reset_mock()
            with self.assertRaisesRegex(ValueError, "another fixture selector"):
                NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env,
                                               duration=90, selector=selector + "|Other")
            self.native.run.assert_not_called()

    def test_missing_trusted_privilege_fails_before_execution(self):
        self.native.privilege_tool.side_effect = ValueError("no trusted native privilege")
        with self.assertRaisesRegex(ValueError, "trusted native privilege"):
            self.invoke()
        self.native.run.assert_not_called()

    def test_unavailable_namespace_keeps_failure_and_never_runs_unisolated(self):
        for output in (b"unshare: uid_map denied\n", "unshare: uid_map denied\n", None):
            with self.subTest(output=output):
                self.native.run.reset_mock()
                self.native.run.side_effect = subprocess.CalledProcessError(7, ["unshare"], output=output)
                self.assertEqual(self.invoke(), (7, "" if output is None else "unshare: uid_map denied\n"))
                self.native.run.assert_called_once()

    def test_timeout_join_failure_never_becomes_a_verdict_or_retry(self):
        self.native.run.side_effect = RuntimeError("owned group could not be joined")
        with self.assertRaisesRegex(RuntimeError, "could not be joined"):
            self.invoke()
        self.native.run.assert_called_once()

    def test_other_hosts_or_cross_targets_cannot_launch_the_linux_fixture(self):
        for system, target in (("Windows", "linux"), ("Darwin", "linux"), ("Linux", "windows"), ("Linux", None)):
            with self.subTest(system=system, target=target), patch.object(NODE.platform, "system", return_value=system):
                self.env["GOOS"] = target
                with self.assertRaisesRegex(ValueError, "native Linux"):
                    self.invoke()
        self.native.privilege_tool.assert_not_called()
        self.native.run.assert_not_called()


class RoutingFixtureImage(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="node-routing-source-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.image = self.work / "original.test"
        self.image.write_bytes(b"exact compiled native fixture")
        self.image.chmod(0o755)

    def test_stages_only_the_exact_read_execute_image_and_preserves_private_source(self):
        original = NODE.retained_binary(self.image)
        with NODE.routing_fixture_image(self.image) as staged:
            self.assertEqual(staged.parent.parent, Path("/tmp"))
            self.assertNotEqual(staged.parent, self.work)
            self.assertEqual(list(staged.parent.iterdir()), [staged])
            self.assertEqual(staged.read_bytes(), self.image.read_bytes())
            self.assertNotEqual(staged.stat().st_ino, self.image.stat().st_ino)
            self.assertEqual(staged.stat().st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(staged.parent.stat().st_mode), 0o711)
            self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)
        self.assertFalse(staged.parent.exists())
        self.assertEqual(NODE.retained_binary(self.image), original)
        self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)

    def test_execution_failure_and_cancellation_remove_only_owned_staging(self):
        for error in (subprocess.CalledProcessError(7, ["owned fixture"]), RuntimeError("joined timeout")):
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    with NODE.routing_fixture_image(self.image) as staged:
                        raise error
                self.assertFalse(staged.parent.exists())
                self.assertTrue(self.image.exists())

    def test_changed_staged_image_identity_bytes_or_permissions_cannot_pass(self):
        for change in ("replacement", "contents", "permissions", "symlink"):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "staged image|owned regular"):
                    with NODE.routing_fixture_image(self.image) as staged:
                        if change == "replacement":
                            other = staged.with_name("replacement.test")
                            other.write_bytes(staged.read_bytes())
                            other.chmod(0o555)
                            other.replace(staged)
                        elif change == "contents":
                            staged.chmod(0o755)
                            staged.write_bytes(b"changed compiled fixture")
                            staged.chmod(0o555)
                        elif change == "permissions":
                            staged.chmod(0o777)
                        else:
                            staged.unlink()
                            staged.symlink_to(self.image)
                self.assertFalse(staged.parent.exists())
                self.assertTrue(self.image.exists())

    def test_changed_original_image_cannot_pass_and_keeps_private_directory(self):
        with self.assertRaisesRegex(ValueError, "source image changed"):
            with NODE.routing_fixture_image(self.image) as staged:
                self.image.write_bytes(b"replacement source fixture")
        self.assertFalse(staged.parent.exists())
        self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)

    def test_corrupted_copy_never_reaches_execution(self):
        def corrupt(source, target):
            target.write(b"different compiled fixture")
        entered = False
        with patch.object(NODE.shutil, "copyfileobj", side_effect=corrupt), \
             self.assertRaisesRegex(ValueError, "staged image"):
            with NODE.routing_fixture_image(self.image):
                entered = True
        self.assertFalse(entered)

    def test_symlink_hardlink_foreign_owner_and_writable_source_are_rejected(self):
        self.image.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "owned executable"):
            with NODE.routing_fixture_image(self.image):
                self.fail("unsafe source executed")
        self.image.chmod(0o755)
        alias = self.work / "symlink.test"
        alias.symlink_to(self.image)
        with self.assertRaisesRegex(ValueError, "owned regular"):
            with NODE.routing_fixture_image(alias):
                self.fail("symlink source executed")
        alias.unlink()
        os.link(self.image, alias)
        with self.assertRaisesRegex(ValueError, "owned regular"):
            with NODE.routing_fixture_image(self.image):
                self.fail("hardlink source executed")
        alias.unlink()
        with patch.object(NODE.os, "geteuid", return_value=self.image.stat().st_uid + 1), \
             self.assertRaisesRegex(ValueError, "owned executable"):
            with NODE.routing_fixture_image(self.image):
                self.fail("foreign source executed")

    def test_staging_directory_permissions_are_part_of_retained_identity(self):
        with self.assertRaisesRegex(ValueError, "staging directory"):
            with NODE.routing_fixture_image(self.image) as staged:
                staged.parent.chmod(0o777)
        self.assertFalse(staged.parent.exists())


class BaselineRoutingDispatch(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="node-routing-runner-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.source = self.work / "source"
        self.source.mkdir()
        self.binary = self.work / "original.test"
        self.binary.write_bytes(b"original compiled image")
        self.package = "github.com/sagernet/sing-tun"
        self.env = {"GOOS": "linux"}
        self.baselines = NODE.BaselineBinaries(self.source, self.work, ["captured-go", "test", "-c"], self.env, {})
        self.baselines.binaries[self.package] = self.binary, NODE.retained_binary(self.binary)
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None, None, None)

    def test_original_named_suite_uses_namespace_runner_and_preserves_receipt(self):
        with patch.object(NODE, "linux_routing_receipt_test", return_value=(0, "native pass")) as native, \
             patch.object(NODE, "run", return_value=(0, "native pass")) as ordinary:
            self.assertEqual(self.baselines.execute("native-routing-receipt", self.package,
                             "^TestRouterVPNNativeLinuxRouting", 90), (0, "native pass"))
        native.assert_called_once_with(self.binary, cwd=self.source, env=self.env, duration=90)
        ordinary.assert_not_called()

    def test_original_resolver_suite_uses_same_retained_binary_privilege_boundary(self):
        with patch.object(NODE, "linux_routing_receipt_test", return_value=(0, "native pass")) as native, patch.object(NODE, "run") as ordinary:
            self.assertEqual(self.baselines.execute("native-resolver-lifetime", self.package,
                             "^TestRouterVPNNativeLinuxResolver", 90), (0, "native pass"))
        native.assert_called_once_with(self.binary, cwd=self.source, env=self.env, duration=90, selector="^TestRouterVPNNativeLinuxResolver")
        ordinary.assert_not_called()
        for package, selector in (("./other", "^TestRouterVPNNativeLinuxResolver"), (self.package, ".*")):
            with self.assertRaisesRegex(ValueError, "another package or selector"):
                self.baselines.execute("native-resolver-lifetime", package, selector, 90)

    def test_unrelated_suites_keep_ordinary_execution(self):
        with patch.object(NODE, "linux_routing_receipt_test") as native, \
             patch.object(NODE, "run", return_value=(0, "ordinary pass")) as ordinary:
            self.assertEqual(self.baselines.execute("unrelated", self.package, "^OtherCase$", 12), (0, "ordinary pass"))
        native.assert_not_called()
        ordinary.assert_called_once_with([self.binary, "-test.run=^OtherCase$", "-test.count=1", "-test.timeout=12s", "-test.v"],
                                         cwd=self.source, env=self.env, timeout=27)

    def test_standard_retirement_uses_privilege_but_admission_stays_ordinary(self):
        name, package, selector, _ = NODE.STANDARD_MTU_RETIRE_SUITE
        self.baselines.binaries[package] = self.binary, NODE.retained_binary(self.binary)
        with patch.object(NODE, "linux_routing_receipt_test", return_value=(0, "native pass")) as native, \
             patch.object(NODE, "run", return_value=(0, "ordinary pass")) as ordinary:
            self.assertEqual(self.baselines.execute(name, package, selector, 90), (0, "native pass"))
            native.assert_called_once_with(self.binary, cwd=self.source, env=self.env, duration=90, selector=selector)
            ordinary.assert_not_called()
            native.reset_mock()
            self.assertEqual(self.baselines.execute(*NODE.STANDARD_MTU_SUITE[:3], 90), (0, "ordinary pass"))
            native.assert_not_called()
            ordinary.assert_called_once()
        for changed_package, changed_selector in (("./foreign", selector), (package, selector + "|Other"), (package, NODE.STANDARD_MTU_SUITE[2])):
            with patch.object(self.baselines, "binary") as compile_image, \
                 patch.object(NODE, "linux_routing_receipt_test") as native, \
                 self.assertRaisesRegex(ValueError, "another package or selector"):
                self.baselines.execute(name, changed_package, changed_selector, 90)
            compile_image.assert_not_called()
            native.assert_not_called()

    def test_parent_lifetime_preserves_exact_original_binary_privilege(self):
        for suite in (NODE.STANDARD_MTU_NATIVE_SUITE, NODE.STANDARD_PARENT_SUITE, NODE.STANDARD_PARENT_NATIVE_SUITE):
            name, package, selector, _ = suite
            self.baselines.binaries[package] = self.binary, NODE.retained_binary(self.binary)
            with patch.object(NODE, "linux_routing_receipt_test", return_value=(0, "native pass")) as native, \
                 patch.object(NODE, "run") as ordinary:
                self.assertEqual(self.baselines.execute(name, package, selector, 90), (0, "native pass"))
                native.assert_called_once_with(self.binary, cwd=self.source, env=self.env, duration=90, selector=selector)
                ordinary.assert_not_called()
            for foreign_package, foreign_selector in (("./foreign", selector), (package, selector + "|Other")):
                with patch.object(self.baselines, "binary") as compile_image, \
                     patch.object(NODE, "linux_routing_receipt_test") as native, \
                     self.assertRaisesRegex(ValueError, "another package or selector"):
                    self.baselines.execute(name, foreign_package, foreign_selector, 90)
                compile_image.assert_not_called()
                native.assert_not_called()

    def test_changed_package_or_selector_cannot_gain_routing_privilege(self):
        for package, selector in (("./unrelated", "^TestRouterVPNNativeLinuxRouting"),
                                  (self.package, ".*"), (self.package, "^TestRouterVPNNativeLinuxRouting|OtherCase")):
            with self.subTest(package=package, selector=selector), \
                 patch.object(self.baselines, "binary") as compile_image, \
                 patch.object(NODE, "linux_routing_receipt_test") as native:
                with self.assertRaisesRegex(ValueError, "another package or selector"):
                    self.baselines.execute("native-routing-receipt", package, selector, 90)
                compile_image.assert_not_called()
                native.assert_not_called()

    def test_privileged_execution_cannot_replace_its_original_compiled_image(self):
        def replacement(*args, **kwargs):
            self.binary.write_bytes(b"replaced compiled image")
            return 0, "native pass"
        with patch.object(NODE, "linux_routing_receipt_test", side_effect=replacement), \
             self.assertRaisesRegex(ValueError, "original compiled image"):
            self.baselines.execute("native-routing-receipt", self.package, "^TestRouterVPNNativeLinuxRouting", 90)

    def test_namespace_runner_and_its_checks_remain_captured_source_inputs(self):
        deploy = self.work / "deploy"
        deploy.mkdir()
        for key, name in (("namespace-launcher", "test_desktop_socket_uid.py"),
                          ("routing-runner", "test_desktop_node_routing_runner.py")):
            with self.subTest(key=key), patch.object(NODE, "ROOT", self.work):
                path = deploy / name
                path.write_bytes(b"original owned runner")
                self.baselines.records = {key: hashlib.sha256(path.read_bytes()).hexdigest()}
                self.baselines.check_inputs()
                path.write_bytes(b"different runner")
                with self.assertRaisesRegex(ValueError, "captured source input"):
                    self.baselines.check_inputs()


class HysteriaPhaseDispatch(unittest.TestCase):
    """Exercise the ordinary cached-image dispatch and its required verdicts.

    Only compiler/process outputs are modeled here. The real six encrypted
    peer groups remain mandatory in the native gate and use the same helper.
    """

    ROOTS = {
        "hysteria2-credentials": ("WrongCredential", "WrongWhitening"),
        "hysteria2-identity": ("LayerTLSIdentity", "ReferenceCapture"),
        "hysteria2-cover": ("LayerCover", "OuterCannotBypassFinal"),
    }
    LEAVES = {
        "WrongCredential": (
            "off/hysteria-password", "off/hysteria-trust", "off/hysteria-salamander",
            "aes-256-gcm/hysteria-password", "aes-256-gcm+xor-whitening/hysteria-password",
            "aes-256-gcm/aes-key", "aes-256-gcm+xor-whitening/aes-key",
            "aes-256-gcm/hysteria-trust", "aes-256-gcm+xor-whitening/hysteria-trust",
            "aes-256-gcm/hysteria-salamander", "aes-256-gcm+xor-whitening/hysteria-salamander"),
        "LayerTLSIdentity": tuple(layer + "/" + identity for layer in
                                  ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening")
                                  for identity in ("ip-absent", "ip-empty", "ip-wrong-certificate")),
        "ReferenceCapture": ("unchanged", "ip-absent", "ip-empty", "wrong-ip", "unknown-identity",
                             "other-mode", "whitening", "wrong-layer", "wrong-mode"),
        "LayerCover": tuple(layer + "/" + fault for layer in ("aes-256-gcm", "aes-256-gcm+xor-whitening")
                            for fault in ("owned", "wrong-node", "drop-cover")),
        "OuterCannotBypassFinal": ("aes-256-gcm", "aes-256-gcm+xor-whitening"),
    }
    PREFIX = "TestRouterVPNDesktopNodeHysteria2"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="node-hysteria-phases-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.source = self.work / "source"
        self.source.mkdir()
        self.input = self.source / "captured.go"
        self.input.write_bytes(b"original shipping source")
        records = {"captured.go": hashlib.sha256(self.input.read_bytes()).hexdigest()}
        self.env = {"GOOS": "linux", "CGO_ENABLED": "1", "EXACT_COMPILER_ENV": "captured"}
        self.build = ["captured-go", "test", "-c", "-mod=readonly", "-race"]
        self.baselines = NODE.BaselineBinaries(self.source, self.work, self.build, self.env, records)
        self.compiles, self.invocations = [], []
        self.outputs = {}
        self.status = 0
        self.mutation = None
        for suite in NODE.HYSTERIA2_SUITES:
            names = self.ROOTS[suite[0]]
            required = [self.PREFIX + name for name in names]
            leaves = [self.PREFIX + name + "/" + leaf for name in names for leaf in self.LEAVES.get(name, ())]
            self.outputs[suite[2]] = "".join("--- PASS: " + name + " (0.01s)\n" for name in (*required, *leaves))
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None, None, None)
        runner = patch.object(NODE, "run", side_effect=self.observe_run)
        runner.start()
        self.addCleanup(runner.stop)

    def observe_run(self, command, *, cwd, env, timeout):
        self.assertEqual(cwd, self.source)
        self.assertEqual(env, self.env)
        if command[0] == "captured-go":
            self.assertEqual(command[:-3], self.build)
            self.assertEqual(command[-3], "-o")
            self.assertEqual(command[-1], "./protocol/routervpnamnezia")
            self.assertEqual(timeout, 600)
            self.compiles.append(command)
            Path(command[-2]).write_bytes(b"one captured encrypted peer test image")
            return 0, "compiled fixture boundary\n"
        self.assertEqual(command[2:], ["-test.count=1", "-test.timeout=90s", "-test.v"])
        self.assertEqual(timeout, 105)
        selector = command[1].removeprefix("-test.run=")
        self.assertIn(selector, self.outputs)
        self.invocations.append((tuple(command), timeout))
        if self.mutation is not None:
            self.mutation(Path(command[0]))
        return self.status, self.outputs[selector]

    def test_three_disjoint_phases_execute_the_original_six_roots_on_one_cached_image(self):
        all_roots = {self.PREFIX + root for roots in self.ROOTS.values() for root in roots}
        self.assertEqual(len(NODE.HYSTERIA2_SUITES), 3)
        admitted = []
        for suite in NODE.HYSTERIA2_SUITES:
            name, package, selector, required = suite
            self.assertEqual(package, "./protocol/routervpnamnezia")
            self.assertEqual(tuple(self.PREFIX + root for root in self.ROOTS[name]), required)
            self.assertTrue(selector.startswith("^") and selector.endswith("$"))
            selected = {root for root in all_roots if re.search(selector, root)}
            self.assertEqual(selected, set(required))
            self.assertFalse(any(re.search(selector, root + "Unselected") for root in all_roots))
            admitted.extend(selected)
            NODE.execute_baseline_suite(self.baselines, suite)
        self.assertCountEqual(admitted, all_roots)
        self.assertEqual(len(self.compiles), 1)
        self.assertEqual(len(self.invocations), 3)
        self.assertEqual(len({command[0] for command, _ in self.invocations}), 1)
        self.assertEqual([command[1] for command, _ in self.invocations],
                         ["-test.run=" + suite[2] for suite in NODE.HYSTERIA2_SUITES])

    def test_each_original_root_and_required_leaf_must_pass_in_its_own_phase(self):
        for suite in NODE.HYSTERIA2_SUITES:
            selector = suite[2]
            original = self.outputs[selector]
            for line in original.splitlines(keepends=True):
                with self.subTest(phase=suite[0], missing=line.strip()):
                    self.outputs[selector] = original.replace(line, "", 1)
                    with self.assertRaisesRegex(ValueError, "omitted"):
                        NODE.execute_baseline_suite(self.baselines, suite)
            self.outputs[selector] = original
        self.assertEqual(len(self.compiles), 1)

    def test_successful_text_cannot_hide_failed_process_skip_or_race(self):
        for suite in NODE.HYSTERIA2_SUITES:
            original = self.outputs[suite[2]]
            for status, trailer in ((1, ""), (0, "--- SKIP: hidden boundary\n"), (0, "WARNING: DATA RACE\n")):
                with self.subTest(phase=suite[0], status=status, trailer=trailer):
                    self.status = status
                    self.outputs[suite[2]] = original + trailer
                    with self.assertRaisesRegex(ValueError, "required native boundary"):
                        NODE.execute_baseline_suite(self.baselines, suite)
            self.status = 0
            self.outputs[suite[2]] = original

    def test_timeout_is_propagated_without_recompilation_or_another_phase(self):
        suite = NODE.HYSTERIA2_SUITES[0]
        def timeout(_):
            raise subprocess.TimeoutExpired("captured test image", 105)
        self.mutation = timeout
        with self.assertRaises(subprocess.TimeoutExpired):
            NODE.execute_baseline_suite(self.baselines, suite)
        self.assertEqual(len(self.compiles), 1)
        self.assertEqual(len(self.invocations), 1)

    def test_source_change_between_phases_prevents_cached_execution(self):
        NODE.execute_baseline_suite(self.baselines, NODE.HYSTERIA2_SUITES[0])
        self.input.write_bytes(b"replacement source")
        with self.assertRaisesRegex(ValueError, "captured source input"):
            NODE.execute_baseline_suite(self.baselines, NODE.HYSTERIA2_SUITES[1])
        self.assertEqual(len(self.compiles), 1)
        self.assertEqual(len(self.invocations), 1)

    def test_replaced_image_cannot_supply_a_phase_verdict(self):
        self.mutation = lambda binary: binary.write_bytes(b"replacement executable")
        with self.assertRaisesRegex(ValueError, "original compiled image"):
            NODE.execute_baseline_suite(self.baselines, NODE.HYSTERIA2_SUITES[0])
        self.assertEqual(len(self.compiles), 1)
        self.assertEqual(len(self.invocations), 1)


if __name__ == "__main__":
    unittest.main()
