#!/usr/bin/env python3
"""Run Startup/Last/Speed Lab race tests in complete, bounded, disjoint phases.

Compile the shipping client tests once; each phase keeps the 180-second Go
alarm. Whole roots execute future children automatically. The divided root is
bound to reviewed source bytes, so an added leaf cannot be silently filtered.
Controller fixtures do not constitute native OS or encrypted traffic acceptance.
"""
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "router-vpn/cmd/client"
FOCUSED = re.compile(
    r"^Test(Startup(NodeChain|ProfileToken|Selection|External)|"
    r"OrderedStartupCannotFallback|"
    r"Desktop(SpeedLabDNSObservation|WindowsExternalSpeedLabRestoresOriginalTypedHost))"
)
NAME = re.compile(r"(?:Test|Benchmark|Example|Fuzz)\w*")
TEST_TIMEOUT = "180s"
# Outer process-reaping allowance only; the Go test alarm stays at 180s.
PROCESS_TIMEOUT = 210
SPLIT = frozenset(("TestStartupNodeChainLastRejectsRetiredOrSubstitutedOwner",))
# Exact Git blob identity for reviewed split-case source. Whole-root phases
# need no pin because they run every child, including newly added children.
SOURCE_BLOBS = {
    "cmd/client/startup_node_chain_owned_test.go": "a0c7f02e86cac0bcd7b187c1c44644d5b031e17c",
}

REQUIRED = {
    "TestStartupProfileTokenTracksPathPolicyButNotMeasurementFields": (
    ),
    "TestStartupSelectionRequiresProfileTokenAndRejectsLegacyState": (
    ),
    "TestStartupSelectionRoundTripsBoundProfileToken": (
    ),
    "TestStartupExternalProcessFixture": (
    ),
    "TestStartupExternalSavedProtocolUsesActualOwnedChild": (
        "auto",
        "smart-auto",
        "last",
    ),
    "TestStartupExternalLastRetainsProvedExecutionWithoutCompare": (
        "local",
        "server",
    ),
    "TestStartupExternalCapturedSelectionAndSourceCannotDrift": (
        "selection",
        "dns",
        "credential",
        "entry",
        "entry-source",
        "auto-connect",
    ),
    "TestStartupExternalCancellationAndBadProofCannotConnect": (
        "waiting",
        "wrong-session",
        "wrong-dns",
    ),
    "TestStartupExternalManualConnectAndDisconnectRetireDelay": (
        "disconnect",
        "manual-connect",
    ),
    "TestStartupExternalLateProofCannotAdoptChangedSelectionOrReplacement": (
        "changed-selection",
        "replacement-owner",
    ),
    "TestStartupExternalLastEvidenceRejectsChangedPolicyEntryAndSource": (
    ),
    "TestStartupExternalHomeDNSNeverFallsBackToPublicResolver": (
    ),
    "TestStartupExternalTorRejectsRetiredCaptureBeforeRuntimeAccess": (
    ),
    "TestStartupExternalImportsRemainManualUntilEnabled": (
    ),
    "TestOrderedStartupCannotFallbackToDirectLastOrAuto": (
        "last",
        "auto",
        "smart-auto",
    ),
    "TestStartupNodeChainCapturesAllOriginalModesAndPrivateSources": (
        "2/auto",
        "2/smart-auto",
        "3/auto",
        "3/smart-auto",
        "4/auto",
        "4/smart-auto",
        "8/auto",
        "8/smart-auto",
    ),
    "TestStartupNodeChainDelayRejectsEveryMemberAndSourceReplacement": (
        "first-credential",
        "middle-policy",
        "final-policy",
        "selected-control",
        "order",
        "mode",
        "missing-middle",
        "duplicate-middle",
        "startup-policy",
        "auto-connect",
        "canonical-root",
        "asset-0-wg",
        "asset-0-shadowsocks",
        "asset-1-wg",
        "asset-1-awg2-fast",
        "asset-1-shadowsocks",
        "asset-2-wg",
        "asset-2-awg2-strong",
        "asset-2-shadowsocks",
        "asset-3-wg",
        "asset-3-shadowsocks",
    ),
    "TestStartupNodeChainLastKeepsProvedDraftAndNormalizedPolicy": (
    ),
    "TestStartupNodeChainLastRejectsMalformedOrCrossFamilyReceipt": (
        "missing-tag",
        "missing-chain",
        "null-tag",
        "null-tag-no-chain",
        "empty-tag-no-chain",
        "case-tag-no-chain",
        "empty-tag",
        "wrong-tag",
        "number-tag",
        "case-tag",
        "null-chain",
        "case-chain",
        "cross-family",
        "null-external",
        "unknown",
        "wrong-schema",
        "server",
        "compare",
        "bad-root",
        "too-few-members",
        "duplicate-member",
        "wrong-final",
        "wrong-prefix",
        "wrong-base",
        "foreign-control",
        "missing-identity-source",
        "bad-source-digest",
        "unknown-member",
        "case-member-id",
        "unknown-source",
        "source-order",
        "duplicate-tag",
        "duplicate-chain",
        "trailing-json",
        "typed-record-without-editor-graph",
        "valid-typed-record-wrong-selected-control",
    ),
    "TestStartupNodeChainPreservesHistoricalUntaggedPairAndExternalReceipts": (
        "external",
    ),
    "TestStartupNodeChainAdaptersRejectTransientSourceAndPreflightChanges": (
        "none",
        "capture-source-revert",
        "preflight-source",
        "preflight-policy",
        "preflight-cancel",
        "preflight-owner",
        "stage-source",
        "proof-source",
        "proof-cancel",
    ),
    "TestStartupNodeChainAdaptersRejectReplacementCalls": (
    ),
    "TestStartupNodeChainCancelledIntentNeverEntersAnotherTransaction": (
        "cancelled",
        "manual-connect",
        "disconnect",
        "busy-transaction",
    ),
    "TestStartupNodeChainLastRequiresConnectedOriginalOwner": (
        "before-launch",
        "before-connected",
        "3",
        "4",
    ),
    "TestStartupNodeChainLastRejectsRetiredOrSubstitutedOwner": (
        "foreign-context",
        "cancelled-operation",
        "middle-policy",
        "middle-source",
        "wrong-command",
        "stale-proof",
        "missing-proof",
        "missing-runtime",
        "foreign-runtime",
        "changed-caller-order",
        "changed-caller-mode",
    ),
    "TestStartupNodeChainOrdinaryRecorderCannotEraseRetainedGraph": (
    ),
    "TestStartupNodeChainOrdinaryRecorderKeepsActualPairedOwner": (
    ),
    "TestDesktopSpeedLabDNSObservationJoinsAdmission": (
    ),
    "TestDesktopWindowsExternalSpeedLabRestoresOriginalTypedHost": (
        "router-external-router",
        "external-router-external",
        "external-router-original-host",
        "external-router-retired-controller",
        "router-hysteria2-router",
        "hysteria2-router-hysteria2",
        "router-hysteria2-aes-router",
        "hysteria2-aes-router-hysteria2-aes",
        "router-hysteria2-aes-xor-router",
        "hysteria2-aes-xor-router-hysteria2-aes-xor",
        "router-socks5-router",
        "socks5-router-socks5",
        "router-wireguard-router",
        "wireguard-router-wireguard",
        "router-amneziawg-fast-router",
        "amneziawg-fast-router-amneziawg-fast",
        "router-amneziawg-strong-router",
        "amneziawg-strong-router-amneziawg-strong",
        "router-openvpn-tcp-router",
        "openvpn-tcp-router-openvpn-tcp",
        "router-openvpn-udp-router",
        "openvpn-udp-router-openvpn-udp",
        "router-openvpn-mixed-router",
        "openvpn-mixed-router-openvpn-mixed",
    ),
}


@dataclass(frozen=True)
class Phase:
    root: str
    leaf: str = ""

    @property
    def label(self):
        return self.root + ("/" + self.leaf if self.leaf else "")

    @property
    def selector(self):
        # Go matches slash-delimited components independently. No fictitious
        # ancestor receipt is required for a direct t.Run("2/auto", ...).
        return "/".join("^" + re.escape(part) + "$" for part in self.label.split("/"))

    @property
    def cases(self):
        if self.leaf:
            return (self.label,)
        children = REQUIRED.get(self.root, ())
        return tuple(self.root + "/" + child for child in children) or (self.root,)

    @property
    def required_events(self):
        return frozenset((self.root,) + self.cases)

    def allows(self, name):
        if self.leaf:
            return name in self.required_events
        return name == self.root or name.startswith(self.root + "/")


def source_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def verify_sources(base, pins=SOURCE_BLOBS):
    for relative, expected in pins.items():
        path = base / relative
        if not path.is_file() or source_blob(path.read_bytes()) != expected:
            raise ValueError("Divided race source changed; review complete leaf inventory: " + relative)


def inventory(output):
    names = []
    for line in output.splitlines():
        if not line:
            continue
        if not NAME.fullmatch(line):
            raise ValueError("Malformed compiled test inventory: " + repr(line))
        names.append(line)
    if not names or len(names) != len(set(names)):
        raise ValueError("Empty or duplicate compiled test inventory")
    selected = sorted(name for name in names if FOCUSED.match(name))
    missing = set(REQUIRED) - set(selected)
    if missing:
        raise ValueError("Required focused roots missing: " + ", ".join(sorted(missing)))
    return selected


def expected_cases(roots):
    return {root + "/" + leaf if leaf else root
            for root in roots for leaf in (REQUIRED.get(root, ()) or ("",))}


def validate_partition(roots, phases):
    if not roots or len(roots) != len(set(roots)) or not set(REQUIRED).issubset(roots):
        raise ValueError("Invalid or incomplete focused root inventory")
    if any(not FOCUSED.match(root) or not NAME.fullmatch(root) for root in roots):
        raise ValueError("Partition contains an unrelated root")
    counts, whole = Counter(), Counter()
    for phase in phases:
        if phase.root not in roots:
            raise ValueError("Phase references an undiscovered root")
        if phase.root in SPLIT:
            if not phase.leaf or phase.leaf not in REQUIRED[phase.root]:
                raise ValueError("Divided root has an unknown leaf or whole-root overlap")
        elif phase.leaf:
            raise ValueError("Only reviewed source-bound roots may be divided")
        else:
            whole[phase.root] += 1
        counts.update(phase.cases)
    if set(counts) != expected_cases(roots) or any(count != 1 for count in counts.values()):
        raise ValueError("Race phases omit or duplicate a required case")
    if any(whole[root] != 1 for root in roots if root not in SPLIT):
        raise ValueError("Whole roots must execute exactly once")


def partition(roots):
    phases = []
    for root in roots:
        if root in SPLIT:
            phases.extend(Phase(root, leaf) for leaf in REQUIRED[root])
        else:
            phases.append(Phase(root))
    validate_partition(roots, phases)
    return phases


def command(binary, phase):
    return ["go", "tool", "test2json", "-p", PACKAGE, "-t", str(binary),
            "-test.v=test2json", "-test.count=1", "-test.timeout=" + TEST_TIMEOUT,
            "-test.run=" + phase.selector]


def verdict(output, returncode, phase, stderr=""):
    """Require original run/pass receipts, not zero exit or a PASS string."""
    if returncode != 0:
        raise ValueError("Race phase exited nonzero: " + str(returncode))
    runs, passes = Counter(), Counter()
    started = finished = False
    text = [stderr]
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError) as exc:
            raise ValueError("Malformed test2json event") from exc
        if not isinstance(event, dict) or event.get("Package") != PACKAGE:
            raise ValueError("Missing or substituted test package")
        action, name = event.get("Action"), event.get("Test", "")
        if not isinstance(name, str) or action not in {
            "start", "run", "pause", "cont", "pass", "fail", "skip", "output"
        }:
            raise ValueError("Unexpected test event")
        if finished:
            raise ValueError("Event arrived after the package verdict")
        if not started:
            if action != "start" or name:
                raise ValueError("Missing package start")
            started = True
            continue
        if action == "start":
            raise ValueError("Duplicate package start")
        if action in ("fail", "skip"):
            raise ValueError("Failed or skipped race evidence: " + (name or phase.label))
        if name and not phase.allows(name):
            raise ValueError("Unselected test executed: " + name)
        if action == "output":
            value = event.get("Output")
            if not isinstance(value, str):
                raise ValueError("Malformed test output")
            text.append(value)
        elif action == "run":
            if not name or runs[name] or (name != phase.root and not runs[phase.root]):
                raise ValueError("Missing parent or duplicate test execution")
            if any(name.startswith(ancestor + "/") and passes[ancestor] for ancestor in runs):
                raise ValueError("Child began after an original ancestor already passed")
            runs[name] += 1
        elif action == "pass":
            if name:
                if runs[name] != 1 or passes[name]:
                    raise ValueError("PASS without one original run")
                if any(child.startswith(name + "/") and not passes[child] for child in runs):
                    raise ValueError("Parent passed before its child finished")
                passes[name] += 1
            else:
                if not runs or runs != passes:
                    raise ValueError("Package passed without complete test receipts")
                finished = True
        elif action in ("pause", "cont"):
            if not name or runs[name] != 1 or passes[name]:
                raise ValueError("Invalid suspended test receipt")
    joined = "".join(text)
    if "WARNING: DATA RACE" in joined or "race detected during execution of test" in joined:
        raise ValueError("Race detector reported an unsafe execution")
    if not finished or not phase.required_events.issubset(passes) or runs != passes:
        raise ValueError("Missing required parent or leaf run/PASS receipts")
    return {name for name in runs if not any(other.startswith(name + "/") for other in runs)}


def run_phase(binary, phase):
    print("Focused race: " + phase.label + " (Go alarm " + TEST_TIMEOUT + ")", flush=True)
    # Match go test ./cmd/client: the process runs in the package directory.
    process = subprocess.Popen(command(binary, phase), cwd=ROOT / "cmd/client",
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        output, errors = process.communicate(timeout=PROCESS_TIMEOUT)
    except BaseException:
        # Reap only this newly-created process group, including its test binary.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    try:
        leaves = verdict(output, process.returncode, phase, errors)
    except ValueError:
        print(output, end="" if output.endswith("\n") else "\n")
        if errors:
            print(errors, file=sys.stderr)
        raise
    # Preserve original compiler-produced names and timings as reviewable CI
    # evidence. Never manufacture PASS events from the expected inventory.
    for line in output.splitlines():
        event = json.loads(line)
        if event.get("Action") == "pass" and event.get("Test"):
            print(line, flush=True)
    print("Verified " + str(len(leaves)) + " executed case receipt(s): " + phase.label, flush=True)
    return leaves


def receipt(phase, extra=()):
    """Synthetic streams are solely verdict-parser selftest inputs."""
    names = [phase.root] + sorted((phase.required_events | set(extra)) - {phase.root})
    result = [{"Action": "start", "Package": PACKAGE}]
    result.extend({"Action": "run", "Package": PACKAGE, "Test": name} for name in names)
    result.extend({"Action": "pass", "Package": PACKAGE, "Test": name}
                  for name in sorted(names, key=lambda name: name.count("/"), reverse=True))
    result.append({"Action": "pass", "Package": PACKAGE})
    return result



def encoded(events):
    return "\n".join(json.dumps(event) for event in events)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.roots = sorted(REQUIRED)
        self.phase = Phase("TestStartupNodeChainLastRejectsRetiredOrSubstitutedOwner", "foreign-context")

    def test_reviewed_inventory_and_exactly_once_partition(self):
        roots = inventory("\n".join(self.roots + ["TestUnrelated", "Example", "FuzzSeed",
                                                        "BenchmarkSpeedLabPatternReader"]))
        phases = partition(roots)
        self.assertEqual(len(roots), 29)
        self.assertEqual(len(expected_cases(roots)), 152)
        self.assertEqual(len(phases), 39)
        self.assertNotIn("BenchmarkSpeedLabPatternReader", roots)
        self.assertFalse(any(phase.root.startswith("Benchmark") for phase in phases))
        self.assertEqual(Counter(case for phase in phases for case in phase.cases),
                         Counter(expected_cases(roots)))
        for phase in phases:
            selector = phase.selector.split("/")
            for candidate in expected_cases(roots):
                components = candidate.split("/")
                matches = len(components) >= len(selector) and all(
                    re.fullmatch(pattern, component)
                    for pattern, component in zip(selector, components))
                self.assertEqual(matches, candidate in phase.cases)
            args = command(Path("/reviewed/client.test"), phase)
            self.assertIn("-test.timeout=180s", args)
            self.assertIn("-test.count=1", args)
            self.assertIn("-test.v=test2json", args)

    def test_all_legacy_ordered_and_speed_lab_receipts_are_required(self):
        phases = partition(self.roots)
        self.assertEqual(sum(phase.root in SPLIT for phase in phases), 11)
        for phase in phases:
            base = receipt(phase)
            verdict(encoded(base), 0, phase)
            for missing in phase.required_events:
                changed = [event for event in base if event.get("Test") != missing]
                with self.subTest(phase=phase.label, missing=missing), self.assertRaises(ValueError):
                    verdict(encoded(changed), 0, phase)
        speed = REQUIRED["TestDesktopWindowsExternalSpeedLabRestoresOriginalTypedHost"]
        self.assertEqual(len(speed), 24)
        self.assertIn("TestDesktopSpeedLabDNSObservationJoinsAdmission", self.roots)
        capture = Phase("TestStartupNodeChainCapturesAllOriginalModesAndPrivateSources")
        self.assertIn(capture.root + "/2/auto", capture.required_events)
        self.assertNotIn(capture.root + "/2", capture.required_events)

    def test_future_root_runs_whole_and_all_children_must_finish(self):
        root = "TestStartupNodeChainFuturePolicy"
        roots = inventory("\n".join(self.roots + [root]))
        phase = next(phase for phase in partition(roots) if phase.root == root)
        self.assertFalse(phase.leaf)
        events = receipt(phase, (root + "/future-case",))
        self.assertEqual(verdict(encoded(events), 0, phase), {root + "/future-case"})
        events = [event for event in events if not (
            event.get("Test") == root + "/future-case" and event["Action"] == "pass")]
        with self.assertRaises(ValueError):
            verdict(encoded(events), 0, phase)

    def test_whole_root_executes_future_children_without_filtering(self):
        phase = Phase("TestStartupNodeChainDelayRejectsEveryMemberAndSourceReplacement")
        extra = phase.root + "/future-source-case"
        self.assertIn(extra, verdict(encoded(receipt(phase, (extra,))), 0, phase))
        for action in ("skip", "fail"):
            events = receipt(phase, (extra,))
            next(event for event in events if event.get("Test") == extra and event["Action"] == "pass")["Action"] = action
            with self.subTest(action=action), self.assertRaises(ValueError):
                verdict(encoded(events), 0, phase)

    def test_missing_duplicate_malformed_root_inventories(self):
        outputs = ["", "\n".join(self.roots + [self.roots[0]]),
                   "\n".join(self.roots + ["TestBad/child"]),
                   "\n".join(self.roots + ["PASS"])]
        outputs.extend("\n".join(root for root in self.roots if root != omitted) for omitted in self.roots)
        for output in outputs:
            with self.subTest(output=output[:80]), self.assertRaises(ValueError):
                inventory(output)

    def test_partition_omission_overlap_unselected_and_unknown_leaf_reject(self):
        phases = partition(self.roots)
        mutations = [
            phases[:-1], phases + [phases[0]],
            phases + [Phase("TestUnrelated")],
            phases + [Phase(self.phase.root)],
            phases + [Phase(self.phase.root, "new-undeclared-leaf")],
            phases + [Phase(self.roots[0], "not-a-divided-root")],
        ]
        for changed in mutations:
            with self.subTest(phases=len(changed)), self.assertRaises(ValueError):
                validate_partition(self.roots, changed)

    def test_split_source_addition_removal_or_replacement_rejects(self):
        raw = b'func TestOwned(t *testing.T) { t.Run("original", caseFn) }\n'
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / "owned_test.go"
            pins = {"owned_test.go": source_blob(raw)}
            path.write_bytes(raw)
            verify_sources(base, pins)
            for changed in (raw + b'// added case\n', raw.replace(b'original', b'new-case'), b""):
                path.write_bytes(changed)
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    verify_sources(base, pins)
            path.unlink()
            with self.assertRaises(ValueError):
                verify_sources(base, pins)

    def test_pass_only_empty_or_nonzero_cannot_be_acceptance(self):
        for output, status in (("", 0), ("PASS\n", 0),
                               (encoded([{"Action": "pass", "Package": PACKAGE}]), 0),
                               (encoded(receipt(self.phase)), 1)):
            with self.subTest(status=status, output=output[:40]), self.assertRaises(ValueError):
                verdict(output, status, self.phase)

    def test_missing_run_pass_package_or_truncated_stream_rejects(self):
        base = receipt(self.phase)
        for index in range(len(base)):
            with self.subTest(index=index), self.assertRaises(ValueError):
                verdict(encoded(base[:index] + base[index + 1:]), 0, self.phase)
        with self.assertRaises(ValueError):
            verdict(encoded(base) + '\n{"Action":', 0, self.phase)

    def test_skipped_failed_raced_or_duplicate_events_reject(self):
        base = receipt(self.phase)
        for action in ("skip", "fail"):
            for target in ("", self.phase.root, self.phase.label):
                events = [dict(event) for event in base]
                next(event for event in events if event.get("Test", "") == target and event["Action"] == "pass")["Action"] = action
                with self.subTest(action=action, target=target), self.assertRaises(ValueError):
                    verdict(encoded(events), 0, self.phase)
        for index in (0, 1, 2, 3, len(base) - 1):
            with self.subTest(duplicate=index), self.assertRaises(ValueError):
                verdict(encoded(base[:index] + [base[index]] + base[index:]), 0, self.phase)
        events = [dict(event) for event in base]
        events[1:1] = [{"Action": "output", "Package": PACKAGE, "Output": "WARNING: DATA "},
                       {"Action": "output", "Package": PACKAGE, "Output": "RACE\n"}]
        with self.assertRaises(ValueError):
            verdict(encoded(events), 0, self.phase)
        with self.assertRaises(ValueError):
            verdict(encoded(base), 0, self.phase, "WARNING: DATA RACE\n")

    def test_wrong_package_extra_sibling_or_descendant_rejects(self):
        for extra in ("TestUnrelated", self.phase.root + "/middle-source", self.phase.label + "/undeclared-child"):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                verdict(encoded(receipt(self.phase, (extra,))), 0, self.phase)
        events = receipt(self.phase)
        events[1]["Package"] = "substituted/package"
        with self.assertRaises(ValueError):
            verdict(encoded(events), 0, self.phase)

    def test_late_child_cannot_follow_a_passed_original_ancestor(self):
        events = receipt(self.phase)
        passed = next(event for event in events
                      if event["Action"] == "pass" and event.get("Test") == self.phase.root)
        events.remove(passed)
        events.insert(2, passed)
        with self.assertRaises(ValueError):
            verdict(encoded(events), 0, self.phase)
        phase = Phase("TestStartupSelectionRoundTripsBoundProfileToken")
        parent = phase.root + "/future-parent"
        child = parent + "/late-child"
        events = [
            {"Action": "start", "Package": PACKAGE},
            {"Action": "run", "Package": PACKAGE, "Test": phase.root},
            {"Action": "run", "Package": PACKAGE, "Test": parent},
            {"Action": "pass", "Package": PACKAGE, "Test": parent},
            {"Action": "run", "Package": PACKAGE, "Test": child},
            {"Action": "pass", "Package": PACKAGE, "Test": child},
            {"Action": "pass", "Package": PACKAGE, "Test": phase.root},
            {"Action": "pass", "Package": PACKAGE},
        ]
        with self.assertRaises(ValueError):
            verdict(encoded(events), 0, phase)

    def test_parent_pass_before_child_and_event_after_completion_reject(self):
        events = receipt(self.phase)
        indexes = [index for index, event in enumerate(events) if event["Action"] == "pass" and event.get("Test")]
        events[indexes[0]], events[indexes[1]] = events[indexes[1]], events[indexes[0]]
        with self.assertRaises(ValueError):
            verdict(encoded(events), 0, self.phase)
        events = receipt(self.phase) + [{"Action": "output", "Package": PACKAGE, "Output": "late receipt"}]
        with self.assertRaises(ValueError):
            verdict(encoded(events), 0, self.phase)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RunnerTests)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        return 1
    verify_sources(ROOT)
    if args.self_test:
        return 0
    with tempfile.TemporaryDirectory(prefix="routervpn-startup-race-") as directory:
        binary = Path(directory) / "client.test"
        subprocess.run(["go", "test", "-c", "-race", "-o", str(binary), "./cmd/client"],
                       cwd=ROOT, check=True, timeout=300)
        listed = subprocess.check_output([str(binary), "-test.list=."], cwd=ROOT / "cmd/client",
                                         text=True, timeout=30)
        roots = inventory(listed)
        phases = partition(roots)
        print("Compiled focused race inventory: " + str(len(roots)) + " roots, " +
              str(len(expected_cases(roots))) + " required case receipts, " +
              str(len(phases)) + " disjoint phases", flush=True)
        observed, completed = Counter(), Counter()
        for phase in phases:
            observed.update(run_phase(binary, phase))
            completed.update(phase.cases)
        if set(completed) != expected_cases(roots) or any(count != 1 for count in completed.values()):
            raise ValueError("Final focused inventory is incomplete or duplicated")
        if any(count != 1 for count in observed.values()):
            raise ValueError("A terminal test executed in more than one phase")
        print("Focused race complete: " + str(len(roots)) + " roots; " +
              str(len(observed)) + " executed terminal tests passed exactly once; " +
              str(len(phases)) + " phases retained the 180s Go alarm", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
