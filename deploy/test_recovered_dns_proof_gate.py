#!/usr/bin/env python3
"""Mutation checks for the recovered DNS proof predicate, without scoring a release."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RecoveredDNSProofGateTests(unittest.TestCase):
    def setUp(self) -> None:
        source = (ROOT / "deploy/recovered-release-audit-v3.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        predicate = next(node for node in tree.body
                         if isinstance(node, ast.FunctionDef) and node.name == "selected_dns_proof")
        # Execute the actual shipping predicate only: importing the whole scorer
        # would run unrelated platform checks and publish accounting output.
        module = ast.Module(body=[predicate], type_ignores=[])
        self.files = {
            path: (ROOT / path).read_text(encoding="utf-8")
            for path in ("cmd/client/dns_proof.go", "cmd/client/session_state.go",
                         "cmd/client/dns_proof_path.go", "cmd/client/session_dns_lifecycle.go",
                         "cmd/client/controller_shutdown.go")
        }
        namespace = {"mod": types.SimpleNamespace(has=self.has, body=lambda path: self.files.get(path, ""))}
        exec(compile(module, "recovered-dns-proof-predicate", "exec"), namespace)
        self.predicate = namespace["selected_dns_proof"]

    def has(self, path: str, *markers: str) -> bool:
        source = self.files.get(path, "")
        return bool(source) and all(marker in source for marker in markers)

    def test_current_owned_implementation_is_required(self) -> None:
        self.assertTrue(self.predicate())

    def test_each_ownership_and_runtime_requirement_is_load_bearing(self) -> None:
        requirements = {
            "cmd/client/dns_proof.go": (
                "verifyKernelDNSRuntime", "verifySingBoxDNSRuntime",
                "net.DefaultResolver.LookupHost", "selected-dns", "hijack-dns",
                'result.Status = "passed"',
            ),
            "cmd/client/session_state.go": (
                "t.startDNSProofLocked(t.session.ID, s, runtimeID, proveSelectedDNSContext)",
                "t.cancelStaleDNSProofLocked(s, runtimeID)", "t.invalidateDNSProofBindingLocked()",
            ),
            "cmd/client/session_dns_lifecycle.go": (
                "const sessionDNSProofBudget = 30 * time.Second",
                "t.dnsProofClosed", "t.session.ID != sessionID", "case <-previous.done:",
                "ctx, cancel := context.WithTimeout(", ", sessionDNSProofBudget)",
                "cancel: cancel, done: make(chan struct{})", "t.dnsProofWork = work",
                't.session.DNSProof.Status = "checking"',
                "defer close(work.done)", "defer cancel()",
                "t.proveDNSAsyncWithProbeContext(ctx, sessionID, s, runtimeID, probe)",
                "t.session.ID != work.sessionID", "runtimeID != work.runtimeID",
                "asyncMeasurementProfileToken(s.Profile) != work.profile", "work.cancel()",
                "desktopnetwork.LockContext(ctx, &t.mu)", "t.dnsProofClosed = true",
                "work := t.dnsProofWork", "case <-work.done:", "case <-ctx.Done():",
                "return ctx.Err()", "sessionTrackers.Load(a)", "tracker.a != a",
                "5*time.Second", "return tracker.stopDNSProofs(ctx)",
            ),
            "cmd/client/controller_shutdown.go": (
                "if err := stopSessionDNSProofs(a); err != nil {",
            ),
            "cmd/client/dns_proof_path.go": (
                "sessionTrackers.Load(t.a)", "owner != t",
                "measurementSessionContext(parent, t.a, t)",
                "asyncMeasurementPathContext(parent, t.a, s.Profile, st, before,",
                "t.dnsProofPathContextWithCaller(parent, sessionID, s, runtimeID)",
                "proof := probe(ctx, t.a, s, runtimeID)", "beginAsyncMeasurementAdoption(ctx)",
                "defer stop()", "defer release()", "dnsProofBinding.validateLocked(t.session)",
                '"dns-proof"', "t.session.DNSProof = proof",
            ),
        }
        for path, markers in requirements.items():
            original = self.files[path]
            for marker in markers:
                with self.subTest(path=path, requirement=marker):
                    self.assertIn(marker, original)
                    self.files[path] = original.replace(marker, "REMOVED_CONTRACT_REQUIREMENT")
                    self.assertFalse(self.predicate(), f"gate ignored missing {marker}")
            self.files[path] = original

    def test_missing_owned_helper_cannot_pass_through_legacy_markers(self) -> None:
        self.files["cmd/client/dns_proof_path.go"] = ""
        self.files["cmd/client/session_state.go"] += '\n"dns-proof"\nt.session.DNSProof = proof\n'
        self.assertFalse(self.predicate())

    def test_retained_observation_parent_keeps_the_same_bounded_worker(self) -> None:
        path = "cmd/client/session_dns_lifecycle.go"
        self.files[path], replaced = re.subn(
            r"ctx, cancel := context\.WithTimeout\([^\n]+, sessionDNSProofBudget\)",
            "ctx, cancel := context.WithTimeout(t.observationContext(), sessionDNSProofBudget)",
            self.files[path], count=1,
        )
        self.assertEqual(replaced, 1)
        self.assertTrue(self.predicate())

    def test_detached_probe_cannot_borrow_a_compatibility_wrapper(self) -> None:
        path = "cmd/client/session_dns_lifecycle.go"
        call = "t.proveDNSAsyncWithProbeContext(ctx, sessionID, s, runtimeID, probe)"
        self.assertIn(call, self.files[path])
        self.files[path] = self.files[path].replace(call, call.replace("(ctx,", "(context.Background(),"))
        # The old wrapper in dns_proof_path.go still has the bounded call.
        self.assertIn(call, self.files["cmd/client/dns_proof_path.go"])
        self.assertFalse(self.predicate())

    def test_lifecycle_markers_outside_the_owned_function_do_not_count(self) -> None:
        for path, marker in (
            ("cmd/client/session_state.go", "t.startDNSProofLocked(t.session.ID, s, runtimeID, proveSelectedDNSContext)"),
            ("cmd/client/session_dns_lifecycle.go", 't.session.DNSProof.Status = "checking"'),
            ("cmd/client/session_dns_lifecycle.go", "defer close(work.done)"),
            ("cmd/client/session_dns_lifecycle.go", "case <-work.done:"),
            ("cmd/client/controller_shutdown.go", "if err := stopSessionDNSProofs(a); err != nil {"),
        ):
            with self.subTest(path=path, marker=marker):
                original = self.files[path]
                self.assertIn(marker, original)
                self.files[path] = original.replace(marker, "REMOVED_OWNED_WIRING") + "\nfunc unusedProofFixture() {\n// " + marker + "\n}\n"
                self.assertFalse(self.predicate())
                self.files[path] = original

    def test_missing_worker_lifetime_cannot_pass_through_legacy_dispatch(self) -> None:
        self.files["cmd/client/session_dns_lifecycle.go"] = ""
        self.files["cmd/client/session_state.go"] += (
            '\nproveDNSAsyncWithProbe(sessionID, s, runtimeID, proveSelectedDNSContext)\n'
            'DNSProof.Status = "checking"\n')
        self.assertFalse(self.predicate())

if __name__ == "__main__":
    unittest.main()
