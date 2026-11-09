#!/usr/bin/env python3
"""Mutation checks for the recovered DNS proof predicate, without scoring a release."""
from __future__ import annotations

import ast
from pathlib import Path
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
        namespace = {"mod": types.SimpleNamespace(has=self.has)}
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
                "context.WithTimeout(context.Background(), sessionDNSProofBudget)",
                "t.dnsProofWork = work", 'DNSProof.Status = "checking"',
                "t.proveDNSAsyncWithProbeContext(ctx, sessionID, s, runtimeID, probe)",
                "defer close(work.done)", "work.cancel()", "t.dnsProofClosed = true",
                "desktopnetwork.LockContext(ctx, &t.mu)", "case <-work.done:",
                "case <-ctx.Done():", "return tracker.stopDNSProofs(ctx)",
            ),
            "cmd/client/controller_shutdown.go": ("stopSessionDNSProofs(a)",),
            "cmd/client/dns_proof_path.go": (
                "measurementSessionContext(parent, t.a, t)",
                "asyncMeasurementPathContext(parent, t.a, s.Profile",
                "t.dnsProofPathContextWithCaller(parent, sessionID, s, runtimeID)",
                "beginAsyncMeasurementAdoption(ctx)",
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

    def test_missing_worker_lifetime_cannot_pass_through_legacy_dispatch(self) -> None:
        self.files["cmd/client/session_dns_lifecycle.go"] = ""
        self.files["cmd/client/session_state.go"] += (
            '\nproveDNSAsyncWithProbe(sessionID, s, runtimeID, proveSelectedDNSContext)\n'
            'DNSProof.Status = "checking"\n')
        self.assertFalse(self.predicate())


if __name__ == "__main__":
    unittest.main()
