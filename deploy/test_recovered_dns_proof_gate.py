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
                         "cmd/client/dns_proof_path.go")
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
                "proveDNSAsyncWithProbe(sessionID, s, runtimeID, proveSelectedDNSContext)",
                'DNSProof.Status = "checking"', "t.invalidateDNSProofBindingLocked()",
            ),
            "cmd/client/dns_proof_path.go": (
                "asyncMeasurementPathContext", "beginAsyncMeasurementAdoption(ctx)",
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


if __name__ == "__main__":
    unittest.main()
