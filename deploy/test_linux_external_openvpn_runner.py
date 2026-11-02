#!/usr/bin/env python3
"""Require exact native OpenVPN source, toolchain, namespace and verdict evidence."""
from pathlib import Path
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("linux_external_openvpn_gate", Path(__file__).with_name("test_linux_external_openvpn.py"))
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)


def completed():
    return ["--- PASS: " + G.PARENT + " (1.00s)",
            *("    --- PASS: " + G.PARENT + "/" + name + " (0.10s)" for name in G.CASES)]


def success_output():
    return "\n".join(completed()) + "\n"


class Execution:
    """Model only compiler/privilege boundaries; keep real binary file checks."""
    def __init__(self, test, root, *, fault=None, arch="amd64", sudo=None, host="Linux", identity=None):
        self.test, self.root, self.fault, self.arch, self.sudo, self.host = test, root, fault, arch, sudo, host
        self.source = root / "core"
        self.source.mkdir()
        self.pq = root / "pq"
        self.pq.mkdir()
        self.compiler = str(root / "captured-go")
        self.env = {"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "1", "GOTOOLCHAIN": "go1.26.3", "GOWORK": "foreign-work"}
        self.identity = identity or {"GOOS": "linux", "GOHOSTOS": "linux", "GOARCH": arch, "GOHOSTARCH": arch, "CGO_ENABLED": "1"}
        self.calls, self.source_checks, self.pq_checks = [], 0, 0
        self.compiled, self.executed = False, False
        self.exception = RuntimeError("actual controlled boundary refusal")
        self.binary = None
        self.output = io.StringIO()

    def sources(self, source):
        self.test.assertEqual(source, self.source)
        self.source_checks += 1
        marker = "original"
        if self.fault == "compile-source" and self.compiled or self.fault == "execute-source" and self.executed:
            marker = "changed"
        return self.source, {"captured-source": marker}

    def compiler_toolchain(self, source, go, env):
        self.test.assertEqual((source, go), (self.source, "owned-go"))
        self.test.assertEqual(env, dict(self.env, GOWORK="off"))
        return self.compiler, dict(env, OWNED_COMPILER="captured")

    def pq_receipt(self, directory, target):
        self.test.assertEqual((directory, target), (self.pq, "linux/" + self.arch))
        self.pq_checks += 1
        marker = "original"
        if self.fault == "compile-pq" and self.compiled or self.fault == "execute-pq" and self.executed:
            marker = "changed"
        return {"native_static_libs": ["-lpq", "-lm"], "source": marker}

    def run(self, command, **kwargs):
        args = [str(value) for value in command]
        self.calls.append(args)
        self.test.assertEqual(kwargs["env"].get("OWNED_COMPILER"), "captured")
        self.test.assertEqual(kwargs["env"]["GOWORK"], "off")
        if args[:3] == [self.compiler, "env", "-json"]:
            self.test.assertEqual(args[3:], ["GOOS", "GOARCH", "GOHOSTOS", "GOHOSTARCH", "CGO_ENABLED"])
            self.test.assertEqual(kwargs["cwd"], self.source)
            self.test.assertEqual(kwargs["timeout"], 30)
            return json.dumps(self.identity)
        if args[:3] == [self.compiler, "test", "-c"]:
            self.test.assertEqual(kwargs["cwd"], self.source)
            self.test.assertEqual(kwargs["timeout"], 600)
            self.test.assertEqual(args[3:7], ["-race", "-mod=readonly", "-tags=with_openvpn,routervpn_native_pq", "-ldflags=-checklinkname=0"])
            self.test.assertEqual(args[-1], ".")
            self.test.assertEqual(kwargs["env"]["CGO_LDFLAGS"], "-L" + str(self.pq) + " -lpq -lm")
            if self.fault == "compile-failure":
                raise self.exception
            self.binary = Path(args[args.index("-o") + 1])
            self.binary.write_bytes(b"original compiled native image")
            self.binary.chmod(0o700)
            self.compiled = True
            if self.fault == "compile-mode":
                self.binary.chmod(0o777)
            elif self.fault == "compile-no-exec":
                self.binary.chmod(0o600)
            elif self.fault == "compile-empty":
                self.binary.write_bytes(b"")
            elif self.fault == "compile-hardlink":
                os.link(self.binary, self.binary.with_suffix(".link"))
            elif self.fault == "compile-symlink":
                original = self.binary.with_suffix(".original")
                self.binary.rename(original)
                self.binary.symlink_to(original)
            return ""
        expected = [sys.executable, str(Path(G.__file__).resolve()), "--namespace-test-binary", str(self.binary),
                    "--namespace-test-sha256", hashlib.sha256(b"original compiled native image").hexdigest()]
        if self.sudo is not None:
            expected = [self.sudo, "-n", "--", *expected]
        self.test.assertEqual(args, expected)
        self.test.assertEqual(kwargs["cwd"], G.ROOT)
        self.test.assertEqual(kwargs["timeout"], 150)
        self.test.assertEqual(kwargs["sudo"], self.sudo)
        self.executed = True
        if self.fault == "execute-failure":
            raise self.exception
        if self.fault == "execute-bytes":
            self.binary.write_bytes(b"foreign compiled native image!")
        elif self.fault == "execute-inode":
            other = self.binary.with_suffix(".replacement")
            other.write_bytes(self.binary.read_bytes())
            other.chmod(0o700)
            other.replace(self.binary)
        elif self.fault == "execute-mode":
            self.binary.chmod(0o711)
        elif self.fault == "execute-hardlink":
            os.link(self.binary, self.binary.with_suffix(".link"))
        elif self.fault == "execute-symlink":
            original = self.binary.with_suffix(".original")
            self.binary.rename(original)
            self.binary.symlink_to(original)
        return success_output() if self.fault != "execute-verdict" else "\n".join(completed()[:-1]) + "\n"

    def execute(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(G.platform, "system", return_value=self.host))
            stack.enter_context(patch.object(G, "checked_sources", side_effect=self.sources))
            stack.enter_context(patch.object(G.GUARD.UID, "privilege_tool", return_value=self.sudo))
            stack.enter_context(patch.object(G.GUARD.UID, "compiler_toolchain", side_effect=self.compiler_toolchain))
            stack.enter_context(patch.object(G.GUARD.UID, "run", side_effect=self.run))
            stack.enter_context(patch.object(G.BUILD.PQ, "verify", side_effect=self.pq_receipt))
            tags = stack.enter_context(patch.object(G.BUILD, "tags", return_value=["with_openvpn", "routervpn_native_pq"]))
            stack.enter_context(redirect_stdout(self.output))
            G.execute(self.source, self.pq, "owned-go", env=self.env)
            tags.assert_called_once_with("linux/" + self.arch)


class LinuxExternalOpenVPNRunner(unittest.TestCase):
    def test_exact_terminated_inventory_is_required(self):
        self.assertEqual(len(G.CASES), 12)
        self.assertEqual(len(set(G.CASES)), 12)
        G.check_verdict(success_output())
        G.check_verdict(success_output().replace("\n", "\r\n"))
        rows = completed()
        for index in range(len(rows)):
            for mutation in ("missing", "duplicate", "prefix", "unterminated"):
                altered = list(rows)
                if mutation == "missing":
                    altered.pop(index)
                elif mutation == "duplicate":
                    altered.append(rows[index])
                elif mutation == "prefix":
                    altered[index] = "untrusted-prefix " + altered[index]
                else:
                    altered.pop(index)
                    altered.append(rows[index])
                output = "\n".join(altered) + ("" if mutation == "unterminated" else "\n")
                with self.subTest(index=index, mutation=mutation), self.assertRaises(ValueError):
                    G.check_verdict(output)

    def test_failed_skipped_unknown_or_empty_output_is_rejected(self):
        for suffix in ("--- FAIL: actual child (1s)\n", "--- SKIP: native dependency (0s)\n", "DATA RACE\n",
                       "--- PASS: " + G.PARENT + "/unrecognized-case (1.00s)\n"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                G.check_verdict(success_output() + suffix)
        for value in ("", None, b"not text"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                G.check_verdict(value)

    def test_namespace_delegation_retains_original_binary_and_digest(self):
        original = RuntimeError("actual original namespace denial")
        with patch.object(G.GUARD, "namespace_test", return_value=31) as enter:
            self.assertEqual(G.namespace_test(Path("/owned-image"), "a" * 64), 31)
        enter.assert_called_once_with(Path("/owned-image"), "ExternalOpenVPN", "a" * 64)
        with patch.object(G.GUARD, "namespace_test", side_effect=original), self.assertRaises(RuntimeError) as caught:
            G.namespace_test(Path("/owned-image"), "a" * 64)
        self.assertIs(caught.exception, original)

    def test_actual_authority_files_and_required_native_inputs_are_captured(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "deploy").mkdir()
            source = root / "core"
            source.mkdir()
            for name in G.RUNNERS:
                (root / "deploy" / name).write_bytes(("actual authority " + name).encode())
            records = {name: hashlib.sha256(name.encode()).hexdigest() for name in G.REQUIRED}
            with patch.object(G, "ROOT", root), patch.object(G.NODE, "checked_sources", side_effect=lambda path: (source, dict(records))):
                captured_source, captured = G.checked_sources(source)
                self.assertEqual(captured_source, source)
                for name in G.RUNNERS:
                    path = root / "deploy" / name
                    self.assertEqual(captured["gate/" + name], hashlib.sha256(path.read_bytes()).hexdigest())
                    original = path.read_bytes()
                    path.write_bytes(original + b" changed")
                    self.assertNotEqual(G.checked_sources(source)[1], captured)
                    path.unlink()
                    with self.assertRaises(ValueError):
                        G.checked_sources(source)
                    target = root / "foreign-authority"
                    target.write_bytes(original)
                    path.symlink_to(target)
                    with self.assertRaises(ValueError):
                        G.checked_sources(source)
                    path.unlink()
                    path.write_bytes(original)
                for name in G.REQUIRED:
                    original = records.pop(name)
                    with self.subTest(missing=name), self.assertRaises(ValueError):
                        G.checked_sources(source)
                    records[name] = original

    def test_matching_host_uses_exact_pq_compiler_and_namespace(self):
        for arch in ("amd64", "arm64"):
            for sudo in (None, "/owned/sudo"):
                with self.subTest(arch=arch, sudo=sudo), tempfile.TemporaryDirectory() as temporary:
                    case = Execution(self, Path(temporary).resolve(), arch=arch, sudo=sudo)
                    case.execute()
                    self.assertTrue(case.compiled and case.executed)
                    self.assertEqual((case.source_checks, case.pq_checks), (3, 3))
                    self.assertEqual(len(case.calls), 3)
                    self.assertIn("installed-device acceptance remain separate", case.output.getvalue())

    def test_foreign_host_architecture_or_cgo_never_compiles(self):
        identities = [{"GOOS": "windows"}, {"GOHOSTOS": "darwin"}, {"GOARCH": "arm64"},
                      {"GOHOSTARCH": "arm64"}, {"GOARCH": "386", "GOHOSTARCH": "386"}, {"CGO_ENABLED": "0"}]
        for mutation in ("host", "target", *identities):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                case = Execution(self, Path(temporary).resolve())
                if mutation == "host":
                    case.host = "Darwin"
                elif mutation == "target":
                    case.env["GOOS"] = "windows"
                else:
                    case.identity.update(mutation)
                with self.assertRaises(ValueError):
                    case.execute()
                self.assertFalse(case.compiled or case.executed)

    def test_source_and_pq_changes_refuse_next_stage(self):
        for fault in ("compile-source", "compile-pq", "execute-source", "execute-pq"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                case = Execution(self, Path(temporary).resolve(), fault=fault)
                with self.assertRaises(ValueError):
                    case.execute()
                self.assertTrue(case.compiled)
                self.assertEqual(case.executed, fault.startswith("execute-"))
                self.assertEqual(case.output.getvalue(), "")

    def test_invalid_or_replaced_actual_executable_never_passes(self):
        for fault in ("compile-mode", "compile-no-exec", "compile-empty", "compile-hardlink", "compile-symlink",
                      "execute-bytes", "execute-inode", "execute-mode", "execute-hardlink", "execute-symlink", "execute-verdict"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                case = Execution(self, Path(temporary).resolve(), fault=fault)
                with self.assertRaises(ValueError):
                    case.execute()
                self.assertEqual(case.executed, fault.startswith("execute-"))
                self.assertEqual(case.output.getvalue(), "")

    def test_original_compilation_and_native_failures_propagate(self):
        for fault in ("compile-failure", "execute-failure"):
            for error in (subprocess.CalledProcessError(37, ["original-child"]), subprocess.TimeoutExpired(["original-child"], 17)):
                with self.subTest(fault=fault, error=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                    case = Execution(self, Path(temporary).resolve(), fault=fault)
                    case.exception = error
                    with self.assertRaises(type(error)) as caught:
                        case.execute()
                    self.assertIs(caught.exception, error)
                    self.assertEqual(case.executed, fault.startswith("execute-"))
                    self.assertEqual(case.output.getvalue(), "")

    def test_cli_preserves_original_error_and_namespace_status(self):
        output = b"old-prefix\n" + b"x" * 40000 + b"\xfforiginal failure\n"
        error = subprocess.CalledProcessError(37, ["original-child"], output=output)
        diagnostic = io.StringIO()
        with patch.object(G, "execute", side_effect=error), redirect_stderr(diagnostic), self.assertRaises(subprocess.CalledProcessError) as caught:
            G.main(["/source", "--pq", "/pq", "--go", "/go"])
        self.assertIs(caught.exception, error)
        self.assertEqual(diagnostic.getvalue(), output[-32768:].decode("utf-8", errors="replace"))
        self.assertNotIn("old-prefix", diagnostic.getvalue())
        with patch.object(G, "namespace_test", return_value=23) as enter, patch.object(G, "execute") as execute:
            with self.assertRaises(SystemExit) as caught:
                G.main(["--namespace-test-binary", "/native-image", "--namespace-test-sha256", "b" * 64])
        self.assertEqual(caught.exception.code, 23)
        enter.assert_called_once_with(Path("/native-image"), "b" * 64)
        execute.assert_not_called()
        for args in (["/source"], ["--pq", "/pq"], ["--namespace-test-binary", "/image"],
                     ["/source", "--pq", "/pq", "--namespace-test-binary", "/image", "--namespace-test-sha256", "b" * 64]):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                G.main(args)


if __name__ == "__main__":
    unittest.main()
