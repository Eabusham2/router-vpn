#!/usr/bin/env python3
"""Exact full-path Windows source/verdict controls; no native receipt is simulated."""
from pathlib import Path
import importlib.util
import inspect
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('windows_socks_host_gate',ROOT/'deploy/test_windows_socks_node_chain_host.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)


def completed():
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in G.REQUIRED)+''.join('verified installed Windows typed SOCKS full path and joined retirement: '+case+'\n' for case in G.CASES)+'PASS\n'


class FullPathGate(unittest.TestCase):
    def test_exact_inventory(self):
        self.assertEqual(G.CASES,('wg-connect','awg-fast-connect','awg-strong-connect','wg-wrong-middle-key','wg-wrong-middle-public','wg-final-dns-failure','wg-final-node-failure','wg-middle-source'))
        G.require_verdicts(completed())
        with self.assertRaises(ValueError):G.require_verdicts('PASS\n')
        original=''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in G.PREFIX_GATE.REQUIRED)+'PASS\n'
        with self.assertRaises(ValueError):G.require_verdicts(original)
    def test_every_full_path_verdict_and_witness_required(self):
        for line in completed().splitlines(True):
            for bad in (completed().replace(line,'',1),completed()+line,completed().replace(line,'foreign '+line,1)):
                with self.subTest(line=line),self.assertRaises(ValueError):G.require_verdicts(bad)
        for fault in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE'):
            with self.assertRaises(ValueError):G.require_verdicts(completed()+fault)
    def test_crypto_overlay_changes_only_explicit_platform_tuple(self):
        values=G.SCOPE.peer_sources();base=G.SCOPE.BASE.peer_sources()
        for name,raw in base.items():self.assertEqual(values[name],raw)
        for name in G.SCOPE.EXTRA:
            projected=values['routervpn_windows_socks_'+name.removesuffix('.tmpl')].decode().split('\n',1)[1]
            if name=='node_chain_socks_peer_test.go.tmpl':
                projected=projected.replace(' if runtime.GOOS == "windows" {\n  if !desktopWindowsPrefixReferenceAddressPair(address, client) { return netip.Addr{}, netip.Addr{}, bad }\n  return netip.MustParseAddr(address), netip.MustParseAddr(client), nil\n }\n','')
            self.assertEqual(projected,(ROOT/'mobile/desktop'/name).read_text().split('\n',1)[1])
        self.assertEqual(len(values),len(base)+4)
    def test_complete_source_identity_includes_projected_peer_and_originals(self):
        with patch.object(G.NODE,'checked_sources',return_value=(ROOT,{'original_native':'a'*64})),patch.object(G.CONTROLLER,'sources',return_value={'original_controller':'b'*64}):
            _,records=G.sources(ROOT)
        for name in G.OWNED:self.assertIn('gate/'+name,records)
        for name in G.SCOPE.peer_sources():self.assertIn('peer-overlay/'+name,records)
        self.assertIn('native/original_native',records);self.assertIn('controller/original_controller',records)
        body=inspect.getsource(G.execute)+inspect.getsource(G.execute_typed)+inspect.getsource(G.original_prefix)
        self.assertIn('PREFIX_GATE.execute(source, bundle, go, env=env)',body)
        self.assertIn('if sources(source)[1] != before or BUILD.reuse(bundle, target, env=captured) != original:',body)
        self.assertIn('if identities != {name: hashlib.sha256(path.read_bytes()).hexdigest()',body)
        self.assertIn('"original_prefix_acceptance": original_prefix_receipt',body)
        self.assertIn('"remote_associations_after_retirement": 0',body)
    def test_only_actual_elevated_windows_can_execute(self):
        with patch.object(G.platform,'system',return_value='Linux'),patch.object(G.PREFIX_GATE,'execute') as original:
            with self.assertRaisesRegex(ValueError,'actual elevated Windows'):G.execute(ROOT,ROOT)
            original.assert_not_called()


class CommandOwnership(unittest.TestCase):
    def test_owned_commands_preserve_exact_outcomes_and_workspace(self):
        command = ["native-controller", "original-case"]
        failures = (
            (subprocess.CalledProcessError(7, command, b"original out", b"original error"), True),
            (subprocess.TimeoutExpired(command, 1820), True),
            (subprocess.TimeoutExpired(["bootstrap", "join"], 1820), False),
            (RuntimeError("unproved native join"), False),
        )
        for failure, joined in failures:
            owner = G.COMMAND_OWNER.MAXCommandOwner()
            with self.subTest(failure=type(failure).__name__, joined=joined):
                try:
                    with owner.workspace(prefix="routervpn-socks-owner-control-") as work:
                        (work / "captured-image").write_bytes(b"original")
                        with patch.object(G.COMMAND_OWNER.REFERENCE.BUILD.BUILD_OWNER, "run", side_effect=failure):
                            if isinstance(failure, subprocess.CalledProcessError):
                                self.assertEqual(owner.run(command, cwd=work, env={}, timeout=1820), (7, "original outoriginal error"))
                            else:
                                with self.assertRaises(type(failure)) as observed:
                                    owner.run(command, cwd=work, env={}, timeout=1820)
                                self.assertIs(observed.exception, failure)
                        self.assertEqual(owner.retired, joined)
                        if not joined:
                            with self.assertRaisesRegex(RuntimeError, "unjoined"):
                                owner.run(command, cwd=work, env={}, timeout=1820)
                    self.assertEqual(work.exists(), not joined)
                finally:
                    if work.exists(): shutil.rmtree(work)

    def test_prefix_owned_once_and_restores_on_all_outcomes(self):
        for failure in (None, ValueError("original nonzero"), subprocess.TimeoutExpired(["original"], 600), RuntimeError("unproved join")):
            owner = G.COMMAND_OWNER.MAXCommandOwner()
            originals = (G.PREFIX_GATE.CONTROLLER.NATIVE.run, G.PREFIX_GATE.BUILD.reuse, G.PREFIX_GATE.tempfile)
            def prefix(*args, **kwargs):
                self.assertIsNot(G.PREFIX_GATE.CONTROLLER.NATIVE.run, originals[0])
                self.assertEqual(G.PREFIX_GATE.tempfile.TemporaryDirectory, owner.workspace)
                with patch.object(owner, "run", return_value=(0, "compiler")) as run:
                    self.assertEqual(G.PREFIX_GATE.CONTROLLER.NATIVE.run(["compiler"], cwd=ROOT, env={}), (0, "compiler"))
                    run.assert_called_once_with(["compiler"], cwd=ROOT, env={}, timeout=180)
                if failure: raise failure
                return {"original": 6}
            with self.subTest(failure=failure), patch.object(G.PREFIX_GATE, "execute", side_effect=prefix) as execute:
                if failure:
                    with self.assertRaises(type(failure)) as observed: G.original_prefix(owner, ROOT, ROOT, "go", {})
                    self.assertIs(observed.exception, failure)
                else: self.assertEqual(G.original_prefix(owner, ROOT, ROOT, "go", {}), {"original": 6})
                execute.assert_called_once_with(ROOT, ROOT, "go", env={})
            self.assertEqual((G.PREFIX_GATE.CONTROLLER.NATIVE.run, G.PREFIX_GATE.BUILD.reuse, G.PREFIX_GATE.tempfile), originals)

    def test_failed_prefix_blocks_typed_and_retains_unproved_workspace(self):
        owner = G.COMMAND_OWNER.MAXCommandOwner()
        failure = subprocess.TimeoutExpired(["bootstrap", "join"], 600)
        work = None
        def prefix(*args, **kwargs):
            nonlocal work
            with G.PREFIX_GATE.tempfile.TemporaryDirectory(prefix="routervpn-socks-prefix-control-") as work:
                G.PREFIX_GATE.CONTROLLER.NATIVE.run(["original"], cwd=work, env={}, timeout=600)
        try:
            with patch.object(G.platform, "system", return_value="Windows"), patch.object(G.ctypes, "windll", SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: True)), create=True), patch.object(G, "sources", return_value=(ROOT, {})), patch.object(G.COMMAND_OWNER, "MAXCommandOwner", return_value=owner), patch.object(G.PREFIX_GATE, "execute", side_effect=prefix) as original, patch.object(G, "execute_typed") as typed, patch.object(G.COMMAND_OWNER.REFERENCE.BUILD.BUILD_OWNER, "run", side_effect=failure):
                with self.assertRaises(subprocess.TimeoutExpired) as observed: G.execute(ROOT, ROOT)
                self.assertIs(observed.exception, failure)
                original.assert_called_once()
                typed.assert_not_called()
            self.assertFalse(owner.retired)
            self.assertTrue(work.is_dir())
        finally:
            if work is not None and work.exists(): shutil.rmtree(work)

    def test_preparation_failure_retains_workspace_and_restores_bindings(self):
        owner = G.COMMAND_OWNER.MAXCommandOwner()
        failure = RuntimeError("reuse bootstrap did not join")
        original_run = G.PREFIX_GATE.CONTROLLER.NATIVE.run
        original_tempfile = G.PREFIX_GATE.tempfile
        try:
            with patch.object(G.PREFIX_GATE.BUILD, "reuse", side_effect=failure) as original_reuse:
                with owner.workspace(prefix="routervpn-socks-reuse-control-") as work:
                    with self.assertRaises(RuntimeError) as observed:
                        with G.owned_bindings(G.PREFIX_GATE, owner, workspace=True): G.PREFIX_GATE.BUILD.reuse(work, "windows/amd64")
                    self.assertIs(observed.exception, failure)
                self.assertIs(G.PREFIX_GATE.BUILD.reuse, original_reuse)
            self.assertFalse(owner.retired)
            self.assertTrue(work.exists())
            self.assertIs(G.PREFIX_GATE.CONTROLLER.NATIVE.run, original_run)
            self.assertIs(G.PREFIX_GATE.tempfile, original_tempfile)
        finally:
            if work.exists(): shutil.rmtree(work)

    def test_unrelated_binding_replacement_is_not_overwritten(self):
        owner = G.COMMAND_OWNER.MAXCommandOwner()
        original_run, original_tempfile = G.PREFIX_GATE.CONTROLLER.NATIVE.run, G.PREFIX_GATE.tempfile
        foreign = lambda: None
        try:
            with self.assertRaisesRegex(RuntimeError, "binding was replaced"):
                with G.owned_bindings(G.PREFIX_GATE, owner, workspace=True): G.PREFIX_GATE.CONTROLLER.NATIVE.run = foreign
            self.assertIs(G.PREFIX_GATE.CONTROLLER.NATIVE.run, foreign)
            self.assertIs(G.PREFIX_GATE.tempfile, original_tempfile)
        finally: G.PREFIX_GATE.CONTROLLER.NATIVE.run = original_run

if __name__=='__main__':unittest.main()
