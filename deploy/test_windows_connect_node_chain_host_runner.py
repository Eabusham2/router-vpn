#!/usr/bin/env python3
"""Reject incomplete Windows CONNECT verdicts without simulating native acceptance."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import hashlib
import importlib.util
import os
import re
import shutil
import tempfile
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'windows_connect_host_gate', ROOT / 'deploy/test_windows_connect_node_chain_host.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def completed():
    return (''.join('=== RUN   ' + name + '\n--- PASS: ' + name + ' (0.01s)\n' for name in G.REQUIRED) +
            ''.join('verified installed Windows typed CONNECT full path and joined retirement: ' + case + '\n' for case in G.CASES) +
            ''.join('verified installed Windows public CONNECT route and capability: ' + case + '\n' for case in G.CASES) + 'PASS\n')


def original_receipt():
    prefix = dict(schema=1, native=True, cases=list(G.REQUIRED_PREFIX_CASES), samples_per_case=50,
                  native_down_before_review=True, original_final_unreachable=True,
                  target='windows/amd64', bundle_sha256='a' * 64, source_sha256='b' * 64)
    return dict(schema=1, native=True, cases=list(G.ORIGINAL_SOCKS_CASES), typed_full_path=True,
                native_joined=True, command_job_joined=True, remote_associations_after_retirement=0,
                positive_application_and_selected_dns_proved=True, original_prefix_acceptance=prefix,
                target=prefix['target'], bundle_sha256=prefix['bundle_sha256'], source_sha256=prefix['source_sha256'])



def owned_tuple_source():
    """Compile the actual three admission/retained-identity expressions.

    Only their surrounding peer/process setup is modeled. This portable check
    grants no native socket, process, WFP, or installed-path acceptance.
    """
    files = {
        "CONNECT": "desktop_node_chain_connect_windows_peer_native_test.go",
        "SOCKS": "desktop_node_chain_socks_windows_peer_native_test.go",
        "Prefix": "ordered_candidate_prefix_windows_native_test.go",
    }
    result = []
    for family, name in files.items():
        text = (ROOT / "cmd/client" / name).read_text()
        guards = re.findall(r'\t(endpoint, endpointError := netip.ParseAddrPort\(peer.reply.Address\))\n\tif (peer.reply.Schema[^\n]+) \{\n\t\tt.Fatal\("prefix peer changed original physical/key inventory"\)', text)
        retained = re.findall(r'\t\tif (value.Address != peer.reply.Address[^\n]+) \{\n\t\t\tt.Fatal\("prefix peer replaced original identity"\)', text)
        if len(guards) != 1 or len(retained) != 1:
            raise ValueError("Original Windows peer tuple assertion changed: " + family)
        declaration, condition = guards[0]
        count = 2 if family == "Prefix" else 1
        protocol = "socks5" if family == "SOCKS" else "http-connect"
        setup = f'''physical := struct{{Address string}}{{host}}
 peer := struct{{reply reply}}{{reply{{Schema:1,Address:address,Prefixes:make([]int,{count}),PublicCA:"original-ca"}}}}
 first := reply{{Protocol:"{protocol}",FinalUOTVersion:2,OpenStreams:new(int),Associations:new(int)}}
 first.Middle.Method = "{protocol}"
 protocol := "{protocol}"
 _ = first; _ = protocol
'''
        result.append(f'func admit{family}(host,address string)bool{{\n{setup}{declaration}\n_ = endpoint; _ = endpointError\nreturn !({condition})\n}}\n')
        result.append(f'''func retain{family}(address,next string)bool{{
 peer := struct{{reply reply}}{{reply{{Address:address,PublicCA:"original-ca"}}}}
 first := reply{{Protocol:"{protocol}",FinalUOTVersion:2,OpenStreams:new(int),Associations:new(int)}}
 value := first; value.Address=next; value.PublicCA=peer.reply.PublicCA
 _ = first
 return !({retained[0]})
}}
''')
    return '\n'.join(result)


OWNED_TUPLE_TEST = r'''package tuple
import "testing"
func TestActualOwnedTuple(t *testing.T){
 for _,f:=range []struct{name string;admit func(string,string)bool;retain func(string,string)bool}{
  {"CONNECT",admitCONNECT,retainCONNECT},{"SOCKS",admitSOCKS,retainSOCKS},{"Prefix",admitPrefix,retainPrefix},
 }{t.Run(f.name,func(t *testing.T){
  const host="192.168.50.10"
  const original="192.168.50.10:49173"
  if !f.admit(host,original){t.Fatal("owned ephemeral tuple rejected")}
  if !f.admit(host,"192.168.50.10:51820"){t.Fatal("valid owned fixed tuple rejected")}
  for _,bad:=range []string{"192.168.50.10:0","192.168.50.11:49173","192.168.50.10:049173","192.168.050.10:49173","[::ffff:192.168.50.10]:49173","[2001:db8::1]:49173","192.168.50.10","192.168.50.10:65536","host.invalid:49173","192.168.50.10:49173 ",""}{
   if f.admit(host,bad){t.Fatalf("unowned or noncanonical tuple admitted: %q",bad)}
  }
  if f.admit("192.168.050.10",original){t.Fatal("changed physical capture admitted")}
  if !f.retain(original,original){t.Fatal("original tuple was not retained")}
  for _,next:=range []string{"192.168.50.10:49174","192.168.50.11:49173","192.168.50.10:049173",""}{
   if f.retain(original,next){t.Fatal("changed tuple replaced original identity")}
  }
 })}
}
'''


def execute_owned_tuple_guards():
    compiler = shutil.which("go")
    if compiler is None:
        raise ValueError("Actual Go compiler required for Windows peer assertion regression")
    source = owned_tuple_source()
    header = '''package tuple
import "net/netip"
type reply struct{Schema int;Address,PublicCA,Protocol,ConnectCA,ServerName string;Prefixes []int;FinalUOTVersion int;OpenStreams,Associations *int;Middle struct{Method string}}
'''
    env = dict(os.environ, GOWORK="off", GOFLAGS="", GOTOOLCHAIN="local", GOMAXPROCS="1")
    with tempfile.TemporaryDirectory(prefix="windows-peer-tuple-") as directory:
        work = Path(directory)
        (work / "go.mod").write_text("module tuple\n\ngo 1.25\n")
        (work / "tuple_test.go").write_text(OWNED_TUPLE_TEST)
        def run(body, imports=header):
            (work / "tuple.go").write_text(imports + body)
            return subprocess.run([compiler,"test","-count=1","-timeout=10s","-v","."], cwd=work,
                                  env=env, capture_output=True, text=True, timeout=45)
        good = run(source)
        if good.returncode != 0:
            raise AssertionError("Actual Windows tuple assertions failed:\n" + good.stdout + good.stderr)
        print(good.stdout, end="")
        guard = 'endpointError != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 || endpoint.String() != peer.reply.Address || endpoint.Addr().String() != physical.Address'
        for family in ("CONNECT", "SOCKS", "Prefix"):
            start = source.index("func admit" + family + "(")
            end = source.index("\nfunc retain" + family + "(", start)
            body = source[start:end]
            if body.count(guard) != 1:
                raise ValueError("Exact original tuple guard mutation anchor changed")
            changed = source[:start] + body.replace(guard, 'peer.reply.Address != net.JoinHostPort(physical.Address, "51820")') + source[end:]
            result = run(changed, header.replace('import "net/netip"', 'import("net";"net/netip")'))
            output = result.stdout + result.stderr
            if result.returncode != 1 or '--- FAIL: TestActualOwnedTuple/' + family not in output or 'owned ephemeral tuple rejected' not in output or 'build failed' in output or 'panic:' in output:
                raise AssertionError("Original fixed-port causal control lost its exact failure:\n" + output)
            print("rejected original fixed-port guard: " + family)


class FullPathGate(unittest.TestCase):
    def test_actual_original_peer_tuple_guards(self):
        execute_owned_tuple_guards()

    def test_exact_http_https_and_packet_inventory(self):
        self.assertEqual(G.CASES, (
            'http-wg-connect', 'http-awg-fast-connect', 'http-awg-strong-connect',
            'https-wg-connect', 'https-awg-fast-connect', 'https-awg-strong-connect',
            'https-wg-wrong-middle-key', 'http-wg-wrong-middle-public',
            'https-wg-tls-name', 'https-wg-tls-trust', 'http-wg-final-dns-failure',
            'https-wg-final-node-failure', 'https-wg-final-key', 'https-wg-middle-source', 'http-wg-connect-off', 'https-wg-connect-off'))
        self.assertEqual(len(G.REQUIRED), 17)
        G.require_verdicts(completed())
        for old in (G.PREFIX_GATE, G.SOCKS_GATE):
            original = ''.join('=== RUN   ' + name + '\n--- PASS: ' + name + ' (0.01s)\n' for name in old.REQUIRED) + 'PASS\n'
            with self.assertRaises(ValueError):
                G.require_verdicts(original)

    def test_every_verdict_and_native_receipt_required_once(self):
        good = completed()
        for line in good.splitlines(True):
            for bad in (good.replace(line, '', 1), good + line, good.replace(line, 'foreign ' + line, 1)):
                with self.subTest(line=line), self.assertRaises(ValueError):
                    G.require_verdicts(bad)
        for failure in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:'):
            with self.assertRaises(ValueError):
                G.require_verdicts(good + failure)

    def test_original_prefix6_and_socks8_receipts_cannot_be_substituted(self):
        good = original_receipt()
        self.assertIs(G.require_originals(good), good)
        for parent, original in ((False, good), (True, good['original_prefix_acceptance'])):
            for key in original:
                changed = deepcopy(good)
                target = changed['original_prefix_acceptance'] if parent else changed
                del target[key]
                with self.subTest(parent=parent, key=key), self.assertRaises(ValueError):
                    G.require_originals(changed)
        for key in ('cases', 'target', 'bundle_sha256', 'source_sha256'):
            changed = deepcopy(good)
            changed['original_prefix_acceptance'][key] = ['foreign'] if key == 'cases' else 'foreign'
            with self.subTest(key=key), self.assertRaises(ValueError):
                G.require_originals(changed)
        for removed in G.PREFIX_OFF_CASES:
            changed = deepcopy(good)
            changed['original_prefix_acceptance']['cases'].remove(removed)
            with self.subTest(off=removed), self.assertRaises(ValueError):
                G.require_originals(changed)
        with patch.object(G.SOCKS_GATE, 'CASES', G.SOCKS_GATE.CASES[:-1]), self.assertRaises(ValueError):
            G.require_originals(good)
        with patch.object(G.PREFIX_GATE, 'CASES', G.PREFIX_GATE.CASES[:-1]), self.assertRaises(ValueError):
            G.require_originals(good)

    def test_real_connect_peer_projection_changes_only_test_selector(self):
        values, original = G.SCOPE.peer_sources(), G.SCOPE.BASE.peer_sources()
        for name, raw in original.items():
            self.assertEqual(values[name], raw)
        for source, name in G.SCOPE.EXTRA.items():
            header, body = values[name].decode().split('\n', 1)
            self.assertEqual(header, '//go:build windows && ' + G.SCOPE.TAG)
            self.assertEqual(body, (ROOT / source).read_text().split('\n', 1)[1])
        self.assertEqual(len(values), len(original) + 3)
        self.assertEqual(values['routervpn_windows_connect_physical_test.go'], (ROOT / G.SCOPE.WRAPPER).read_bytes())

    def test_complete_source_identity_binds_all_new_and_original_inputs(self):
        with patch.object(G.NODE, 'checked_sources', return_value=(ROOT, {'original_native': 'a' * 64})), patch.object(G.CONTROLLER, 'sources', return_value={'original_controller': 'b' * 64}):
            _, records = G.sources(ROOT)
        for name in G.OWNED:
            self.assertEqual(records['gate/' + name], hashlib.sha256((ROOT / name).read_bytes()).hexdigest())
        for name, raw in G.SCOPE.peer_sources().items():
            self.assertEqual(records['peer-overlay/' + name], hashlib.sha256(raw).hexdigest())
        self.assertIn('native/original_native', records)
        self.assertIn('controller/original_controller', records)

    def test_foreign_platform_cannot_begin_native_prerequisites(self):
        with patch.object(G.platform, 'system', return_value='Linux'), patch.object(G.SOCKS_GATE, 'execute') as original:
            with self.assertRaisesRegex(ValueError, 'actual elevated Windows'):
                G.execute(ROOT, ROOT)
            original.assert_not_called()

    def test_failed_originals_block_connect_and_keep_failure(self):
        for failure in (ValueError('original nonzero'), subprocess.TimeoutExpired(['original'], 600), RuntimeError('unproved join')):
            with self.subTest(failure=type(failure).__name__), patch.object(G.platform, 'system', return_value='Windows'), patch.object(G.ctypes, 'windll', SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: True)), create=True), patch.object(G, 'sources', return_value=(ROOT, {})), patch.object(G.SOCKS_GATE, 'execute', side_effect=failure) as original, patch.object(G, 'execute_typed') as typed, patch.object(G.COMMAND_OWNER, 'MAXCommandOwner') as owner:
                with self.assertRaises(type(failure)) as observed:
                    G.execute(ROOT, ROOT, 'captured-go', env={'captured': 'environment'})
                self.assertIs(observed.exception, failure)
                original.assert_called_once_with(ROOT, ROOT, 'captured-go', env={'captured': 'environment'})
                typed.assert_not_called()
                owner.assert_not_called()

    def test_substituted_original_source_blocks_connect_compile(self):
        with patch.object(G, 'sources', return_value=(ROOT, {'changed': 'source'})), patch.object(G.CONTROLLER.NATIVE, 'selected_compiler') as compiler:
            with self.assertRaisesRegex(ValueError, 'source changed'):
                G.execute_typed(ROOT, ROOT, 'go', {}, {'original': 'source'}, original_receipt(), object())
            compiler.assert_not_called()

    def test_private_command_bindings_restore_on_all_failures(self):
        owner = G.COMMAND_OWNER.MAXCommandOwner()
        module = SimpleNamespace(CONTROLLER=G.CONTROLLER, BUILD=G.BUILD)
        original_run, original_reuse = module.CONTROLLER.NATIVE.run, module.BUILD.reuse
        failure = RuntimeError('original native command failed')
        with self.assertRaisesRegex(RuntimeError, 'original native command failed'):
            with G.owned_bindings(module, owner):
                self.assertIsNot(module.CONTROLLER.NATIVE.run, original_run)
                self.assertIsNot(module.BUILD.reuse, original_reuse)
                raise failure
        self.assertIs(module.CONTROLLER.NATIVE.run, original_run)
        self.assertIs(module.BUILD.reuse, original_reuse)


if __name__ == '__main__':
    unittest.main()
