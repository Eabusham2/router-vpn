#!/usr/bin/env python3
"""Causal tests of the encrypted Server gate; these are not native acceptance."""
from pathlib import Path
import importlib.util
import ast
import hashlib
import subprocess
import sys
import json
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_encrypted_gate_test', ROOT/'deploy/test_server_node_chain_encrypted.py')
GATE = importlib.util.module_from_spec(spec); spec.loader.exec_module(GATE)


def sample(case='wg'):
    ready = case not in GATE.NEGATIVE
    receipt = dict(modes=list(GATE.MODES[case]), case=case, capture_sha256='a'*64, source_sha256='b'*64, prefixes=3 if case == 'mixed-three' else 2,
                   ready=ready, retired=True, selected_dns=ready, final_tcp=14 if ready else 0, final_udp=9 if ready else 0,
                   peer_joined=True, worker_joined=True, carrier_change_refused=case=='wg')
    if case.startswith('candidate-'):receipt.update(candidate_connects=50,candidate_closed=True)
    # Go's real nested output reports the parent PASS before buffered child
    # PASS. A receipt belongs to native work and must precede that parent.
    return '\n'.join(('=== RUN   '+GATE.NATIVE, '=== RUN   '+GATE.NATIVE+'/'+case,
        '    fixture_test.go:140: ENCRYPTED_SERVER_RECEIPT '+json.dumps(receipt),
        '--- PASS: '+GATE.NATIVE+' (1.20s)', '    --- PASS: '+GATE.NATIVE+'/'+case+' (1.20s)', 'PASS', ''))


def workflow(value):
    # Only the upload step runs on failure; native execution remains unconditional.
    upload='      - uses: actions/upload-artifact@v4\n        if: always()\n        with:'
    if value.count(upload)!=1:raise ValueError('Required failure artifact retention changed')
    value=value.replace(upload,'      - uses: actions/upload-artifact@v4\n        with:',1)
    required = ('  workflow_call:\n', '  encrypted:\n', '    runs-on: ${{ matrix.runner }}',
        '          - arch: amd64\n            runner: ubuntu-24.04\n',
        '          - arch: arm64\n            runner: ubuntu-24.04-arm\n',
        "  group: server-node-chain-encrypted-${{ github.workflow }}-${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && github.workflow == 'Ordered Server encrypted suffix acceptance' && github.ref || github.run_id }}",
        '  cancel-in-progress: false', '          persist-credentials: false', '          go-version: \'1.26.3\'',
        'python3 deploy/test_server_node_chain_encrypted_runner.py',
        'python3 deploy/test_server_node_chain_encrypted.py --standalone --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_SERVER_RECEIPT"',
        '          if-no-files-found: error')
    if any(value.count(anchor) != 1 for anchor in required) or re.search(r'^\s*(?:if|continue-on-error|inputs):', value, re.M) or '--compile-only' in value or '|| true' in value:
        raise ValueError('Required native Server architecture/invocation was removed or made conditional')


def workflow_concurrency_cases(raw):
    """Evaluate the actual small expression; reusable calls retain caller context."""
    blocks = re.findall(r'^concurrency:\n((?:[ \t]+[^\n]*\n|\n)+)', raw, re.M)
    if len(blocks) != 1 or blocks[0].count('  cancel-in-progress: false\n') != 1:
        raise ValueError('An active native run must finish before the next automatic push')
    groups = re.findall(r'^  group: (.+)$', blocks[0], re.M)
    if len(groups) != 1:
        raise ValueError('Native concurrency must have one exact group')
    own = 'Ordered Server encrypted suffix acceptance'
    cases = (
        ('old-main', own, 'push', 'refs/heads/main', '100', 'a'*40, 'refs/heads/main'),
        ('new-main', own, 'push', 'refs/heads/main', '101', 'b'*40, 'refs/heads/main'),
        ('manual-same-sha', own, 'workflow_dispatch', 'refs/heads/main', '102', 'b'*40, '102'),
        ('second-manual-same-sha', own, 'workflow_dispatch', 'refs/heads/main', '103', 'b'*40, '103'),
        ('manual-other-sha', own, 'workflow_dispatch', 'refs/heads/main', '104', 'c'*40, '104'),
        ('manual-tag', own, 'workflow_dispatch', 'refs/tags/v1', '105', 'b'*40, '105'),
        ('pull-request', own, 'pull_request', 'refs/pull/1/merge', '106', 'b'*40, '106'),
        ('other-branch', own, 'push', 'refs/heads/feature', '107', 'b'*40, '107'),
        ('called-push', 'Build all Router VPN release gates', 'push', 'refs/heads/main', '108', 'b'*40, '108'),
        ('second-called-push', 'Build all Router VPN release gates', 'push', 'refs/heads/main', '109', 'b'*40, '109'),
        ('called-release-manual', 'Router VPN release candidate', 'workflow_dispatch', 'refs/heads/main', '110', 'b'*40, '110'),
        ('called-build-manual', 'Build all Router VPN release gates', 'workflow_dispatch', 'refs/heads/main', '111', 'b'*40, '111'),
    )
    for label, workflow_name, event, ref, run, sha, lane in cases:
        context = dict(workflow=workflow_name, event_name=event, ref=ref, run_id=run, sha=sha)
        def expression(match):
            code = re.sub(r'github\.(workflow|event_name|ref|run_id|sha)\b',
                          lambda item: repr(context[item.group(1)]), match.group(1))
            tree = ast.parse(code.replace('&&', ' and ').replace('||', ' or ').strip(), mode='eval')
            if any(not isinstance(node, (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq, ast.Constant))
                   for node in ast.walk(tree)):
                raise ValueError('Unexpected native concurrency expression')
            return str(eval(compile(tree, '<captured native concurrency>', 'eval'), {'__builtins__': {}}))
        actual = re.sub(r'\$\{\{\s*(.*?)\s*\}\}', expression, groups[0])
        expected = 'server-node-chain-encrypted-' + workflow_name + '-' + lane
        if actual != expected:
            raise ValueError('Native concurrency lost original context isolation: '+label)
    return len(cases)


class GateTests(unittest.TestCase):
    def test_multiple_import_original_proof_boundaries_and_join_are_mandatory(self):
        for case in GATE.MULTIPLE_CASES:
            sparse = case != 'adjacent'
            ready = case in ('adjacent', 'sparse', 'packet-first', 'joined-active-udp')
            first_proven = case != 'wrong-key-first'
            second_reached = first_proven and case != 'wrong-public-first'
            second_proven = second_reached and case != 'wrong-key-second'
            final_reached = second_proven and case != 'wrong-public-second'
            value = dict(case=case, positions=[0,1] if case == 'packet-first' else [0,2] if sparse else [0], ready=ready,
                         pending_closed=True, worker_joined=True, peer_joined=True, in_flight=case=='joined-active-udp',
                         outer_tcp=2, outer_udp=int(ready), outer_proofs=int(first_proven),
                         outer_auth_failures=int(case=='wrong-key-first'), inner_auth_failures=int(case=='wrong-key-second'),
                         packet_udp=int(sparse and second_reached), packet_proofs=int(sparse and second_reached),
                         inner_tcp=int(second_reached), inner_proofs=int(second_proven), inner_udp=int(ready),
                         final_health=int(final_reached), final_dns=int(final_reached), final_public=int(ready),
                         final_udp=int(ready), echo_replies=int(ready), capture_sha256='a'*64, source_sha256='b'*64)
            root = GATE.MULTIPLE_NATIVE
            def transcript(v):
                return '\n'.join(('=== RUN   '+root, '=== RUN   '+root+'/'+case,
                                  '    witness.go:1: MULTIPLE_SERVER_RECEIPT '+json.dumps(v),
                                  '--- PASS: '+root+' (0.01s)', '    --- PASS: '+root+'/'+case+' (0.01s)', 'PASS'))
            self.assertEqual(GATE.check_imported_verdict(transcript(value), case, multiple=True), value)
            for field in ('positions','ready','pending_closed','worker_joined','peer_joined','outer_tcp','outer_proofs',
                          'outer_auth_failures','inner_auth_failures','packet_proofs','inner_tcp','inner_proofs','final_dns','final_health','final_public','in_flight'):
                changed = value.copy()
                if field == 'positions':
                    changed[field] = [0, 3]
                elif type(value[field]) is bool:
                    changed[field] = not value[field]
                else:
                    changed[field] = int(not value[field])
                with self.subTest(case=case, field=field), self.assertRaises(ValueError):
                    GATE.check_imported_verdict(transcript(changed), case, multiple=True)
        program = GATE.namespace_program(hashlib.sha256(Path(GATE.__file__).read_bytes()).hexdigest(), multiple=True)
        scope = {'__name__':'inspection'}
        exec(program, scope)
        self.assertEqual(scope['CASES'], GATE.MULTIPLE_CASES)
        self.assertEqual(scope['NATIVE'], GATE.MULTIPLE_NATIVE)

    def test_candidate_receipt_exact_quota_and_join(self):
        for case in ('candidate-wg','candidate-awg'):
            baseline=sample(case);GATE.check_verdict(baseline,case)
            for old,new in (('"candidate_connects": 50','"candidate_connects": 49'),('"candidate_closed": true','"candidate_closed": false'),('"candidate_connects": 50, ','')):
                with self.subTest(case=case,old=old),self.assertRaises(ValueError):GATE.check_verdict(baseline.replace(old,new),case)

    def test_actual_hostname_tcp_transport_is_required_and_exact(self):
        name = GATE.HOSTNAME_TCP_ROOT
        output = '=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\nPASS\n'
        GATE.check_hostname_tcp_verdict(output)
        for changed in (output.replace('=== RUN   '+name+'\n',''),output.replace('--- PASS: '+name+' (0.01s)\n',''),
                        output.replace('\nPASS\n','\n'),output+output,output.replace(name,'Foreign',1),
                        output.replace('--- PASS:', 'log --- PASS:',1),output+'--- SKIP: ignored (0.01s)\n',
                        output+'WARNING: DATA RACE\n',output+'panic: owner\n',output+'PASS\n'):
            with self.subTest(changed=changed),self.assertRaises(ValueError): GATE.check_hostname_tcp_verdict(changed)
        source=(ROOT/'deploy/test_server_node_chain_encrypted.py').read_text()
        self.assertEqual(source.count('check_hostname_tcp_verdict(hostname_tcp_output)'),1)
        self.assertIn("[peer, '-test.run=^'+HOSTNAME_TCP_ROOT+'$'",source)
        fixture=(ROOT/'mobile/desktop/node_chain_imported_server_peer_test.go.tmpl').read_text()
        self.assertEqual(fixture.count('func '+name+'(t *testing.T)'),1)
        self.assertIn('DNST.NewTCPRaw(',fixture)

    def test_actual_logger_io_copy_obeys_snapshot_mutex(self):
        template=(ROOT/GATE.TEMPLATE).read_text()
        begin=template.index('type serverChainEncryptedLog struct {')
        end=template.index('type serverChainEncryptedProcess struct {',begin)
        shipping=template[begin:end]
        harness=r'''package main
import("bytes";"io";"runtime";"strings";"sync";"testing")
SHIPPING
func TestNoPromotedReadFrom(t *testing.T){var log serverChainEncryptedLog;if _,ok:=any(&log).(io.ReaderFrom);ok{t.Fatal("logger exposes unguarded ReaderFrom")}}
func TestActualCopyAndSnapshot(t *testing.T){
 var log serverChainEncryptedLog;start:=make(chan struct{});done:=make(chan struct{})
 go func(){defer close(done);<-start;for i:=0;i<512;i++{if _,err:=io.Copy(&log,struct{io.Reader}{strings.NewReader(strings.Repeat("x",1024))});err!=nil{panic(err)};runtime.Gosched()}}()
 close(start);for i:=0;i<1000;i++{if len(log.text())>8192{t.Fatal("unbounded snapshot")};runtime.Gosched()};<-done
 if got:=log.text();len(got)!=8192||got!=strings.Repeat("x",8192){t.Fatal("original complete logger tail lost")}
}
'''
        with tempfile.TemporaryDirectory(prefix='server-actual-log-race-') as directory:
            root=Path(directory);(root/'go.mod').write_text('module routervpn-server-log-test\n\ngo 1.26\n')
            test=root/'log_test.go';test.write_text(harness.replace('SHIPPING',shipping))
            command=['go','test','-race','-count=1','-timeout=30s','.']
            result=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=45)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(shipping.count('buffer bytes.Buffer'),1)
            old=shipping.replace('buffer bytes.Buffer','bytes.Buffer',1).replace('b.buffer.','b.Buffer.')
            test.write_text(harness.replace('SHIPPING',old))
            failed=subprocess.run(command[:-1]+['-run=^TestActualCopyAndSnapshot$','.'],cwd=root,capture_output=True,text=True,timeout=45)
            self.assertNotEqual(failed.returncode,0,failed.stdout+failed.stderr)
            self.assertIn('WARNING: DATA RACE',failed.stdout+failed.stderr)


    def test_actual_hostname_tcp_reuse_probes_are_not_application_dns(self):
        template=(ROOT/'mobile/desktop/node_chain_imported_server_peer_test.go.tmpl').read_text()
        begin=template.index('type desktopNodeChainImportedServerDNS struct')
        end=template.index('\nfunc TestRouterVPNDesktopNodeChainImportedServerReferenceProcess',begin)
        shipping=template[begin:end]
        harness=r'''package main
import("fmt";"os";"net";"strings";"sync";"sync/atomic";"testing";"time";"github.com/miekg/dns")
const desktopImportedHostname="Middle.EXAMPLE.test"
const desktopImportedHostnameDNS="10.78.0.53:5353"
type desktopReferenceRule struct{Network,Address string;Port int;Target string}
type serverEntry struct{rules map[string]desktopReferenceRule}
type serverPaired struct{entry *serverEntry}
type desktopNodeChainImportedPeer struct{paired *serverPaired}
func serverPeer()*desktopNodeChainImportedPeer{return &desktopNodeChainImportedPeer{&serverPaired{&serverEntry{make(map[string]desktopReferenceRule)}}}}
SHIPPING
type serverWriter struct {dns.ResponseWriter; address net.Addr}
func(w *serverWriter)RemoteAddr()net.Addr{return w.address}
func serverQuestion(id,kind uint16)*dns.Msg{q:=new(dns.Msg).SetQuestion(desktopImportedHostname+".",kind);q.Id=id;return q}
func TestHostnameQuestionBoundaries(t *testing.T){
 original:=serverQuestion(2,dns.TypeAAAA);address:=&serverWriter{address:&net.TCPAddr{IP:net.IPv4(127,0,0,1),Port:12345}}
 for label,mutate:=range map[string]func(*dns.Msg){
 "id":func(q *dns.Msg){q.Id=0},"name":func(q *dns.Msg){q.Question[0].Name="foreign.example."},"private":func(q *dns.Msg){q.Question[0].Name="10.0.0.1."},"mapped":func(q *dns.Msg){q.Question[0].Name="::ffff:127.0.0.1."},"class":func(q *dns.Msg){q.Question[0].Qclass=dns.ClassCHAOS},"type":func(q *dns.Msg){q.Question[0].Qtype=dns.TypeTXT},"duplicate":func(q *dns.Msg){q.Question=append(q.Question,q.Question[0])},"missing":func(q *dns.Msg){q.Question=nil},"response":func(q *dns.Msg){q.Response=true},"opcode":func(q *dns.Msg){q.Opcode=dns.OpcodeStatus},"rcode":func(q *dns.Msg){q.Rcode=dns.RcodeNameError},"authoritative":func(q *dns.Msg){q.Authoritative=true},"truncated":func(q *dns.Msg){q.Truncated=true},"available":func(q *dns.Msg){q.RecursionAvailable=true},"rd":func(q *dns.Msg){q.RecursionDesired=false},"ad":func(q *dns.Msg){q.AuthenticatedData=true},"cd":func(q *dns.Msg){q.CheckingDisabled=true},"answer":func(q *dns.Msg){q.Answer=[]dns.RR{new(dns.A)}},"ns":func(q *dns.Msg){q.Ns=[]dns.RR{new(dns.NS)}},"extra":func(q *dns.Msg){q.Extra=[]dns.RR{new(dns.OPT)}},
 }{t.Run(label,func(t *testing.T){owner:=new(desktopNodeChainImportedServerDNS);if owner.question(serverQuestion(1,dns.TypeA),address)!=1{t.Fatal("original probe A rejected")};q:=original.Copy();mutate(q);if owner.question(q,address)>=0{t.Fatal("foreign question acquired reuse authority")}})}
 if desktopNodeChainImportedServerQuestion(nil)!=-1{t.Fatal("nil question admitted")}
 owner:=new(desktopNodeChainImportedServerDNS)
 if owner.question(original,address)>=0{t.Fatal("unpaired AAAA acquired reuse authority")}
 if owner.question(serverQuestion(1,dns.TypeA),address)!=1{t.Fatal("canonical probe A rejected")}
 foreign:=&serverWriter{address:address.address}
 if owner.question(original,foreign)>=0{t.Fatal("foreign socket acquired reuse authority")}
 if owner.question(original,&serverWriter{address:&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:12345}})>=0{t.Fatal("foreign transport acquired reuse authority")}
 if owner.question(original,address)!=2{t.Fatal("canonical paired AAAA probe rejected")}
 if owner.question(original,address)>=0{t.Fatal("completed probe replay admitted")}
 if owner.question(serverQuestion(0,dns.TypeA),address)!=0{t.Fatal("original application A rejected")}
}
func TestHostnameTCPProbeCounters(t *testing.T){
 peer:=serverPeer();owner:=desktopNodeChainImportedServerHostname(t,peer);rule:=peer.paired.entry.rules["tcp/"+desktopImportedHostnameDNS]
 if rule.Network!="tcp"||rule.Address!="10.78.0.53"||rule.Port!=5353{t.Fatal("captured resolver route changed")}
 client:=&dns.Client{Net:"tcp",Timeout:time.Second}
 reply,_,err:=client.Exchange(serverQuestion(0,dns.TypeA),rule.Target)
 if err!=nil||len(reply.Answer)!=1||reply.Answer[0].(*dns.A).A.String()!="10.79.0.1"{t.Fatal("original A answer lost",err)}
 raw,err:=net.DialTimeout("tcp",rule.Target,time.Second);if err!=nil{t.Fatal(err)};defer raw.Close();_ =raw.SetDeadline(time.Now().Add(2*time.Second));connection:=&dns.Conn{Conn:raw}
 for _,q:=range []*dns.Msg{serverQuestion(1,dns.TypeA),serverQuestion(2,dns.TypeAAAA)}{if err=connection.WriteMsg(q);err!=nil{t.Fatal(err)};reply,err=connection.ReadMsg();if err!=nil||reply.Rcode!=dns.RcodeSuccess{t.Fatal("canonical transport probe failed",err)};if q.Question[0].Qtype==dns.TypeAAAA&&len(reply.Answer)!=0{t.Fatal("transport probe gained IPv6 answer")}}
 if owner.queries.Load()!=1||owner.probeA.Load()!=1||owner.probeAAAA.Load()!=1{t.Fatal("probe counted as application DNS")}
 owner.failed.Store(true);reply,_,err=client.Exchange(serverQuestion(0,dns.TypeA),rule.Target);if err!=nil||reply.Rcode!=dns.RcodeNameError||owner.queries.Load()!=2{t.Fatal("selected original DNS refusal lost",err)}
}
'''
        with tempfile.TemporaryDirectory(prefix='server-hostname-reuse-') as directory:
            root=Path(directory)
            (root/'go.mod').write_text('module routervpn-server-hostname-reuse\n\ngo 1.26\n\nrequire github.com/miekg/dns v1.1.72\n')
            (root/'go.sum').write_text('github.com/miekg/dns v1.1.72 h1:vhmr+TF2A3tuoGNkLDFK9zi36F2LS+hKTRW0Uf8kbzI=\ngithub.com/miekg/dns v1.1.72/go.mod h1:+EuEPhdHOsfk6Wk5TT2CzssZdqkmFhf8r+aVyDEToIs=\n')
            test=root/'actual_test.go';test.write_text(harness.replace('SHIPPING',shipping))
            command=['go','test','-mod=mod','-race','-count=1','-timeout=15s','-v','.']
            result=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=45)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            for old,new,witness in (
                ('if kind == 2 && !owner.probes[key]', 'if false && kind == 2 && !owner.probes[key]', 'unpaired AAAA acquired reuse authority'),
                ('case 1:\n\t\t\towner.probeA.Add(1)', 'case 1:\n\t\t\towner.probeA.Add(1); owner.queries.Add(1)', 'probe counted as application DNS'),
            ):
                self.assertEqual(shipping.count(old),1)
                test.write_text(harness.replace('SHIPPING',shipping.replace(old,new,1)))
                failed=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=45)
                self.assertNotEqual(failed.returncode,0,failed.stdout+failed.stderr)
                self.assertIn(witness,failed.stdout+failed.stderr)

    def test_all_required_native_success_and_refusal_shapes(self):
        self.assertEqual(len(GATE.CASES), 16)
        self.assertEqual(GATE.CASES[-2:],('candidate-wg','candidate-awg'))
        for case in GATE.CASES:
            with self.subTest(case=case): self.assertEqual(GATE.check_verdict(sample(case), case)['case'], case)

    def test_missing_native_case_or_receipt_cannot_pass(self):
        text=sample()
        for before in ('=== RUN   '+GATE.NATIVE+'/wg\n', '    --- PASS: '+GATE.NATIVE+'/wg (1.20s)\n', 'PASS\n'):
            with self.subTest(before=before), self.assertRaises(ValueError): GATE.check_verdict(text.replace(before, '', 1), 'wg')
        with self.assertRaises(ValueError): GATE.check_verdict('\n'.join(line for line in text.splitlines() if 'ENCRYPTED_SERVER_RECEIPT' not in line), 'wg')

    def test_failed_skipped_raced_or_duplicate_is_never_native_success(self):
        for extra in ('--- FAIL: irrelevant (0.1s)\n', '--- SKIP: irrelevant (0.1s)\n', 'WARNING: DATA RACE\n', 'panic: owner\n', '=== RUN   '+GATE.NATIVE+'/wg\n', '--- PASS: '+GATE.NATIVE+'/wg (0.1s)\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError): GATE.check_verdict(sample()+extra, 'wg')

    def test_real_buffered_pass_order_allowed_but_late_work_receipt_rejected(self):
        text=sample();self.assertTrue(GATE.check_verdict(text, 'wg')['retired'])
        lines=text.splitlines();receipt=lines.pop(2);lines.insert(4,receipt)
        with self.assertRaises(ValueError): GATE.check_verdict('\n'.join(lines), 'wg')
        lines=text.splitlines();passed=lines.pop(3);lines.insert(1,passed)
        with self.assertRaises(ValueError): GATE.check_verdict('\n'.join(lines), 'wg')

    def test_exact_original_retirement_and_source_identity_required(self):
        for before,after in (('"carrier_change_refused": true','"carrier_change_refused": false'), ('"retired": true','"retired": false'), ('"peer_joined": true','"peer_joined": false'),
             ('"worker_joined": true','"worker_joined": false'), ('"prefixes": 2','"prefixes": 1'),
             ('"ready": true','"ready": false'), ('"final_udp": 9','"final_udp": 0'),
             ('"selected_dns": true','"selected_dns": false'), ('"case": "wg"','"case": "awg-fast"'),
             ('"capture_sha256": "'+'a'*64+'"','"capture_sha256": "foreign"'),
             ('"ready": true','"ready": true, "ready": true'), ('"retired": true','"unexpected": true, "retired": true')):
            with self.subTest(before=before), self.assertRaises(ValueError): GATE.check_verdict(sample().replace(before,after,1), 'wg')

    def test_actual_awg_mode_cannot_be_relabelled_as_wireguard(self):
        text=sample('awg-fast')
        with self.assertRaisesRegex(ValueError, 'downgraded'):
            GATE.check_verdict(text.replace('"modes": ["wg", "awg2-fast"]','"modes": ["wg", "wg"]',1),'awg-fast')

    def test_source_inventory_is_separate_from_encrypted_receipts(self):
        lines=['=== RUN   '+GATE.SOURCE, '    fixture.go:1: ENCRYPTED_SERVER_CARRIER_CAPACITY 2092']
        for case in GATE.CASES: lines.append('=== RUN   '+GATE.SOURCE+'/'+case)
        lines.append('--- PASS: '+GATE.SOURCE+' (1.00s)')
        for case in GATE.CASES: lines.append('    --- PASS: '+GATE.SOURCE+'/'+case+' (0.01s)')
        lines.append('PASS');text='\n'.join(lines)
        self.assertEqual(GATE.check_verdict(text,None,source_only=True)['source_cases'],list(GATE.CASES))
        self.assertEqual(GATE.check_verdict(text,None,source_only=True)['carrier_mtu'],2092)
        for declaration in ('', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 1279', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 9001', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 02092', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 2092 junk', 'ENCRYPTED_SERVER_CARRIER_CAPACITY 2092\nENCRYPTED_SERVER_CARRIER_CAPACITY 2092'):
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                GATE.check_verdict(text.replace('ENCRYPTED_SERVER_CARRIER_CAPACITY 2092',declaration),None,source_only=True)
        with self.assertRaises(ValueError): GATE.check_verdict(text,'wg')
        with self.assertRaises(ValueError): GATE.check_verdict(text.replace('=== RUN   '+GATE.SOURCE+'/awg-fast','=== RUN   foreign'),None,source_only=True)

    def test_changed_generated_or_linked_native_source_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            core=Path(temporary);target=core/GATE.TARGET;target.parent.mkdir(parents=True)
            with mock.patch.object(GATE.subprocess,'check_output',return_value=GATE.BUILD.PIN+'\n'):
                GATE.install_fixture(core);original=target.read_bytes();GATE.install_fixture(core)
                target.write_bytes(original+b'\n// unowned change\n')
                with self.assertRaisesRegex(ValueError,'generated fixture was changed'): GATE.install_fixture(core)
                target.unlink();target.symlink_to(ROOT/GATE.TEMPLATE)
                with self.assertRaisesRegex(ValueError,'linked owner'): GATE.install_fixture(core)

    def test_compiled_image_must_be_original_regular_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'image';path.write_bytes(b'not a fake acceptance; identity-only unit fixture');path.chmod(0o755)
            self.assertEqual(GATE.image_identity(path)[2],path.stat().st_size)
            linked=path.with_name('link');linked.symlink_to(path)
            with self.assertRaises(ValueError): GATE.image_identity(linked)
            path.chmod(0o777)
            with self.assertRaises(ValueError): GATE.image_identity(path)

    def test_namespace_projection_preserves_exact_functions_and_guards(self):
        path = ROOT/'deploy/test_server_node_chain_encrypted.py'
        original = path.read_bytes()
        program = GATE.namespace_program(hashlib.sha256(original).hexdigest())
        source = ast.parse(original)
        projected = ast.parse(program)
        names = ('image_identity', 'inside_namespace')
        actual = {node.name: node for node in source.body if isinstance(node, ast.FunctionDef) and node.name in names}
        transferred = {node.name: node for node in projected.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual(set(transferred), set(names))
        for name in names:
            self.assertEqual(ast.dump(actual[name]), ast.dump(transferred[name]))
        imports = [ast.unparse(node) for node in projected.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual(imports, ['from pathlib import Path', 'import hashlib', 'import os', 'import platform', 'import re', 'import stat', 'import subprocess', 'import sys'])
        namespace = {'__name__': 'projection_verification'}
        exec(compile(program, '<captured-native-namespace>', 'exec'), namespace)
        self.assertEqual(namespace['CASES'], GATE.CASES)
        self.assertEqual(namespace['NATIVE'], GATE.NATIVE)
        # This real interpreter test stops at the mandatory case/privilege
        # boundary before any native image, mount or network operation.
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-I', '-c', program, 'driver', 'peer', 'worker',
                                     'a'*64, 'b'*64, 'c'*64, 'foreign-case'], cwd=directory,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Encrypted Server needs its isolated native Linux root', result.stderr)
        self.assertNotIn('ENCRYPTED_SERVER_RECEIPT', result.stdout)

    def test_projected_valid_case_dispatches_exact_driver_and_joins_cleanup(self):
        original = (ROOT/'deploy/test_server_node_chain_encrypted.py').read_bytes()
        program = GATE.namespace_program(hashlib.sha256(original).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            images = {role: Path(directory)/role for role in ('driver', 'peer', 'worker')}
            for role, path in images.items():
                path.write_bytes(('identity-only regression image: '+role).encode())
                path.chmod(0o755)
            identities = {role: GATE.image_identity(path)[-1] for role, path in images.items()}
            declared = 2092  # Unit-boundary declaration; production derives this in native source inventory.
            def execute(projected, *, missing_dependency=False, carrier=None):
                namespace = {'__name__': 'projection_verification'}
                exec(compile(projected, '<captured-native-namespace>', 'exec'), namespace)
                # Execute the actual transferred function through valid image,
                # case and isolated-namespace guards. Only privileged process
                # effects are mocked; this is not native acceptance evidence.
                with mock.patch.object(namespace['platform'], 'system', return_value='Linux'), \
                     mock.patch.object(namespace['os'], 'geteuid', return_value=0), \
                     mock.patch.dict(namespace['os'].environ, {'ROUTERVPN_SERVER_CHAIN_OUTER_NETNS': '0:0', 'ROUTERVPN_SERVER_CHAIN_CARRIER_MTU':str(declared)}), \
                     mock.patch.object(namespace['subprocess'], 'run', return_value=subprocess.CompletedProcess([], 7)) as run, \
                     mock.patch.object(namespace['subprocess'], 'check_output', side_effect=carrier or [f'1: rvpn-test: mtu {declared} state UP',f'2: rvpn-peer: mtu {declared} state UP']) as read:
                    if missing_dependency:
                        with self.assertRaisesRegex(NameError, "name 're' is not defined"):
                            namespace['inside_namespace'](images['driver'], images['peer'], images['worker'], identities, 'wrong-first-key')
                    elif carrier:
                        with self.assertRaisesRegex(ValueError,'actual carrier differs'):
                            namespace['inside_namespace'](images['driver'], images['peer'], images['worker'], identities, 'wrong-first-key')
                        self.assertFalse(any(call.args[0][0]==str(images['driver']) for call in run.call_args_list))
                    else:
                        self.assertEqual(read.call_count,0)
                        self.assertEqual(namespace['inside_namespace'](images['driver'], images['peer'], images['worker'], identities, 'wrong-first-key'), 7)
                        calls = [call for call in run.call_args_list if call.args[0][0] == str(images['driver'])]
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(read.call_count,2)
                        for name in ('rvpn-test','rvpn-peer'):
                            self.assertIn(mock.call(['ip','link','set',name,'mtu',str(declared)],check=True,timeout=5),run.call_args_list)
                        command = [str(images['driver']), '-test.run=^'+GATE.NATIVE+'$/^'+re.escape('wrong-first-key')+'$',
                                   '-test.v', '-test.count=1', '-test.timeout=90s']
                        self.assertEqual(calls[0].args, (command,))
                        self.assertEqual(calls[0].kwargs['timeout'], 105)
                        self.assertEqual(calls[0].kwargs['env']['ROUTERVPN_SERVER_CHAIN_PEER_SHA256'], identities['peer'])
                        self.assertEqual(calls[0].kwargs['env']['ROUTERVPN_SERVER_CHAIN_IMAGE_SHA256'], identities['worker'])
                    if not missing_dependency:
                        self.assertEqual(run.call_args, mock.call(['ip', 'netns', 'delete', 'rvpn-peer'], check=True, timeout=5))
            for invalid in ('', '1500junk', '01280', '1279', '9001'):
                namespace = {'__name__': 'projection_verification'}
                exec(compile(program, '<captured-native-namespace>', 'exec'), namespace)
                with mock.patch.object(namespace['platform'], 'system', return_value='Linux'), \
                     mock.patch.object(namespace['os'], 'geteuid', return_value=0), \
                     mock.patch.dict(namespace['os'].environ, {'ROUTERVPN_SERVER_CHAIN_OUTER_NETNS':'0:0', 'ROUTERVPN_SERVER_CHAIN_CARRIER_MTU':invalid}), \
                     mock.patch.object(namespace['subprocess'], 'run') as run:
                    with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError,'compiled carrier declaration'):
                        namespace['inside_namespace'](images['driver'], images['peer'], images['worker'], identities, 'wrong-first-key')
                    run.assert_not_called()
            execute(program)
            execute(program.replace('import re\n', '', 1), missing_dependency=True)
            execute(program,carrier=['1: rvpn-test: mtu 1500 state UP'])
            execute(program,carrier=[f'1: rvpn-test: mtu {declared} state UP','2: rvpn-peer: mtu 1500 state UP'])

    def test_namespace_projection_rejects_source_tamper_or_lost_inventory(self):
        path = ROOT/'deploy/test_server_node_chain_encrypted.py'
        original = path.read_bytes()
        captured = hashlib.sha256(original).hexdigest()
        with self.assertRaisesRegex(ValueError, 'source changed after capture'):
            GATE.namespace_program('0'*64)
        mutations = (
            original.replace(b'def inside_namespace(', b'def lost_inside_namespace(', 1),
            original + b'\ndef image_identity(path):\n    return None\n',
            original.replace(b"CASES = ('wg',", b"CASES = ('missing-wg',", 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory)/'source.py'
            for changed in mutations:
                copy.write_bytes(changed)
                with mock.patch.object(GATE, '__file__', str(copy)):
                    with self.assertRaisesRegex(ValueError, 'source changed after capture'):
                        GATE.namespace_program(captured)
                    with self.assertRaisesRegex(ValueError, 'required function|case inventory'):
                        GATE.namespace_program(hashlib.sha256(changed).hexdigest())

    def test_required_workflow_and_native_architectures(self):
        value=(ROOT/'.github/workflows/server-node-chain-encrypted.yml').read_text();workflow(value)
        for before,after in (('          - arch: arm64\n            runner: ubuntu-24.04-arm\n',''),
                            ('  workflow_call:\n','  workflow_call:\n    inputs: {}\n'),
                            ('  encrypted:\n','  encrypted:\n    if: false\n'),
                            ('    timeout-minutes: 105','    continue-on-error: true\n    timeout-minutes: 105'),
                            (' || github.run_id }}',' || github.ref }}'), ('--standalone --require-commit','--compile-only --require-commit')):
            with self.subTest(before=before), self.assertRaises(ValueError): workflow(value.replace(before,after,1))


    def test_direct_push_coalesces_without_cancelling_native_or_exact_callers(self):
        raw = (ROOT/'.github/workflows/server-node-chain-encrypted.yml').read_text()
        self.assertEqual(workflow_concurrency_cases(raw), 12)

    def test_removed_concurrency_boundaries_cannot_pass(self):
        raw = (ROOT/'.github/workflows/server-node-chain-encrypted.yml').read_text()
        changes = (
            ('active-native-cancel', 'cancel-in-progress: false', 'cancel-in-progress: true'),
            ('missing-event-boundary', "github.event_name == 'push' && ", ''),
            ('missing-main-boundary', "github.ref == 'refs/heads/main' && ", ''),
            ('missing-caller-boundary', "github.workflow == 'Ordered Server encrypted suffix acceptance' && ", ''),
            ('shared-manual-lane', ' || github.run_id }}', ' || github.ref }}'),
            ('commit-per-push-lane', '&& github.ref ||', '&& github.sha ||'),
            ('run-per-push-lane', '&& github.ref ||', '&& github.run_id ||'),
            ('shared-leaf-prefix', '  group: server-node-chain-encrypted-', '  group: native-shared-'),
        )
        for name, before, after in changes:
            self.assertEqual(raw.count(before), 1, name)
            with self.subTest(change=name), self.assertRaises(ValueError):
                workflow_concurrency_cases(raw.replace(before, after, 1))


class ImportedServerBoundaries(unittest.TestCase):
    def sample(self, case='original'):
        original=case.removeprefix('prefix-').removeprefix('hostname-')
        ready=original in ('original','joined-active-udp','admission-restrictions','wg-one','awg-fast','awg-strong','max-five')
        packet_fault=original in ('wrong-first-packet-key','wrong-later-packet-key')
        modes=None
        if case.startswith('prefix-'):
            modes={'wg-one':['wg'],'awg-fast':['wg','awg2-fast'],'awg-strong':['awg2-strong','wg'],
                   'max-five':['wg','awg2-fast','awg2-strong','wg','awg2-fast']}.get(original,['wg','wg'])
        packets=[4 if not packet_fault or original=='wrong-first-packet-key' and i==0 or original=='wrong-later-packet-key' and i<=1 else 0 for i in range(len(modes))] if modes else None
        proofs=[3 if not packet_fault or original=='wrong-later-packet-key' and i==0 else 0 for i in range(len(modes))] if modes else None
        value=dict(case=case,prefix_modes=modes,prefix_packets=packets,prefix_proofs=proofs,capture_sha256='a'*64,source_sha256='b'*64,
                   ready=ready,selected_dns=ready,middle_tcp=0 if packet_fault or original=='wrong-transport-dns' else 4,middle_udp=3 if ready else 0,
                   final_tcp=2 if ready else 0,final_udp=1 if ready else 0,
                   transport_dns_queries=2 if case.startswith('prefix-hostname-') and not packet_fault else 0,
                   retired=True,worker_joined=True,peer_joined=True,private_udp_refused=original=='admission-restrictions',
                   private_sink_packets=0 if original=='admission-restrictions' else 1, private_sink_replies=0 if original=='admission-restrictions' else 1)
        root=GATE.IMPORTED_NATIVE
        return '\n'.join(('=== RUN   '+root,'=== RUN   '+root+'/'+case,
            '    source.go:1: IMPORTED_SERVER_RECEIPT '+json.dumps(value),
            '--- PASS: '+root+' (1.0s)','    --- PASS: '+root+'/'+case+' (1.0s)','PASS',''))

    def test_exact_imported_native_receipts_and_refusals(self):
        self.assertEqual(GATE.IMPORTED_CASES[:8],('original','wrong-middle-key','wrong-final-key','wrong-final-identity','failed-selected-dns','wrong-public-identity','joined-active-udp','admission-restrictions'))
        for case in GATE.IMPORTED_CASES:
            text=self.sample(case)
            self.assertEqual(GATE.check_imported_verdict(text,case)['case'],case)
            for before,after in (('"worker_joined": true','"worker_joined": false'),
                                 ('"peer_joined": true','"peer_joined": false'),
                                 ('"retired": true','"retired": false'),
                                 (('"middle_tcp": 0','"middle_tcp": 1') if case.removeprefix('prefix-').removeprefix('hostname-') in ('wrong-first-packet-key','wrong-later-packet-key','wrong-transport-dns') else ('"middle_tcp": 4','"middle_tcp": 0')),
                                 ('--- PASS:', '--- SKIP:')):
                self.assertIn(before,text)
                with self.subTest(case=case, mutation=before),self.assertRaises(ValueError):
                    GATE.check_imported_verdict(text.replace(before,after,1),case)
            with self.assertRaises(ValueError): GATE.check_imported_verdict(text+text,case)
        for before,after in (('"selected_dns": true','"selected_dns": false'),('"final_udp": 1','"final_udp": 0'),('"capture_sha256": "'+'a'*64+'"','"capture_sha256": "bad"')):
            with self.assertRaises(ValueError):GATE.check_imported_verdict(self.sample().replace(before,after), 'original')
        with self.assertRaises(ValueError):GATE.check_imported_verdict(self.sample('wrong-middle-key').replace('"ready": false','"ready": true'),'wrong-middle-key')

    def test_longer_imported_packet_receipts_are_causal_and_mandatory(self):
        expected = ('prefix-original','prefix-wrong-middle-key','prefix-wrong-final-key','prefix-wrong-final-identity',
                    'prefix-failed-selected-dns','prefix-wrong-public-identity','prefix-joined-active-udp','prefix-admission-restrictions',
                    'prefix-wg-one','prefix-awg-fast','prefix-awg-strong','prefix-max-five',
                    'prefix-wrong-first-packet-key','prefix-wrong-later-packet-key')
        self.assertEqual(GATE.IMPORTED_CASES[8:22], expected)
        for case in expected:
            text = self.sample(case)
            for field in ('prefix_modes','prefix_packets','prefix_proofs'):
                value = json.loads(text.split('IMPORTED_SERVER_RECEIPT ',1)[1].splitlines()[0])
                value[field] = value[field][:-1]
                changed = re.sub(r'IMPORTED_SERVER_RECEIPT [^\n]+', 'IMPORTED_SERVER_RECEIPT '+json.dumps(value), text)
                with self.subTest(case=case,field=field), self.assertRaises(ValueError):
                    GATE.check_imported_verdict(changed,case)
        for case, field, index, count in (('prefix-original','prefix_proofs',1,0),
                                         ('prefix-wrong-first-packet-key','prefix_packets',1,1),
                                         ('prefix-wrong-later-packet-key','prefix_proofs',1,1)):
            text=self.sample(case)
            value=json.loads(text.split('IMPORTED_SERVER_RECEIPT ',1)[1].splitlines()[0])
            value[field][index]=count
            changed=re.sub(r'IMPORTED_SERVER_RECEIPT [^\n]+','IMPORTED_SERVER_RECEIPT '+json.dumps(value),text)
            with self.assertRaises(ValueError):GATE.check_imported_verdict(changed,case)

    def test_hostname_packet_dns_receipts_are_required_and_causal(self):
        expected = ('prefix-hostname-wg-one', 'prefix-hostname-awg-fast', 'prefix-hostname-awg-strong',
                    'prefix-hostname-max-five', 'prefix-hostname-wrong-transport-dns', 'prefix-hostname-wrong-middle-key',
                    'prefix-hostname-failed-selected-dns', 'prefix-hostname-joined-active-udp',
                    'prefix-hostname-wrong-first-packet-key', 'prefix-hostname-wrong-later-packet-key')
        self.assertEqual(GATE.IMPORTED_CASES[22:], expected)
        for case in GATE.IMPORTED_CASES:
            text = self.sample(case)
            value = json.loads(text.split('IMPORTED_SERVER_RECEIPT ', 1)[1].splitlines()[0])
            for mutation in ('missing', 'bool', 'opposite'):
                changed = dict(value)
                if mutation == 'missing':
                    del changed['transport_dns_queries']
                elif mutation == 'bool':
                    changed['transport_dns_queries'] = bool(value['transport_dns_queries'])
                else:
                    changed['transport_dns_queries'] = 0 if value['transport_dns_queries'] else 1
                output = re.sub(r'IMPORTED_SERVER_RECEIPT [^\n]+', 'IMPORTED_SERVER_RECEIPT '+json.dumps(changed), text)
                with self.subTest(case=case, mutation=mutation), self.assertRaises(ValueError):
                    GATE.check_imported_verdict(output, case)
        text = self.sample('prefix-hostname-wrong-transport-dns')
        for before, after in (('"final_tcp": 0', '"final_tcp": 1'),
                              ('"middle_udp": 0', '"middle_udp": 1'),
                              ('"ready": false', '"ready": true')):
            with self.subTest(mutation=before), self.assertRaises(ValueError):
                GATE.check_imported_verdict(text.replace(before, after), 'prefix-hostname-wrong-transport-dns')

    def test_imported_lan_policy_receipt_cannot_be_omitted_or_relabelled(self):
        text=self.sample('admission-restrictions')
        for before,after in (('"private_udp_refused": true','"private_udp_refused": false'),
                             ('"private_sink_packets": 0','"private_sink_packets": 1'),
                             ('"private_sink_replies": 0','"private_sink_replies": 1'),
                             ('"selected_dns": true','"selected_dns": false'),
                             ('"ready": true','"ready": false')):
            with self.subTest(mutation=before), self.assertRaises(ValueError):
                GATE.check_imported_verdict(text.replace(before,after), 'admission-restrictions')
        with self.assertRaises(ValueError):
            GATE.check_imported_verdict(self.sample().replace('"private_udp_refused": false','"private_udp_refused": true'), 'original')

    def test_imported_source_inventory_cannot_substitute_native(self):
        root=GATE.IMPORTED_SOURCE
        text='\n'.join(['=== RUN   '+root]+['=== RUN   '+root+'/'+c for c in GATE.IMPORTED_CASES]+['--- PASS: '+root+' (1.0s)']+['    --- PASS: '+root+'/'+c+' (1.0s)' for c in GATE.IMPORTED_CASES]+['PASS'])
        self.assertEqual(GATE.check_imported_verdict(text,None,source_only=True)['source_cases'],list(GATE.IMPORTED_CASES))
        with self.assertRaises(ValueError):GATE.check_imported_verdict(text,'original')
        with self.assertRaises(ValueError):GATE.check_imported_verdict(text.replace('=== RUN   '+root+'/wrong-final-key','=== RUN   foreign'),None,source_only=True)

    def test_imported_namespace_keeps_original_owned_function_and_limits(self):
        raw=(ROOT/'deploy/test_server_node_chain_encrypted.py').read_bytes()
        program=GATE.namespace_program(hashlib.sha256(raw).hexdigest(),imported=True)
        scope={'__name__':'test_only'};exec(compile(program,'captured-imported-namespace','exec'),scope)
        self.assertEqual(scope['CASES'],GATE.IMPORTED_CASES);self.assertEqual(scope['NATIVE'],GATE.IMPORTED_NATIVE)
        function=next(n for n in ast.parse(program).body if isinstance(n,ast.FunctionDef) and n.name=='inside_namespace')
        original=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='inside_namespace')
        self.assertEqual(ast.dump(function,include_attributes=False),ast.dump(original,include_attributes=False))
        self.assertIn("'-test.timeout=90s'",program);self.assertIn('timeout=105',program)
        with self.assertRaises(ValueError):GATE.namespace_program('0'*64,imported=True)

    def test_imported_cases_are_mandatory_in_original_compiled_image(self):
        tree=ast.parse((ROOT/'deploy/test_server_node_chain_encrypted.py').read_text())
        execute=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute')
        loops=[n for n in ast.walk(execute) if isinstance(n,ast.For) and isinstance(n.iter,ast.Name) and n.iter.id=='IMPORTED_CASES']
        self.assertEqual(len(loops),1)
        text=ast.unparse(loops[0])
        for required in ("check_imported_verdict(output, case)","str(driver)","str(peer)","str(worker)","images['driver'][-1]","images['peer'][-1]","images['worker'][-1]","timeout=125"):
            self.assertIn(required,text)
        self.assertNotIn('continue',text);self.assertNotIn('break',text)
        fixture=(ROOT/GATE.IMPORTED_TEMPLATE).read_text()
        self.assertIn('worker.stop(t)',fixture);self.assertIn('p.original.process.join(t)',fixture)
        self.assertIn('policy.NativeConfig(foreign)',fixture)
        self.assertNotIn('InsecureSkipVerify',fixture)
        prep=(ROOT/'deploy/prepare-desktop-external.py').read_text()
        self.assertEqual(prep.count("'node_chain_imported_server_peer_test.go.tmpl': 'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_server_peer_test.go'"),1)
        with tempfile.TemporaryDirectory() as temporary:
            core=Path(temporary)
            GATE.NODE.PREP.copy_encrypted_peer_templates(core)
            target=core/'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_server_peer_test.go'
            self.assertEqual(target.read_bytes(),(ROOT/'mobile/desktop/node_chain_imported_server_peer_test.go.tmpl').read_bytes())
            GATE.NODE.PREP.copy_encrypted_peer_templates(core)
            self.assertEqual(target.read_bytes(),(ROOT/'mobile/desktop/node_chain_imported_server_peer_test.go.tmpl').read_bytes())


    def test_imported_generated_projection_retains_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            core=Path(temporary);target=core/GATE.IMPORTED_TARGET;target.parent.mkdir(parents=True)
            with mock.patch.object(GATE.subprocess,'check_output',return_value=GATE.BUILD.PIN+'\n'):
                GATE.install_imported_fixture(core);GATE.install_imported_fixture(core)
                target.write_bytes(target.read_bytes()+b'\n// changed owner\n')
                with self.assertRaisesRegex(ValueError,'generated fixture was changed'):GATE.install_imported_fixture(core)


class DNSFailureDiagnosticTests(unittest.TestCase):
    def core(self, directory):
        module=GATE.DNS_DIAGNOSTIC;core=Path(directory)/'core';core.mkdir()
        for name,anchors in module.ANCHORS.items():
            path=core/name;path.parent.mkdir(exist_ok=True);path.write_text('package dns\n'+''.join(anchor+'\n return nil,nil\n}\n' for anchor,_ in anchors))
        path=core/module.DRIVER;path.parent.mkdir(parents=True);path.write_text('package main\nfunc fixture(){\n'+module.DRIVER_ANCHOR+'}\n')
        return core

    def test_diagnostic_only_for_actual_hostname_aaaa_failure(self):
        module=GATE.DNS_DIAGNOSTIC
        error=subprocess.CalledProcessError(1,[],output=b'ROUTERVPN_SERVER_PEER_FAILURE hostname-question-aaaa')
        self.assertTrue(module.eligible('prefix-hostname-wg-one',error))
        for case,failure in [('original',error),('prefix-hostname-wg-one',ValueError()),('prefix-hostname-wg-one',subprocess.CalledProcessError(1,[],output=b'hostname-question-name'))]:
            self.assertFalse(module.eligible(case,failure))

    def test_overlay_preserves_complete_original_sources(self):
        module=GATE.DNS_DIAGNOSTIC
        with tempfile.TemporaryDirectory() as directory:
            core=self.core(directory);before={str(p):p.read_bytes() for p in core.rglob('*.go')}
            mapping,receipt=module.overlay(core,Path(directory)/'shadow')
            rows=json.loads(mapping.read_text())['Replace'];self.assertEqual(len(rows),4)
            self.assertEqual(before,{str(p):p.read_bytes() for p in core.rglob('*.go')})
            for name,anchors in module.ANCHORS.items():
                actual=Path(rows[str(core/name)]).read_text()
                for _,addition in anchors: actual=actual.replace(addition,'',1)
                self.assertEqual(actual,before[str(core/name)].decode())
            self.assertEqual(receipt['scope'],'non-accepting-hostname-diagnostic')
            self.assertFalse((core/'dns/routervpn_server_dns_failure_diagnostic.go').exists())
            (core/'dns/router.go').write_text('changed original')
            with self.assertRaisesRegex(ValueError,'anchor differs'):module.overlay(core,Path(directory)/'changed')

    def test_original_failure_survives_success_or_failed_diagnostic(self):
        tree=ast.parse((ROOT/'deploy/test_server_node_chain_encrypted.py').read_text())
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.Try) and any(isinstance(x,ast.Attribute) and x.attr=='observe_failure' for h in n.handlers for x in ast.walk(h)))
        original=subprocess.CalledProcessError(1,[],output='ROUTERVPN_SERVER_PEER_FAILURE hostname-question-aaaa')
        values=dict(subprocess=subprocess,case='prefix-hostname-wg-one',command=[],workspace='unused',native_env={},sudo=None,core='unused',compiler='go',captured={},common=[],driver_flags=[],peer='unused',imported_program='unused',image_identity=lambda p:None,DNS_DIAGNOSTIC=GATE.DNS_DIAGNOSTIC,checked_sources=lambda core:(core,{}),before={})
        values['run']=mock.Mock(side_effect=original)
        for result in (None,ValueError('diagnostic refused'),subprocess.CalledProcessError(2,[])):
            with mock.patch.object(GATE.DNS_DIAGNOSTIC,'execute',side_effect=result):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'original-failure','exec'),values)
                self.assertIs(caught.exception,original)
        self.assertIsInstance(node.handlers[0].body[-1],ast.Raise)
        self.assertIsNone(node.handlers[0].body[-1].exc)

    def test_diagnostic_compile_and_native_bounds_are_original(self):
        module=GATE.DNS_DIAGNOSTIC
        with tempfile.TemporaryDirectory() as directory:
            core=self.core(directory);workspace=Path(directory)/'work';workspace.mkdir();calls=[]
            def run(command,**options):calls.append((command,options));return ''
            module.execute(core=core,workspace=workspace,compiler='go',captured={},common=['-race'],driver_flags=['-race','-tags=original'],peer='original-peer',case='prefix-hostname-wg-one',program='original namespace program',native_env={},sudo=None,run=run,image_identity=lambda path:(0,0,0,0,'a'*64),source_identity=lambda:{'original':'retained'},expected_source={'original':'retained'})
            self.assertEqual([options['timeout'] for _,options in calls],[600,600,125])
            self.assertIn('-race',calls[0][0]);self.assertIn('-tags=original',calls[1][0])
            self.assertEqual(calls[2][0][-1],'prefix-hostname-wg-one')
            self.assertIn('original namespace program',calls[2][0])


if __name__=='__main__': unittest.main()
