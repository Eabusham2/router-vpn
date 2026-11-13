#!/usr/bin/env python3
"""Causal source/runner boundary tests; these never claim native Darwin acceptance."""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('darwin_child_gate', ROOT/'deploy/test_darwin_node_child_tun.py')
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)


def transcript():
    lines = ['=== RUN   '+G.HARNESS, '=== RUN   '+G.NATIVE]
    for case in G.CASES:
        name = G.NATIVE+'/'+case
        lines += ['=== RUN   '+name, '    native_test.go:1: verified original Darwin child retirement: '+case,
                  '--- PASS: '+name+' (1.00s)']
    lines += ['--- PASS: '+G.NATIVE+' (8.00s)', 'PASS', '--- PASS: '+G.HARNESS+' (9.00s)', 'PASS']
    return '\n'.join(lines)+'\n'


def workflow_inventory(raw):
    """Check the small exact native gate surface without optional YAML packages."""
    if not isinstance(raw, str) or len(raw) > 16384:
        raise ValueError('native workflow is not bounded source')
    if re.search(r'^\s*(?:if|continue-on-error|inputs):', raw, re.M):
        raise ValueError('native workflow became conditional, nonblocking or caller-replaced')
    if re.search(r'\b(?:fallback|workflow_run)\b', raw):
        raise ValueError('native workflow added an alternate result authority')
    required = (
        '  workflow_call:\n  push:',
        '  group: darwin-node-child-tun-${{ github.ref }}-${{ github.sha }}-${{ github.run_id }}',
        '  cancel-in-progress: true',
        'jobs:\n  child:',
        '    runs-on: ${{ matrix.runner }}',
        '    timeout-minutes: 60',
        '      fail-fast: false',
        '          - arch: amd64\n            runner: macos-15-intel',
        '          - arch: arm64\n            runner: macos-15',
        "          ROUTERVPN_DARWIN_NODE_CHILD_ACCEPTANCE: '1'",
        '          ROUTERVPN_EXPECTED_SOURCE: ${{ github.sha }}',
        '          ROUTERVPN_CHILD_RECEIPT: ${{ runner.temp }}/darwin-node-child-${{ matrix.arch }}.json',
        "          CGO_ENABLED: '1'",
        '          if-no-files-found: error',
        '          name: RouterVPN-Darwin-ordered-child-${{ matrix.arch }}-${{ github.sha }}',
        '          path: ${{ runner.temp }}/darwin-node-child-${{ matrix.arch }}.json',
    )
    if any(raw.count(value) != 1 for value in required):
        raise ValueError('native workflow lost its exact required architecture/source/receipt inventory')
    if len(re.findall(r'^          - arch:', raw, re.M)) != 2 or re.findall(r'^  ([A-Za-z][\w-]*):', raw.split('jobs:\n', 1)[1], re.M) != ['child']:
        raise ValueError('native workflow changed its complete job or architecture inventory')
    command = 'python3 deploy/test_darwin_node_child_tun.py --standalone --require-commit "$ROUTERVPN_EXPECTED_SOURCE" --receipt "$ROUTERVPN_CHILD_RECEIPT"'
    run = re.findall(r'^        run: \|\n((?:          [^\n]*\n)+)', raw, re.M)
    if len(run) != 1:
        raise ValueError('native workflow lost its one actual standalone invocation')
    commands = [line.strip() for line in run[0].splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if commands != [command] or raw.count('run: python3 deploy/test_darwin_node_child_tun_runner.py') != 1:
        raise ValueError('native workflow weakened actual invocation or its runner checks')


class NativeVerdict(unittest.TestCase):
    def test_complete_exact_native_transcript(self):
        G.check_verdict(transcript())
        G.check_verdict(transcript().replace('\n', '\r\n'))

    def test_actual_go_buffered_subtest_pass_order_is_preserved(self):
        # Captured native Go component logs print root PASS before child PASS
        # lines, after every RUN and t.Log receipt. Model that exact ordering.
        lines = transcript().splitlines()
        child_passes = [line for line in lines if line.startswith('--- PASS: '+G.NATIVE+'/')]
        lines = [line for line in lines if line not in child_passes]
        parent = next(index for index, line in enumerate(lines) if line.startswith('--- PASS: '+G.NATIVE+' ('))
        lines[parent+1:parent+1] = child_passes
        G.check_verdict('\n'.join(lines)+'\n')

    def test_every_case_and_original_retirement_is_mandatory(self):
        original = transcript()
        for name in G.EXPECTED:
            for prefix in ('=== RUN   ', '--- PASS: '):
                with self.subTest(name=name, prefix=prefix):
                    target = next(line for line in original.splitlines() if line == prefix+name or line.startswith(prefix+name+' ('))
                    with self.assertRaises(ValueError):
                        G.check_verdict(original.replace(target+'\n', '', 1))
        for case in G.CASES:
            with self.subTest(retirement=case), self.assertRaises(ValueError):
                G.check_verdict(original.replace('verified original Darwin child retirement: '+case, 'missing native retirement: '+case))

    def test_failure_skip_race_panic_remain_failure_even_with_all_passes(self):
        for line in ('--- FAIL: '+G.NATIVE+' (0.00s)', '--- SKIP: '+G.NATIVE+' (0.00s)',
                     'WARNING: DATA RACE', 'panic: original owner missing', 'fatal error: native join'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                G.check_verdict(transcript()+line+'\n')

    def test_duplicate_unknown_and_unrun_cannot_be_native_evidence(self):
        for line in ('=== RUN   '+G.NATIVE, '--- PASS: '+G.NATIVE+' (1.00s)',
                     '=== RUN   TestUnrelated', '--- PASS: TestUnrelated (1.00s)',
                     'native.go:2: verified original Darwin child retirement: '+G.CASES[0],
                     'native.go:2: verified original Darwin child retirement: foreign'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                G.check_verdict(transcript()+line+'\n')
        with self.assertRaises(ValueError):
            G.check_verdict(transcript().replace('=== RUN   '+G.NATIVE+'\n', ''))

    def test_late_native_children_and_retirement_cannot_extend_a_passed_owner(self):
        original = transcript()
        for root in (G.HARNESS, G.NATIVE):
            line = next(line for line in original.splitlines() if line.startswith('--- PASS: '+root+' ('))
            without = original.replace(line+'\n', '', 1)
            before = '=== RUN   '+(G.NATIVE if root == G.HARNESS else G.NATIVE+'/'+G.CASES[0])
            with self.subTest(root=root), self.assertRaises(ValueError):
                G.check_verdict(without.replace(before, line+'\n'+before, 1))
        name = G.NATIVE+'/'+G.CASES[0]
        receipt = next(line for line in original.splitlines() if line.endswith('retirement: '+G.CASES[0]))
        without = original.replace(receipt+'\n', '', 1)
        passed = next(line for line in original.splitlines() if line.startswith('--- PASS: '+name+' ('))
        with self.assertRaises(ValueError):
            G.check_verdict(without.replace(passed, passed+'\n'+receipt, 1))

    def test_parent_pass_requires_all_native_work_and_joined_receipts(self):
        original = transcript()
        native_pass = next(line for line in original.splitlines() if line.startswith('--- PASS: '+G.NATIVE+' ('))
        without = original.replace(native_pass+'\n', '', 1)
        receipt = next(line for line in original.splitlines() if line.endswith('retirement: '+G.CASES[-1]))
        with self.assertRaisesRegex(ValueError, 'before all original native joins'):
            G.check_verdict(without.replace(receipt, native_pass+'\n'+receipt, 1))
        harness_pass = next(line for line in original.splitlines() if line.startswith('--- PASS: '+G.HARNESS+' ('))
        without = original.replace(harness_pass+'\n', '', 1)
        with self.assertRaisesRegex(ValueError, 'before all original child reports'):
            G.check_verdict(without.replace(native_pass, harness_pass+'\n'+native_pass, 1))
        case_pass = next(line for line in original.splitlines() if line.startswith('--- PASS: '+G.NATIVE+'/'+G.CASES[-1]+' ('))
        without = original.replace(case_pass+'\n', '', 1)
        with self.assertRaisesRegex(ValueError, 'before all original child reports'):
            G.check_verdict(without.replace(harness_pass, harness_pass+'\n'+case_pass, 1))

    def test_native_source_and_runner_inventory_match(self):
        raw = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        import re
        body = re.search(r'var darwinChildCases = \[\]string\{([^}]+)\}', raw)
        self.assertIsNotNone(body)
        self.assertEqual(tuple(re.findall(r'"([^"\n]+)"', body[1])), G.CASES)
        for name in (G.NATIVE, G.HARNESS):
            self.assertIn('func '+name+'(', raw)
        for required in ('macosprocess.OpenCapture(', 'macosprocess.BindCreated(', 'o.bootstrap.Stop(ctx)',
                         'NodeChainTransferSHA256(o.capture.Selection())', 'mobiletor.RunDesktopDarwinPFBaseline(',
                         'ParseDesktopNodeChainReadyRecord(', 'net.InterfaceByName(mtu.Interface)',
                         'status.Reader != old.Reader+1', 'device.Index == old.Index',
                         'stats.Final.DirectQueries != 0', 'stats.Final.EntryPublicQueries != 0'):
            self.assertIn(required, raw)
        self.assertNotIn('t.Skip(', raw)


class ActualHostSelection(unittest.TestCase):
    def test_fixture_debug_stripping_keeps_actual_race_and_native_tags(self):
        for package in ('./cmd/sing-box', './protocol/routervpnamnezia'):
            command = G.native_fixture_compile('/captured/go', Path('/captured/native.test'), package)
            self.assertEqual(command[:6], ['/captured/go', 'test', '-c', '-race', '-mod=readonly', '-tags='+','.join(G.TAGS)])
            self.assertEqual(command[6:], ['-ldflags=-checklinkname=0 -s -w', '-o', Path('/captured/native.test'), package])
        source = (ROOT/'deploy/test_darwin_node_child_tun.py').read_text()
        self.assertIn('UID.run(native_fixture_compile(compiler, image, package), cwd=source, env=captured, timeout=600)', source)
        self.assertIn("identities = {path: image_identity(path) for path in (child, peer)}", source)
        self.assertIn('any(image_identity(path) != value for path, value in identities.items())', source)

    def test_signing_failure_keeps_original_deadline_and_uncancelled_cause(self):
        source = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        start = source.index('for _, p := range []string{macosprocess.ControllerPath, macosprocess.EnginePath}')
        stop = source.index('\n\tpeer := macosprocess.InstallRoot', start)
        signing = source[start:stop]
        self.assertIn('darwinChildImage(t, image, p, expected)', signing)
        self.assertIn('context.WithTimeout(context.Background(), 10*time.Second)', signing)
        self.assertIn('cause := ctx.Err()\n\t\tcancel()', signing)
        self.assertIn('native fixture signing image=%s bytes=%d elapsed=%s context=%v: %v', signing)
        self.assertIn('p, before.Size(), time.Since(started), cause, e, out', signing)
        self.assertNotIn('continue', signing)

    def test_explicit_native_host_and_ordinary_uid(self):
        with patch.object(G.platform, 'system', return_value='Darwin'), patch.object(G.platform, 'machine', return_value='arm64'), patch.object(G.os, 'getuid', return_value=501):
            self.assertEqual(G.required_host({G.FLAG: '1'}), ('arm64', 501))
            for value in ({}, {G.FLAG:'0'}, {G.FLAG:'1','GOOS':'linux'}, {G.FLAG:'1','GOARCH':'amd64'}, {G.FLAG:'1','CGO_ENABLED':'0'}):
                with self.subTest(environment=value), self.assertRaises(ValueError):
                    G.required_host(value)
        with patch.object(G.platform, 'system', return_value='Darwin'), patch.object(G.platform, 'machine', return_value='x86_64'), patch.object(G.os, 'getuid', return_value=0):
            self.assertEqual(G.required_host({G.FLAG:'1','SUDO_UID':'501'}), ('amd64',501))
            for uid in ('0','-1',str(2**32-1),'unknown'):
                with self.subTest(uid=uid), self.assertRaises(ValueError):
                    G.required_host({G.FLAG:'1','SUDO_UID':uid})
        with patch.object(G.platform, 'system', return_value='Linux'), self.assertRaises(ValueError):
            G.required_host({G.FLAG:'1'})

    def test_image_identity_rejects_links_writeability_empty_and_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'native.test'
            path.write_bytes(b'owned compiled fixture')
            path.chmod(0o755)
            original = G.image_identity(path)
            self.assertEqual(G.image_identity(path), original)
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises(ValueError): G.image_identity(link)
            link.unlink(); os.link(path, link)
            with self.assertRaises(ValueError): G.image_identity(path)
            link.unlink(); path.chmod(0o777)
            with self.assertRaises(ValueError): G.image_identity(path)
            path.chmod(0o755); path.write_bytes(b'')
            with self.assertRaises(ValueError): G.image_identity(path)
            # Allocate the replacement while the original inode still exists;
            # unlink/recreate can immediately recycle that same inode on tmpfs.
            replacement = path.with_name('replacement')
            replacement.write_bytes(b'owned compiled fixture'); replacement.chmod(0o755)
            self.assertNotEqual(replacement.stat().st_ino, path.stat().st_ino)
            replacement.replace(path)
            self.assertNotEqual(G.image_identity(path), original)
        with self.assertRaises(ValueError): G.image_identity(Path('relative'))

    def test_receipt_requires_new_file_and_joined_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=G.receipt_path(root/'receipt.json');workspace=root/'unjoined';workspace.mkdir()
            with self.assertRaises(ValueError):G.publish_receipt(path, {'native':True}, workspace)
            self.assertFalse(path.exists())
            workspace.rmdir();G.publish_receipt(path, {'scope':'actual'}, workspace)
            self.assertIn('actual',path.read_text())
            with self.assertRaises(ValueError):G.receipt_path(path)
            with self.assertRaises(FileExistsError):G.publish_receipt(path, {'overwrite':True}, workspace)


class EncryptedPeerSourceClosure(unittest.TestCase):
    def test_darwin_projects_only_original_build_constraint(self):
        copies=G.NODE.PREP.darwin_node_chain_peer_copies()
        self.assertEqual(set(copies),set(G.NODE.PREP.DARWIN_NODE_CHAIN_PEERS.values()))
        before=b'//go:build linux && !android\n\npackage routervpnamnezia\n'
        after=b'//go:build darwin && routervpn_darwin_node_chain && routervpn_darwin_external_host\n\npackage routervpnamnezia\n'
        for name,target in G.NODE.PREP.DARWIN_NODE_CHAIN_PEERS.items():
            source=(ROOT/'mobile/desktop'/name).read_bytes()
            self.assertTrue(source.startswith(before))
            self.assertEqual(copies[target],after+source[len(before):])
            self.assertTrue(target.endswith('_darwin_test.go'))

    def test_wrong_original_platform_or_symlink_cannot_be_projected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'mobile/desktop';source.mkdir(parents=True)
            for name in G.NODE.PREP.DARWIN_NODE_CHAIN_PEERS:
                (source/name).write_bytes((ROOT/'mobile/desktop'/name).read_bytes())
            with patch.object(G.NODE.PREP,'ROOT',root):
                G.NODE.PREP.darwin_node_chain_peer_copies()
                target=source/next(iter(G.NODE.PREP.DARWIN_NODE_CHAIN_PEERS));raw=target.read_bytes()
                target.write_bytes(raw.replace(b'linux && !android',b'windows',1))
                with self.assertRaises(ValueError):G.NODE.PREP.darwin_node_chain_peer_copies()
                target.unlink();other=source/'foreign';other.write_bytes(raw);target.symlink_to(other)
                with self.assertRaises(ValueError):G.NODE.PREP.darwin_node_chain_peer_copies()

    def test_address_and_final_only_benchmark_scope_remain_explicit(self):
        raw=(ROOT/'mobile/desktop/node_chain_peer_linux_test.go.tmpl').read_text()
        for needle in ('address == "192.168.210.2" && client == "192.168.210.1"',
                       'address != client', 'ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS', 'found == 1',
                       'request.BenchmarkPort != 0 && request.BenchmarkPort != 45998',
                       'Destination: "10.77.0.1:45998"', 'if p.held.Load()', 'n > 8972'):
            self.assertIn(needle,raw)
        imported=(ROOT/'mobile/desktop/node_imported_peer_linux_test.go.tmpl').read_text()
        self.assertIn('if !request.Cover || n < 1 || n > 1200',imported)
        self.assertNotIn('45998',imported)


class BoundedHarnessReporting(unittest.TestCase):
    def test_actual_escaped_output_writer_cannot_hide_controller_failure(self):
        source = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        signature = 'func darwinChildHarnessOutput(command *exec.Cmd) ([]byte, error) {'
        self.assertEqual(source.count(signature), 1)
        self.assertEqual(source.count('output, e := darwinChildHarnessOutput(command)'), 1)
        start = source.index(signature)
        end = source.index('\n}', start) + 2
        original = source[start:end]
        needle = 'command.WaitDelay = 5 * time.Second'
        self.assertEqual(original.count(needle), 1)
        go = shutil.which('go')
        self.assertIsNotNone(go, 'actual process-pipe reporting requires Go')
        fixture = r'''package main
import (
 "context"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "strconv"
 "strings"
 "syscall"
 "time"
)
// SHIPPING_HARNESS_OUTPUT
func main() {
 if len(os.Args)>1 && os.Args[1]=="writer" {
  fmt.Println("original escaped writer")
  time.Sleep(20*time.Second)
  return
 }
 if len(os.Args)>1 && os.Args[1]=="parent" {
  child:=exec.Command(os.Args[0],"writer")
  child.SysProcAttr=&syscall.SysProcAttr{Setpgid:true}
  child.Stdout=os.Stdout;child.Stderr=os.Stderr
  if err:=child.Start();err!=nil {panic(err)}
  if err:=os.WriteFile(os.Args[2],[]byte(strconv.Itoa(child.Process.Pid)),0600);err!=nil {panic(err)}
  return
 }
 if err:=verify(os.Args[1]);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 fmt.Println("actual escaped output pipe bounded; native retirement remains unproved")
}
func verify(pidFile string) error {
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 command:=exec.CommandContext(ctx,os.Args[0],"parent",pidFile)
 type result struct {output []byte;failure error}
 joined:=make(chan result,1)
 go func(){out,err:=darwinChildHarnessOutput(command);joined<-result{out,err}}()
 deadline:=time.Now().Add(2*time.Second)
 pid:=0
 for time.Now().Before(deadline) {
  raw,err:=os.ReadFile(pidFile)
  if err==nil {pid,err=strconv.Atoi(string(raw));if err!=nil{return err};break}
  time.Sleep(5*time.Millisecond)
 }
 if pid<=1 {return errors.New("actual escaped writer was never created")}
 group,err:=syscall.Getpgid(pid)
 if err!=nil || group!=pid || group==syscall.Getpgrp() {
  return errors.New("actual writer did not retain its independent process group")
 }
 // This fixture owns only a disposable writer, no native VPN/PF resources.
 // Never use this group signal as evidence of the production guardian join.
 defer syscall.Kill(-pid,syscall.SIGKILL)
 select {
 case result:=<-joined:
  if command.ProcessState==nil || !command.ProcessState.Success() {
   return errors.New("original direct controller did not exit successfully")
  }
  if !errors.Is(result.failure,exec.ErrWaitDelay) || !strings.Contains(string(result.output),"original escaped writer") {
   return errors.New("escaped output closure lost its failure or original diagnostic")
  }
  return nil
 case <-time.After(7*time.Second):
  syscall.Kill(-pid,syscall.SIGKILL)
  select {case <-joined:case <-time.After(2*time.Second):return errors.New("reporting control could not join its disposable writer")}
  return errors.New("Darwin native harness waited beyond its retained output bound")
 }
}
'''
        with tempfile.TemporaryDirectory(prefix='darwin-child-reporting-') as temporary:
            work = Path(temporary); code = work/'main.go'; image = work/'reporting'
            for mutated in (False, True):
                helper = original.replace(needle, '', 1) if mutated else original
                self.assertEqual(helper != original, mutated)
                code.write_text(fixture.replace('// SHIPPING_HARNESS_OUTPUT', helper))
                subprocess.run([go, 'build', '-p=1', '-o', str(image), str(code)], cwd=work, check=True, timeout=90)
                result = subprocess.run([str(image), str(work/('mutant.pid' if mutated else 'original.pid'))],
                                        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
                if mutated:
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn('Darwin native harness waited beyond its retained output bound', result.stdout)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertIn('actual escaped output pipe bounded; native retirement remains unproved', result.stdout)


class UnstartedFixtureRetirement(unittest.TestCase):
    def test_actual_prestart_plan_and_monotonic_start_barriers(self):
        source = (ROOT/'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl').read_text()
        def member(signature):
            self.assertEqual(source.count(signature), 1)
            begin = source.index(signature)
            return source[begin:source.index('\n}', begin)+2]
        install = member('func (o *darwinChildOwner) installBaseline(ctx context.Context) error {')
        retire = member('func (o *darwinChildOwner) stopUnstarted(ctx context.Context, failed bool) error {')
        start = member('func (o *darwinChildOwner) start(')
        self.assertEqual(start.count('o.childStartAttempted = true'), 1)
        self.assertLess(start.index('o.childStartAttempted = true'), start.index('o.command.Start()'))
        self.assertEqual(source.count('o.childStartAttempted = true'), 1)
        self.assertNotIn('o.childStartAttempted = false', source)
        self.assertIn('if owner.childStartAttempted {\n\t\t\t\t\te = owner.stop(cleanup)\n\t\t\t\t} else {\n\t\t\t\t\te = owner.stopUnstarted(cleanup, t.Failed())', source)
        # Only the PF/syscall and retained-descriptor boundaries are replaced.
        # Both complete fixture methods above execute with their actual guards.
        fixture = r"""package main
import("context";"errors";"fmt";"os";"os/exec";"time")
type DesktopDarwinPFBaselineProof struct {Present bool;RulesSHA256 string}
type DesktopDarwinPFBaselineRequest struct {Schema int;Action,SessionID,SourceSHA256 string;Expected []DesktopDarwinPFBaselineProof}
type DesktopDarwinPFBaselineResult struct {Schema int;Applied bool;Previous,Target DesktopDarwinPFBaselineProof}
type metadata struct{SessionID,SourceSHA256 string}
type policy struct{}
func(*policy)Metadata()metadata{return metadata{"original-session","original-source"}}
type retained struct{failure bool;closes int}
func(r *retained)Current(ctx context.Context)error{if r.failure{return errors.New("changed retained source")};return ctx.Err()}
func(r *retained)Close()error{r.closes++;return nil}
type files struct{root *retained}
type darwinChildOwner struct{
 policy *policy;baseline *DesktopDarwinPFBaselineResult;childStartAttempted bool
 command *exec.Cmd;bootstrap *int;done chan struct{};observed map[int]string
 closed bool;capture,channel *retained;files *files
}
var absent=DesktopDarwinPFBaselineProof{}
var target=DesktopDarwinPFBaselineProof{true,"exact-original-target"}
var actual DesktopDarwinPFBaselineProof
var lateFailure,children bool
var writes int
func darwinChildBaseline(ctx context.Context,r DesktopDarwinPFBaselineRequest,apply bool)(DesktopDarwinPFBaselineResult,error){
 if err:=ctx.Err();err!=nil{return DesktopDarwinPFBaselineResult{},err}
 accepted:=false;for _,value:=range r.Expected{accepted=accepted || value==actual}
 if !accepted || children{return DesktopDarwinPFBaselineResult{},errors.New("unknown PF owner remains")}
 next:=target;if r.Action=="clear"{next=absent}
 result:=DesktopDarwinPFBaselineResult{Schema:1,Applied:apply,Previous:actual,Target:next}
 if apply{writes++;actual=next;if lateFailure && r.Action=="replace"{return DesktopDarwinPFBaselineResult{},errors.New("committed but readback unavailable")}}
 return result,nil
}
// SHIPPING_PRESTART_METHODS
func fresh()*darwinChildOwner{actual=absent;lateFailure=false;children=false;writes=0;return &darwinChildOwner{policy:&policy{},capture:&retained{},channel:&retained{},files:&files{root:&retained{}}}}
func check(ok bool,text string){if !ok{panic(text)}}
func main(){
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
 for _,committed:=range []bool{false,true}{
  owner:=fresh();lateFailure=committed;err:=owner.installBaseline(ctx)
  check((err!=nil)==committed,"baseline boundary did not exercise late apply failure")
  check(owner.baseline!=nil && owner.baseline.Previous==absent && owner.baseline.Target==target,"lost original PF plan after partial apply")
  if !committed{actual=absent} // An apply that made no change is also an allowed exact prior.
  check(owner.stopUnstarted(ctx,true)==nil && owner.closed && actual==absent,"never-started failed fixture did not retire its exact PF plan")
  check(owner.capture.closes==1 && owner.channel.closes==1 && owner.files.root.closes==1,"never-started cleanup lost original descriptor joins")
 }
 for _,fault:=range []string{"attempted","process","bootstrap","joined-channel","utun","capture","missing-capture","foreign-baseline","child-rules","not-failed","deadline"}{
  owner:=fresh();check(owner.installBaseline(ctx)==nil,"original baseline install");before:=writes;failed:=true;call:=ctx
  switch fault{
  case "attempted":owner.childStartAttempted=true
  case "process":owner.command=&exec.Cmd{Process:&os.Process{Pid:os.Getpid()}}
  case "bootstrap":value:=1;owner.bootstrap=&value
  case "joined-channel":owner.done=make(chan struct{})
  case "utun":owner.observed=map[int]string{7:"utun-original"}
  case "capture":owner.capture.failure=true
  case "missing-capture":owner.capture=nil
  case "foreign-baseline":actual=DesktopDarwinPFBaselineProof{true,"foreign-owner"}
  case "child-rules":children=true
  case "not-failed":failed=false
  case "deadline":var cancel context.CancelFunc;call,cancel=context.WithCancel(ctx);cancel()
  }
  err:=owner.stopUnstarted(call,failed)
  check(err!=nil && !owner.closed && writes==before,"unproved pre-start cleanup erased PF: "+fault)
 }
 fmt.Println("actual pre-start fixture: planned late failure, both exact prior states, descriptor joins and11 ownership refusals PASS")
}
"""
        with tempfile.TemporaryDirectory(prefix='darwin-child-prestart-') as temporary:
            work = Path(temporary); code = work/'main.go'; image = work/'prestart'
            original = install+'\n'+retire
            controls = (
                ('baseline plan', 'o.baseline = &plan', '', 'lost original PF plan after partial apply'),
                ('attempted start', '|| o.childStartAttempted ||', '||', 'unproved pre-start cleanup erased PF: attempted'),
                ('failed fixture', '!failed ||', '', 'unproved pre-start cleanup erased PF: not-failed'),
            )
            for label,before,after,witness in (('baseline','','',''),*controls):
                helper=original
                if before:
                    self.assertEqual(helper.count(before),1,label)
                    helper=helper.replace(before,after,1)
                    self.assertNotEqual(helper,original,label)
                code.write_text(fixture.replace('// SHIPPING_PRESTART_METHODS',helper.replace('mobiletor.','')))
                subprocess.run([shutil.which('go'),'build','-p=1','-o',str(image),str(code)],cwd=work,check=True,timeout=90)
                result=subprocess.run([str(image)],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
                if witness:
                    self.assertNotEqual(result.returncode,0,label+result.stdout)
                    self.assertIn(witness,result.stdout)
                else:
                    self.assertEqual(result.returncode,0,result.stdout)
                    self.assertIn('and11 ownership refusals PASS',result.stdout)


class RequiredWorkflowInventory(unittest.TestCase):
    def test_both_actual_native_architectures_and_exact_caller_receipts(self):
        raw = (ROOT/'.github/workflows/darwin-node-child-tun.yml').read_text()
        workflow_inventory(raw)

    def test_missing_architecture_or_weakened_invocation_cannot_pass(self):
        raw = (ROOT/'.github/workflows/darwin-node-child-tun.yml').read_text()
        changes = (
            ('missing-amd64', '          - arch: amd64\n            runner: macos-15-intel\n', ''),
            ('missing-arm64', '          - arch: arm64\n            runner: macos-15\n', ''),
            ('wrong-runner', 'runner: macos-15-intel', 'runner: ubuntu-latest'),
            ('conditional-job', '  child:\n', '  child:\n    if: false\n'),
            ('nonblocking-job', '  child:\n', '  child:\n    continue-on-error: true\n'),
            ('caller-input', '  workflow_call:\n', '  workflow_call:\n    inputs:\n'),
            ('cross-caller-cancel', '-${{ github.sha }}-${{ github.run_id }}', ''),
            ('no-standalone', ' --standalone ', ' '),
            ('no-exact-commit', ' --require-commit "$ROUTERVPN_EXPECTED_SOURCE"', ''),
            ('no-receipt', ' --receipt "$ROUTERVPN_CHILD_RECEIPT"', ''),
            ('ignored-native-failure', ' --receipt "$ROUTERVPN_CHILD_RECEIPT"', ' --receipt "$ROUTERVPN_CHILD_RECEIPT" || true'),
            ('optional-artifact', 'if-no-files-found: error', 'if-no-files-found: warn'),
            ('fallback-result', '    timeout-minutes: 60', '    fallback: true\n    timeout-minutes: 60'),
        )
        for name, before, after in changes:
            self.assertEqual(raw.count(before), 1, name)
            with self.subTest(change=name), self.assertRaises(ValueError):
                workflow_inventory(raw.replace(before, after, 1))


if __name__=='__main__':
    unittest.main(verbosity=2)
