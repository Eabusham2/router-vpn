#!/usr/bin/env python3
"""Check exact original native Box owner preparation before compiled tests."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ordered_execution_owner', ROOT/'deploy/prepare-node-chain-execution-owner.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
BOX = '''package box
type Box struct {
\trouterVPNNodeChainOptions string
\tpreserveOtherState string
}
func New(options Options) (*Box, error) {
\tchainOptionsDigest := routerVPNNodeChainOptionsDigest(options.Context, options.Options)
\tpreserveOriginalConstruction()
\treturn &Box{
\t\trouterVPNNodeChainOptions: chainOptionsDigest,
\t\tpreserveOtherState: "original",
\t}, nil
}
func (s *Box) Close() error { return originalManagerClose() }
'''
DAEMON = 'package daemon\n'+PREP.DAEMON_CLOSE_ORIGINAL+'\nfunc (s *StartedService) SetError(err error) {}\n'


class Preparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.vendor = Path(self.temp.name)/'core'
        self.vendor.mkdir()
        (self.vendor/'box.go').write_text(BOX)
        (self.vendor/'daemon').mkdir()
        (self.vendor/'daemon/started_service.go').write_text(DAEMON)
        (self.vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')

    def snapshot(self):
        return {p.relative_to(self.vendor).as_posix(): p.read_bytes() for p in self.vendor.rglob('*') if p.is_file()}

    def prepare(self, vendor=None, pin=None):
        with patch.object(PREP.subprocess, 'check_output', return_value=(pin or PREP.PIN)+'\n'), contextlib.redirect_stdout(io.StringIO()):
            PREP.prepare(vendor or self.vendor)

    def test_exact_idempotent_source_inventory(self):
        self.prepare()
        before = self.snapshot()
        self.prepare()
        self.assertEqual(self.snapshot(), before)
        self.assertIn('preserveOriginalConstruction()', (self.vendor/'box.go').read_text())
        manifest = json.loads((self.vendor/PREP.OWNER).read_text())
        self.assertEqual(set(manifest['files']), set(PREP.TEMPLATES.values()))
        for template, name in PREP.TEMPLATES.items():
            self.assertEqual((self.vendor/name).read_bytes(), (ROOT/'mobile/chain'/template).read_bytes())
            self.assertEqual(hashlib.sha256((self.vendor/name).read_bytes()).hexdigest(), manifest['files'][name])

    def test_snapshot_stays_after_original_local_capture(self):
        derived = PREP.box_source(BOX).decode()
        self.assertEqual(PREP.box_source(derived).decode(), derived)
        for before, after in (
            ('routerVPNNodeChainExecutionOptions string', 'routerVPNNodeChainExecutionOptions string\n\trouterVPNNodeChainExecutionOptions string'),
            ('options.Context, options.Options)\n\tpreserveOriginalConstruction', 'context.Background(), options.Options)\n\tpreserveOriginalConstruction'),
            ('\t\trouterVPNNodeChainExecutionOptions: chainExecutionOptionsDigest,', '\t\trouterVPNNodeChainExecutionOptions: "",'),
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                PREP.box_source(derived.replace(before, after, 1))

    def test_original_close_and_daemon_error_are_exact_and_idempotent(self):
        derived = PREP.box_source(BOX).decode()
        self.assertIn('func (s *Box) routerVPNCloseOriginal() error { return originalManagerClose() }', derived)
        patched = PREP.daemon_source(DAEMON).decode()
        self.assertEqual(PREP.daemon_source(patched).decode(), patched)
        self.assertIn('closeErr = instance.Close()', patched)
        self.assertIn('return closeErr', patched)
        for wrong in (patched.replace('return closeErr', 'return nil'), patched.replace('closeErr = instance.Close()', '_ = instance.Close()')):
            with self.assertRaises(ValueError): PREP.daemon_source(wrong)
        with self.assertRaises(ValueError): PREP.box_source(derived.replace('routerVPNCloseOriginal', 'foreignClose'))

    def test_actual_pinned_daemon_close_keeps_original_failure(self):
        # The preparer matches the entire pinned method, including its real
        # lock/instance-removal order. Only the service and native instance
        # boundary types are substituted in this isolated executable fixture.
        body = PREP.daemon_source(DAEMON).decode().split('package daemon\n', 1)[1].split('\nfunc (s *StartedService) SetError', 1)[0]
        prefix = '''package daemon
import("errors"; "runtime/debug"; "sync"; "testing"; "time")
var runtimeDebug = struct{FreeOSMemory func()}{debug.FreeOSMemory}
const(ServiceStatus_STARTING=iota;ServiceStatus_STARTED;ServiceStatus_STOPPING;ServiceStatus_IDLE;ServiceStatus_FATAL)
type Instance struct{close func()error}
func(i *Instance)Close()error{return i.close()}
type StartedService struct{lifecycleAccess,serviceAccess sync.Mutex;instance *Instance;serviceStatus struct{Status int};startedAt time.Time}
func(s *StartedService)interruptStart(){}
func(s *StartedService)updateStatus(v int){s.serviceStatus.Status=v}
func(s *StartedService)updateStatusError(error){s.serviceStatus.Status=ServiceStatus_FATAL}
'''
        test = '''
func TestActualClose(t *testing.T){
 sentinel:=errors.New("original native close failure");entered,release:=make(chan struct{}),make(chan struct{})
 s:=&StartedService{instance:&Instance{close:func()error{close(entered);<-release;return sentinel}}}
 done:=make(chan error,1);go func(){done<-s.CloseService()}();<-entered
 s.serviceAccess.Lock();empty:=s.instance==nil;status:=s.serviceStatus.Status;s.serviceAccess.Unlock()
 if !empty||status!=ServiceStatus_STOPPING{t.Fatal("fixture lost actual early service removal")}
 select{case <-done:t.Fatal("service returned before original close joined");default:}
 close(release);if err:=<-done;!errors.Is(err,sentinel){t.Fatal("daemon discarded original native close failure",err)}
 if s.serviceStatus.Status!=ServiceStatus_FATAL{t.Fatal("failed native close reported idle success")}
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/'go.mod').write_text('module closefixture\ngo 1.25\n')
            environment = dict(os.environ, GOWORK='off')
            target = json.loads(subprocess.check_output(['go', 'env', '-json', 'GOOS', 'GOARCH'], cwd=path, env=environment, text=True, timeout=30))
            race = [] if (target['GOOS'], target['GOARCH']) == ('windows', 'arm64') else ['-race']
            for label, source in [('positive', body), ('discarded-error', body.replace('return closeErr', 'return nil'))]:
                # Keep the deleted-return mutant compilable, so a compiler
                # error can never count as the intended causal rejection.
                if label != 'positive': source = source.replace('return nil\n}', '_ = closeErr\n\treturn nil\n}')
                (path/'close_test.go').write_text(prefix+source+test)
                result = subprocess.run(['go', 'test', *race, '-count=1', '-timeout=10s', '.'], cwd=path,
                    env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
                if label == 'positive': self.assertEqual(result.returncode, 0, result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn('daemon discarded original native close failure', result.stdout)
                    self.assertNotIn('[build failed]', result.stdout)

    def test_partial_source_change_refuses_all_mutation(self):
        self.prepare()
        (self.vendor/'routervpn_node_chain_execution.go').write_text('foreign original owner\n')
        before = self.snapshot()
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.snapshot(), before)

    def test_incomplete_or_foreign_owner_refused(self):
        self.prepare()
        original = (self.vendor/PREP.OWNER).read_bytes()
        for fault in ('missing', 'foreign'):
            with self.subTest(fault=fault):
                record = json.loads(original)
                if fault == 'missing': record['files'].pop(next(iter(record['files'])))
                else: record['files']['unrelated.go'] = 'a'*64
                (self.vendor/PREP.OWNER).write_text(json.dumps(record))
                before = self.snapshot()
                with self.assertRaises(ValueError): self.prepare()
                self.assertEqual(self.snapshot(), before)

    def test_pin_and_module_are_required(self):
        before = self.snapshot()
        with self.assertRaises(ValueError): self.prepare(pin='0'*40)
        self.assertEqual(self.snapshot(), before)
        (self.vendor/'go.mod').write_text('module another/core\n')
        before = self.snapshot()
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.snapshot(), before)

    def test_unowned_output_refused(self):
        (self.vendor/'routervpn_node_chain_execution.go').write_text('unrelated original\n')
        before = self.snapshot()
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(self.snapshot(), before)

    def test_linked_checkout_and_output_refused(self):
        link = Path(self.temp.name)/'linked'
        link.symlink_to(self.vendor, target_is_directory=True)
        with self.assertRaises(ValueError): self.prepare(vendor=link)
        foreign = Path(self.temp.name)/'foreign.go'
        foreign.write_text('retained\n')
        (self.vendor/'routervpn_node_chain_execution.go').symlink_to(foreign)
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(foreign.read_text(), 'retained\n')


if __name__ == '__main__':
    unittest.main()
