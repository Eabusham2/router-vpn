#!/usr/bin/env python3
"""Pin the actual alias-owner extraction boundary and strict causal verdicts."""
from pathlib import Path
import importlib.util
import subprocess
import unittest

P=Path(__file__).with_name('test_macos_imported_execution_alias.py')
spec=importlib.util.spec_from_file_location('alias_gate',P)
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

class AliasGateTests(unittest.TestCase):
    def source(self):
        return (gate.ROOT/gate.HELPER).read_text()
    def positive(self):
        return '\n'.join('=== RUN   '+v for v in gate.VERDICTS)+'\n'+'\n'.join('--- PASS: '+v+' (0.00s)' for v in gate.VERDICTS)+'\nok\trouter-vpn/probe\t0.01s\n'
    def result(self,text,code=0):
        return subprocess.CompletedProcess([],code,text,'')
    def test_verbatim_owner_and_real_lock(self):
        original=self.source(); extracted=gate.extract(original)
        expected=original.split('\n',1)[1].lstrip('\n').replace('\n\t"os/exec"','').replace('net.InterfaceByName(','aliasInterfaceByName(').replace('net.Interfaces()','aliasInterfaces()').replace('exec.CommandContext(','aliasCommandContext(')
        self.assertEqual(extracted,expected)
        self.assertIn('desktopnetwork.LockContext(ctx, &macOSImportedExecutionAliasGate)',extracted)
        for marker in ('type macOSImportedExecutionAliasOwner struct','func macOSImportedExecutionAliasInventory()','func macOSImportedExecutionOwnAliases(', 'func (owner *macOSImportedExecutionAliasOwner) release()', 'func (owner *macOSImportedExecutionAliasOwner) Close('):
            self.assertEqual(extracted.count(marker),1)
    def test_changed_os_seam_refuses(self):
        with self.assertRaises(ValueError):gate.extract(self.source().replace('net.Interfaces()','otherInterfaces()'))
    def test_unprivileged_source_refuses(self):
        with self.assertRaises(ValueError):gate.extract(self.source().replace('darwin && routervpn_controller_privileged','darwin'))
    def test_exact_controls(self):
        controls=gate.mutations(gate.extract(self.source()))
        self.assertEqual(set(controls),{'cancelled-waiter','attempted-intent','mask','address-index','join'})
        self.assertEqual(len({value[1] for value in controls.values()}),5)
    def test_positive_inventory(self):
        gate.validate_result(self.result(self.positive()))
        self.assertEqual(len(gate.VERDICTS),14)
    def test_positive_omission_duplicate_unknown_refused(self):
        source=self.positive()
        for changed in (source.replace('--- PASS: TestActualAliasCancelledWaiter (0.00s)\n',''),source+'--- PASS: TestActualAliasCancelledWaiter (0.00s)\n',source+'--- PASS: Unknown (0.00s)\n',source.replace('=== RUN   TestActualAliasCancelledWaiter\n','')):
            with self.subTest(output=changed):
                with self.assertRaises(RuntimeError):gate.validate_result(self.result(changed))
    def test_no_tests_success_refused(self):
        with self.assertRaises(RuntimeError):gate.validate_result(self.result('testing: warning: no tests to run\nPASS\nok  \trouter-vpn/probe\t0.006s [no tests to run]\n'))
    def test_exact_mutant_verdict(self):
        witness='attempted alias mutation escaped owned cleanup'
        selection='TestActualAliasOwner/partial-add-error-retains-intent'
        output='=== RUN   TestActualAliasOwner\n=== RUN   '+selection+'\n    alias_test.go:99: '+witness+'\n--- FAIL: TestActualAliasOwner (0.00s)\n    --- FAIL: '+selection+' (0.00s)\nFAIL\trouter-vpn/probe\t0.01s\n'
        gate.validate_result(self.result(output,1),witness=witness,selection=selection)
        for changed,code in ((output,0),(output,2),(output.replace(witness,witness+' extra'),1),(output.replace(witness,'prefix '+witness),1),(output+output,1),(output.replace(witness,'unrelated failure'),1)):
            with self.subTest(output=changed,code=code):
                with self.assertRaises(RuntimeError):gate.validate_result(self.result(changed,code),witness=witness,selection=selection)
    def test_wrong_leaf_same_witness_refuses(self):
        witness='foreign alias mask or index acquired deletion authority'
        selection='TestActualAliasOwner/mask'
        output='=== RUN   TestActualAliasOwner\n=== RUN   TestActualAliasOwner/address-index\n    alias_test.go:88: '+witness+'\n--- FAIL: TestActualAliasOwner (0.00s)\n    --- FAIL: TestActualAliasOwner/address-index (0.00s)\nFAIL\trouter-vpn/probe\t0.01s\n'
        with self.assertRaises(RuntimeError):gate.validate_result(self.result(output,1),witness=witness,selection=selection)
        correct=output.replace('address-index','mask')
        gate.validate_result(self.result(correct,1),witness=witness,selection=selection)
        for changed in (correct+'--- PASS: TestForeign (0.00s)\n',correct+'--- SKIP: TestForeign (0.00s)\n',correct+'=== RUN   TestForeign\n',correct.replace('--- FAIL: TestActualAliasOwner/mask','--- FAIL: TestActualAliasOwner/foreign')):
            with self.assertRaises(RuntimeError):gate.validate_result(self.result(changed,1),witness=witness,selection=selection)
    def test_crash_compiler_and_race_refuse(self):
        for suffix in ('WARNING: DATA RACE\n','panic: unrelated\n','fatal error: deadlock\n','[build failed]\n'):
            with self.subTest(suffix=suffix):
                with self.assertRaises(RuntimeError):gate.validate_result(self.result(self.positive()+suffix))
    def test_timeout_and_selected_source_boundaries(self):
        source=P.read_text()
        self.assertIn("'-timeout=15s'",source)
        self.assertIn('timeout=45',source)
        self.assertIn("(directory/'internal/desktopnetwork/desktop_network_lock.go').write_bytes(inputs[LOCK])",source)
        self.assertIn("if any((root/p).read_bytes()!=content for p,content in inputs.items()):",source)

if __name__=='__main__':unittest.main()
