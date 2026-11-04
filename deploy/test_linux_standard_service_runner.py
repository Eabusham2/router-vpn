#!/usr/bin/env python3
"""Reject silent missing, renamed, duplicate, failed or skipped service gates."""
from pathlib import Path
import importlib.util
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('standard_service_gate',ROOT/'deploy/linux_standard_service_gate.py')
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class StandardServiceGateTests(unittest.TestCase):
    def output(self, group):
        return '\n'.join('--- PASS: '+name+' (0.01s)' for parent,children in gate.GROUPS[group].items()
                         for name in (gate.PREFIX+parent,*(gate.PREFIX+parent+'/'+child for child in children)))

    def test_exact_source_inventory(self):
        gate.validate_inventory(ROOT)

    def test_required_case_verdicts(self):
        for group in gate.GROUPS:
            output=self.output(group)
            gate.check_verdict(output,group)
            for line in output.splitlines():
                for mutation in (output.replace(line,'',1),output.replace(line,line.replace('TestLinux','TestOther'),1),output+'\n'+line,output.replace(line,line.replace('PASS','SKIP'),1),output.replace(line,line.replace('PASS','FAIL'),1)):
                    with self.assertRaises(ValueError):gate.check_verdict(mutation,group)

    def test_cleanup_required_verdicts(self):
        output='\n'.join('--- PASS: '+name+' (0.01s)' for parent,children in gate.CLEANUP.items()
                         for name in (parent,*(parent+'/'+child for child in children)))
        gate.check_cleanup_verdict(output)
        for line in output.splitlines():
            for mutation in (output.replace(line,'',1),output.replace(line,line.replace('TestCleanup','TestOther'),1),output+'\n'+line,output.replace(line,line.replace('PASS','SKIP'),1),output.replace(line,line.replace('PASS','FAIL'),1)):
                with self.assertRaises(ValueError):gate.check_cleanup_verdict(mutation)
        runner=(ROOT/'deploy/test_linux_controller_privilege.py').read_text()
        self.assertIn("'./internal/standardengine'",runner)
        self.assertIn('SERVICE.check_cleanup_verdict(cleanup_output)',runner)
        self.assertIn("namespace_test(args.namespace_cleanup_binary, '^TestCleanup', digest)",runner)

    def test_renamed_or_omitted_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            copy=Path(temporary)
            for name in gate.SOURCE:
                target=copy/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
            gate.validate_inventory(copy)
            selected=copy/'cmd/client/linux_standard_service_namespace_test.go'
            original=selected.read_text()
            selected.write_text(original.replace('TestLinuxStandardServiceNamespaceInstalledIdleUpgradeAndAlwaysRetention','TestLinuxStandardServiceOmittedNativeGate'))
            with self.assertRaises(ValueError):gate.validate_inventory(copy)
            selected.unlink()
            with self.assertRaises(ValueError):gate.validate_inventory(copy)

if __name__=='__main__':unittest.main()
