#!/usr/bin/env python3
"""Reject silent missing, renamed, duplicate, failed or skipped service gates."""
from pathlib import Path
import importlib.util
import hashlib
import re
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('standard_service_gate',ROOT/'deploy/linux_standard_service_gate.py')
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class StandardServiceGateTests(unittest.TestCase):
    def output(self, group):
        return '\n'.join('--- PASS: '+name+' (0.01s)' for name in gate.case_names(group))

    def test_bootstrap_sources_and_native_inventory_are_mandatory(self):
        required = {'cmd/client/linux_standard_service_boot_bootstrap_linux.go',
                    'cmd/client/linux_standard_service_boot_bootstrap_client_linux.go',
                    'cmd/client/linux_standard_service_boot_hostname_namespace_native_test.go',
                    'cmd/client/linux_standard_service_boot_resolver_linux.go',
                    'internal/mobiletor/desktop_standard_linux_bootstrap.go',
                    'internal/mobiletor/desktop_standard_linux_bootstrap_native_test.go',
                    'internal/mobiletor/desktop_standard_linux_bootstrap_netlink.go',
                    'internal/mobiletor/desktop_standard_linux_bootstrap_netlink_test.go',
                    'internal/mobiletor/desktop_standard_linux_bootstrap_netlink_native_test.go',
                    'internal/linuxprocess/bootstrap_cleanup_gate_linux_native_test.go',
                    'internal/dnsmeasure/transport_bootstrap.go'}
        required.update('internal/mobiletor/desktop_standard_linux_bootstrap_grant_'+suffix+'.go' for suffix in ('wire','receipt','transport','observe','wire_test','native_test'))
        self.assertTrue(required.issubset(gate.SOURCE))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in gate.SOURCE:
                target = root/name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT/name).read_bytes())
            gate.validate_inventory(root)
            for name in required:
                target = root/name; body = target.read_bytes(); target.unlink()
                with self.assertRaises(ValueError): gate.validate_inventory(root)
                target.write_bytes(body)
        spec=importlib.util.spec_from_file_location('bootstrap_guardian',ROOT/'deploy/test_desktop_linux_guardian.py')
        guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
        self.assertIn('StandardBootstrapSocket', guardian.STANDARD_KERNEL_CASES)
        self.assertIn('StandardBootstrapConditionalRemoval', guardian.STANDARD_KERNEL_CASES)
        self.assertIn('StandardBootstrapFiniteGrant', guardian.STANDARD_KERNEL_CASES)
        output='\n'.join('--- PASS: TestLinuxStandardBootstrap'+case+' (0.01s)' for case in guardian.BOOTSTRAP_PARSER)
        guardian.require_socks_verdicts(output,'TestLinuxStandardBootstrap',guardian.BOOTSTRAP_PARSER)
        for line in output.splitlines():
            for bad in (output.replace(line,'',1), output+'\n'+line, output.replace(line,line.replace('PASS','SKIP'))):
                with self.assertRaises(ValueError): guardian.require_socks_verdicts(bad,'TestLinuxStandardBootstrap',guardian.BOOTSTRAP_PARSER)
        prefix='TestDesktopLinuxGuardianKernelStandardBootstrapConditionalRemoval/'
        output='\n'.join('--- PASS: '+prefix+case+' (0.01s)' for case in guardian.BOOTSTRAP_REMOVAL_NATIVE)
        guardian.require_socks_verdicts(output,prefix,guardian.BOOTSTRAP_REMOVAL_NATIVE)
        for line in output.splitlines():
            for bad in (output.replace(line,'',1), output+'\n'+line, output.replace(line,line.replace('PASS','SKIP')), output.replace(line,line.replace('PASS','FAIL'))):
                with self.assertRaises(ValueError): guardian.require_socks_verdicts(bad,prefix,guardian.BOOTSTRAP_REMOVAL_NATIVE)

    def test_finite_bootstrap_kernel_verdicts_are_mandatory(self):
        spec=importlib.util.spec_from_file_location('finite_bootstrap_guardian',ROOT/'deploy/test_desktop_linux_guardian.py')
        guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
        prefix='TestDesktopLinuxGuardianKernelStandardBootstrapFiniteGrant/'
        output='\n'.join('--- PASS: '+prefix+case+' (0.01s)' for case in guardian.BOOTSTRAP_FINITE_NATIVE)
        guardian.require_socks_verdicts(output,prefix,guardian.BOOTSTRAP_FINITE_NATIVE)
        for line in output.splitlines():
            for bad in (output.replace(line,'',1), output+'\n'+line, output.replace(line,line.replace('PASS','SKIP')), output.replace(line,line.replace('PASS','FAIL'))):
                with self.assertRaises(ValueError): guardian.require_socks_verdicts(bad,prefix,guardian.BOOTSTRAP_FINITE_NATIVE)

    def test_scoped_bootstrap_upstream_verdicts_are_mandatory(self):
        spec=importlib.util.spec_from_file_location('scoped_bootstrap_guardian',ROOT/'deploy/test_desktop_linux_guardian.py')
        guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
        self.assertIn('StandardBootstrapUpstream',guardian.STANDARD_KERNEL_CASES)
        for name in ('desktop_standard_linux_bootstrap_upstream.go','desktop_standard_linux_bootstrap_upstream_test.go','desktop_standard_linux_bootstrap_upstream_native_test.go'):
            self.assertIn(name,guardian.STANDARD_SOURCE_FILES)
        prefix='TestDesktopLinuxGuardianKernelStandardBootstrapUpstream/'
        output='\n'.join('--- PASS: '+prefix+case+' (0.01s)' for case in guardian.BOOTSTRAP_UPSTREAM_NATIVE)
        guardian.require_socks_verdicts(output,prefix,guardian.BOOTSTRAP_UPSTREAM_NATIVE)
        for line in output.splitlines():
            for bad in (output.replace(line,'',1), output+'\n'+line, output.replace(line,line.replace('PASS','SKIP')), output.replace(line,line.replace('PASS','FAIL'))):
                with self.assertRaises(ValueError): guardian.require_socks_verdicts(bad,prefix,guardian.BOOTSTRAP_UPSTREAM_NATIVE)

    def test_concurrent_bootstrap_group_verdicts_are_mandatory(self):
        spec=importlib.util.spec_from_file_location('group_bootstrap_guardian',ROOT/'deploy/test_desktop_linux_guardian.py')
        guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
        self.assertIn('StandardBootstrapGroup',guardian.STANDARD_KERNEL_CASES)
        for suffix in ('','_exchange','_test','_native_test'):
            self.assertIn('desktop_standard_linux_bootstrap_group'+suffix+'.go',guardian.STANDARD_SOURCE_FILES)
        prefix='TestDesktopLinuxGuardianKernelStandardBootstrapGroup/'
        output='\n'.join('--- PASS: '+prefix+case+' (0.01s)' for case in guardian.BOOTSTRAP_GROUP_NATIVE)
        guardian.require_socks_verdicts(output,prefix,guardian.BOOTSTRAP_GROUP_NATIVE)
        for line in output.splitlines():
            for bad in (output.replace(line,'',1),output+'\n'+line,output.replace(line,line.replace('PASS','SKIP')),output.replace(line,line.replace('PASS','FAIL'))):
                with self.assertRaises(ValueError): guardian.require_socks_verdicts(bad,prefix,guardian.BOOTSTRAP_GROUP_NATIVE)

    def test_opportunistic_bootstrap_verdicts_are_mandatory(self):
        spec=importlib.util.spec_from_file_location('group_bootstrap_guardian',ROOT/'deploy/test_desktop_linux_guardian.py')
        guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
        self.assertIn('StandardBootstrapOpportunistic',guardian.STANDARD_KERNEL_CASES)
        for suffix in ('','_test','_native_test'):
            self.assertIn('desktop_standard_linux_bootstrap_opportunistic'+suffix+'.go',guardian.STANDARD_SOURCE_FILES)
        prefix='TestDesktopLinuxGuardianKernelStandardBootstrapOpportunistic/'
        output='\n'.join('--- PASS: '+prefix+case+' (0.01s)' for case in guardian.BOOTSTRAP_OPPORTUNISTIC_NATIVE)
        guardian.require_socks_verdicts(output,prefix,guardian.BOOTSTRAP_OPPORTUNISTIC_NATIVE)
        for line in output.splitlines():
            for bad in (output.replace(line,'',1),output+'\n'+line,output.replace(line,line.replace('PASS','SKIP')),output.replace(line,line.replace('PASS','FAIL'))):
                with self.assertRaises(ValueError): guardian.require_socks_verdicts(bad,prefix,guardian.BOOTSTRAP_OPPORTUNISTIC_NATIVE)

    def test_dnssec_bootstrap_verdicts_are_mandatory(self):
        spec=importlib.util.spec_from_file_location('dnssec_bootstrap_guardian',ROOT/'deploy/test_desktop_linux_guardian.py')
        guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
        self.assertIn('StandardBootstrapDNSSEC',guardian.STANDARD_KERNEL_CASES)
        for suffix in ('','_test','_alias_test','_native_test'):
            name='desktop_standard_linux_bootstrap_dnssec'+suffix+'.go'
            self.assertIn(name,guardian.STANDARD_SOURCE_FILES)
            self.assertIn('internal/mobiletor/'+name,gate.SOURCE)
        prefix='TestDesktopLinuxGuardianKernelStandardBootstrapDNSSEC/'
        output='\n'.join('--- PASS: '+prefix+case+' (0.01s)' for case in guardian.BOOTSTRAP_DNSSEC_NATIVE)
        guardian.require_socks_verdicts(output,prefix,guardian.BOOTSTRAP_DNSSEC_NATIVE)
        for line in output.splitlines():
            for bad in (output.replace(line,'',1),output+'\n'+line,output.replace(line,line.replace('PASS','SKIP')),output.replace(line,line.replace('PASS','FAIL'))):
                with self.assertRaises(ValueError): guardian.require_socks_verdicts(bad,prefix,guardian.BOOTSTRAP_DNSSEC_NATIVE)

    def test_bootstrap_removal_uses_original_observed_generation(self):
        source=(ROOT/'internal/mobiletor/desktop_standard_linux_bootstrap.go').read_text()
        start=source.index('func (p *DesktopLinuxStandardProtection) cleanupBootstrapLocked(')
        end=source.index('// The source port/cookie',start)
        cleanup=source[start:end]
        prior=-1
        for step in ('present, generation, e := t.observeGeneration(ctx, b)',
                     'desktopLinuxStandardLease(lease)',
                     'b.netlink.deleteBootstrapRule(ctx, generation, b.nft.table(), t.handle)',
                     'if !acknowledged', 'present, e = t.observe(ctx, b)', 't.closeSocket()'):
            position=cleanup.find(step,prior+1)
            self.assertGreater(position,prior,'bootstrap cleanup lost its original conditional native ordering: '+step)
            prior=position
        self.assertNotIn('desktopLinuxNFTCommandFiles',cleanup)

    def test_actual_worker_bounded_join_and_causal(self):
        spec=importlib.util.spec_from_file_location('standard_worker_stop',ROOT/'deploy/test_standard_worker_stop.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.execute()

    def test_actual_shared_run_clock_and_causals(self):
        spec=importlib.util.spec_from_file_location('standard_run_clock',ROOT/'deploy/test_standard_run_clock.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.execute()

    def test_exact_source_inventory(self):
        gate.validate_inventory(ROOT)

    def test_required_case_verdicts(self):
        for group in gate.GROUPS:
            output=self.output(group)
            gate.check_verdict(output,group)
            for line in output.splitlines():
                for mutation in (output.replace(line,'',1),output.replace(line,line.replace('TestLinux','TestOther'),1),output+'\n'+line,output.replace(line,line.replace('PASS','SKIP'),1),output.replace(line,line.replace('PASS','FAIL'),1)):
                    with self.assertRaises(ValueError):gate.check_verdict(mutation,group)

    def test_mtu_patterns_execute_each_registered_parent(self):
        for group in ('mtu', 'mtu-native'):
            pattern = re.compile(gate.pattern(group))
            for suffix in gate.GROUPS[group]:
                self.assertIsNotNone(pattern.fullmatch(gate.MTU_PREFIX + suffix))
                self.assertIsNone(pattern.fullmatch(gate.PREFIX + suffix))
            self.assertIsNone(pattern.fullmatch(gate.MTU_PREFIX + 'UnregisteredCase'))
            output = self.output(group)
            with self.assertRaises(ValueError):
                gate.check_verdict(output.replace('--- PASS:', '=== RUN:'), group)
            with self.assertRaises(ValueError):
                gate.check_verdict(output + '\n--- PASS: ' + gate.MTU_PREFIX + 'UnregisteredCase (0.01s)', group)
            parent = next(iter(gate.GROUPS[group]))
            with self.assertRaises(ValueError):
                gate.check_verdict(output + '\n--- PASS: ' + gate.MTU_PREFIX + parent + '/unregistered (0.01s)', group)

    def test_auxiliary_required_verdicts(self):
        for group, (_, cases) in gate.AUXILIARY.items():
            output='\n'.join('--- PASS: '+name+' (0.01s)' for parent, children in cases.items()
                             for name in (parent, *(parent+'/'+child for child in children)))
            gate.check_auxiliary_verdict(output, group)
            for line in output.splitlines():
                for mutation in (output.replace(line,'',1), output+'\n'+line,
                                 output.replace(line,line.replace('PASS','SKIP'),1),
                                 output.replace(line,line.replace('PASS','FAIL'),1),
                                 output.replace(line,line.replace('Test','TestRenamed',1),1)):
                    with self.assertRaises(ValueError):
                        gate.check_auxiliary_verdict(mutation, group)

    def test_image_transactions_have_independent_bounded_groups(self):
        required = {
            'original': 'Original', 'abort-prepared': 'AbortPrepared',
            'abort-promoted': 'AbortPromoted', 'lost-freeze-reply': 'LostFreezeReply',
            'lost-commit-reply': 'LostCommitReply', 'lost-ready-reply': 'LostReadyReply',
            'changed-sequence': 'ChangedSequence', 'expired-prepare': 'ExpiredPrepare',
            'repeat-after-success': 'RepeatAfterSuccess',
            'repeat-after-abort': 'RepeatAfterAbort',
            'guard-lost-after-ready': 'GuardLostAfterReady',
        }
        self.assertEqual({group for group in gate.GROUPS if group.startswith('image-native-')},
                         {'image-native-' + scenario for scenario in required})
        for scenario, suffix in required.items():
            group = 'image-native-' + scenario
            parent = gate.PREFIX + 'NamespaceImageUpgrade' + suffix
            self.assertEqual(gate.case_names(group), (parent,))
            pattern = re.compile(gate.pattern(group))
            self.assertIsNotNone(pattern.fullmatch(parent))
            for other in required.values():
                if other != suffix:
                    self.assertIsNone(pattern.fullmatch(gate.PREFIX + 'NamespaceImageUpgrade' + other))
            output = self.output(group)
            for foreign in ('Unregistered', suffix + '/unregistered'):
                with self.assertRaises(ValueError):
                    gate.check_verdict(output + '\n--- PASS: ' + gate.PREFIX +
                                       'NamespaceImageUpgrade' + foreign + ' (0.01s)', group)
        runner = (ROOT/'deploy/test_linux_controller_privilege.py').read_text()
        self.assertIn("'-test.timeout=120s'", runner)
        self.assertIn('UID.run(service_command, cwd=ROOT, timeout=150, sudo=sudo)', runner)

    def test_each_image_source_and_installed_tag_is_mandatory(self):
        self.assertTrue({'client/install-linux-native.py', 'deploy/test_linux_native_install.py'}.issubset(gate.SOURCE))
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary)
            for name in gate.SOURCE:
                target = copy/name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT/name).read_bytes())
            gate.validate_inventory(copy)
            actual = {path.relative_to(ROOT).as_posix() for path in
                      (ROOT/'cmd/client').glob('linux_standard_service_image_*.go')}
            self.assertTrue(actual)
            actual.update({'client/install-linux-native.py', 'deploy/test_linux_native_install.py'})
            self.assertTrue(actual.issubset(gate.SOURCE))
            for name in sorted(actual):
                target = copy/name
                original = target.read_bytes()
                target.unlink()
                with self.assertRaises(ValueError):
                    gate.validate_inventory(copy)
                target.write_bytes(original)
            selected = copy/'cmd/client/linux_standard_service_image_upgrade_namespace_test.go'
            original = selected.read_text()
            for tag in (' && routervpn_controller_privileged', ' && routervpn_standard_service_native'):
                selected.write_text(original.replace(tag, '', 1))
                with self.assertRaises(ValueError):
                    gate.validate_inventory(copy)
                selected.write_text(original)
            unexpected = copy/'cmd/client/linux_standard_service_image_unregistered_linux.go'
            unexpected.write_text('//go:build linux\n\npackage main\n')
            with self.assertRaises(ValueError):
                gate.validate_inventory(copy)
            unexpected.unlink()
            selected.write_text(original.replace(
                'TestLinuxStandardServiceNamespaceImageUpgradeOriginal',
                'TestLinuxStandardServiceNamespaceImageUpgradeOmitted', 1))
            with self.assertRaises(ValueError):
                gate.validate_inventory(copy)

    def test_shipping_identity_captures_actual_installer_bytes(self):
        spec = importlib.util.spec_from_file_location(
            'standard_service_privilege_identity', ROOT/'deploy/test_linux_controller_privilege.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        # Exercise the shipping identity function, including all declared
        # service sources. Broader engine inputs are independently captured by
        # the builder; this fixture isolates the service closure on real bytes.
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary)
            for name in gate.SOURCE:
                target = copy/name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT/name).read_bytes())
            with mock.patch.object(runner, 'ROOT', copy), mock.patch.object(
                    runner.BUNDLE, 'builder') as builder:
                builder.return_value.inputs.return_value = []
                before = runner.source_identity()
                self.assertTrue(gate.SOURCE.issubset(before),
                                'Shipping identity omitted declared service source bytes')
                for name in ('client/install-linux-native.py', 'deploy/test_linux_native_install.py'):
                    with self.subTest(source=name):
                        target = copy/name
                        original = target.read_bytes()
                        self.assertEqual(before[name], hashlib.sha256(original).hexdigest())
                        changed = original + b'\n# exact original-byte mutation witness\n'
                        target.write_bytes(changed)
                        after = runner.source_identity()
                        self.assertEqual(after[name], hashlib.sha256(changed).hexdigest())
                        self.assertEqual({key for key in before if before[key] != after[key]}, {name})
                        target.write_bytes(original)
                        self.assertEqual(runner.source_identity(), before)

    def test_shipping_identity_rejects_missing_required_source(self):
        spec = importlib.util.spec_from_file_location(
            'standard_service_privilege_missing', ROOT/'deploy/test_linux_controller_privilege.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary)
            for name in gate.SOURCE:
                target = copy/name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT/name).read_bytes())
            with mock.patch.object(runner, 'ROOT', copy), mock.patch.object(
                    runner.BUNDLE, 'builder') as builder, mock.patch.object(runner.UID, 'run') as execute:
                builder.return_value.inputs.return_value = []
                for name in ('client/install-linux-native.py', 'deploy/test_linux_native_install.py'):
                    with self.subTest(source=name):
                        target = copy/name
                        original = target.read_bytes()
                        target.unlink()
                        self.assertNotIn(name, runner.source_identity())
                        with self.assertRaisesRegex(ValueError, 'original source inventory is incomplete'):
                            runner.execute()
                        execute.assert_not_called()
                        target.write_bytes(original)

    def test_shipping_runner_executes_same_captured_candidate(self):
        runner=(ROOT/'deploy/test_linux_controller_privilege.py').read_text()
        self.assertIn('required.union(SERVICE.SOURCE).issubset(before)',runner)
        self.assertIn("'-tags=routervpn_controller_privileged,routervpn_standard_service_native'",runner)
        self.assertIn('for group in SERVICE.GROUPS:',runner)
        self.assertIn("'--namespace-service-group', group",runner)
        self.assertIn('SERVICE.check_verdict(service_output, group)',runner)
        self.assertIn('SERVICE.pattern(args.namespace_service_group)',runner)
        self.assertIn('source_identity() != before',runner)
        self.assertIn('hashlib.sha256(service_binary.read_bytes()).hexdigest() != service_digest',runner)
        self.assertIn('for group, (package, _) in SERVICE.AUXILIARY.items():',runner)
        self.assertIn("'-run=' + SERVICE.auxiliary_pattern(group), package",runner)
        self.assertIn('SERVICE.check_auxiliary_verdict(output, group)',runner)

    def test_each_mtu_source_and_privileged_tag_is_mandatory(self):
        with tempfile.TemporaryDirectory() as temporary:
            copy=Path(temporary)
            for name in gate.SOURCE:
                target=copy/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
            for name in sorted(gate.SOURCE):
                if '/linux_standard_service_mtu_' not in name:
                    continue
                target=copy/name;original=target.read_bytes();target.unlink()
                with self.assertRaises(ValueError):gate.validate_inventory(copy)
                target.write_bytes(original)
            for name in gate.NATIVE_MTU_SOURCES:
                target=copy/name;original=target.read_text()
                target.write_text(original.replace('//go:build linux && routervpn_controller_privileged','//go:build linux',1))
                with self.assertRaises(ValueError):gate.validate_inventory(copy)
                target.write_text(original)
            unexpected=copy/'cmd/client/linux_standard_service_mtu_unregistered_linux.go'
            unexpected.write_text('//go:build linux\n\npackage main\n')
            with self.assertRaises(ValueError):gate.validate_inventory(copy)
            unexpected.unlink()
            selected=copy/'cmd/client/linux_standard_service_mtu_client_linux_test.go'
            original=selected.read_text()
            selected.write_text(original.replace('TestLinuxStandardMTUUsesActivationAfterActualConnectCompletion','TestLinuxStandardMTURenamedActivation'))
            with self.assertRaises(ValueError):gate.validate_inventory(copy)

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
