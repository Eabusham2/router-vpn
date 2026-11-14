#!/usr/bin/env python3
"""Require prefix6, SOCKS8 and CONNECT14 before Windows package publication.

These tests validate receipts and orchestration. They do not manufacture a
native Windows result; the real builder must execute every composed stage.
"""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


BUILD = load('windows_connect_release_build', 'build-native-runtime.py')
PARENT = load('windows_connect_release_parent', 'test_desktop_connect_parent.py')
ORIGINAL = load('windows_connect_original_receipts', 'test_windows_socks_release_receipt.py')
GATE = load('windows_connect_release_gate', 'test_windows_connect_node_chain_host.py')
FULL = 'Native Windows typed CONNECT full-path acceptance: '


def receipts(digest):
    prefix, socks = ORIGINAL.receipts(digest)
    connect = copy.deepcopy(socks)
    for name in ('remote_associations_after_retirement', 'original_prefix_acceptance', 'typed_socks_parent_controls', 'public_connect_path'):
        del connect[name]
    connect.update(schema=1, cases=list(GATE.CASES), original_socks_acceptance=copy.deepcopy(socks),
                   remote_connect_streams_after_retirement=0, final_udp_transport='SS-UoT-v2',
                   connect_middle_tcp_only=True, connect_protocols=['http-connect', 'https-connect'],
                   typed_connect_public_source_controls=dict(scope='registered-public-connect-source-controls',
                       native_kernel_acceptance=False, target='windows', cases=list(GATE.CONNECT_PUBLIC.REQUIRED), output_sha256='9' * 64),
                   ordered_latency_samples_per_hop=50, public_admission='public-typed-connect',
                   public_route='/api/multihop/connect', public_profile_capability=True,
                   typed_connect_parent_controls=dict(scope='compiled-parent-model-and-source-controls',
                       native_kernel_acceptance=False, target='windows', cases=list(PARENT.inventory('windows')[1]), output_sha256='8' * 64))
    return prefix, socks, connect


class WindowsCONNECTReleaseReceipt(unittest.TestCase):
    def verify(self, connect, socks):
        return BUILD.verify_installed_windows_connect_receipt(FULL + json.dumps(connect), 'windows/amd64',
                                                              {'policy_sha256': 'a' * 64}, '7' * 64, socks)

    def test_every_complete_connect_receipt_field_required(self):
        _, socks, connect = receipts('7' * 64)
        self.assertEqual(self.verify(connect, socks), connect)
        for field in connect:
            broken = copy.deepcopy(connect)
            del broken[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.verify(broken, socks)

    def test_carrier_source_ownership_and_numeric_types_cannot_be_substituted(self):
        _, socks, connect = receipts('7' * 64)
        faults = (
            ('schema', True), ('schema', 2), ('native', 1), ('target', 'windows/arm64'), ('source_sha256', '8' * 64),
            ('bundle_sha256', '9' * 64), ('cases', connect['cases'][:-1]), ('cases', socks['cases']),
            ('unmodified_shipping_image', True), ('test_scope', 'modeled'), ('typed_full_path', 1),
            ('positive_application_and_selected_dns_proved', False), ('measurement_bytes_per_direction_per_hop', float(8 << 20)),
            ('measurement_bytes_per_direction_per_hop', 4 << 20), ('measurement_hops', 2), ('measurement_hops', 3.0),
            ('ordered_latency_samples_per_hop', 49), ('ordered_latency_samples_per_hop', 50.0),
            ('native_joined', 1), ('command_job_joined', False), ('command_job_joined', 1),
            ('tun_absent_all_outcomes', False), ('tun_absent_all_outcomes', 1),
            ('remote_connect_streams_after_retirement', 1), ('remote_connect_streams_after_retirement', False),
            ('public_admission', 'closed'), ('public_admission', 'complete'),
            ('public_route', '/api/native-connect/connect'), ('public_profile_capability', False), ('public_profile_capability', 1), ('original_socks_acceptance', {}), ('final_udp_transport', 'SOCKS-UDP'),
            ('connect_middle_tcp_only', 1), ('connect_protocols', ['https-connect']),
            ('sources', {}), ('sources', {'actual': 'invalid'}), ('images', {'controller': '3' * 64}),
            ('scope_sources', {'foreign': '2' * 64}))
        for field, value in faults:
            broken = copy.deepcopy(connect)
            broken[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.verify(broken, socks)
        for case in connect['cases']:
            broken = copy.deepcopy(connect)
            broken['cases'].remove(case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.verify(broken, socks)

    def test_parent_model_cannot_replace_native_or_drop_original_controls(self):
        _, socks, connect = receipts('7' * 64)
        for field in connect['typed_connect_parent_controls']:
            broken = copy.deepcopy(connect)
            del broken['typed_connect_parent_controls'][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(broken, socks)
        for field, value in (('native_kernel_acceptance', True), ('target', 'linux'), ('cases', []), ('scope', 'native'), ('output_sha256', 'bad')):
            broken = copy.deepcopy(connect)
            broken['typed_connect_parent_controls'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(broken, socks)

    def test_unique_structured_connect_receipt_required(self):
        _, socks, connect = receipts('7' * 64)
        good = FULL + json.dumps(connect)
        for output in ('', good + '\n' + good, FULL + '[]', good.replace('"native": true', '"native": true, "native": true', 1)):
            with self.subTest(output=output[:80]), self.assertRaises(ValueError):
                BUILD.verify_installed_windows_connect_receipt(output, 'windows/amd64', {'policy_sha256': 'a' * 64}, '7' * 64, socks)

    def test_real_builder_requires_all_three_native_receipts_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            (bundle / 'NATIVE-RUNTIME.json').write_bytes(b'original completed native bundle')
            digest = hashlib.sha256((bundle / 'NATIVE-RUNTIME.json').read_bytes()).hexdigest()
            prefix, socks, connect = receipts(digest)
            parts = (ORIGINAL.PREFIX + json.dumps(prefix), ORIGINAL.FULL + json.dumps(socks), FULL + json.dumps(connect))
            good = '\n'.join(parts)
            outcomes = [(good, True)]
            for index in range(3):
                outcomes.append(('\n'.join(part for i, part in enumerate(parts) if i != index), False))
                outcomes.append((good + '\n' + parts[index], False))
            for output, accepted in outcomes:
                with self.subTest(accepted=accepted), patch.object(BUILD.platform, 'system', return_value='Windows'), patch.object(BUILD, 'native_host_target', return_value='windows/amd64'), patch.object(BUILD, 'reuse', return_value={'policy_sha256': 'a' * 64}) as reuse, patch.object(BUILD, 'run', side_effect=['', '', '', '', '', '', '', output]) as run:
                    if accepted:
                        BUILD.verify_installed_windows_prefix(ROOT, bundle, 'windows/amd64', {})
                        self.assertEqual(reuse.call_count, 2)
                    else:
                        with self.assertRaises(ValueError):
                            BUILD.verify_installed_windows_prefix(ROOT, bundle, 'windows/amd64', {})
                        self.assertEqual(reuse.call_count, 1)
                    self.assertEqual([Path(call.args[0][1]).name for call in run.call_args_list], [
                        'test_windows_candidate_prefix_runner.py', 'test_windows_socks_node_chain_host_runner.py',
                        'test_windows_socks_release_receipt.py', 'test_desktop_connect_parent_runner.py',
                        'test_desktop_connect_admission_runner.py',
                        'test_windows_connect_node_chain_host_runner.py', 'test_windows_connect_release_receipt.py',
                        'test_windows_connect_node_chain_host.py'])
                    self.assertEqual(run.call_args_list[-1].kwargs['timeout'], 3000 + 4200 + 4200)

    def test_expanded_outer_budget_preserves_existing_inner_limits_and_other_platforms(self):
        self.assertEqual(BUILD.WINDOWS_INSTALLED_NATIVE_GATE_TIMEOUT, 3000 + 4200 + 4200)
        workflow = (ROOT / '.github/workflows/desktop-native-runtime.yml').read_text()
        self.assertEqual(workflow.count("timeout-minutes: ${{ startsWith(matrix.target, 'darwin/') && 60 || startsWith(matrix.target, 'linux/') && 200 || 220 }}"), 1)
        source = (ROOT / 'deploy/test_windows_connect_node_chain_host.py').read_text()
        for limit in ('timeout=600', '"-test.timeout=1800s"', 'timeout=1820'):
            self.assertIn(limit, source)


if __name__ == '__main__':
    unittest.main()
