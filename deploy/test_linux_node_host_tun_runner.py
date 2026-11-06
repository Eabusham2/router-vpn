#!/usr/bin/env python3
"""Require real installed-host lifecycle evidence and exact namespace inputs."""
from pathlib import Path
from contextlib import redirect_stderr
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

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installed_linux_host_runner', ROOT / 'deploy/test_linux_node_host_tun.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class InstalledReverseServiceVerdict(unittest.TestCase):
    def completed(self):
        parent = 'TestDesktopLinuxGuardianKernelNodeStandardServiceReverse'
        return '\n'.join(line for case in G.REVERSE_CASES for line in (
            '--- PASS: ' + parent + ' (1.0s)',
            '    --- PASS: ' + parent + '/' + case + ' (1.0s)',
            '    fixture.go:1: verified installed Node to standard service original creators, DNS, private encrypted proof and joined retirement: ' + case)) + '\n'

    def test_exact_native_cases(self):
        G.check_reverse_verdict(self.completed())
        self.assertEqual(G.REVERSE_CASES[:3], ('node-standard-original', 'node-standard-lost-commit-reply', 'node-standard-lost-prepare-reply'))
        self.assertEqual(G.REVERSE_CASES[3:], ('node-standard-lost-start-reply', 'node-standard-cancel-before-remove', 'node-standard-longer-deadline', 'node-standard-post-removal-failure', 'node-standard-always-lost-prepare', 'node-standard-always-cancel-before-remove'))
        self.assertEqual(len(G.CASES), 458 + len(G.EXTERNAL_SS_ENTRY_CASES) + len(G.BOOT_RESOLVER_CASES) + len(G.EXTERNAL_SS_CONNECT_CASES) + len(G.EXTERNAL_SS_HYSTERIA_CASES) + len(G.RESOLVED_CASES) + len(G.EXTERNAL_SS_LAYER_CASES) + len(G.EXTERNAL_SS_HYSTERIA_LAYER_CASES))
        self.assertEqual(len(G.REVERSE_CASES), 9)


    def test_missing_duplicate_foreign_and_skip(self):
        good = self.completed()
        for line in good.splitlines(True):
            with self.subTest(line=line):
                with self.assertRaises(ValueError): G.check_reverse_verdict(good.replace(line, '', 1))
                with self.assertRaises(ValueError): G.check_reverse_verdict(good + line)
        for changed in (good.replace('node-standard-original', 'node-standard-foreign'), good + '--- SKIP: foreign (0.1s)\n', good + '--- FAIL: foreign (0.1s)\n'):
            with self.assertRaises(ValueError): G.check_reverse_verdict(changed)


class InstalledLinuxHostVerdict(unittest.TestCase):
    def test_resolved_composition_requires_original_helper_receipt(self):
        self.assertEqual(G.CASES[524:524+len(G.RESOLVED_CASES)], G.RESOLVED_CASES)
        self.assertEqual(G.CASES[524+len(G.RESOLVED_CASES):], G.EXTERNAL_SS_LAYER_CASES + G.EXTERNAL_SS_HYSTERIA_LAYER_CASES)
        self.assertEqual(G.RESOLVED_CASES, ('service-boot-resolved-udp','service-boot-resolved-tcp','service-boot-resolved-local', 'service-boot-resolved-parallel', 'service-boot-resolved-opportunistic-tls', 'service-boot-resolved-opportunistic-fallback', 'service-boot-resolved-dnssec-nta', 'service-boot-resolved-dnssec-cname', 'service-boot-resolved-dnssec-dname','service-boot-resolved-dnssec-private-tld','service-boot-resolved-dnssec-private-tld-unrelated-nta'))
        for case in G.RESOLVED_CASES:
            self.assertIn(case, G.HOSTNAME_CASES)
            self.assertIn(case, G.PUBLIC_CASES)
            self.assertIn(case, G.OFF_CASES)
            good = self.completed((case,))
            G.check_verdict(good, case)
            marker = 'verified installed resolved helper original broker and scoped upstream: ' + case
            line = next(line for line in good.splitlines(True) if marker in line)
            with self.assertRaises(ValueError): G.check_verdict(good.replace(line, '', 1), case)
            with self.assertRaises(ValueError): G.check_verdict(good + line, case)

    def test_alias_requires_separate_target_capture_and_original_wire_proof(self):
        for case in ('service-boot-resolved-dnssec-cname', 'service-boot-resolved-dnssec-dname'):
            good = self.completed((case,))
            G.check_verdict(good, case)
            lines = [line for line in good.splitlines(True) if 'verified installed DNSSEC alias' in line]
            self.assertEqual(len(lines), 2)
            for line in lines:
                for changed in (good.replace(line, '', 1), good + line, good.replace(line, line.replace(case, case+'-foreign'), 1)):
                    with self.subTest(case=case), self.assertRaises(ValueError): G.check_verdict(changed, case)

    def test_private_tld_requires_root_and_independent_query_receipts(self):
        for case in G.RESOLVED_CASES:
            if not case.startswith('service-boot-resolved-dnssec-private-tld'):continue
            good=self.completed((case,));G.check_verdict(good,case)
            lines=[line for line in good.splitlines(True) if 'verified installed private-TLD' in line]
            self.assertEqual(len(lines),2)
            for line in lines:
                for changed in (good.replace(line,'',1),good+line):
                    with self.assertRaises(ValueError):G.check_verdict(changed,case)

    def test_private_tld_causal_must_reach_exact_denial_boundary(self):
        source=(G.ROOT/'mobile/desktop/node_resolved_private_tld_test.go.tmpl').read_text()
        changed=G.private_tld_missing_denial_source(source)
        self.assertEqual(changed.count('const privateTLDCompleteDenial = false'),1)
        output='private-TLD proof is not exact authenticated secure NXDOMAIN\nverified installed private-TLD original and auxiliary wire queries: service-boot-resolved-dnssec-private-tld\n--- FAIL: TestDesktopLinuxGuardianKernelNodeHostTUN/service-boot-resolved-dnssec-private-tld (1.0s)\n'
        cleanup=('Linux guardian namespace phase: private account workspace removed; return test status 1 (pid=1, monotonic=1.000)\n'
                 'Linux guardian namespace phase: original namespace child joined (pid=2, monotonic=1.001)\n')
        output+=cleanup
        G.check_private_tld_control(1,output)
        for bad in ('',output.replace('secure NXDOMAIN','unknown error'),output+'DATA RACE',output+'--- SKIP: case',output+'private-TLD omitted actual original/proof/root-key exchange',output.replace('wire queries: service-boot-resolved-dnssec-private-tld','wire queries: service-boot-resolved-dnssec-private-tld-unrelated-nta')):
            with self.assertRaises(ValueError):G.check_private_tld_control(1,bad)
        with self.assertRaises(ValueError):G.check_private_tld_control(1,output.replace(cleanup,''))
        for diagnostic in ('Linux guardian namespace failed: cleanup error', 'panic: late crash', 'fatal error: unexpected fault',
                           'panic: test timed out after 90s', 'TimeoutExpired',
                           'Traceback (most recent call last):', 'signal: killed',
                           'signal: segmentation fault', 'context deadline exceeded',
                           'joined original installed host retirement: failed',
                           'failed-readiness original joined retirement: failed',
                           'joined original installed session retirement: failed',
                           'owned active network replacement cleanup: failed',
                           'installed host omitted its actual source/process join and durable retirement',
                           'installed controller did not join after its original native retirement',
                           'installed-host retirement did not persist its exact original settled journal',
                           'installed-host TUN retirement requires a successful native inventory'):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                G.check_private_tld_control(1,output+diagnostic)
        for status in (0, -9, 2, 124, 137):
            with self.subTest(status=status), self.assertRaises(ValueError):
                G.check_private_tld_control(status,output)
        G.check_private_tld_control(1,output+'verified original joined retirement\n')

    def completed(self, cases=None):
        cases = G.CASES if cases is None else cases
        prefix = '--- PASS: TestDesktopLinuxGuardianKernelNodeHostTUN'
        return '\n'.join([prefix + ' (0.1s)', *(prefix + '/' + case + ' (0.1s)' for case in cases),
                          *('    native_test.go:1: verified installed host native lifecycle: ' + case for case in cases),
                          *('    native_test.go:2: verified installed host active lifetime: ' + case for case in cases if case in G.ACTIVE_CASES),
                          *('    native_test.go:3: verified installed host retained DNS observation: ' + case for case in cases if case in ('active-request-ended', *G.PUBLIC_CASES)),
                          *('    native_test.go:4: verified installed host original MTU lease: ' + case for case in cases if case in G.MTU_CASES),
                          *('    native_test.go:5: verified installed host live MTU status: ' + case for case in cases if case in ('active-request-ended', *G.PUBLIC_CASES, *G.MTU_CASES)),
                          *('    native_test.go:6: verified installed host sealed temporary restoration: ' + case for case in cases if case in G.RESTORE_CASES),
                          *('    native_test.go:7: verified installed host public Connect and Disconnect: ' + case for case in cases if case in G.PUBLIC_CASES),
                          *('    native_test.go:8: verified installed host native cover: ' + case for case in cases if case in G.COVER_CASES),
                          *('    native_test.go:9: verified installed host saved Linux protection Off: ' + case for case in cases if case in G.OFF_CASES),
                          *('    native_test.go:10: verified installed host captured Start Layer: ' + case for case in cases if case in G.LAYER_CASES),
                          *('    native_test.go:11: verified installed host plain WireGuard: ' + case for case in cases if case in G.WIREGUARD_CASES),
                          *('    native_test.go:12: verified installed host plain Hysteria2: ' + case for case in cases if case in G.HYSTERIA2_CASES),
                          *('    native_test.go:13: verified installed host captured AWG2: ' + case for case in cases if case in G.AMNEZIA_CASES),
                          *('    native_test.go:14: verified installed host layered Hysteria2: ' + case for case in cases if case in G.HYSTERIA2_LAYER_CASES),
                          *('    native_test.go:15: verified installed host layered WireGuard: ' + case for case in cases if case in G.WIREGUARD_LAYER_CASES),
                          *('    native_test.go:16: verified installed host layered AWG2: ' + case for case in cases if case in G.AMNEZIA_LAYER_CASES),
                          *('    native_test.go:17: verified installed host captured SIP003 lanes: ' + case for case in cases if case in G.SIP003_CASES),
                          *('    native_test.go:23: verified installed host independent WireGuard entry and Hysteria2 final: ' + case for case in cases if case in G.EXTERNAL_WG_HYSTERIA_CASES),
                          *('    native_test.go:25: verified installed host independent WireGuard entry and layered Hysteria2 final: ' + case for case in cases if case in G.EXTERNAL_WG_HYSTERIA_LAYER_CASES),
                          *('    native_test.go:26: verified installed host independent SS2022 entry and SS2022 final: ' + case for case in cases if case in G.EXTERNAL_SS_ENTRY_CASES or case in G.EXTERNAL_SS_LAYER_CASES),
                          *('    native_test.go:27: verified installed host independent SS2022 entry and Hysteria2 final: ' + case for case in cases if case in G.EXTERNAL_SS_HYSTERIA_CASES or case in G.EXTERNAL_SS_HYSTERIA_LAYER_CASES),
                          *('    native_test.go:27: verified installed host independent SS2022 entry and CONNECT final: ' + case for case in cases if case in G.EXTERNAL_SS_CONNECT_CASES),
                          *('    native_test.go:24: verified installed host original boot service transfer: ' + case for case in cases if case in G.BOOT_TRANSFER_CASES + G.BOOT_RESOLVER_CASES + G.RESOLVED_CASES),
                          *('    native_test.go:25: verified installed host captured resolver policy: ' + case for case in cases if case in G.HOSTNAME_CASES),
                          *('    native_test.go:26: verified installed resolved helper original broker and scoped upstream: ' + case for case in cases if case in G.RESOLVED_CASES),
                          *('    native_test.go:29: '+prefix+case for case in cases if case.startswith('service-boot-resolved-dnssec-private-tld') for prefix in ('verified installed private-TLD original and auxiliary wire queries: ', 'verified installed private-TLD original complete root plan and monitor: ')),
                          *('    native_test.go:27: verified installed DNSSEC original NTA and absent-anchor recheck' for case in cases if case == 'service-boot-resolved-dnssec-nta'),
                          *('    native_test.go:28: '+prefix+case for case in cases if case in ('service-boot-resolved-dnssec-cname','service-boot-resolved-dnssec-dname') for prefix in ('verified installed DNSSEC alias target independently captured and adopted: ', 'verified installed DNSSEC alias original proof and target wire queries: ')),
                          *('    native_test.go:22: verified installed host original service transfer: ' + case for case in cases if case in G.TRANSFER_CASES),
                          *('    native_test.go:18: verified installed host retained external succession: ' + case for case in cases if case in G.EXTERNAL_CASES),
                          *('    native_test.go:21: verified installed host independent WireGuard entry and CONNECT final: ' + case for case in cases if case in G.EXTERNAL_WG_CONNECT_CASES),
                          *('    native_test.go:20: verified installed host independent WireGuard entry and SS final: ' + case for case in cases if case in G.EXTERNAL_WG_ENTRY_CASES),
                          *('    native_test.go:19: verified installed host retained layered Hysteria2: ' + case for case in cases if case in (*G.EXTERNAL_HYSTERIA2_LAYER_CASES, *G.EXTERNAL_WG_HYSTERIA_LAYER_CASES))]) + '\n'

    def test_layered_wireguard_hysteria_requires_exact_three_owner_completion(self):
        expected = tuple('external-' + mode + '-' + action for mode in ('wghy2aes', 'wghy2xor') for action in ('on-connect', 'always', 'public', 'cancelled', 'wrong-entry-public', 'wrong-layer-key', 'wrong-key', 'wrong-trust', 'wrong-ca', 'dns-failure', 'source', 'replacement')) + ('external-wghy2xor-wrong-whitening',)
        self.assertEqual(G.EXTERNAL_WG_HYSTERIA_LAYER_CASES, expected)
        self.assertEqual(G.CASES[433:458], expected)
        good = self.completed()
        G.check_verdict(good)
        for case in expected:
            lines = [line for line in good.splitlines(True) if ('layered Hysteria2 final: ' + case + '\n') in line or ('KernelNodeHostTUN/' + case + ' (') in line]
            self.assertEqual(len(lines), 2)
            for line in lines:
                for changed in (good.replace(line, '', 1), good + line, good.replace(line, line.replace(case, 'foreign-layer-entry'), 1)):
                    with self.subTest(case=case), self.assertRaises(ValueError):
                        G.check_verdict(changed)
            with self.assertRaises(ValueError):
                G.check_verdict(good.replace('retained layered Hysteria2: ' + case, 'unverified layer: ' + case))
        for changed in (self.completed(G.CASES[:433]), good + '--- SKIP: foreign (0.1s)\n'):
            with self.assertRaises(ValueError):
                G.check_verdict(changed)

    def test_wireguard_hysteria_keeps_prior_inventory_and_original_receipts(self):
        expected = tuple('external-wghy2-' + action for action in ('on-connect', 'always', 'public', 'cancelled', 'wrong-entry-public', 'wrong-key', 'wrong-trust', 'wrong-ca', 'dns-failure'))
        self.assertEqual(G.EXTERNAL_WG_HYSTERIA_CASES, expected)
        self.assertEqual(G.CASES[417:420], G.TRANSFER_CASES)
        self.assertEqual(G.CASES[420:429], expected)
        self.assertEqual(len(G.CASES), 458 + len(G.EXTERNAL_SS_ENTRY_CASES) + len(G.BOOT_RESOLVER_CASES) + len(G.EXTERNAL_SS_CONNECT_CASES) + len(G.EXTERNAL_SS_HYSTERIA_CASES) + len(G.RESOLVED_CASES) + len(G.EXTERNAL_SS_LAYER_CASES) + len(G.EXTERNAL_SS_HYSTERIA_LAYER_CASES))
        good = self.completed()
        G.check_verdict(good)
        for case in expected:
            lines = [line for line in good.splitlines(True) if ('Hysteria2 final: ' + case + '\n') in line or ('KernelNodeHostTUN/' + case + ' (') in line]
            self.assertEqual(len(lines), 2)
            for line in lines:
                for changed in (good.replace(line, ''), good + line):
                    with self.subTest(case=case), self.assertRaises(ValueError):
                        G.check_verdict(changed)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:420]))

    def test_boot_transfer_keeps_existing_inventory_and_exact_creator_receipts(self):
        self.assertEqual(G.CASES[429:433], G.BOOT_TRANSFER_CASES)
        self.assertEqual(G.BOOT_TRANSFER_CASES, ('service-boot-transfer', 'service-boot-transfer-cancel', 'service-boot-transfer-lost-reply', 'service-boot-hostname'))
        good = self.completed()
        G.check_verdict(good)
        for case in G.BOOT_TRANSFER_CASES:
            lines = [line for line in good.splitlines(True) if ('original boot service transfer: ' + case + '\n') in line or ('KernelNodeHostTUN/' + case + ' (') in line]
            self.assertEqual(len(lines), 2)
            for line in lines:
                for changed in (good.replace(line, '', 1), good + line, good.replace(line, line.replace(case, 'foreign-boot'), 1)):
                    with self.subTest(case=case), self.assertRaises(ValueError):
                        G.check_verdict(changed)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:429]))

    def test_boot_resolver_preserves_prior_inventory_and_exact_policy_receipts(self):
        self.assertEqual(G.CASES[:481][-23:], G.EXTERNAL_SS_ENTRY_CASES)
        self.assertEqual(G.CASES[481:484], G.BOOT_RESOLVER_CASES)
        self.assertEqual(G.BOOT_RESOLVER_CASES, ('service-boot-hosts', 'service-boot-hostname-tcp', 'service-boot-hostname-truncated'))
        self.assertEqual(len(G.CASES), 484 + len(G.EXTERNAL_SS_CONNECT_CASES) + len(G.EXTERNAL_SS_HYSTERIA_CASES) + len(G.RESOLVED_CASES) + len(G.EXTERNAL_SS_LAYER_CASES) + len(G.EXTERNAL_SS_HYSTERIA_LAYER_CASES))
        good = self.completed()
        G.check_verdict(good)
        for case in G.HOSTNAME_CASES:
            lines = [line for line in good.splitlines(True) if ('captured resolver policy: ' + case + '\n') in line]
            self.assertEqual(len(lines), 1)
            for line in lines:
                for changed in (good.replace(line, '', 1), good + line, good.replace(line, line.replace(case, 'foreign-resolver'), 1)):
                    with self.subTest(case=case), self.assertRaises(ValueError):
                        G.check_verdict(changed)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:481]))

    def test_service_transfer_requires_original_completion_and_exact_verdict(self):
        good = self.completed()
        G.check_verdict(good)
        for case in G.TRANSFER_CASES:
            lines = [line for line in good.splitlines(True) if ('original service transfer: ' + case + '\n') in line or ('KernelNodeHostTUN/' + case + ' (') in line]
            self.assertEqual(len(lines), 2)
            for line in lines:
                for changed in (good.replace(line, ''), good + line):
                    with self.assertRaises(ValueError):
                        G.check_verdict(changed)

    def test_connect_tls_requires_actual_captured_and_rejected_certificates(self):
        lines = ['--- PASS: TestRouterVPNDesktopExternalCONNECTCertificateRefusal (0.01s)',
                 *('    --- PASS: ' + case + ' (0.01s)' for case in G.CONNECT_TLS_CASES)]
        good = '\n'.join(lines) + '\n'
        G.check_connect_tls_verdict(good)
        for line in lines:
            for changed in (good.replace(line + '\n', ''), good + line + '\n', good.replace(line, 'prefix ' + line)):
                with self.assertRaises(ValueError):
                    G.check_connect_tls_verdict(changed)
        for bad in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:', '[build failed]'):
            with self.assertRaises(ValueError):
                G.check_connect_tls_verdict(good + bad)

    def test_hysteria_auth_requires_actual_captured_and_rejected_certificates(self):
        lines = ['--- PASS: TestRouterVPNDesktopExternalHysteriaAuthenticationAndTrust (0.01s)',
                 *('    --- PASS: ' + case + ' (0.01s)' for case in G.HYSTERIA_AUTH_CASES)]
        good = '\n'.join(lines) + '\n'
        G.check_hysteria_auth_verdict(good)
        for line in lines:
            for changed in (good.replace(line + '\n', ''), good + line + '\n', good.replace(line, 'prefix ' + line)):
                with self.assertRaises(ValueError):
                    G.check_hysteria_auth_verdict(changed)
        for bad in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:', '[build failed]'):
            with self.assertRaises(ValueError):
                G.check_hysteria_auth_verdict(good + bad)

    def test_layered_entry_compiled_authority_requires_original_graph_and_mutations(self):
        names = G.LAYERED_ENTRY_AUTHORITY_CASES
        self.assertEqual(len(names), 17)
        good = ''.join('=== RUN   ' + name + '\n--- PASS: ' + name + ' (0.01s)\n' for name in names)
        G.check_layered_entry_authority_verdict(good)
        for line in good.splitlines(True):
            for changed in (good.replace(line, '', 1), good + line, good.replace(line, line.replace('Authority', 'Foreign'), 1)):
                with self.assertRaises(ValueError):
                    G.check_layered_entry_authority_verdict(changed)
        for bad in ('--- FAIL:', '--- SKIP:', 'DATA RACE', 'panic:'):
            with self.assertRaises(ValueError):
                G.check_layered_entry_authority_verdict(good + bad)
        self.assertEqual(set(G.EXTERNAL_WG_HYSTERIA_LAYER_CASES) & set(G.WHITENING_CASES), {case for case in G.EXTERNAL_WG_HYSTERIA_LAYER_CASES if case.startswith('external-wghy2xor-')})

    def test_compiled_layer_authority_requires_both_modes(self):
        self.assertEqual(len(G.LAYER_AUTHORITY_CASES), 2)
        lines = ['    --- PASS: ' + case + ' (0.01s)' for case in G.LAYER_AUTHORITY_CASES]
        good = '\n'.join(lines) + '\n'
        G.check_layer_peer_verdict(good, authority=True)
        for line in lines:
            for changed in (good.replace(line + '\n', ''), good + line + '\n', good.replace(line, 'prefix ' + line)):
                with self.assertRaises(ValueError):
                    G.check_layer_peer_verdict(changed, authority=True)

    def test_actual_layer_carrier_requires_each_exact_once_leaf(self):
        self.assertEqual(len(G.LAYER_PEER_CASES), 7)
        lines = ['        --- PASS: ' + case + ' (0.01s)' for case in G.LAYER_PEER_CASES]
        good = '\n'.join(lines) + '\n'
        G.check_layer_peer_verdict(good)
        for line in lines:
            for changed in (good.replace(line + '\n', ''), good + line + '\n', good.replace(line, 'prefix ' + line)):
                with self.assertRaises(ValueError):
                    G.check_layer_peer_verdict(changed)
        for bad in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:', '[build failed]'):
            with self.assertRaises(ValueError):
                G.check_layer_peer_verdict(good + bad)

    def test_new_hysteria2_layers_preserve_every_original_case_and_receipt(self):
        self.assertEqual(len(G.ORIGINAL_CASES), 299)
        self.assertEqual(len(G.HYSTERIA2_LAYER_CASES), 33)
        self.assertEqual(len(set(G.ORIGINAL_CASES) - set(G.SIP003_CASES) - set(G.HYSTERIA2_LAYER_CASES) - set(G.WIREGUARD_LAYER_CASES) - set(G.AMNEZIA_LAYER_CASES)), 93)
        self.assertEqual(len(G.CASES), len(set(G.CASES)))
        self.assertEqual(set(G.HYSTERIA2_LAYER_CASES) & set(G.WHITENING_CASES),
                         {case for case in G.HYSTERIA2_LAYER_CASES if case.startswith('hy2-whitening-')})
        for case in G.HYSTERIA2_LAYER_CASES:
            self.assertIn(case, G.LAYER_CASES)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(tuple(case for case in G.CASES if case not in G.HYSTERIA2_LAYER_CASES)))

    def test_wireguard_layers_preserve_original_inventory_and_complete_receipts(self):
        self.assertEqual(len(G.ORIGINAL_CASES), 299)
        self.assertEqual(len(G.WIREGUARD_LAYER_CASES), 31)
        self.assertEqual(len(set(G.ORIGINAL_CASES) - set(G.SIP003_CASES) - set(G.WIREGUARD_LAYER_CASES) - set(G.AMNEZIA_LAYER_CASES)), 126)
        self.assertEqual(len(G.CASES), len(set(G.CASES)))
        self.assertEqual(set(G.WIREGUARD_LAYER_CASES) & set(G.WHITENING_CASES),
                         {case for case in G.WIREGUARD_LAYER_CASES if case.startswith('wg-whitening-')})
        for case in G.WIREGUARD_LAYER_CASES:
            self.assertIn(case, G.LAYER_CASES)
            self.assertNotIn(case, G.WIREGUARD_CASES)
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host layered WireGuard:',
                                               'verified installed host plain WireGuard:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(tuple(case for case in G.CASES if case not in G.WIREGUARD_LAYER_CASES)))

    def test_amnezia_layers_preserve_every_original_case_and_exact_native_receipt(self):
        self.assertEqual(len(G.ORIGINAL_CASES), 299)
        self.assertEqual(len(G.AMNEZIA_LAYER_CASES), 70)
        self.assertEqual(len(set(G.ORIGINAL_CASES) - set(G.SIP003_CASES) - set(G.AMNEZIA_LAYER_CASES)), 157)
        self.assertEqual(len(G.CASES), len(set(G.CASES)))
        self.assertEqual(set(G.AMNEZIA_LAYER_CASES) & set(G.WHITENING_CASES),
                         {case for case in G.AMNEZIA_LAYER_CASES if '-whitening-' in case})
        for case in G.AMNEZIA_LAYER_CASES:
            self.assertIn(case, G.LAYER_CASES)
            self.assertNotIn(case, G.AMNEZIA_CASES)
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host layered AWG2:',
                                               'verified installed host captured AWG2:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(tuple(case for case in G.CASES if case not in G.AMNEZIA_LAYER_CASES)))

    def test_sip003_preserves_original_cases_and_both_lane_receipts(self):
        self.assertEqual(len(G.SIP003_CASES), 72)
        self.assertEqual(len(G.ORIGINAL_CASES), 299)
        self.assertEqual(len(G.CASES), len(set(G.CASES)))
        self.assertEqual(len(set(G.ORIGINAL_CASES) - set(G.SIP003_CASES)), 227)
        self.assertEqual(G.ORIGINAL_CASES[-72:], G.SIP003_CASES)
        self.assertEqual(set(G.SIP003_CASES) & set(G.WHITENING_CASES),
                         {case for case in G.SIP003_CASES if case.startswith('ss-v2ray-whitening-')})
        for case in G.SIP003_CASES:
            self.assertEqual(case in G.LAYER_CASES, not case.startswith('ss-v2ray-off-'))
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host captured SIP003 lanes:',
                                               'verified installed host plain Hysteria2:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(tuple(case for case in G.CASES if case not in G.SIP003_CASES)))

    def test_external_succession_keeps_all_original_cases_and_real_lifecycle(self):
        self.assertEqual(len(G.ORIGINAL_CASES), 299)
        self.assertEqual(len(G.EXTERNAL_PROXY_CASES), 11)
        self.assertEqual(len(G.EXTERNAL_CASES), 152 + len(G.EXTERNAL_SS_ENTRY_CASES) + len(G.EXTERNAL_SS_CONNECT_CASES) + len(G.EXTERNAL_SS_HYSTERIA_CASES) + len(G.EXTERNAL_SS_LAYER_CASES) + len(G.EXTERNAL_SS_HYSTERIA_LAYER_CASES))
        self.assertEqual(len(G.CASES), 417 + len(G.TRANSFER_CASES) + len(G.EXTERNAL_WG_HYSTERIA_CASES) + len(G.BOOT_TRANSFER_CASES) + len(G.EXTERNAL_WG_HYSTERIA_LAYER_CASES) + len(G.EXTERNAL_SS_ENTRY_CASES) + len(G.BOOT_RESOLVER_CASES) + len(G.EXTERNAL_SS_CONNECT_CASES) + len(G.EXTERNAL_SS_HYSTERIA_CASES) + len(G.RESOLVED_CASES) + len(G.EXTERNAL_SS_LAYER_CASES) + len(G.EXTERNAL_SS_HYSTERIA_LAYER_CASES))
        self.assertEqual(G.CASES[:299], G.ORIGINAL_CASES)
        self.assertEqual(G.CASES[299:310], G.EXTERNAL_PROXY_CASES)
        self.assertEqual(G.CASES[299:417] + G.CASES[417+len(G.TRANSFER_CASES):429] + G.CASES[433:458] + G.EXTERNAL_SS_ENTRY_CASES + G.EXTERNAL_SS_CONNECT_CASES + G.EXTERNAL_SS_HYSTERIA_CASES + G.EXTERNAL_SS_LAYER_CASES + G.EXTERNAL_SS_HYSTERIA_LAYER_CASES, G.EXTERNAL_CASES)
        self.assertEqual(len(G.CASES), len(set(G.CASES)))
        self.assertEqual(set(G.EXTERNAL_CASES) & set(G.ORIGINAL_CASES), set())
        for case in G.EXTERNAL_CASES:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained external succession:',
                                               'verified installed host public Connect and Disconnect:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.ORIGINAL_CASES))

    def test_external_hysteria2_preserves_every_prior_case_and_requires_real_receipts(self):
        self.assertEqual(len(G.EXTERNAL_HYSTERIA2_CASES), 7)
        self.assertEqual(G.CASES[:310], G.ORIGINAL_CASES + G.EXTERNAL_PROXY_CASES)
        self.assertEqual(G.CASES[310:317], G.EXTERNAL_HYSTERIA2_CASES)
        self.assertEqual(set(G.EXTERNAL_HYSTERIA2_CASES) & set(G.CASES[:310]), set())
        self.assertEqual(G.EXTERNAL_HYSTERIA2_CASES, tuple('external-hy2-' + action for action in
                         ('on-connect', 'always', 'public', 'cancelled', 'wrong-key', 'wrong-trust', 'dns-failure')))
        for case in G.EXTERNAL_HYSTERIA2_CASES:
            self.assertNotIn(case, G.HYSTERIA2_CASES)
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained external succession:',
                                               'verified installed host plain Hysteria2:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:310]))

    def test_external_wireguard_preserves_prior_cases_and_requires_distinct_receipts(self):
        self.assertEqual(len(G.EXTERNAL_WIREGUARD_CASES), 8)
        self.assertEqual(G.CASES[:317], G.ORIGINAL_CASES + G.EXTERNAL_PROXY_CASES + G.EXTERNAL_HYSTERIA2_CASES)
        self.assertEqual(G.CASES[317:325], G.EXTERNAL_WIREGUARD_CASES)
        self.assertEqual(set(G.EXTERNAL_WIREGUARD_CASES) & set(G.CASES[:317]), set())
        self.assertEqual(G.EXTERNAL_WIREGUARD_CASES, tuple('external-wg-' + action for action in
                         ('on-connect', 'always', 'public', 'cancelled', 'wrong-key', 'wrong-psk', 'dns-failure', 'replacement')))
        for case in G.EXTERNAL_WIREGUARD_CASES:
            self.assertNotIn(case, G.WIREGUARD_CASES)
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained external succession:',
                                               'verified installed host plain WireGuard:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:317]))

    def test_external_amnezia_preserves_both_variants_and_exact_prior_inventory(self):
        self.assertEqual(len(G.EXTERNAL_AMNEZIA_CASES), 18)
        self.assertEqual(G.CASES[:325], G.ORIGINAL_CASES + G.EXTERNAL_PROXY_CASES +
                         G.EXTERNAL_HYSTERIA2_CASES + G.EXTERNAL_WIREGUARD_CASES)
        self.assertEqual(G.CASES[325:343], G.EXTERNAL_AMNEZIA_CASES)
        self.assertEqual(set(G.EXTERNAL_AMNEZIA_CASES) & set(G.CASES[:325]), set())
        self.assertEqual(G.EXTERNAL_AMNEZIA_CASES, tuple('external-' + variant + '-' + action
                         for variant in ('awgfast', 'awgstrong')
                         for action in ('on-connect', 'always', 'public', 'cancelled', 'wrong-key', 'wrong-psk',
                                        'dns-failure', 'replacement', 'wrong-parameters')))
        for case in G.EXTERNAL_AMNEZIA_CASES:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained external succession:',
                                               'verified installed host plain WireGuard:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:325]))

    def test_external_openvpn_preserves_every_prior_case_and_ordered_provider_variants(self):
        self.assertEqual(len(G.EXTERNAL_OPENVPN_CASES), 18)
        self.assertEqual(G.CASES[:343], G.ORIGINAL_CASES + G.EXTERNAL_PROXY_CASES +
                         G.EXTERNAL_HYSTERIA2_CASES + G.EXTERNAL_WIREGUARD_CASES + G.EXTERNAL_AMNEZIA_CASES)
        self.assertEqual(G.CASES[343:361], G.EXTERNAL_OPENVPN_CASES)
        self.assertEqual(set(G.EXTERNAL_OPENVPN_CASES) & set(G.CASES[:343]), set())
        self.assertEqual(G.EXTERNAL_OPENVPN_CASES, tuple('external-' + variant + '-' + action
                         for variant in ('ovpntcp', 'ovpnudp')
                         for action in ('on-connect', 'always', 'public', 'cancelled', 'wrong-trust', 'wrong-control',
                                        'dns-failure', 'replacement', 'fallback')))
        for case in G.EXTERNAL_OPENVPN_CASES:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained external succession:',
                                               'verified installed host plain Hysteria2:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:343]))

    def test_external_socks_requires_original_controls_and_all_prior_cases(self):
        self.assertEqual(G.CASES[:361], G.ORIGINAL_CASES + G.EXTERNAL_PROXY_CASES +
                         G.EXTERNAL_HYSTERIA2_CASES + G.EXTERNAL_WIREGUARD_CASES +
                         G.EXTERNAL_AMNEZIA_CASES + G.EXTERNAL_OPENVPN_CASES)
        self.assertEqual(G.CASES[361:372], G.EXTERNAL_SOCKS_CASES)
        self.assertEqual(G.EXTERNAL_SOCKS_CASES, tuple('external-socks-' + action for action in
                         ('on-connect', 'always', 'public', 'cancelled', 'wrong-auth', 'auth-downgrade',
                          'relay-domain', 'control-eof', 'dns-failure', 'replacement', 'source')))
        self.assertEqual(set(G.EXTERNAL_SOCKS_CASES) & set(G.CASES[:361]), set())
        for case in G.EXTERNAL_SOCKS_CASES:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained external succession:',
                                               'verified installed host plain Shadowsocks:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:361]))

    def test_external_layered_hysteria2_keeps_original_inventory_and_exact_receipts(self):
        expected = tuple('external-' + mode + '-' + action for mode in ('hy2aes', 'hy2xor')
            for action in ('on-connect', 'always', 'public', 'cancelled', 'wrong-key', 'wrong-trust', 'dns-failure', 'wrong-layer-key', 'source', 'replacement')) + ('external-hy2xor-wrong-whitening',)
        self.assertEqual(len(expected), 21)
        self.assertEqual(G.EXTERNAL_HYSTERIA2_LAYER_CASES, expected)
        self.assertEqual(G.CASES[372:393], expected)
        self.assertEqual(G.CASES[:372], G.ORIGINAL_CASES + G.EXTERNAL_PROXY_CASES + G.EXTERNAL_HYSTERIA2_CASES + G.EXTERNAL_WIREGUARD_CASES + G.EXTERNAL_AMNEZIA_CASES + G.EXTERNAL_OPENVPN_CASES + G.EXTERNAL_SOCKS_CASES)
        for case in expected:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained external succession:', 'generic encrypted peer:'), case)
            with self.subTest(layer=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained layered Hysteria2:', 'generic encrypted peer:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:372]))

    def test_wireguard_entry_requires_both_proofs_and_original_host_lifecycle(self):
        expected = ('external-wgss-on-connect', 'external-wgss-always', 'external-wgss-public', 'external-wgss-cancelled', 'external-wgss-wrong-entry-public', 'external-wgss-dns-failure')
        self.assertEqual(G.EXTERNAL_WG_ENTRY_CASES, expected)
        self.assertEqual(G.CASES[393:399], expected)
        for case in expected:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host retained external succession:', 'generic encrypted peer:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:393]))
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed().replace('verified installed host independent WireGuard entry and SS final:', 'generic proof:'))

    def test_wireguard_connect_keeps_captured_credentials_tls_and_prior_inventory(self):
        expected = tuple('external-wg' + protocol + '-' + action for protocol in ('http','https') for action in ('on-connect','always','public','cancelled','wrong-entry-public','wrong-proxy-password','wrong-proxy-username','dns-failure')) + ('external-wghttps-wrong-proxy-sni','external-wghttps-wrong-proxy-trust')
        self.assertEqual(G.EXTERNAL_WG_CONNECT_CASES, expected)
        self.assertEqual(G.CASES[399:417], expected)
        for case in expected:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output.replace('verified installed host independent WireGuard entry and CONNECT final:', 'generic encrypted peer:'), case)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(G.CASES[:399]))

    def test_requires_every_real_positive_negative_and_joined_lifecycle(self):
        output = self.completed()
        G.check_verdict(output)
        for line in output.splitlines():
            with self.subTest(line=line), self.assertRaises(ValueError):
                G.check_verdict(output.replace(line, ''))

    def test_indexed_verdict_preserves_exact_terminated_receipts(self):
        case = G.EXTERNAL_CASES[-1]
        output = self.completed((case,))
        G.check_verdict(output.replace('\n', '\r\n'), case)
        receipt = 'verified installed host retained external succession: ' + case
        passed = '--- PASS: TestDesktopLinuxGuardianKernelNodeHostTUN/' + case
        for changed in (output.removesuffix('\n'),
                        output.replace(receipt + '\n', receipt + '-other\n'),
                        output.replace(receipt + '\n', receipt + ' \n'),
                        output.replace(passed + ' (', passed + '-other (')):
            with self.subTest(output=changed), self.assertRaises(ValueError):
                G.check_verdict(changed, case)

    def test_same_architecture_and_case_remain_required(self):
        for case in G.CASES:
            output = self.completed((case,))
            G.check_verdict(output, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                G.check_verdict(output)
        with self.assertRaises(ValueError):
            G.check_verdict(self.completed(), 'unrelated')

    def test_failed_skipped_or_child_only_output_cannot_replace_installed_host(self):
        for output in ('', '--- PASS: TestDesktopLinuxGuardianKernelNodeChildCommandTUN (1s)',
                       '--- PASS: TestDesktopLinuxGuardianKernelNodeRouterHealthPeer (1s)',
                       self.completed() + '--- FAIL: original-controller (1s)', self.completed() + '--- SKIP: unavailable-TUN (1s)'):
            with self.subTest(output=output[-100:]), self.assertRaises(ValueError):
                G.check_verdict(output)

    def test_failed_original_child_retains_status_and_bounded_native_output(self):
        for noisy in (False, True):
            with self.subTest(noisy=noisy):
                command = [sys.executable, '-c',
                           'import os; ' + ("os.write(1, b'old-prefix\\n' + b'x' * 60000 + b'\\xff'); "
                           "os.write(2, b'original installed host failure\\n'); " if noisy else '') + 'raise SystemExit(37)']
                failures = []
                def failed(source, bundle, go, *, receipt_path):
                    self.assertEqual((source, bundle, go, receipt_path),
                                     (Path('/captured-core'), Path('/captured-bundle'), '/captured-go', Path('/captured-receipt')))
                    try:
                        G.GUARD.UID.run(command, timeout=5)
                    except subprocess.CalledProcessError as error:
                        failures.append(error)
                        raise
                diagnostic = io.StringIO()
                with patch.object(G, 'execute', side_effect=failed), redirect_stderr(diagnostic):
                    with self.assertRaises(subprocess.CalledProcessError) as caught:
                        G.main(['/captured-core', '--bundle', '/captured-bundle', '--go', '/captured-go', '--receipt', '/captured-receipt'])
                self.assertEqual(len(failures), 1)
                self.assertIs(caught.exception, failures[0])
                self.assertEqual(caught.exception.returncode, 37)
                self.assertEqual(caught.exception.cmd, command)
                original = caught.exception.output
                self.assertEqual(diagnostic.getvalue(), original[-32768:].decode('utf-8', errors='replace'))
                if noisy:
                    self.assertNotIn('old-prefix', diagnostic.getvalue())
                    self.assertIn('\uFFFDoriginal installed host failure', diagnostic.getvalue())
                    self.assertLessEqual(len(diagnostic.getvalue()), 32768)
                else:
                    self.assertEqual(diagnostic.getvalue(), '')

    def test_cli_preserves_success_namespace_and_other_failure_types(self):
        arguments = ['/captured-core', '--bundle', '/captured-bundle', '--go', '/captured-go']
        diagnostic = io.StringIO()
        with patch.object(G, 'execute') as execute, redirect_stderr(diagnostic):
            G.main(arguments)
        execute.assert_called_once_with(Path('/captured-core'), Path('/captured-bundle'), '/captured-go', receipt_path=None)
        self.assertEqual(diagnostic.getvalue(), '')
        with patch.object(G, 'namespace_test', return_value=23) as enter, patch.object(G, 'execute') as execute:
            with self.assertRaises(SystemExit) as caught:
                G.main(['--bundle', '/captured-bundle', '--namespace-test-binary', '/captured-controller',
                        '--peer-binary', '/captured-peer', '--namespace-test-sha256', 'a' * 64,
                        '--peer-sha256', 'b' * 64, '--bundle-sha256', 'c' * 64, '--case', 'home-lan'])
        self.assertEqual(caught.exception.code, 23)
        enter.assert_called_once_with(Path('/captured-controller'), Path('/captured-peer'), Path('/captured-bundle'),
                                      'a' * 64, 'b' * 64, 'c' * 64, 'home-lan', whitening=None, whitening_sha256=None)
        execute.assert_not_called()
        for error in (subprocess.TimeoutExpired(['original-child'], 5), ValueError('original native validation')):
            diagnostic = io.StringIO()
            with self.subTest(error=type(error).__name__), patch.object(G, 'execute', side_effect=error), redirect_stderr(diagnostic):
                with self.assertRaises(type(error)) as caught:
                    G.main(arguments)
            self.assertIs(caught.exception, error)
            self.assertEqual(diagnostic.getvalue(), '')

    def images(self, root):
        images = []
        for name in ('controller', 'peer'):
            path = root / name
            path.write_bytes(name.encode())
            path.chmod(0o755)
            images.append((path, hashlib.sha256(path.read_bytes()).hexdigest()))
        bundle = root / 'bundle'
        bundle.mkdir()
        receipt = bundle / 'NATIVE-RUNTIME.json'
        receipt.write_bytes(b'{"original":"receipt boundary; complete verifier remains native"}')
        receipt.chmod(0o644)
        return (*images, bundle, hashlib.sha256(receipt.read_bytes()).hexdigest())

    def test_foreign_compiled_image_or_bundle_never_enters_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            (binary, image_sha), (peer, peer_sha), bundle, bundle_sha = self.images(Path(temporary).resolve())
            cases = ((image_sha, peer_sha, '0' * 64, 'on-connect'),
                     (image_sha, '0' * 64, bundle_sha, 'on-connect'),
                     ('0' * 64, peer_sha, bundle_sha, 'on-connect'),
                     (image_sha, peer_sha, bundle_sha, 'unknown'))
            for first, second, third, case in cases:
                with self.subTest(case=(first, second, third, case)), patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                    G.namespace_test(binary, peer, bundle, first, second, third, case)
                native.assert_not_called()
            receipt = bundle / 'NATIVE-RUNTIME.json'
            receipt.rename(bundle / 'original.json')
            receipt.symlink_to(bundle / 'original.json')
            with patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'on-connect')
            native.assert_not_called()

    def test_original_namespace_and_complete_inputs_are_restored_on_refusal(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ):
            (binary, image_sha), (peer, peer_sha), bundle, bundle_sha = self.images(Path(temporary).resolve())
            previous = {name: 'previous-' + str(index) for index, name in enumerate(G.NAMESPACE_ENVIRONMENT)}
            os.environ.update(previous)
            current = os.stat('/proc/self/ns/net')
            def native(actual, selector, digest):
                self.assertEqual(actual, binary)
                self.assertEqual(selector, 'NodeHostTUN/home-lan')
                self.assertEqual(digest, image_sha)
                self.assertEqual(os.environ['ROUTERVPN_NODE_OUTER_NETNS_ID'], str(current.st_dev) + ':' + str(current.st_ino))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_BUNDLE'], str(bundle))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_BUNDLE_SHA256'], bundle_sha)
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_PEER_BINARY'], str(peer))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_PEER_SHA256'], peer_sha)
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_WHITENING_BINARY'], '')
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_WHITENING_SHA256'], '')
                raise RuntimeError('actual namespace refusal')
            with patch.object(G.GUARD, 'namespace_test', side_effect=native), self.assertRaisesRegex(RuntimeError, 'actual namespace refusal'):
                G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'home-lan')
            self.assertEqual({name: os.environ[name] for name in previous}, previous)

    def test_whitening_requires_exact_shipping_image_before_namespace_entry(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ):
            root = Path(temporary).resolve()
            (binary, image_sha), (peer, peer_sha), bundle, bundle_sha = self.images(root)
            relay = root / 'start-layer-relay'
            relay.write_bytes(b'exact shipping relay image boundary')
            relay.chmod(0o755)
            digest = hashlib.sha256(relay.read_bytes()).hexdigest()
            previous = {name: 'previous-' + str(index) for index, name in enumerate(G.NAMESPACE_ENVIRONMENT)}
            os.environ.update(previous)
            for selected, expected in ((None, None), (relay, None), (relay, '0' * 64)):
                with self.subTest(selected=selected, expected=expected), patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                    G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'layer-whitening-connect',
                                     whitening=selected, whitening_sha256=expected)
                native.assert_not_called()
            def native(actual, selector, identity):
                self.assertEqual((actual, selector, identity), (binary, 'NodeHostTUN/layer-whitening-connect', image_sha))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_WHITENING_BINARY'], str(relay))
                self.assertEqual(os.environ['ROUTERVPN_NODE_HOST_WHITENING_SHA256'], digest)
                raise RuntimeError('original whitening namespace refusal')
            with patch.object(G.GUARD, 'namespace_test', side_effect=native), self.assertRaisesRegex(RuntimeError, 'original whitening namespace refusal'):
                G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'layer-whitening-connect',
                                 whitening=relay, whitening_sha256=digest)
            self.assertEqual({name: os.environ[name] for name in previous}, previous)
            original = root / 'original-relay'
            relay.rename(original)
            relay.symlink_to(original)
            with patch.object(G.GUARD, 'namespace_test') as native, self.assertRaises(ValueError):
                G.namespace_test(binary, peer, bundle, image_sha, peer_sha, bundle_sha, 'layer-whitening-connect',
                                 whitening=relay, whitening_sha256=digest)
            native.assert_not_called()

    def test_bundle_capture_calls_the_ordinary_complete_verifier_first(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary).resolve()
            receipt = {'files': {'engine': {}}}
            for name in ('engine', 'NATIVE-RUNTIME.json'):
                (bundle / name).write_bytes(name.encode())
                (bundle / name).chmod(0o644)
            calls = []
            def reuse(path, target, env=None):
                calls.append((path, target, env))
                return receipt
            with patch.object(G.BUILD, 'reuse', side_effect=reuse):
                actual, records = G.bundle_identity(bundle, 'linux/amd64', {'captured': 'env'})
            self.assertEqual(actual, receipt)
            self.assertEqual(calls, [(bundle, 'linux/amd64', {'captured': 'env'})])
            self.assertEqual(set(records), {'engine', 'NATIVE-RUNTIME.json'})
            with patch.object(G.BUILD, 'reuse', side_effect=ValueError('changed complete native bundle')), self.assertRaisesRegex(ValueError, 'changed complete native bundle'):
                G.bundle_identity(bundle, 'linux/amd64')
            (bundle / 'engine').chmod(0o666)
            with patch.object(G.BUILD, 'reuse', return_value=receipt), self.assertRaises(ValueError):
                G.bundle_identity(bundle, 'linux/amd64')

    def test_bundle_builder_requires_verified_stage_before_any_host_execution(self):
        for target in ('linux/amd64', 'linux/arm64'):
            with self.subTest(target=target):
                source, bundle, env = Path('/captured/core'), Path('/captured/complete-stage'), {'GOOS': 'linux', 'GOARCH': target.split('/')[1]}
                calls = []
                def reuse(directory, selected, env=None):
                    calls.append(('reuse', directory, selected, env))
                def stock_dns(directory, selected, captured_env):
                    calls.append(('stock-dns', directory, selected, captured_env))
                def run(arguments, **kwargs):
                    calls.append(('run', [str(value) for value in arguments], kwargs))
                # This fixture checks builder ordering. The actual stock-DNS
                # gate has its own exact built-image/host and verdict tests.
                with patch.object(G.BUILD, 'reuse', side_effect=reuse), patch.object(G.BUILD, 'verify_linux_stock_dns', side_effect=stock_dns), patch.object(G.BUILD, 'run', side_effect=run):
                    G.BUILD.verify_installed_linux_host(source, bundle, target, env)
                self.assertEqual(len(calls), 4)
                self.assertEqual(calls[0], ('reuse', bundle, target, env))
                self.assertEqual(calls[1], ('stock-dns', bundle, target, env))
                self.assertEqual(calls[2][1][1:], [str(ROOT / 'deploy/test_linux_node_host_tun_runner.py')])
                self.assertEqual(calls[3][1][1:], [str(ROOT / 'deploy/test_linux_node_host_tun.py'), str(source), '--bundle', str(bundle)])
                self.assertEqual(calls[2][2]['env'], env)
                self.assertEqual(calls[3][2]['env'], env)
                with patch.object(G.BUILD, 'reuse', side_effect=ValueError('unverified stage')), patch.object(G.BUILD, 'verify_linux_stock_dns') as dns, patch.object(G.BUILD, 'run') as run, self.assertRaisesRegex(ValueError, 'unverified stage'):
                    G.BUILD.verify_installed_linux_host(source, bundle, target, env)
                dns.assert_not_called()
                run.assert_not_called()
                with patch.object(G.BUILD, 'reuse') as reuse, patch.object(G.BUILD, 'verify_linux_stock_dns', side_effect=ValueError('unproved stock DNS')) as dns, patch.object(G.BUILD, 'run') as run, self.assertRaisesRegex(ValueError, 'unproved stock DNS'):
                    G.BUILD.verify_installed_linux_host(source, bundle, target, env)
                reuse.assert_called_once_with(bundle, target, env=env)
                dns.assert_called_once_with(bundle, target, env)
                run.assert_not_called()
        for target, env in (('windows/amd64', {'GOOS': 'windows', 'GOARCH': 'amd64'}), ('linux/amd64', {'GOOS': 'linux', 'GOARCH': 'arm64'})):
            with patch.object(G.BUILD, 'reuse') as reuse, patch.object(G.BUILD, 'verify_linux_stock_dns') as dns, patch.object(G.BUILD, 'run') as run, self.assertRaises(ValueError):
                G.BUILD.verify_installed_linux_host(Path('/core'), Path('/bundle'), target, env)
            reuse.assert_not_called()
            dns.assert_not_called()
            run.assert_not_called()

    def test_missing_binding_requires_the_actual_targeted_native_failure(self):
        output = ('installed Router proof used the direct LAN response or bypassed its exact encrypted graph\n'
                  '--- FAIL: TestDesktopLinuxGuardianKernelNodeHostTUN/home-lan (1.0s)\n')
        G.check_missing_binding_control(1, output)
        for code, text in ((0, output), (1, 'compile failed'), (1, output.replace('home-lan', 'wrong-node')),
                           (1, output + '--- SKIP: missing TUN (1s)'), (1, output.split('\n', 1)[1])):
            with self.subTest(code=code, output=text), self.assertRaises(ValueError):
                G.check_missing_binding_control(code, text)
        original = 'before\nreturn bindDesktopLinuxNodeProofSocket(ctx, actualNetwork, raw, live)\nafter\n'
        changed = G.missing_binding_source(original)
        self.assertIn('before\nreturn nil', changed)
        self.assertTrue(changed.endswith('\nafter\n'))
        for source in ('other source', original + original):
            with self.assertRaises(ValueError):
                G.missing_binding_source(source)




class SS2022EntryVerdicts(unittest.TestCase):
    def test_inventory_and_original_compiled_authority(self):
        self.assertEqual(len(G.EXTERNAL_SS_ENTRY_CASES), 23)
        self.assertEqual(len(set(G.EXTERNAL_SS_ENTRY_CASES)), 23)
        names = G.SS_ENTRY_AUTHORITY_CASES
        self.assertEqual(len(names), 19)
        good = ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)
        G.check_ss_entry_authority_verdict(good)
        for line in good.splitlines(True):
            for changed in (good.replace(line, '', 1), good+line, good.replace(line, line.replace('SSEntry','ForeignEntry'),1)):
                with self.assertRaises(ValueError): G.check_ss_entry_authority_verdict(changed)
        for marker in ('--- SKIP:', '--- FAIL:', 'DATA RACE', 'panic:'):
            with self.assertRaises(ValueError): G.check_ss_entry_authority_verdict(good+marker+' foreign\n')

    def test_each_original_installed_receipt_and_verdict_is_unique(self):
        prefix='TestDesktopLinuxGuardianKernelNodeHostTUN'
        for case in G.EXTERNAL_SS_ENTRY_CASES:
            good='--- PASS: '+prefix+' (0.01s)\n--- PASS: '+prefix+'/'+case+' (0.01s)\n'
            good+='    native_test.go:1: verified installed host native lifecycle: '+case+'\n'
            good+='    native_test.go:2: verified installed host retained external succession: '+case+'\n'
            line='    native_test.go:3: verified installed host independent SS2022 entry and SS2022 final: '+case+'\n'
            good+=line
            G.check_verdict(good,case)
            verdict='--- PASS: '+prefix+'/'+case+' (0.01s)\n'
            for required in (line,verdict):
                for changed in (good.replace(required,'',1),good+required,good.replace(required,required.replace(case,case+'-foreign'),1)):
                    with self.subTest(case=case),self.assertRaises(ValueError): G.check_verdict(changed,case)

class SSCONNECTVerdicts(unittest.TestCase):
    def test_inventory_and_original_compiled_authority(self):
        self.assertEqual(len(G.EXTERNAL_SS_CONNECT_CASES), 23)
        self.assertEqual(len(set(G.EXTERNAL_SS_CONNECT_CASES)), 23)
        self.assertEqual(G.CASES[484:507], G.EXTERNAL_SS_CONNECT_CASES)
        self.assertEqual(len(G.CASES), 524 + len(G.RESOLVED_CASES) + len(G.EXTERNAL_SS_LAYER_CASES) + len(G.EXTERNAL_SS_HYSTERIA_LAYER_CASES))
        self.assertEqual(len(G.REVERSE_CASES), 9)
        names = G.SS_CONNECT_AUTHORITY_CASES
        self.assertEqual(len(names), 7)
        good = ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)
        G.check_ss_connect_authority_verdict(good)
        for line in good.splitlines(True):
            for changed in (good.replace(line, '', 1), good+line, good.replace(line, line.replace('SSCONNECT','ForeignCONNECT'),1)):
                with self.assertRaises(ValueError): G.check_ss_connect_authority_verdict(changed)
        for marker in ('--- SKIP:', '--- FAIL:', 'DATA RACE', 'panic:'):
            with self.assertRaises(ValueError): G.check_ss_connect_authority_verdict(good+marker+' foreign\n')

    def test_each_original_installed_receipt_and_verdict_is_unique(self):
        prefix='TestDesktopLinuxGuardianKernelNodeHostTUN'
        for case in G.EXTERNAL_SS_CONNECT_CASES:
            good='--- PASS: '+prefix+' (0.01s)\n--- PASS: '+prefix+'/'+case+' (0.01s)\n'
            good+='    native_test.go:1: verified installed host native lifecycle: '+case+'\n'
            good+='    native_test.go:2: verified installed host retained external succession: '+case+'\n'
            line='    native_test.go:3: verified installed host independent SS2022 entry and CONNECT final: '+case+'\n'
            good+=line
            G.check_verdict(good,case)
            verdict='--- PASS: '+prefix+'/'+case+' (0.01s)\n'
            for required in (line,verdict):
                for changed in (good.replace(required,'',1),good+required,good.replace(required,required.replace(case,case+'-foreign'),1)):
                    with self.subTest(case=case),self.assertRaises(ValueError): G.check_verdict(changed,case)

class SSHysteriaVerdicts(unittest.TestCase):
    def test_inventory_and_original_compiled_authority(self):
        self.assertEqual(len(G.EXTERNAL_SS_HYSTERIA_CASES), 17)
        self.assertEqual(len(set(G.EXTERNAL_SS_HYSTERIA_CASES)), 17)
        self.assertEqual(G.CASES[507:524], G.EXTERNAL_SS_HYSTERIA_CASES)
        self.assertEqual(len(G.CASES), 524 + len(G.RESOLVED_CASES) + len(G.EXTERNAL_SS_LAYER_CASES) + len(G.EXTERNAL_SS_HYSTERIA_LAYER_CASES))
        self.assertEqual(len(G.REVERSE_CASES), 9)
        names = G.SS_HYSTERIA_AUTHORITY_CASES
        self.assertEqual(len(names), 13)
        good = ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)
        G.check_ss_hysteria_authority_verdict(good)
        for line in good.splitlines(True):
            for changed in (good.replace(line, '', 1), good+line, good.replace(line, line.replace('SSHysteria','ForeignCONNECT'),1)):
                with self.assertRaises(ValueError): G.check_ss_hysteria_authority_verdict(changed)
        for marker in ('--- SKIP:', '--- FAIL:', 'DATA RACE', 'panic:'):
            with self.assertRaises(ValueError): G.check_ss_hysteria_authority_verdict(good+marker+' foreign\n')

    def test_each_original_installed_receipt_and_verdict_is_unique(self):
        prefix='TestDesktopLinuxGuardianKernelNodeHostTUN'
        for case in G.EXTERNAL_SS_HYSTERIA_CASES + G.EXTERNAL_SS_HYSTERIA_LAYER_CASES:
            good='--- PASS: '+prefix+' (0.01s)\n--- PASS: '+prefix+'/'+case+' (0.01s)\n'
            good+='    native_test.go:1: verified installed host native lifecycle: '+case+'\n'
            good+='    native_test.go:2: verified installed host retained external succession: '+case+'\n'
            line='    native_test.go:3: verified installed host independent SS2022 entry and Hysteria2 final: '+case+'\n'
            good+=line
            G.check_verdict(good,case)
            verdict='--- PASS: '+prefix+'/'+case+' (0.01s)\n'
            for required in (line,verdict):
                for changed in (good.replace(required,'',1),good+required,good.replace(required,required.replace(case,case+'-foreign'),1)):
                    with self.subTest(case=case),self.assertRaises(ValueError): G.check_verdict(changed,case)

if __name__ == '__main__':
    unittest.main()
