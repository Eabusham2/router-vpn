#!/usr/bin/env python3
"""Check the exact server Tor source closure and no embedded/mobile lifecycle."""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('server_tor_preparation',ROOT/'deploy/prepare-server-tor.py')
PREP=importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)


class ServerTorPreparation(unittest.TestCase):
    def test_all_copied_pure_and_pt_sources_enter_digest(self):
        inputs=set(PREP.inputs())
        for package in ('common','mobiletor','awgpolicy','nativeopenvpn','linuxprocess'):
            for path in (ROOT/'internal'/package).glob('*.go'):
                if not path.name.endswith('_test.go'):
                    self.assertIn(path,inputs)
        for path in (ROOT/'mobile/torpt').rglob('*'):
            if path.is_file():self.assertIn(path,inputs)
        for path in (ROOT/'mobile/server_tor').glob('*.tmpl'):self.assertIn(path,inputs)

    def test_preparation_installs_actual_command_and_no_embedded_tor(self):
        content=PREP.copies()
        self.assertIn('cmd/sing-box/routervpn_server_tor_command.go',content)
        self.assertIn('cmd/sing-box/routervpn_server_tor_native.go',content)
        self.assertIn('cmd/sing-box/routervpn_server_tor_padding.go',content)
        self.assertIn('cmd/sing-box/routervpn_server_tor_data.go',content)
        self.assertIn('cmd/sing-box/routervpn_server_tor_data_test.go',content)
        self.assertIn('cmd/sing-box/routervpn_server_tor_lastrelay.go',content)
        self.assertIn('cmd/sing-box/routervpn_server_tor_lastrelay_test.go',content)
        self.assertIn('routervpn/mobiletor/desktop_server_lastrelay.go',content)
        self.assertIn('routervpn/mobiletor/server_lastrelay_client.go',content)
        self.assertIn('routervpn/mobiletor/desktop_server_padding.go',content)
        self.assertIn('routervpn/mobiletor/padding_lease.go',content)
        self.assertIn('routervpn/servertor/network_owner.go',content)
        self.assertIn('routervpn_server_tor_box.go',content)
        self.assertIn('routervpn-server-tor-pt-notices.json',content)
        self.assertFalse(any(name.startswith(('protocol/routervpntor/','routervpn/torpack/','routervpn/desktoppt/')) for name in content))
        for name,raw in content.items():
            if name.endswith('.go'):
                self.assertNotIn(b'"router-vpn/internal/',raw,name)
                self.assertNotIn(b'"router-vpn/mobile/',raw,name)
        self.assertIn('SERVER_TOR.prepare(vendor)',(ROOT/'deploy/prepare-relay-core.py').read_text())

    def test_server_mutex_dependency_is_exact_and_closed(self):
        content=PREP.copies()
        source=ROOT/'internal/desktopnetwork/desktop_network_lock.go'
        self.assertIn(source,set(PREP.inputs()))
        supplied={name:raw for name,raw in content.items() if name.startswith('routervpn/desktopnetwork/')}
        self.assertEqual(supplied,{'routervpn/desktopnetwork/desktop_network_lock.go':source.read_bytes()})
        expected_import=b'"github.com/sagernet/sing-box/routervpn/desktopnetwork"'
        users={name:raw for name,raw in content.items() if b'desktopnetwork' in raw and name not in supplied}
        self.assertEqual(set(users),{'routervpn/mobiletor/padding_lease.go','routervpn/mobiletor/server_client.go'})
        for name,raw in users.items():
            self.assertIn(expected_import,raw,name)
            self.assertEqual(set(re.findall(rb'desktopnetwork\.(\w+)',raw)),{b'LockContext'},name)
        # This projection is the complete package, and these symbols must be
        # supplied by its exact shipped bytes rather than another dependency.
        exports=set(re.findall(rb'func (\w+)\(',source.read_bytes()))
        self.assertIn(b'LockContext',exports)

    def test_server_mutex_dependency_rejects_missing_foreign_and_substituted_projection(self):
        original=PREP.copies
        for change in ('missing','source-bytes','extra-native-file','foreign-import','missing-symbol'):
            with self.subTest(change=change):
                def substituted():
                    content=original()
                    key='routervpn/desktopnetwork/desktop_network_lock.go'
                    if change=='missing':del content[key]
                    elif change=='source-bytes':content[key]+=b'\n// substituted lock\n'
                    elif change=='extra-native-file':content['routervpn/desktopnetwork/native_tun.go']=b'package desktopnetwork\n'
                    elif change=='foreign-import':
                        key='routervpn/mobiletor/padding_lease.go'
                        content[key]=content[key].replace(b'"github.com/sagernet/sing-box/routervpn/desktopnetwork"',b'"github.com/sagernet/sing-box/routervpn/foreignnetwork"')
                    else:
                        key='routervpn/mobiletor/server_client.go'
                        content[key]=content[key].replace(b'desktopnetwork.LockContext',b'desktopnetwork.UnapprovedContext')
                    return content
                with mock.patch.object(PREP,'copies',side_effect=substituted):
                    with self.assertRaises(AssertionError):self.test_server_mutex_dependency_is_exact_and_closed()

    def test_linux_process_owners_are_copied_without_substitution(self):
        content=PREP.copies()
        originals={path.name:path.read_bytes() for path in (ROOT/'internal/linuxprocess').glob('*.go')
                   if not path.name.endswith('_test.go')}
        self.assertTrue({'abi_linux.go','bootstrap_linux.go','channel_linux.go','pidfd_linux.go',
                         'process_linux.go','record.go'}.issubset(originals))
        copied={name.removeprefix('routervpn/linuxprocess/'):raw for name,raw in content.items()
                if name.startswith('routervpn/linuxprocess/')}
        # The shared observation classifier is a declared package dependency.
        # Independently spell its one import relocation; all other source bytes
        # and the complete member set must remain identical. Do not use the
        # shipping rewriter as the expected-value oracle.
        expected={name:raw.replace(b'"router-vpn/internal/common"',
                    b'"github.com/sagernet/sing-box/routervpn/common"')
                  for name,raw in originals.items()}
        self.assertEqual(copied,expected)
        self.assertEqual(content['routervpn/common/observation_context.go'],
                         (ROOT/'internal/common/observation_context.go').read_bytes())
        for name in ('desktop_socket_linux_guardian_process.go','desktop_socket_linux_guardian_record.go'):
            expected=(ROOT/'internal/mobiletor'/name).read_bytes().replace(b'"router-vpn/internal/linuxprocess"',
                b'"github.com/sagernet/sing-box/routervpn/linuxprocess"')
            self.assertEqual(content['routervpn/mobiletor/'+name],expected)

    def test_linux_process_projection_rejects_substituted_source_or_import(self):
        original=PREP.TOR.rewrite
        for change in ('source-bytes','foreign-common-import'):
            with self.subTest(change=change):
                def substituted(raw):
                    projected=original(raw)
                    if b'package linuxprocess\n' not in raw:
                        return projected
                    if change=='source-bytes':
                        return projected+b'\n// substituted process owner\n'
                    return projected.replace(b'"github.com/sagernet/sing-box/routervpn/common"',
                                             b'"github.com/sagernet/sing-box/routervpn/foreign-common"')
                with mock.patch.object(PREP.TOR,'rewrite',side_effect=substituted):
                    with self.assertRaises(AssertionError):
                        self.test_linux_process_owners_are_copied_without_substitution()

    def test_unrelocated_dependency_refuses_the_complete_copy(self):
        original=PREP.TOR.rewrite
        def foreign(raw):
            return original(raw).replace(b'"router-vpn/internal/linuxprocess"',b'"router-vpn/internal/uncaptured-process"')
        with mock.patch.object(PREP.TOR,'rewrite',side_effect=foreign):
            with self.assertRaisesRegex(ValueError,'shared import closure is incomplete'):
                PREP.copies()

    def prepare_fixture(self, vendor):
        # Only dependency Git/module/DNS preparation is a boundary fixture.
        # Generated application bytes and ownership checks execute unchanged;
        # actual pinned Linux compilation is a separate native build gate.
        with mock.patch.object(PREP.subprocess,'check_output',return_value=PREP.CORE+'\n'), \
             mock.patch.object(PREP.TOR,'prepare_modules'), \
             mock.patch.object(PREP.TOR,'bootstrap_dns_source',return_value=b'package dns\n'):
            PREP.prepare(vendor)

    def test_process_receipt_is_exact_idempotent_and_removes_only_proved_old_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            vendor=Path(temporary);(vendor/'dns').mkdir()
            self.prepare_fixture(vendor)
            owner=vendor/PREP.OWNER
            first=owner.read_bytes()
            record=json.loads(first)
            expected=PREP.copies()
            for name,raw in expected.items():
                if name.startswith('routervpn/linuxprocess/') or name=='routervpn/desktopnetwork/desktop_network_lock.go':
                    self.assertEqual((vendor/name).read_bytes(),raw)
                    self.assertEqual(record['files'][name],hashlib.sha256(raw).hexdigest())
            self.prepare_fixture(vendor)
            self.assertEqual(owner.read_bytes(),first)
            old='routervpn/linuxprocess/obsolete_owned.go'
            (vendor/old).write_bytes(b'package linuxprocess\n')
            record['files'][old]=hashlib.sha256((vendor/old).read_bytes()).hexdigest()
            owner.write_text(json.dumps(record))
            self.prepare_fixture(vendor)
            self.assertFalse((vendor/old).exists())
            self.assertEqual(owner.read_bytes(),first)

    def test_changed_missing_or_unowned_process_member_is_never_repaired(self):
        for change in ('changed','missing','unowned'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                vendor=Path(temporary);(vendor/'dns').mkdir()
                target=vendor/'routervpn/linuxprocess/record.go'
                if change!='unowned':
                    self.prepare_fixture(vendor)
                    receipt=(vendor/PREP.OWNER).read_bytes()
                else:
                    target.parent.mkdir(parents=True)
                    receipt=None
                if change=='missing':
                    target.unlink()
                else:
                    target.write_bytes(b'package linuxprocess\n// different original\n')
                with self.assertRaisesRegex(ValueError,'Changed server Tor generated source|Unowned server Tor generated source'):
                    self.prepare_fixture(vendor)
                if change=='missing':
                    self.assertFalse(target.exists())
                else:
                    self.assertEqual(target.read_bytes(),b'package linuxprocess\n// different original\n')
                if receipt is None:
                    self.assertFalse((vendor/PREP.OWNER).exists())
                else:
                    self.assertEqual((vendor/PREP.OWNER).read_bytes(),receipt)

    def test_changed_missing_or_unowned_mutex_member_is_never_repaired(self):
        for change in ('changed','missing','unowned'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                vendor=Path(temporary);(vendor/'dns').mkdir()
                target=vendor/'routervpn/desktopnetwork/desktop_network_lock.go'
                if change!='unowned':
                    self.prepare_fixture(vendor)
                    receipt=(vendor/PREP.OWNER).read_bytes()
                else:
                    target.parent.mkdir(parents=True)
                    receipt=None
                if change=='missing':target.unlink()
                else:target.write_bytes(b'package desktopnetwork\n// foreign original\n')
                with self.assertRaisesRegex(ValueError,'Changed server Tor generated source|Unowned server Tor generated source'):
                    self.prepare_fixture(vendor)
                if change=='missing':self.assertFalse(target.exists())
                else:self.assertEqual(target.read_bytes(),b'package desktopnetwork\n// foreign original\n')
                if receipt is None:self.assertFalse((vendor/PREP.OWNER).exists())
                else:self.assertEqual((vendor/PREP.OWNER).read_bytes(),receipt)

    def test_no_tun_worker_retains_exact_control_front_and_proof(self):
        native=(ROOT/'mobile/server_tor/native.go.tmpl').read_text()
        for gate in ('len(options.Inbounds) != 0','policy.NativeConfig(','.Configure(initialize,',
                     'RouterVPNServerTorDNSProof(ctx)','mobiletor.Prove(ctx,',
                     'mobiletor.StartServerTorFront(','.Bootstrap(ctx)',
                     'n.proofGeneration++','n.expire(generation)',
                     'n.startPadding(initial)','n.data.Begin()','n.data.Close(ctx)','padding.Join(ctx)',
                     'newRouterVPNServerTorData(owned, n.trafficCurrent, n.trafficUntil, n.finalDial, n.cancel)',
                     'n.child.Close(ctx)','n.network.Close(ctx)','n.proofNetwork.Close(ctx)'):
            self.assertIn(gate,native)
        cover=(ROOT/'mobile/server_tor/padding.go.tmpl').read_text()
        for gate in ('n.child.Session().PaddingLease(', 'n.paddingProofUntil',
                     'lease.Start(ctx)', 'lease.NativeReceipt()', 'receipt.ChannelCells',
                     'receipt.SessionSHA256 != n.capture.OwnerID',
                     'string(raw) == n.policy.Source()'):
            self.assertIn(gate,cover)

    def test_comparison_uses_exact_native_front_and_no_dns_token_fallback(self):
        native=(ROOT/'mobile/server_tor/native.go.tmpl').read_text()
        comparison=(ROOT/'mobile/server_tor/lastrelay.go.tmpl').read_text()
        for gate in ('n.prepareComparison()', 'n.comparisonData.Begin()', 'n.comparisonData.Close(ctx)',
                     'n.comparison.Close(ctx)', 'n.dnsProofAt = dnsAt', 'n.proofGate <- struct{}{}'):
            self.assertIn(gate,native)
        self.assertLess(native.index('n.child.Close(ctx)'),native.index('n.comparison.Close(ctx)'))
        for gate in ('mobiletor.NewServerTorLastRelay(', 'n.front.SetComparison(', 'NativeJoined: n.child.Joined',
                     'n.comparisonData.DialContext', 'n.final.DialContext(', 'string(raw) == n.policy.Source()'):
            self.assertIn(gate,comparison)
        self.assertNotIn('n.dns.Lookup(',comparison)


if __name__=='__main__':unittest.main()
