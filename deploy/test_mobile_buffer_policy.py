#!/usr/bin/env python3
"""Verify exact buffer edits and native socket-protection composition."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('buffer_policy',ROOT/'deploy/prepare-mobile-buffers.py')
MODULE=importlib.util.module_from_spec(spec);spec.loader.exec_module(MODULE)
PINNED_FILES=dict(MODULE.PACKET.BUFFER_FILES)
class Tests(unittest.TestCase):
    def test_production_dependency_pins_are_exact(self):
        self.assertEqual(PINNED_FILES,{
            'common/buf/buffer_standard.go':('608fbf3f13067a7568c491990dba764b81107e87','16 * 1024'),
            'common/buf/buffer_low_memory.go':('81fb10a26460dea3586486118d091a43020284eb','8 * 1024'),
        })
        self.assertEqual(MODULE.PACKET.SUM,'h1:nIdH+Yvy4NzTezB+c3z/9of1jLRggnrtMtb3uMOIaNM=')

    def test_only_udp_capacity_changes_and_both_reverse_boundaries_are_strict(self):
        # Full archive, immutable cache, license, actual Go module selection and
        # default/low-memory compilation are covered by test_sing_packet_preparation.
        # This small fixture isolates the byte-level TCP/UDP edit boundary.
        for name,(_,udp) in PINNED_FILES.items():
            low='low_memory' in name
            raw=('//go:build '+('with_low_memory' if low else '!with_low_memory')+'\n\npackage buf\n\nconst (\n\tBufferSize    = '+('16' if low else '32')+' * 1024\n\tUDPBufferSize = '+udp+'\n)\n').encode()
            edits=MODULE.PACKET.PATCHES[name][1]
            with mock.patch.dict(MODULE.PACKET.PATCHES,{name:(MODULE.PACKET.git_blob(raw),edits)}):
                changed=MODULE.PACKET.transform(name,raw)
                self.assertEqual(changed,raw.replace(('UDPBufferSize = '+udp).encode(),b'UDPBufferSize = 65535'))
                self.assertEqual(MODULE.PACKET.transform(name,changed,reverse=True),raw)
                for original,reverse in ((raw,False),(changed,True)):
                    with self.assertRaises(ValueError):MODULE.PACKET.transform(name,original+b'// drift\n',reverse=reverse)

class SocketPolicyTests(unittest.TestCase):
    def test_protection_hooks_are_preserved_and_preparation_is_idempotent(self):
        for path, edits in MODULE.SOCKETS.PATCHES.items():
            original = "// native platform protection remains first\n" + "\n".join(old for old,new in edits)
            fixed = MODULE.SOCKETS.patch_text(path, original)
            self.assertEqual(MODULE.SOCKETS.patch_text(path,fixed),fixed)
            self.assertTrue(fixed.startswith("// native platform protection remains first"))
            for old,new in edits:
                self.assertIn(new,fixed)
                self.assertIn(old,fixed)
            if 'dialer' in path:
                self.assertIn('control.Append(dialer.Control, startwhitening.UDPControl)',fixed)
                self.assertIn('control.Append(listener.Control, startwhitening.UDPControl)',fixed)

    def test_partial_duplicate_or_changed_socket_guards_are_rejected(self):
        for path, edits in MODULE.SOCKETS.PATCHES.items():
            original = "\n".join(old for old,new in edits)
            fixed = MODULE.SOCKETS.patch_text(path,original)
            for invalid in (fixed + "\n" + MODULE.SOCKETS.IMPORT,
                            fixed.replace('control.Append','unreviewedReplacement',1),
                            original.replace(edits[0][0],edits[0][1],1)):
                with self.subTest(path=path),self.assertRaises(ValueError):
                    MODULE.SOCKETS.patch_text(path,invalid)

    def test_socket_patch_preflights_all_files_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner=root/'experimental/libbox/routervpn/startwhitening/udp_buffers.go'
            owner.parent.mkdir(parents=True);owner.write_text('package startwhitening')
            sources={}
            for path,edits in MODULE.SOCKETS.PATCHES.items():
                text="\n".join(old for old,new in edits)
                source=root/path;source.parent.mkdir(parents=True,exist_ok=True);source.write_text(text);sources[path]=text
            broken=root/'common/listener/listener_udp.go'
            broken.write_text('changed upstream source')
            with self.assertRaises(ValueError):MODULE.SOCKETS.prepare(root)
            self.assertEqual((root/'common/dialer/default.go').read_text(),sources['common/dialer/default.go'])

class WireGuardPublicationPolicyTests(unittest.TestCase):
    def test_exact_pin_idempotency_and_drift_rejection(self):
        spec=importlib.util.spec_from_file_location('wg_bind_policy',ROOT/'deploy/mobile_wireguard_bind_policy.py')
        policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
        self.assertEqual(policy.SOURCE_SHA,'b423558e90f6aa2f1d14258ad9ea311c455cd038')
        original=policy.OLD+'\n// isolated unit fixture; native tests use the complete pinned file\n'
        with mock.patch.object(policy,'SOURCE_SHA',policy.blobsha(original.encode())):
            fixed=policy.patch(original)
            self.assertEqual(policy.patch(fixed),fixed)
            self.assertLess(fixed.index('c.connAccess.Lock()'),fixed.index('serverConn := c.conn'))
            for broken in (original+'changed',fixed+'changed',fixed.replace('c.connAccess.Lock()','',1)):
                with self.assertRaises(ValueError):policy.patch(broken)
        with self.assertRaises(ValueError):policy.patch(original)
    def test_build_cache_and_native_test_require_the_owned_fix(self):
        prepare=(ROOT/'deploy/prepare-mobile-multihop.py').read_text()
        self.assertIn('WIREGUARD_BIND.inputs()',prepare)
        self.assertIn('WIREGUARD_BIND.prepare(vendor)',prepare)
        for path in ('ios/RouterVPN/prepare-libbox.sh','android/build-sing-box-libbox.sh'):
            self.assertIn('./transport/wireguard -run TestRouterVPNClientBind', (ROOT/path).read_text())

if __name__=='__main__':unittest.main()
