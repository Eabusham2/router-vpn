#!/usr/bin/env python3
"""Exercise exact native OpenVPN patch composition and whole-module tamper guards."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock
import hashlib
import zipfile

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'deploy'/name);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
REMOTE=load('mobile_openvpn_remote_policy.py');CLOSE=load('mobile_openvpn_close_policy.py');MODULE=REMOTE.MODULE

class Tests(unittest.TestCase):
    def test_windows_text_translation_cannot_rewrite_verified_close_sources(self):
        original='package fixture\n'+CLOSE.OLD+'\n'+''.join(before*count for before,after,count in REMOTE.CHANGES)
        server='package fixture\nfunc closeServer() {\n'+CLOSE.SERVER_OLD+'\n}\n'
        digest=CLOSE.blobsha(original.encode())
        # Model the actual Windows default at the I/O boundary. Production
        # patching, bytes on disk and the strict verifier are not substituted.
        def windows_text(path, text, encoding=None, errors=None, newline=None):
            with path.open('w', encoding=encoding or 'utf-8', errors=errors,
                           newline='\r\n' if newline is None else newline) as stream:
                return stream.write(text)
        with tempfile.TemporaryDirectory() as temporary:
            vendor=Path(temporary).resolve();directory=vendor/'protocol/openvpn';directory.mkdir(parents=True)
            client=directory/'client.go';client.write_bytes(original.encode())
            (directory/'server.go').write_bytes(server.encode())
            with mock.patch.object(REMOTE,'SOURCE_SHA',digest),mock.patch.object(CLOSE,'SOURCE_SHA',digest), \
                    mock.patch.object(CLOSE.REMOTE,'SOURCE_SHA',digest), \
                    mock.patch.object(CLOSE,'SERVER_SOURCE_SHA',CLOSE.blobsha(server.encode())), \
                    mock.patch.object(REMOTE.subprocess,'check_output',return_value=REMOTE.PIN+'\n'), \
                    mock.patch.object(REMOTE.MODULE,'prepare') as module, \
                    mock.patch.object(REMOTE.LAYERS,'prepare') as layers, \
                    mock.patch.object(REMOTE.STACK,'prepare') as stack, \
                    mock.patch.object(Path,'write_text',windows_text):
                CLOSE.prepare(vendor)
                preserved={name:(directory/name).read_bytes() for name in ('server.go','routervpn_close_policy.go')}
                expected=REMOTE.patch(CLOSE.patch(original)).encode('utf-8')
                for _ in range(2):
                    REMOTE.prepare(vendor)
                    self.assertEqual(client.read_bytes(),expected,
                                     'OpenVPN remote preparation changed canonical LF after verified close preparation')
                    records=CLOSE.verify(vendor)
                    self.assertEqual(records['protocol/openvpn/client.go'],hashlib.sha256(expected).hexdigest())
                    self.assertEqual({name:(directory/name).read_bytes() for name in preserved},preserved)
                    for name in ('remote','remote_fixture'):
                        self.assertEqual((directory/('routervpn_'+name+'.go')).read_bytes(),
                                         (ROOT/'mobile'/('routervpn_openvpn_'+name+'.go.tmpl')).read_bytes())
                self.assertEqual(module.call_count,2)
                self.assertEqual(layers.call_count,2)
                self.assertEqual(stack.call_count,2)
                # A verifier must not silently normalize drift to make the
                # producer appear correct on another platform.
                changed=expected.replace(b'\n',b'\r\n')
                self.assertNotEqual(changed,expected)
                client.write_bytes(changed)
                with self.assertRaisesRegex(ValueError,'absent or incomplete'):
                    CLOSE.verify(vendor)
                self.assertEqual(client.read_bytes(),changed)

    def test_full_core_composition_order_and_tamper(self):
        original='package fixture\n'+CLOSE.OLD+'\n'+''.join(before*count for before,after,count in REMOTE.CHANGES)
        digest=CLOSE.blobsha(original.encode())
        with mock.patch.object(REMOTE,'SOURCE_SHA',digest),mock.patch.object(CLOSE,'SOURCE_SHA',digest),mock.patch.object(CLOSE.REMOTE,'SOURCE_SHA',digest):
            remote=REMOTE.patch(original);closed=CLOSE.patch(original)
            together=REMOTE.patch(closed)
            self.assertEqual(CLOSE.patch(remote),together)
            self.assertEqual(CLOSE.patch(together),together)
            self.assertEqual(REMOTE.patch(together),together)
            self.assertEqual(REMOTE.unpatch(together),(closed,True))
            for changed in (together+'changed',together.replace('event.RouterVPNTransportGeneration == 0','false'),together.replace('routerVPNOpenVPNCloseError(c.client.Close())','nil'),remote.replace(REMOTE.CHANGES[-1][1],REMOTE.CHANGES[-1][0])):
                with self.subTest(changed=changed),self.assertRaises(ValueError):REMOTE.patch(changed)
                with self.subTest(close=changed),self.assertRaises(ValueError):CLOSE.patch(changed)

    def test_whole_module_verification_rejects_unrelated_and_partial_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);archive=directory/'source.zip';target=directory/'module';target.mkdir()
            contents={name:('package openvpn\n'+''.join(before+'\n' for before,after in changes)).encode() for name,changes in MODULE.PATCHES.items()}
            contents['unchanged.go']=b'package openvpn\n'
            rows=[(MODULE.PREFIX+name,hashlib.sha256(data).hexdigest()) for name,data in contents.items()]
            with zipfile.ZipFile(archive,'w') as bundle:
                for name,data in contents.items():bundle.writestr(MODULE.PREFIX+name,data)
            with mock.patch.object(MODULE,'SUM',MODULE.h1(rows)):
                MODULE.extract_verified(archive,target);MODULE.verify_tree(target)
                for name in ('unchanged.go','client_session_tls.go','client_tunnel.go',MODULE.FIXTURE):
                    path=target/name;good=path.read_bytes();path.write_bytes(good+b'changed')
                    with self.subTest(name=name),self.assertRaises(ValueError):MODULE.verify_tree(target)
                    path.write_bytes(good)
                (target/'unrelated.go').symlink_to(target/'unchanged.go')
                with self.assertRaises(ValueError):MODULE.verify_tree(target)

if __name__=='__main__':unittest.main()
