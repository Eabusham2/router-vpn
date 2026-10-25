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
