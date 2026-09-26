#!/usr/bin/env python3
"""Test corrected-engine bundle validation without external downloads."""
from pathlib import Path
from unittest import mock
import hashlib
import importlib.util
import json
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
VERIFY=load('bundled_xray',ROOT/'client/verify-bundled-xray.py')
BUILD=load('build_xray',ROOT/'deploy/build-xray-runtime.py')
class Bundle(unittest.TestCase):
    def fixture(self,folder,target='linux/amd64'):
        folder.mkdir();name='xray.exe' if target.startswith('windows/') else 'xray'
        binary=folder/name;binary.write_bytes(b'fixture bytes: not executed')
        meta={'schema_version':1,'runtime':'xray','version':VERIFY.VERSION,'upstream_revision':VERIFY.PIN,
              'policy_sha256':BUILD.POLICY.digest(),'target':target,'toolchain':VERIFY.TOOLCHAIN,
              'size':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        (folder/'XRAY-RUNTIME.json').write_text(json.dumps(meta));(folder/'XRAY-LICENSE').write_text('fixture license')
        return binary,meta
    def test_exact_architecture_for_all_six_targets(self):
        for target in BUILD.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as temp:
                folder=Path(temp)/'bundle';binary,meta=self.fixture(folder,target)
                value,path=VERIFY.verify(folder,target,execute=False)
                self.assertEqual(value,meta);self.assertEqual(path,binary)
                other=target.replace('amd64','arm64') if 'amd64' in target else target.replace('arm64','amd64')
                with self.assertRaises(ValueError):VERIFY.verify(folder,other,execute=False)
    def test_bytes_checked_before_any_executable_is_run(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'bundle';binary,_=self.fixture(folder);binary.write_bytes(b'changed')
            with mock.patch.object(VERIFY.subprocess,'check_output') as run,self.assertRaises(ValueError):VERIFY.verify(folder,'linux/amd64')
            run.assert_not_called()
    def test_upstream_version_alone_is_not_the_corrected_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'bundle';_,meta=self.fixture(folder)
            with mock.patch.object(VERIFY,'host_target',return_value='linux/amd64'):
                with mock.patch.object(VERIFY.subprocess,'check_output',return_value='Xray 26.7.11 (upstream)'),self.assertRaises(ValueError):VERIFY.verify(folder,'linux/amd64')
                marker='Xray 26.7.11 ('+BUILD.marker(meta['policy_sha256'])+')'
                with mock.patch.object(VERIFY.subprocess,'check_output',return_value=marker):self.assertEqual(VERIFY.verify(folder,'linux/amd64')[0],meta)
    def test_receipt_schema_and_fingerprint_fail_closed(self):
        for field,value in [('schema_version',2),('runtime','other'),('version','newest'),('upstream_revision','main'),('policy_sha256',''),('sha256','0'*64),('size',True),('target','linux/386'),('toolchain','go1.99.0')]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as temp:
                folder=Path(temp)/'bundle';_,meta=self.fixture(folder);meta[field]=value
                (folder/'XRAY-RUNTIME.json').write_text(json.dumps(meta))
                with self.assertRaises(ValueError):VERIFY.verify(folder,'linux/amd64',execute=False)
    def test_duplicate_and_unknown_receipt_fields_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'bundle';_,meta=self.fixture(folder)
            raw=json.dumps(meta)
            for text in (raw[:-1]+',"runtime":"xray"}',raw[:-1]+',"extra":"ignored"}'):
                (folder/'XRAY-RUNTIME.json').write_text(text)
                with self.assertRaises(ValueError):VERIFY.verify(folder,'linux/amd64',execute=False)
    def test_symlink_engine_and_missing_license_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'bundle';binary,_=self.fixture(folder)
            (folder/'XRAY-LICENSE').unlink()
            with self.assertRaises(ValueError):VERIFY.verify(folder,'linux/amd64',execute=False)
            (folder/'XRAY-LICENSE').write_text('fixture license')
            outside=Path(temp)/'outside';binary.rename(outside)
            try:binary.symlink_to(outside)
            except (OSError,NotImplementedError):self.skipTest('symlink unsupported by this test host')
            with self.assertRaises(ValueError):VERIFY.verify(folder,'linux/amd64',execute=False)
    def test_builder_environment_is_pinned_and_target_exact(self):
        with mock.patch.dict(BUILD.os.environ,{'GOWORK':'/untrusted/work','CGO_ENABLED':'1','GOFLAGS':'-race','GOSUMDB':'off'}):
            for target in BUILD.TARGETS:
                env=BUILD.environment(target)
                self.assertEqual(env['GOOS']+'/'+env['GOARCH'],target)
                self.assertEqual(env['GOTOOLCHAIN'],BUILD.TOOLCHAIN)
                self.assertEqual(env['GOWORK'],'off');self.assertEqual(env['GOFLAGS'],'')
                self.assertEqual(env['GOSUMDB'],'sum.golang.org');self.assertEqual(env['CGO_ENABLED'],'0')
        with self.assertRaises(ValueError):BUILD.environment('linux/other')
    def test_changed_bundle_cannot_be_reused_or_destroyed(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'bundle';binary,_=self.fixture(folder);binary.write_bytes(b'existing untrusted engine')
            before=binary.read_bytes()
            with mock.patch.object(BUILD,'fetch_source') as fetch,self.assertRaises(ValueError):BUILD.build('linux/amd64',folder)
            fetch.assert_not_called();self.assertEqual(binary.read_bytes(),before)
if __name__=='__main__':unittest.main()
