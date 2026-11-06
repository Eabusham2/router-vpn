#!/usr/bin/env python3
"""Portable source/provenance refusal controls; crypto evidence is separate."""
import hashlib
import importlib.util
import io
import json
import os
from unittest.mock import patch
from pathlib import Path
import tarfile
import tempfile
import unittest
SPEC=importlib.util.spec_from_file_location('builder',Path(__file__).with_name('build-dnssec-validator.py'))
BUILDER=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(BUILDER)
class BuildControls(unittest.TestCase):
    def archive(self,root,name='source/LICENSE',content=b'license'):
        path=root/'source.tar.gz'
        with tarfile.open(path,'w:gz') as tar:
            info=tarfile.TarInfo(name);info.size=len(content);tar.addfile(info,io.BytesIO(content))
        spec={'archive_sha256':BUILDER.digest(path),'licenses':{'LICENSE':hashlib.sha256(content).hexdigest()}}
        return path,spec
    def test_ambient_toolchain_and_loader_are_excluded(self):
        injected={name:'/malicious' for name in ('LD','AS','CPP','CXXFLAGS','CPLUS_INCLUDE_PATH','PKG_CONFIG_LIBDIR','PKG_CONFIG_SYSROOT_DIR','SDKROOT','CROSS_COMPILE','CHOST','CONFIG_SHELL','LD_RUN_PATH','LD_PRELOAD','CC','HOME','PATH')}
        with patch.dict(os.environ,injected):
            env=BUILDER.build_environment(Path('/private/home'),Path('/private/tmp'),123)
        self.assertEqual(env['CC'],'/usr/bin/cc')
        self.assertEqual(env['PATH'],'/usr/bin:/bin')
        self.assertEqual(env['SOURCE_DATE_EPOCH'],'123')
        self.assertNotIn('/malicious',env.values())
    def test_source_matches_existing_openssl_pin(self):
        source=json.loads((BUILDER.SOURCE/'sources.json').read_text())
        tor=json.loads((BUILDER.ROOT/'mobile/torpack/sources.json').read_text())
        self.assertEqual(source['openssl'],tor['sources']['openssl'])
    def test_matching_source_and_license(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);archive,spec=self.archive(root)
            self.assertEqual((BUILDER.extract(archive,root/'out',spec)/'LICENSE').read_bytes(),b'license')
    def test_archive_tamper_refused_before_extraction(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);archive,spec=self.archive(root);archive.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'archive hash'):BUILDER.extract(archive,root/'out',spec)
            self.assertFalse((root/'out').exists())
    def test_license_tamper_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);archive,spec=self.archive(root);spec['licenses']['LICENSE']='0'*64
            with self.assertRaisesRegex(ValueError,'license hash'):BUILDER.extract(archive,root/'out',spec)
    def test_archive_escape_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);archive,spec=self.archive(root,'../escaped')
            with self.assertRaises(tarfile.FilterError):BUILDER.extract(archive,root/'out',spec)
            self.assertFalse((root/'escaped').exists())
    def test_existing_tree_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);archive,spec=self.archive(root);(root/'out').mkdir()
            with self.assertRaises(FileExistsError):BUILDER.extract(archive,root/'out',spec)
if __name__=='__main__':unittest.main()
