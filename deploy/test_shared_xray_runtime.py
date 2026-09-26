#!/usr/bin/env python3
"""Exercise the production shared engine transformations and cache contract."""
from pathlib import Path
from unittest import mock
import importlib.util
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
SHARED=load('shared_xray',ROOT/'deploy/prepare-xray-runtime.py')
APPLE=load('apple_xray_tests',ROOT/'deploy/test_prepare_apple_xray.py')

class SharedRuntime(unittest.TestCase):
    def fixture(self,temp):
        _,source=APPLE.Prepare().fixture(temp)
        return source
    def snapshot(self,source):
        return {str(p.relative_to(source)):p.read_bytes() for p in source.rglob('*') if p.is_file()}
    def test_actual_shared_transform_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            source=self.fixture(temp)
            with mock.patch.object(SHARED,'checkout') as check:
                first=SHARED.prepare(source)
                check.assert_called_once_with(source.resolve())
            before=self.snapshot(source)
            with mock.patch.object(SHARED,'checkout'):second=SHARED.prepare(source)
            self.assertEqual(first,second);self.assertEqual(before,self.snapshot(source))
            self.assertIn('unsafe.Add(p, i.Offset)',(source/'proxy/vless/outbound/outbound.go').read_text())
            self.assertIn('func (c *fragmentConn) CloseWrite()', (source/'transport/internet/finalmask/fragment/conn.go').read_text())
            self.assertIn('buf.NewWithSize(65535)',(source/'proxy/freedom/freedom.go').read_text())
    def test_every_boundary_is_checked_before_any_write(self):
        for bad in [*SHARED.DATAGRAMS.PATCHES,*SHARED.CONNECTIONS.PATCHES,'proxy/vless/outbound/outbound.go']:
            with self.subTest(file=bad),tempfile.TemporaryDirectory() as temp:
                source=self.fixture(temp);(source/bad).write_text('changed upstream boundary')
                before=self.snapshot(source)
                with mock.patch.object(SHARED,'checkout'),self.assertRaises(ValueError):SHARED.prepare(source)
                self.assertEqual(before,self.snapshot(source),'failed preparation changed another file')
    def test_wrong_revision_never_mutates_any_source(self):
        with tempfile.TemporaryDirectory() as temp:
            source=self.fixture(temp);before=self.snapshot(source)
            with mock.patch.object(SHARED,'checkout',side_effect=ValueError('wrong source revision')),self.assertRaises(ValueError):SHARED.prepare(source)
            self.assertEqual(before,self.snapshot(source))
    def test_checkout_requires_exact_revision_and_module(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'go.mod').write_text('module github.com/xtls/xray-core\n')
            with mock.patch.object(SHARED.subprocess,'check_output',return_value=SHARED.XRAY_PIN+'\n'):SHARED.checkout(root)
            with mock.patch.object(SHARED.subprocess,'check_output',return_value='different\n'),self.assertRaises(ValueError):SHARED.checkout(root)
            (root/'go.mod').write_text('module unrelated\n')
            with mock.patch.object(SHARED.subprocess,'check_output',return_value=SHARED.XRAY_PIN+'\n'),self.assertRaises(ValueError):SHARED.checkout(root)
    def test_android_build_and_cache_use_the_exact_shared_source(self):
        build=(ROOT/'android/build-sing-box-libbox.sh').read_text()
        self.assertIn('clone_exact https://github.com/XTLS/Xray-core.git "$XRAY_CORE_VENDOR" '+SHARED.XRAY_PIN,build)
        self.assertIn('python3 "$ROOT/../deploy/prepare-xray-runtime.py" "$XRAY_CORE_VENDOR"',build)
        self.assertIn('go mod edit -replace="github.com/xtls/xray-core=$XRAY_CORE_VENDOR"',build)
        self.assertIn('[[ "$core_dir" == "$XRAY_CORE_VENDOR" ]]',build)
        stamp=next(line for line in build.splitlines() if line.startswith('EXPECTED_STAMP='))
        self.assertIn('$XRAY_POLICY_SHA',stamp)
        self.assertLess(build.index('prepare-xray-runtime.py" "$XRAY_CORE_VENDOR"'),build.index('go_retry mod tidy'))
        gradle=(ROOT/'android/app/build.gradle').read_text()
        for path in SHARED.sources():self.assertIn(path.name,gradle)
    def test_fingerprint_includes_each_transformation(self):
        before=SHARED.digest()
        files=SHARED.sources()
        for selected in files:
            actual=Path.read_bytes
            def changed(path):
                data=actual(path)
                return data+b'\n# regression fingerprint' if path==selected else data
            with mock.patch.object(Path,'read_bytes',changed):self.assertNotEqual(before,SHARED.digest())

if __name__=='__main__':unittest.main()
