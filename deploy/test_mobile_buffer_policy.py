#!/usr/bin/env python3
"""Execute the dependency copy policy without downloading anything."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('buffer_policy',ROOT/'deploy/prepare-mobile-buffers.py')
MODULE=importlib.util.module_from_spec(spec);spec.loader.exec_module(MODULE)
class Tests(unittest.TestCase):
    def fixture(self,root):
        (root/'common/buf').mkdir(parents=True)
        (root/'go.mod').write_text('module github.com/sagernet/sing\n\ngo 1.24\n')
        for name,(_,udp) in MODULE.FILES.items():
            low='low_memory' in name
            (root/name).write_text('//go:build '+('with_low_memory' if low else '!with_low_memory')+'\n\npackage buf\n\nconst (\n\tBufferSize    = '+('16' if low else '32')+' * 1024\n\tUDPBufferSize = '+udp+'\n)\n')
    def test_exact_idempotent_copy_leaves_original_tcp_and_cache_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'source';dst=Path(tmp)/'owned';self.fixture(src)
            before={str(p.relative_to(src)):p.read_bytes() for p in src.rglob('*') if p.is_file()}
            MODULE.copy_verified(src,dst);MODULE.copy_verified(src,dst)
            self.assertEqual(before,{str(p.relative_to(src)):p.read_bytes() for p in src.rglob('*') if p.is_file()})
            for name in MODULE.FILES:
                text=(dst/name).read_text();self.assertIn('UDPBufferSize = 65535',text)
                self.assertIn('BufferSize    = '+('16' if 'low_memory' in name else '32')+' * 1024',text)
            (dst/'common/buf/buffer_standard.go').write_text('drift')
            with self.assertRaises(ValueError):MODULE.copy_verified(src,dst)
    def test_changed_dependency_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'source';dst=Path(tmp)/'owned';self.fixture(src)
            file=src/'common/buf/buffer_low_memory.go';original=file.read_bytes();file.write_text('drift')
            with self.assertRaises(ValueError):MODULE.copy_verified(src,dst)
            self.assertFalse(dst.exists());file.write_bytes(original)
            (src/'escape').symlink_to(Path(tmp)/'outside')
            with self.assertRaises(ValueError):MODULE.copy_verified(src,dst)
            self.assertFalse(dst.exists())
if __name__=='__main__':unittest.main()
