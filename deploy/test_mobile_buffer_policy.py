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
    def test_readonly_go_cache_directories_stay_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'source';dst=Path(tmp)/'owned';self.fixture(src)
            folders=[src,*(p for p in src.rglob('*') if p.is_dir())]
            try:
                for p in folders:p.chmod(0o555)
                MODULE.copy_verified(src,dst)
                MODULE.copy_verified(src,dst)
                for p in folders:self.assertEqual(p.stat().st_mode & 0o777,0o555)
                for p in [dst,*(p for p in dst.rglob('*') if p.is_dir())]:
                    self.assertEqual(p.stat().st_mode & 0o700,0o700)
                self.assertTrue((dst/'.routervpn-buffer-policy.json').is_file())
            finally:
                for p in folders:p.chmod(0o755)

    def test_changed_dependency_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'source';dst=Path(tmp)/'owned';self.fixture(src)
            file=src/'common/buf/buffer_low_memory.go';original=file.read_bytes();file.write_text('drift')
            with self.assertRaises(ValueError):MODULE.copy_verified(src,dst)
            self.assertFalse(dst.exists());file.write_bytes(original)
            (src/'escape').symlink_to(Path(tmp)/'outside')
            with self.assertRaises(ValueError):MODULE.copy_verified(src,dst)
            self.assertFalse(dst.exists())
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

if __name__=='__main__':unittest.main()
