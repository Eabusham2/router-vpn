#!/usr/bin/env python3
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("builder", HERE / "build-download-on-demand.py")
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class DownloadSafetyTests(unittest.TestCase):
    def test_safe_rel_rejects_traversal_and_drive_paths(self):
        for value in ("../x", "/etc/passwd", "a/../../b", "C:/Windows/x", "%2e%2e/secret"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                builder._safe_rel(value)

    def test_zip_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "bad.zip"
            with zipfile.ZipFile(src, "w") as zf:
                zf.writestr("../escape", b"no")
            with self.assertRaises(ValueError):
                builder.safe_extract_zip(src, base / "out")
            self.assertFalse((base / "escape").exists())

    def test_zip_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "bad.zip"
            info = zipfile.ZipInfo("root/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(src, "w") as zf:
                zf.writestr(info, "../../outside")
            with self.assertRaises(ValueError):
                builder.safe_extract_zip(src, base / "out")

    def test_duplicate_normalized_zip_and_tar_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            zpath = base / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                with zipfile.ZipFile(zpath, "w") as zf:
                    zf.writestr("root/value.txt", b"one")
                    zf.writestr("root/value.txt", b"two")
            with self.assertRaisesRegex(ValueError, "duplicate normalized path"):
                builder.safe_extract_zip(zpath, base / "zip-out")

            tpath = base / "duplicate.tar.gz"
            with tarfile.open(tpath, "w:gz") as tf:
                for body in (b"one", b"two"):
                    info = tarfile.TarInfo("root/value.txt")
                    info.size = len(body)
                    tf.addfile(info, io.BytesIO(body))
            with self.assertRaisesRegex(ValueError, "duplicate normalized path"):
                builder.safe_extract_tar(tpath, base / "tar-out")

    def test_unpacked_limit_is_enforced(self):
        old = builder.MAX_UNPACKED
        builder.MAX_UNPACKED = 32
        try:
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                src = base / "large.zip"
                with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("root/data", b"x" * 64)
                with self.assertRaises(ValueError):
                    builder.safe_extract_zip(src, base / "out")
        finally:
            builder.MAX_UNPACKED = old

    def test_copy_tree_rejects_symlink_source_entry(self):
        if os.name == "nt":
            self.skipTest("symlink semantics differ on Windows test runners")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "src"
            src.mkdir()
            outside = base / "outside"
            outside.write_text("secret", encoding="utf-8")
            (src / "link").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlink"):
                builder.copy_tree(src, base / "dst")
            self.assertFalse((base / "dst/link").exists())

    def test_copy_file_rejects_parent_identity_swap(self):
        if os.name == "nt":
            self.skipTest("directory replacement semantics differ on Windows")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            parent = base / "source"
            parent.mkdir()
            src = parent / "payload.bin"
            src.write_bytes(b"original")
            dst = base / "out" / "payload.bin"
            real_open = builder.os.open
            swapped = False

            def swap_on_source_open(path, flags, *args, **kwargs):
                nonlocal swapped
                fd = real_open(path, flags, *args, **kwargs)
                if not swapped and Path(path) == src:
                    swapped = True
                    old = base / "source-old"
                    parent.rename(old)
                    parent.mkdir()
                    (parent / "payload.bin").write_bytes(b"replacement")
                return fd

            with mock.patch.object(builder.os, "open", side_effect=swap_on_source_open):
                with self.assertRaisesRegex(ValueError, "changed during"):
                    builder.copy_file(src, dst)
            self.assertFalse(dst.exists(), "raced source was published into package output")

    def test_copy_tree_rejects_special_entry(self):
        if os.name == "nt" or not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unavailable on this platform")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "src"
            src.mkdir()
            os.mkfifo(src / "pipe")
            with self.assertRaisesRegex(ValueError, "special filesystem entry"):
                builder.copy_tree(src, base / "dst")

    def test_generic_tree_rejects_linked_profile(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "routers.json").write_text(json.dumps({"selected_id": "home", "profiles": [{"id": "home"}]}))
            with self.assertRaises(ValueError):
                builder.assert_generic_tree(root)

    def test_generic_tree_accepts_blank_profile_store(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            builder.write_blank_routers(root / "routers.json")
            (root / "generated").mkdir()
            builder.assert_generic_tree(root)

    def test_zip_dir_failure_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "payload"
            root.mkdir()
            (root / "file.txt").write_text("new payload", encoding="utf-8")
            output = base / "package.zip"
            output.write_bytes(b"previous-valid-package")
            with mock.patch.object(builder.zipfile.ZipFile, "write", side_effect=RuntimeError("injected archive failure")):
                with self.assertRaisesRegex(RuntimeError, "injected archive failure"):
                    builder.zip_dir(root, output)
            self.assertEqual(output.read_bytes(), b"previous-valid-package")
            self.assertFalse(list(base.glob(".package.zip.archive-*")))

    def test_zip_dir_rejects_symlink_output(self):
        if os.name == "nt":
            self.skipTest("symlink semantics differ on Windows")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "payload"
            root.mkdir()
            (root / "file.txt").write_text("payload", encoding="utf-8")
            real = base / "real.zip"
            real.write_bytes(b"keep")
            output = base / "package.zip"
            output.symlink_to(real)
            with self.assertRaisesRegex(ValueError, "unsafe package output target"):
                builder.zip_dir(root, output)
            self.assertEqual(real.read_bytes(), b"keep")

    def test_zip_dir_rejects_target_replacement_before_adoption(self):
        if os.name == "nt":
            self.skipTest("atomic replacement identity semantics differ on Windows")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "payload"
            root.mkdir()
            (root / "file.txt").write_text("payload", encoding="utf-8")
            output = base / "package.zip"
            output.write_bytes(b"owned-old")
            foreign = base / "foreign.zip"
            foreign.write_bytes(b"foreign")
            real_verify = builder.verify_parent_chain
            swapped = False

            def replace_target(snapshot):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    os.replace(foreign, output)
                return real_verify(snapshot)

            with mock.patch.object(builder, "verify_parent_chain", side_effect=replace_target):
                with self.assertRaisesRegex(ValueError, "identity changed before adoption"):
                    builder.zip_dir(root, output)
            self.assertEqual(output.read_bytes(), b"foreign")
            self.assertFalse(list(base.glob(".package.zip.archive-*")))

    def test_zip_dir_atomic_publish_is_private_and_valid(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "payload"
            root.mkdir()
            (root / "file.txt").write_text("payload", encoding="utf-8")
            output = base / "package.zip"
            builder.zip_dir(root, output)
            self.assertTrue(zipfile.is_zipfile(output))
            with zipfile.ZipFile(output) as zf:
                self.assertEqual(zf.read("payload/file.txt"), b"payload")
            if os.name != "nt":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertFalse(list(base.glob(".package.zip.archive-*")))

    def test_github_repack_does_not_overlay_private_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "generic.zip"
            expected_sha = "a" * 40
            expected_family = "windows-amd64"
            package = base / "RouterVPN"
            package.mkdir()
            builder.write_blank_routers(package / "routers.json")
            (package / "LICENSE").write_text("MIT", encoding="utf-8")
            builder._provenance.write_manifest(package, expected_sha, expected_family)
            with zipfile.ZipFile(src, "w") as zf:
                for path in package.rglob("*"):
                    if path.is_file():
                        zf.write(path, path.relative_to(base))
            work = base / "work"
            work.mkdir()
            root = builder.build_from_github(work, src, expected_sha, expected_family)
            self.assertFalse((root / "router-vpn-bundle.json").exists())
            self.assertEqual(json.loads((root / "routers.json").read_text())["profiles"], [])


if __name__ == "__main__":
    unittest.main()
