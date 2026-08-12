#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
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

    def test_github_repack_does_not_overlay_private_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            src = base / "generic.zip"
            with zipfile.ZipFile(src, "w") as zf:
                zf.writestr("RouterVPN/routers.json", json.dumps({"selected_id": "", "profiles": []}))
                zf.writestr("RouterVPN/LICENSE", "MIT")
            work = base / "work"
            work.mkdir()
            root = builder.build_from_github(work, src)
            self.assertFalse((root / "router-vpn-bundle.json").exists())
            self.assertEqual(json.loads((root / "routers.json").read_text())["profiles"], [])


if __name__ == "__main__":
    unittest.main()
