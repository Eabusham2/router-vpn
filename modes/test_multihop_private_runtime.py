#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("router_vpn_multihop", HERE / "multihop.py")
assert SPEC and SPEC.loader
MH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MH)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-multihop-private-") as td:
        root = Path(td)
        path = root / "runtime.env"
        MH.write_private(path, "ENTRY_ID=one\n")
        assert path.read_text() == "ENTRY_ID=one\n"
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        assert not list(root.glob(".runtime.env.multihop-*"))

        original = path.read_bytes()
        with mock.patch.object(MH.os, "replace", side_effect=OSError("injected multihop adoption failure")):
            try:
                MH.write_private(path, "ENTRY_ID=two\n")
            except OSError:
                pass
            else:
                raise AssertionError("injected multihop adoption failure did not fail")
        assert path.read_bytes() == original, "failed multihop adoption changed the prior runtime file"
        assert not list(root.glob(".runtime.env.multihop-*")), "failed multihop adoption leaked a temp file"

        if os.name != "nt":
            real = root / "real.env"
            real.write_text("KEEP=1\n")
            os.chmod(real, 0o600)
            link = root / "link.env"
            link.symlink_to(real)
            try:
                MH.write_private(link, "REPLACE=1\n")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("multihop private publisher followed a symlink target")
            assert real.read_text() == "KEEP=1\n"

            outside = root / "outside"
            outside.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(outside, target_is_directory=True)
            try:
                MH.write_private(linked_parent / "secret.env", "SECRET=1\n")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("multihop private publisher followed a symlink parent")
            assert not (outside / "secret.env").exists()

    print("Multihop private runtime publication tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
