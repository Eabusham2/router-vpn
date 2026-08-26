#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("router_vpn_private_directory", HERE / "private-directory.py")
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-dir-") as td:
        root = Path(td)
        target = root / "state" / "nested"
        got = mod.ensure_private_directory(target)
        assert got == target.resolve()
        if os.name != "nt":
            assert target.stat().st_mode & 0o777 == 0o700

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-private-dir-link-") as td, tempfile.TemporaryDirectory(prefix="router-vpn-private-dir-out-") as out:
            root = Path(td)
            link = root / "state"
            link.symlink_to(Path(out), target_is_directory=True)
            try:
                mod.ensure_private_directory(link / "nested")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("private directory helper accepted symlink ancestor")
            assert list(Path(out).iterdir()) == []

        with tempfile.TemporaryDirectory(prefix="router-vpn-private-dir-leaf-") as td, tempfile.TemporaryDirectory(prefix="router-vpn-private-dir-real-") as out:
            root = Path(td)
            link = root / "downloads"
            link.symlink_to(Path(out), target_is_directory=True)
            try:
                mod.ensure_private_directory(link)
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("private directory helper accepted symlink leaf")

    print("Private directory path tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
