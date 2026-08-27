#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_cleanup_private_runtime", HERE / "cleanup-private-runtime.py")
assert SPEC and SPEC.loader
CLEAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEAN)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-runtime-") as td:
        root = Path(td)
        run = root / "run"
        owned = run / "multihop"
        owned.mkdir(parents=True)
        (owned / "secret.json").write_text("private\n", encoding="utf-8")
        nested = owned / "nested"
        nested.mkdir()
        (nested / "state").write_text("private\n", encoding="utf-8")
        CLEAN.cleanup(str(root), str(owned))
        assert not owned.exists()
        assert not list(run.glob(".router-vpn-cleanup-*"))

        # First launch with no run directory is an intentional no-op.
        fresh = root / "fresh"
        fresh.mkdir()
        CLEAN.cleanup(str(fresh), str(fresh / "run" / "multihop"))

        unrelated = run / "wg"
        unrelated.mkdir()
        try:
            CLEAN.cleanup(str(root), str(unrelated))
        except RuntimeError as exc:
            assert "unrelated" in str(exc)
        else:
            raise AssertionError("cleanup accepted unrelated runtime path")
        assert unrelated.is_dir()

        too_deep = run / "multihop" / "one" / "two"
        try:
            CLEAN.cleanup(str(root), str(too_deep))
        except RuntimeError as exc:
            assert "deep" in str(exc)
        else:
            raise AssertionError("cleanup accepted unexpectedly deep runtime path")

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-leaf-link-") as td:
            root = Path(td)
            run = root / "run"
            run.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep").write_text("keep\n", encoding="utf-8")
            owned = run / "multihop"
            owned.symlink_to(outside, target_is_directory=True)
            CLEAN.cleanup(str(root), str(owned))
            assert not owned.exists(), "owned symlink leaf survived cleanup"
            assert (outside / "keep").read_text(encoding="utf-8") == "keep\n"
            assert not list(run.glob(".router-vpn-cleanup-*"))

        with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-child-link-") as td:
            root = Path(td)
            run = root / "run"
            owned = run / "native-multihop"
            owned.mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep").write_text("keep\n", encoding="utf-8")
            (owned / "outside-link").symlink_to(outside, target_is_directory=True)
            (owned / "owned").write_text("delete\n", encoding="utf-8")
            CLEAN.cleanup(str(root), str(owned))
            assert not owned.exists()
            assert (outside / "keep").read_text(encoding="utf-8") == "keep\n"

        with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-run-link-") as td:
            root = Path(td)
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep").write_text("keep\n", encoding="utf-8")
            (root / "run").symlink_to(outside, target_is_directory=True)
            try:
                CLEAN.cleanup(str(root), str(root / "run" / "multihop"))
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("cleanup followed a symlinked run directory")
            assert (outside / "keep").read_text(encoding="utf-8") == "keep\n"

    print("Private runtime no-follow cleanup tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
