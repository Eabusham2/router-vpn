#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


single = load("router_vpn_atomic_private_write", SCRIPT_DIR / "atomic-private-write.py")
batch = load("router_vpn_atomic_private_batch", SCRIPT_DIR / "atomic-private-batch.py")


def mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-write-") as td:
        root = Path(td)
        target = root / "secret.json"
        target.write_text("old\n", encoding="utf-8")
        os.chmod(target, 0o644)
        single.atomic_private_write(target, b"new\n")
        assert target.read_bytes() == b"new\n"
        if os.name != "nt":
            assert mode(target) == 0o600
        assert not list(root.glob(".secret.json.tmp-*"))

        foreign = root / "foreign-secret"
        foreign.write_bytes(b"foreign\n")
        os.chmod(foreign, 0o600)
        real_mkstemp = single.tempfile.mkstemp

        def mkstemp_then_swap_single(*args, **kwargs):
            fd, name = real_mkstemp(*args, **kwargs)
            os.replace(foreign, target)
            return fd, name

        with mock.patch.object(single.tempfile, "mkstemp", side_effect=mkstemp_then_swap_single):
            try:
                single.atomic_private_write(target, b"must-not-overwrite\n")
            except RuntimeError as exc:
                assert "identity changed before adoption" in str(exc)
            else:
                raise AssertionError("single-file private publisher overwrote a foreign regular replacement")
        assert target.read_bytes() == b"foreign\n"
        assert not list(root.glob(".secret.json.tmp-*"))

        if os.name != "nt":
            real = root / "real-secret"
            real.write_text("keep\n", encoding="utf-8")
            os.chmod(real, 0o600)
            link = root / "link-secret"
            link.symlink_to(real)
            try:
                single.atomic_private_write(link, b"replace\n")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("single-file private publisher accepted a symlink target")
            assert real.read_text(encoding="utf-8") == "keep\n"

            real_dir = root / "real-dir"
            real_dir.mkdir()
            linked_dir = root / "linked-dir"
            linked_dir.symlink_to(real_dir, target_is_directory=True)
            try:
                single.atomic_private_write(linked_dir / "escaped", b"nope\n")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("single-file private publisher accepted a symlink parent")
            assert not (real_dir / "escaped").exists()

            nested_real = root / "nested-real"
            (nested_real / "middle").mkdir(parents=True)
            nested_link = root / "nested-link"
            nested_link.symlink_to(nested_real, target_is_directory=True)
            try:
                single.atomic_private_write(nested_link / "middle" / "state" / "escaped", b"nope\n")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("single-file publisher accepted a nested symlink ancestor")
            assert not (nested_real / "middle" / "state").exists()

    with tempfile.TemporaryDirectory(prefix="router-vpn-private-batch-") as td:
        root = Path(td)
        d1, d2 = root / "one.json", root / "two.json"
        s1, s2 = root / "one.new", root / "two.new"
        d1.write_bytes(b"old-one\n")
        d2.write_bytes(b"old-two\n")
        s1.write_bytes(b"new-one\n")
        s2.write_bytes(b"new-two\n")
        for path in (d1, d2, s1, s2):
            os.chmod(path, 0o600)
        items = [batch.parse_item(f"{d1}={s1}"), batch.parse_item(f"{d2}={s2}")]

        real_replace = batch.os.replace
        calls = 0
        failed = False

        def fail_second_adoption(src, dst):
            nonlocal calls, failed
            calls += 1
            if calls == 2 and not failed:
                failed = True
                raise OSError("injected second-adoption failure")
            return real_replace(src, dst)

        with mock.patch.object(batch.os, "replace", side_effect=fail_second_adoption):
            try:
                batch.adopt(items)
            except RuntimeError as exc:
                assert "prior state restored" in str(exc)
            else:
                raise AssertionError("batch adoption fault did not fail")
        assert d1.read_bytes() == b"old-one\n"
        assert d2.read_bytes() == b"old-two\n"

        batch.adopt([batch.parse_item(f"{d1}={s1}"), batch.parse_item(f"{d2}={s2}")])
        assert d1.read_bytes() == b"new-one\n"
        assert d2.read_bytes() == b"new-two\n"
        if os.name != "nt":
            assert mode(d1) == 0o600 and mode(d2) == 0o600
            real_dir = root / "batch-real-dir"
            real_dir.mkdir()
            linked_dir = root / "batch-linked-dir"
            linked_dir.symlink_to(real_dir, target_is_directory=True)
            source = root / "batch-source"
            source.write_bytes(b"secret\n")
            os.chmod(source, 0o600)
            try:
                batch.parse_item(f"{linked_dir / 'escaped'}={source}")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("batch private publisher accepted a symlink parent")
            assert not (real_dir / "escaped").exists()

            nested_real = root / "batch-nested-real"
            (nested_real / "middle").mkdir(parents=True)
            nested_link = root / "batch-nested-link"
            nested_link.symlink_to(nested_real, target_is_directory=True)
            try:
                batch.parse_item(f"{nested_link / 'middle' / 'state' / 'escaped'}={source}")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("batch publisher accepted a nested symlink ancestor")
            assert not (nested_real / "middle" / "state").exists()
        assert not list(root.glob(".*.batch-*"))

    # A foreign regular file swapped in after destination snapshotting is not
    # Router VPN state and must never be overwritten by batch adoption.
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-batch-swap-") as td:
        root = Path(td)
        dest = root / "owned"
        source = root / "candidate"
        foreign = root / "foreign"
        for path, body in (
            (dest, b"old\n"),
            (source, b"new\n"),
            (foreign, b"foreign\n"),
        ):
            path.write_bytes(body)
            os.chmod(path, 0o600)
        item = batch.parse_item(f"{dest}={source}")
        os.replace(foreign, dest)
        try:
            batch.adopt([item])
        except RuntimeError as exc:
            assert "identity changed before adoption" in str(exc)
        else:
            raise AssertionError("batch publisher overwrote a foreign regular replacement")
        assert dest.read_bytes() == b"foreign\n"

    # Rollback is ownership-bound too. If the first adopted destination is
    # replaced by a foreign inode before a later adoption fails, rollback must
    # report incomplete recovery and leave the foreign bytes untouched.
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-batch-rollback-swap-") as td:
        root = Path(td)
        d1, d2 = root / "one", root / "two"
        s1, s2 = root / "one.new", root / "two.new"
        foreign = root / "foreign"
        for path, body in (
            (d1, b"old-one\n"),
            (d2, b"old-two\n"),
            (s1, b"new-one\n"),
            (s2, b"new-two\n"),
            (foreign, b"foreign-one\n"),
        ):
            path.write_bytes(body)
            os.chmod(path, 0o600)
        items = [batch.parse_item(f"{d1}={s1}"), batch.parse_item(f"{d2}={s2}")]
        real_replace = batch.os.replace
        calls = 0

        def replace_then_foreign_swap(src, dst):
            nonlocal calls
            calls += 1
            if calls == 2:
                real_replace(foreign, d1)
                raise OSError("injected later adoption failure after foreign swap")
            return real_replace(src, dst)

        with mock.patch.object(batch.os, "replace", side_effect=replace_then_foreign_swap):
            try:
                batch.adopt(items)
            except RuntimeError as exc:
                assert "rollback was incomplete" in str(exc)
                assert "identity changed before adoption" in str(exc)
            else:
                raise AssertionError("batch rollback overwrote a foreign replacement")
        assert d1.read_bytes() == b"foreign-one\n"
        assert d2.read_bytes() == b"old-two\n"
        assert not list(root.glob(".*.batch-*"))

    print("Atomic private single/batch publication tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
