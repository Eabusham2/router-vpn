#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_all_result_identity", HERE / "all-result.py")
assert SPEC and SPEC.loader
ALL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ALL
SPEC.loader.exec_module(ALL)


def private_file(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    os.chmod(path, 0o600)


def test_prepare_does_not_delete_foreign_replacement(root: Path) -> None:
    target = root / "state" / "selected"
    ALL.publish(str(root), "state/selected", "max-tls-wg")
    foreign = root / "foreign-prepare"
    private_file(foreign, b"foreign\n")
    real_rename = ALL.os.rename
    swapped = False

    def rename_after_foreign_swap(src, dst):
        nonlocal swapped
        if Path(src) == target and not swapped:
            swapped = True
            os.replace(foreign, target)
        return real_rename(src, dst)

    with mock.patch.object(ALL.os, "rename", side_effect=rename_after_foreign_swap):
        try:
            ALL.prepare(str(root), "state/selected")
        except RuntimeError as exc:
            assert "identity changed during stale-result cleanup" in str(exc)
        else:
            raise AssertionError("ALL stale-result cleanup deleted a foreign replacement")

    assert target.read_bytes() == b"foreign\n"
    assert not list(target.parent.glob(".selected.stale-*"))


def test_publish_rejects_foreign_replacement_before_adoption(root: Path) -> None:
    target = root / "state-before" / "selected"
    ALL.publish(str(root), "state-before/selected", "max-tls-wg")
    foreign = root / "foreign-before"
    private_file(foreign, b"foreign-before\n")
    real_parent_check = ALL.require_parent_state
    swapped = False

    def parent_check_then_swap(*args, **kwargs):
        nonlocal swapped
        result = real_parent_check(*args, **kwargs)
        if not swapped:
            swapped = True
            os.replace(foreign, target)
        return result

    with mock.patch.object(ALL, "require_parent_state", side_effect=parent_check_then_swap):
        try:
            ALL.publish(str(root), "state-before/selected", "max-quic-awg")
        except RuntimeError as exc:
            assert "identity changed before adoption" in str(exc)
        else:
            raise AssertionError("ALL publication overwrote a foreign pre-adoption replacement")

    assert target.read_bytes() == b"foreign-before\n"
    assert not list(target.parent.glob(".selected.all-*"))


def test_publish_rejects_foreign_replacement_after_rename(root: Path) -> None:
    target = root / "state-after" / "selected"
    ALL.publish(str(root), "state-after/selected", "max-tls-wg")
    foreign = root / "foreign-after"
    private_file(foreign, b"foreign-after\n")
    real_replace = ALL.os.replace
    swapped = False

    def replace_then_swap(src, dst):
        nonlocal swapped
        result = real_replace(src, dst)
        if Path(dst) == target and not swapped:
            swapped = True
            real_replace(foreign, target)
        return result

    with mock.patch.object(ALL.os, "replace", side_effect=replace_then_swap):
        try:
            ALL.publish(str(root), "state-after/selected", "max-quic-wg")
        except RuntimeError as exc:
            assert "identity changed before verification" in str(exc)
        else:
            raise AssertionError("ALL publication accepted a foreign post-rename replacement")

    assert target.read_bytes() == b"foreign-after\n"
    assert not list(target.parent.glob(".selected.all-*"))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-all-result-identity-") as td:
        root = Path(td)
        test_prepare_does_not_delete_foreign_replacement(root)
        test_publish_rejects_foreign_replacement_before_adoption(root)
        test_publish_rejects_foreign_replacement_after_rename(root)
    print("ALL result ownership-race tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
