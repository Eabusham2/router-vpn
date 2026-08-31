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


single = load("router_vpn_atomic_private_write_identity", SCRIPT_DIR / "atomic-private-write.py")
batch = load("router_vpn_atomic_private_batch_identity", SCRIPT_DIR / "atomic-private-batch.py")


def private_file(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    os.chmod(path, 0o600)


def test_single_post_rename_foreign_swap(root: Path) -> None:
    target = root / "single-owned"
    foreign = root / "single-foreign"
    private_file(target, b"old\n")
    private_file(foreign, b"foreign\n")
    real_replace = single.os.replace
    swapped = False

    def replace_and_swap(src, dst):
        nonlocal swapped
        result = real_replace(src, dst)
        if Path(dst) == target and not swapped:
            swapped = True
            real_replace(foreign, target)
        return result

    with mock.patch.object(single.os, "replace", side_effect=replace_and_swap):
        try:
            single.atomic_private_write(target, b"new\n")
        except RuntimeError as exc:
            assert "identity changed before verification" in str(exc)
        else:
            raise AssertionError("single private publisher accepted a foreign post-rename replacement")
    assert target.read_bytes() == b"foreign\n"
    assert not list(root.glob(".single-owned.tmp-*"))


def test_batch_post_rename_foreign_swap(root: Path) -> None:
    target = root / "batch-owned"
    source = root / "batch-source"
    foreign = root / "batch-foreign"
    private_file(target, b"old\n")
    private_file(source, b"new\n")
    private_file(foreign, b"foreign\n")
    item = batch.parse_item(f"{target}={source}")
    real_replace = batch.os.replace
    swapped = False

    def replace_and_swap(src, dst):
        nonlocal swapped
        result = real_replace(src, dst)
        if Path(dst) == target and not swapped:
            swapped = True
            real_replace(foreign, target)
        return result

    with mock.patch.object(batch.os, "replace", side_effect=replace_and_swap):
        try:
            batch.adopt([item])
        except RuntimeError as exc:
            text = str(exc)
            assert "identity changed before verification" in text
            assert "rollback was incomplete" in text
        else:
            raise AssertionError("batch private publisher accepted a foreign post-rename replacement")
    assert target.read_bytes() == b"foreign\n"
    assert not list(root.glob(".*.batch-*"))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-adoption-identity-") as td:
        root = Path(td)
        test_single_post_rename_foreign_swap(root)
        test_batch_post_rename_foreign_swap(root)
    print("Atomic private adoption identity tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
