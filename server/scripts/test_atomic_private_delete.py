#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_atomic_private_batch_delete", HERE / "atomic-private-batch.py")
assert SPEC and SPEC.loader
batch = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = batch
SPEC.loader.exec_module(batch)


def private_write(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    os.chmod(path, 0o600)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-delete-") as td:
        root = Path(td)
        delete_path = root / "old-key"
        replace_path = root / "provider"
        replacement = root / "provider.new"
        private_write(delete_path, b"old-secret\n")
        private_write(replace_path, b"old-provider\n")
        private_write(replacement, b"new-provider\n")

        batch.adopt([
            batch.parse_item(f"{replace_path}={replacement}"),
            batch.parse_delete(str(delete_path)),
        ])
        assert replace_path.read_bytes() == b"new-provider\n"
        assert not delete_path.exists()

    # If a later adoption fails after an explicit delete, rollback must restore
    # the deleted private file and leave the not-yet-adopted destination alone.
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-delete-rollback-") as td:
        root = Path(td)
        delete_path = root / "api.key"
        replace_path = root / "provider"
        replacement = root / "provider.new"
        private_write(delete_path, b"preserve-me\n")
        private_write(replace_path, b"old-provider\n")
        private_write(replacement, b"new-provider\n")
        items = [
            batch.parse_delete(str(delete_path)),
            batch.parse_item(f"{replace_path}={replacement}"),
        ]

        real_replace = batch.os.replace
        failed = False

        def fail_first_replace(src, dst):
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("injected adoption failure after delete")
            return real_replace(src, dst)

        with mock.patch.object(batch.os, "replace", side_effect=fail_first_replace):
            try:
                batch.adopt(items)
            except RuntimeError as exc:
                assert "prior state restored" in str(exc)
            else:
                raise AssertionError("delete transaction fault did not fail")

        assert delete_path.read_bytes() == b"preserve-me\n"
        assert replace_path.read_bytes() == b"old-provider\n"

    # A delete owns the exact destination inode observed during parsing. If a
    # foreign regular file is swapped in before adoption, it must survive.
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-delete-swap-") as td:
        root = Path(td)
        target = root / "api.key"
        foreign = root / "foreign"
        private_write(target, b"old-key\n")
        private_write(foreign, b"foreign-key\n")
        item = batch.parse_delete(str(target))
        os.replace(foreign, target)
        try:
            batch.adopt([item])
        except RuntimeError as exc:
            assert "identity changed before adoption" in str(exc)
        else:
            raise AssertionError("transactional delete removed a foreign regular replacement")
        assert target.read_bytes() == b"foreign-key\n"

    # If a delete has already committed but a foreign file reappears before a
    # later mutation fails, rollback may not overwrite that new file to restore
    # the old secret. It must surface incomplete rollback instead.
    with tempfile.TemporaryDirectory(prefix="router-vpn-private-delete-rollback-swap-") as td:
        root = Path(td)
        delete_path = root / "api.key"
        replace_path = root / "provider"
        replacement = root / "provider.new"
        foreign_body = b"foreign-recreated\n"
        private_write(delete_path, b"old-secret\n")
        private_write(replace_path, b"old-provider\n")
        private_write(replacement, b"new-provider\n")
        items = [
            batch.parse_delete(str(delete_path)),
            batch.parse_item(f"{replace_path}={replacement}"),
        ]
        real_replace = batch.os.replace
        failed = False

        def recreate_deleted_then_fail(src, dst):
            nonlocal failed
            if not failed:
                failed = True
                private_write(delete_path, foreign_body)
                raise OSError("injected adoption failure after foreign recreate")
            return real_replace(src, dst)

        with mock.patch.object(batch.os, "replace", side_effect=recreate_deleted_then_fail):
            try:
                batch.adopt(items)
            except RuntimeError as exc:
                assert "rollback was incomplete" in str(exc)
                assert "appeared before adoption" in str(exc)
            else:
                raise AssertionError("delete rollback overwrote a foreign recreated file")
        assert delete_path.read_bytes() == foreign_body
        assert replace_path.read_bytes() == b"old-provider\n"

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-private-delete-symlink-") as td:
            root = Path(td)
            real = root / "real-key"
            link = root / "api.key"
            private_write(real, b"do-not-delete\n")
            link.symlink_to(real)
            try:
                batch.parse_delete(str(link))
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("transactional delete accepted a symlink target")
            assert real.read_bytes() == b"do-not-delete\n"

    with tempfile.TemporaryDirectory(prefix="router-vpn-private-delete-args-") as td:
        root = Path(td)
        target = root / "same"
        source = root / "new"
        private_write(target, b"old\n")
        private_write(source, b"new\n")
        try:
            batch.parse_args(["batch", f"{target}={source}", "--delete", str(target)])
        except RuntimeError as exc:
            assert "duplicate" in str(exc)
        else:
            raise AssertionError("batch accepted duplicate upsert/delete destination")

    print("Atomic private transactional delete tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
