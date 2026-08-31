#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

SCRIPT = Path(__file__).with_name("source_provenance.py")
SPEC = importlib.util.spec_from_file_location("router_vpn_source_provenance_identity", SCRIPT)
assert SPEC and SPEC.loader
PROV = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROV
SPEC.loader.exec_module(PROV)


def regular_file(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    os.chmod(path, 0o644)


def test_record_hash_and_publication_share_one_snapshot(root: Path) -> None:
    source = root / "source.bin"
    publish = root / "published.bin"
    original = b"owned-source-snapshot\n"
    replacement = b"foreign-source-replacement\n"
    regular_file(source, original)
    foreign = root / "foreign-source.bin"
    regular_file(foreign, replacement)
    real_read = PROV._read_regular_file
    reads = 0

    def read_then_replace(path: Path) -> bytes:
        nonlocal reads
        body = real_read(path)
        reads += 1
        if Path(path) == source and reads == 1:
            os.replace(foreign, source)
        return body

    with mock.patch.object(PROV, "_read_regular_file", side_effect=read_then_replace):
        record = PROV.build_file_record(
            source_sha="a" * 40,
            platform="linux",
            source=source,
            artifact_name="router-vpn-linux.bin",
            expected_binary_sha256=hashlib.sha256(original).hexdigest(),
            publish_path=publish,
        )

    assert reads == 1
    assert source.read_bytes() == replacement
    assert publish.read_bytes() == original
    assert record["artifact_sha256"] == hashlib.sha256(original).hexdigest()
    assert record["size"] == len(original)


def test_provenance_post_rename_replacement_is_not_accepted(root: Path) -> None:
    target = root / "manifest.json"
    PROV.write_json(target, {"old": True})
    foreign = root / "foreign-manifest.json"
    foreign_body = b'{"foreign":true}\n'
    regular_file(foreign, foreign_body)
    real_replace = PROV.os.replace
    swapped = False

    def replace_then_swap(src, dst):
        nonlocal swapped
        result = real_replace(src, dst)
        if Path(dst) == target and not swapped:
            swapped = True
            real_replace(foreign, target)
        return result

    with mock.patch.object(PROV.os, "replace", side_effect=replace_then_swap):
        try:
            PROV.write_json(target, {"new": True})
        except RuntimeError as exc:
            assert "identity changed before verification" in str(exc)
        else:
            raise AssertionError("provenance writer accepted a foreign post-rename replacement")

    assert target.read_bytes() == foreign_body
    assert not list(root.glob(".manifest.json.provenance-*"))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-provenance-identity-") as td:
        root = Path(td)
        test_record_hash_and_publication_share_one_snapshot(root)
        test_provenance_post_rename_replacement_is_not_accepted(root)
    print("Source provenance snapshot/adoption identity tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
