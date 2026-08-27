#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

import source_provenance as prov

OLD = "0123456789abcdef0123456789abcdef01234567"
NEW = "89abcdef0123456789abcdef0123456789abcdef"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-source-provenance-") as td:
        root = Path(td)
        path = prov.write_manifest(root, OLD, "windows-amd64")
        data = prov.verify_manifest(root, OLD, "windows-amd64")
        assert data["source_sha"] == OLD
        assert data["repository"] == "Eabusham2/router-vpn"
        assert path.name == prov.MANIFEST
        assert json.loads(path.read_text())["schema_version"] == 1

        try:
            prov.verify_manifest(root, NEW, "windows-amd64")
        except RuntimeError as exc:
            assert "provenance mismatch" in str(exc)
        else:
            raise AssertionError("wrong exact source SHA was accepted")

        try:
            prov.verify_manifest(root, OLD, "linux-amd64")
        except RuntimeError as exc:
            assert "family mismatch" in str(exc)
        else:
            raise AssertionError("wrong package family was accepted")

        path.write_text('{"schema_version":1,"source_sha":"short"}\n')
        try:
            prov.read_manifest(root)
        except RuntimeError:
            pass
        else:
            raise AssertionError("short source SHA was accepted")

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-source-provenance-link-") as td:
            root = Path(td)
            outside = root / "outside"
            outside.write_text("keep\n")
            link = root / prov.MANIFEST
            link.symlink_to(outside)
            try:
                prov.write_manifest(root, OLD, "windows-amd64")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("source provenance writer followed a symlink target")
            assert outside.read_text() == "keep\n"

    print("Exact source package provenance tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
