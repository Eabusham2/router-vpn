#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_verified_regular_read", HERE / "verified-regular-read.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-public-read-") as td:
        root = Path(td)
        source = root / "helper.sh"
        source.write_bytes(b"#!/bin/sh\necho ok\n")
        os.chmod(source, 0o755)
        assert MOD.read_verified_regular(source) == source.read_bytes()

        catalog = root / "modes.json"
        catalog.write_text('{"ok":true}\n', encoding="utf-8")
        os.chmod(catalog, 0o644)
        assert MOD.read_verified_regular(catalog) == catalog.read_bytes()

        if os.name != "nt":
            real = root / "real.sh"
            real.write_text("keep\n", encoding="utf-8")
            link = root / "link.sh"
            link.symlink_to(real)
            try:
                MOD.read_verified_regular(link)
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("verified public reader accepted symlink leaf")

            outside = root / "outside"
            outside.mkdir()
            (outside / "catalog.json").write_text("outside\n", encoding="utf-8")
            redirected = root / "redirected"
            redirected.symlink_to(outside, target_is_directory=True)
            try:
                MOD.read_verified_regular(redirected / "catalog.json")
            except (OSError, RuntimeError) as exc:
                assert "symlink" in str(exc) or "ancestor" in str(exc)
            else:
                raise AssertionError("verified public reader followed symlink ancestor")

        oversized = root / "oversized.bin"
        oversized.write_bytes(b"x" * 5)
        try:
            MOD.read_verified_regular(oversized, 4)
        except RuntimeError as exc:
            assert "oversized" in str(exc)
        else:
            raise AssertionError("verified public reader accepted oversized input")

    print("Verified public metadata reader tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
