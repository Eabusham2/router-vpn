#!/usr/bin/env python3
from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
spec = spec_from_file_location("router_vpn_normalize_verified_input", HERE / "normalize-setup-imports.py")
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load normalize-setup-imports.py")
norm = module_from_spec(spec)
spec.loader.exec_module(norm)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-normalize-input-") as td:
        root = Path(td)
        path = root / "setup-assets.json"
        expected = {"endpoint": "vpn.example", "methods": []}
        path.write_text(json.dumps(expected) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
        assert norm.load_private_setup_assets(path) == expected

        os.chmod(path, 0o644)
        try:
            norm.load_private_setup_assets(path)
        except RuntimeError as exc:
            assert "unsafe setup assets source" in str(exc)
        else:
            raise AssertionError("broad setup assets input was accepted")
        os.chmod(path, 0o600)

        path.write_text("{not-json}\n", encoding="utf-8")
        try:
            norm.load_private_setup_assets(path)
        except RuntimeError as exc:
            assert "invalid setup assets JSON" in str(exc)
        else:
            raise AssertionError("invalid setup assets JSON was accepted")

        path.write_text("[]\n", encoding="utf-8")
        try:
            norm.load_private_setup_assets(path)
        except RuntimeError as exc:
            assert "must be an object" in str(exc)
        else:
            raise AssertionError("non-object setup assets JSON was accepted")

        real = root / "real.json"
        real.write_text(json.dumps(expected) + "\n", encoding="utf-8")
        os.chmod(real, 0o600)
        path.unlink()
        try:
            path.symlink_to(real)
        except OSError:
            pass
        else:
            try:
                norm.load_private_setup_assets(path)
            except RuntimeError as exc:
                assert "unsafe setup assets source" in str(exc)
            else:
                raise AssertionError("symlink setup assets input was accepted")

    print("Setup normalizer verified input tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
