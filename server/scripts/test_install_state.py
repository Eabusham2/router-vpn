#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_install_state", HERE / "install-state.py")
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def write_private(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-install-state-") as td:
        base = Path(td) / "state"
        assert MOD.classify(base) == "absent"

        base.mkdir()
        write_private(base / ".env", "WAN_INTERFACE=eth0\nLAN_CIDR=192.168.50.0/24\nADGUARD4=192.168.50.133\n")
        try:
            MOD.classify(base)
        except RuntimeError as exc:
            assert "partial" in str(exc)
        else:
            raise AssertionError("partial install state was accepted")

        write_private(base / ".initialized", "initialized\n")
        assert MOD.classify(base) == "complete"

        os.chmod(base / ".env", 0o644)
        try:
            MOD.classify(base)
        except RuntimeError as exc:
            assert "0600" in str(exc) or "private mode" in str(exc)
        else:
            raise AssertionError("broad .env mode was accepted")
        os.chmod(base / ".env", 0o600)

        write_private(base / ".initialized", "broken\n")
        try:
            MOD.classify(base)
        except RuntimeError as exc:
            assert "marker" in str(exc)
        else:
            raise AssertionError("invalid initialization marker was accepted")
        write_private(base / ".initialized", "initialized\n")

        write_private(base / ".env", "WAN_INTERFACE=eth0\nLAN_CIDR=192.168.50.0/24\n")
        try:
            MOD.classify(base)
        except RuntimeError as exc:
            assert "ADGUARD4" in str(exc)
        else:
            raise AssertionError("incomplete .env was accepted")

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-install-state-link-") as td:
            root = Path(td)
            base = root / "state"
            outside = root / "outside"
            base.mkdir()
            outside.mkdir()
            write_private(outside / "env", "WAN_INTERFACE=eth0\nLAN_CIDR=x\nADGUARD4=x\n")
            (base / ".env").symlink_to(outside / "env")
            write_private(base / ".initialized", "initialized\n")
            try:
                MOD.classify(base)
            except (OSError, RuntimeError) as exc:
                assert "symlink" in str(exc) or "private" in str(exc)
            else:
                raise AssertionError("symlinked .env was accepted")

    print("Verified install-state classifier tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
