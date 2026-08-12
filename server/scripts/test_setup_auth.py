#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


auth = load("router_vpn_setup_auth", SCRIPT_DIR / "ensure-setup-auth.py")
pair = load("router_vpn_pairing", SCRIPT_DIR / "pairing.py")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-auth-test-") as td:
        base = Path(td)
        path = auth.ensure_token(base)
        first = path.read_text().strip()
        assert len(first) >= 32
        # POSIX mode bits are the production Linux/Docker security contract.
        # Windows runners do not faithfully model chmod(0600), so validate the
        # same helper there without pretending NTFS ACLs are POSIX mode bits.
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        else:
            assert path.is_file() and path.parent.name == "config"
            source = (SCRIPT_DIR / "ensure-setup-auth.py").read_text(encoding="utf-8")
            assert "os.chmod(tmp, 0o600)" in source
            assert "os.chmod(path, 0o600)" in source
        path2 = auth.ensure_token(base)
        assert path2.read_text().strip() == first, "safe upgrade rotated Setup Center token"

    assert pair.lan_source("192.168.50.10")
    assert pair.lan_source("10.77.0.2")
    assert pair.lan_source("fd77:77::2")
    assert not pair.lan_source("8.8.8.8")

    manager = pair.PairingManager()
    item = manager.create(90)
    code = item["code"]
    assert len(code) == 6 and code.isdigit()
    assert item["one_time"] is True and item["lan_only"] is True
    manager.redeem(code, "192.168.50.20")
    try:
        manager.redeem(code, "192.168.50.20")
    except PermissionError:
        pass
    else:
        raise AssertionError("one-time pairing code redeemed twice")

    item2 = manager.create(90)
    try:
        manager.redeem(item2["code"], "8.8.8.8")
    except PermissionError:
        pass
    else:
        raise AssertionError("public/non-LAN source redeemed a pairing code")

    print("Setup Center auth + LAN pairing tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
