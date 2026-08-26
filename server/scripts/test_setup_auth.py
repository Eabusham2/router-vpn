#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
from unittest import mock

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
        # source contract there without pretending NTFS ACLs are POSIX mode bits.
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        else:
            assert path.is_file() and path.parent.name == "config"
            source = (SCRIPT_DIR / "ensure-setup-auth.py").read_text(encoding="utf-8")
            assert "atomic-private-write.py" in source
            assert "refusing silent rotation" in source
        path2 = auth.ensure_token(base)
        assert path2.read_text().strip() == first, "safe upgrade rotated Setup Center token"

    with tempfile.TemporaryDirectory(prefix="router-vpn-auth-corrupt-") as td:
        base = Path(td)
        config = base / "config"
        config.mkdir()
        path = config / "setup-center.token"
        path.write_text("short\n", encoding="utf-8")
        os.chmod(path, 0o600)
        try:
            auth.ensure_token(base)
        except RuntimeError as exc:
            assert "refusing silent rotation" in str(exc)
        else:
            raise AssertionError("corrupt preserved Setup Center token was silently rotated")
        assert path.read_text(encoding="utf-8") == "short\n"

    if os.name != "nt":
        # Older valid installs may have broad mode bits. Harden the same inode
        # through its verified open fd; never rotate the token while converging.
        with tempfile.TemporaryDirectory(prefix="router-vpn-auth-legacy-mode-") as td:
            base = Path(td)
            config = base / "config"
            config.mkdir(mode=0o700)
            path = config / "setup-center.token"
            legacy = "l" * 48
            path.write_text(legacy + "\n", encoding="utf-8")
            os.chmod(path, 0o644)
            assert auth.ensure_token(base) == path
            assert path.read_text(encoding="utf-8").strip() == legacy
            assert path.stat().st_mode & 0o777 == 0o600

        with tempfile.TemporaryDirectory(prefix="router-vpn-auth-symlink-") as td:
            base = Path(td)
            config = base / "config"
            config.mkdir()
            real = config / "real-token"
            real.write_text("x" * 48 + "\n", encoding="utf-8")
            os.chmod(real, 0o600)
            (config / "setup-center.token").symlink_to(real)
            try:
                auth.ensure_token(base)
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("symlink Setup Center token was accepted")

        with tempfile.TemporaryDirectory(prefix="router-vpn-auth-parent-") as td:
            base = Path(td)
            real_config = base / "real-config"
            real_config.mkdir(mode=0o700)
            real_token = real_config / "setup-center.token"
            real_token.write_text("p" * 48 + "\n", encoding="utf-8")
            os.chmod(real_token, 0o600)
            (base / "config").symlink_to(real_config, target_is_directory=True)
            try:
                auth.ensure_token(base)
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("symlink Setup Center config parent was accepted")
            assert real_token.read_text(encoding="utf-8").strip() == "p" * 48

        with tempfile.TemporaryDirectory(prefix="router-vpn-auth-ancestor-") as td:
            root = Path(td)
            real_base = root / "real-base"
            real_config = real_base / "config"
            real_config.mkdir(parents=True, mode=0o700)
            real_token = real_config / "setup-center.token"
            real_token.write_text("n" * 48 + "\n", encoding="utf-8")
            os.chmod(real_token, 0o600)
            linked_base = root / "linked-base"
            linked_base.symlink_to(real_base, target_is_directory=True)
            try:
                auth.ensure_token(linked_base)
            except RuntimeError as exc:
                assert "symlink" in str(exc) and "path component" in str(exc)
            else:
                raise AssertionError("nested Setup Center symlink ancestor was accepted")
            assert real_token.read_text(encoding="utf-8").strip() == "n" * 48

        with tempfile.TemporaryDirectory(prefix="router-vpn-auth-race-") as td:
            base = Path(td)
            config = base / "config"
            config.mkdir(mode=0o700)
            path = config / "setup-center.token"
            path.write_text("a" * 48 + "\n", encoding="utf-8")
            os.chmod(path, 0o600)
            replacement = config / "replacement-token"
            replacement.write_text("b" * 48 + "\n", encoding="utf-8")
            os.chmod(replacement, 0o600)
            real_fstat = auth.os.fstat
            changed = [False]

            def swap_after_open(fd):
                info = real_fstat(fd)
                if not changed[0]:
                    changed[0] = True
                    os.replace(replacement, path)
                return info

            with mock.patch.object(auth.os, "fstat", side_effect=swap_after_open):
                try:
                    auth.ensure_token(base)
                except RuntimeError as exc:
                    assert "changed during open" in str(exc)
                else:
                    raise AssertionError("Setup Center token replacement race was accepted")

        with tempfile.TemporaryDirectory(prefix="router-vpn-auth-read-race-") as td:
            base = Path(td)
            config = base / "config"
            config.mkdir(mode=0o700)
            path = config / "setup-center.token"
            path.write_text("c" * 48 + "\n", encoding="utf-8")
            os.chmod(path, 0o600)
            replacement = config / "replacement-token"
            replacement.write_text("d" * 48 + "\n", encoding="utf-8")
            os.chmod(replacement, 0o600)
            real_read = auth.os.read
            changed = [False]

            def swap_after_bytes(fd, size):
                chunk = real_read(fd, size)
                if chunk and not changed[0]:
                    changed[0] = True
                    os.replace(replacement, path)
                return chunk

            with mock.patch.object(auth.os, "read", side_effect=swap_after_bytes):
                try:
                    auth.read_preserved_token(path)
                except RuntimeError as exc:
                    assert "changed during read" in str(exc)
                else:
                    raise AssertionError("Setup Center token post-read replacement race was accepted")
            assert path.read_text(encoding="utf-8").strip() == "d" * 48

    # Pairing accepts only explicit RFC1918/ULA plus loopback/link-local. Do not
    # use ipaddress.is_private here: Python intentionally treats additional
    # non-globally-routable/documentation ranges as private, which is too broad
    # for a LAN-only authentication boundary.
    for source in (
        "192.168.50.10",
        "10.77.0.2",
        "172.16.4.3",
        "172.31.255.254",
        "fd77:77::2",
        "fc00::1234",
        "127.0.0.1",
        "::1",
        "169.254.10.2",
        "fe80::1%en0",
    ):
        assert pair.lan_source(source), source
    for source in (
        "8.8.8.8",
        "1.1.1.1",
        "192.0.2.10",
        "198.51.100.10",
        "203.0.113.10",
        "100.64.0.1",
        "0.0.0.0",
        "::",
        "2001:4860:4860::8888",
    ):
        assert not pair.lan_source(source), source

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

    print("Setup Center auth + strict LAN pairing tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
