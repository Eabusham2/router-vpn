#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("router_vpn_private_profile_store", HERE / "private_profile_store.py")
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def write_store(path: Path) -> None:
    path.write_text(json.dumps({"selected_id": "home", "profiles": [{"id": "home"}]}) + "\n", encoding="utf-8")


with tempfile.TemporaryDirectory(prefix="router-vpn-private-profile-store-") as td:
    root = Path(td)
    path = root / "routers.json"
    write_store(path)
    if os.name != "nt":
        os.chmod(path, 0o644)
    checked = mod.private_root(str(root))
    store = mod.read_profile_store(checked)
    assert store["selected_id"] == "home"
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600

    path.write_text("{broken\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o600)
    try:
        mod.read_profile_store(root)
    except RuntimeError as exc:
        assert "cannot safely read" in str(exc)
    else:
        raise AssertionError("corrupt profile store was accepted")

with tempfile.TemporaryDirectory(prefix="router-vpn-private-profile-symlink-") as td:
    root = Path(td)
    real = root / "real.json"
    write_store(real)
    if os.name != "nt":
        os.chmod(real, 0o600)
    link = root / "routers.json"
    try:
        link.symlink_to(real)
    except OSError:
        pass
    else:
        try:
            mod.read_profile_store(root)
        except RuntimeError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("symlink profile store was accepted")

with tempfile.TemporaryDirectory(prefix="router-vpn-private-profile-parent-") as td:
    base = Path(td)
    real_root = base / "real"
    real_root.mkdir()
    write_store(real_root / "routers.json")
    if os.name != "nt":
        os.chmod(real_root / "routers.json", 0o600)
    linked = base / "linked"
    try:
        linked.symlink_to(real_root, target_is_directory=True)
    except OSError:
        pass
    else:
        try:
            mod.private_root(str(linked))
        except RuntimeError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("symlink private root was accepted")

with tempfile.TemporaryDirectory(prefix="router-vpn-private-profile-race-") as td:
    root = Path(td)
    path = root / "routers.json"
    write_store(path)
    if os.name != "nt":
        os.chmod(path, 0o600)
    with mock.patch.object(mod.os.path, "samestat", return_value=False):
        try:
            mod.read_profile_store(root)
        except RuntimeError as exc:
            assert "changed during open" in str(exc)
        else:
            raise AssertionError("profile-store identity swap was accepted")

print("Private runtime profile-store tests: OK")
