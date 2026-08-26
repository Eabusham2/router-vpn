#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def private_json(path: Path, value) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o600)


with tempfile.TemporaryDirectory(prefix="router-vpn-profile-consumers-") as td:
    root = Path(td)
    (root / "modes.json").write_text("[]\n", encoding="utf-8")
    store_path = root / "routers.json"
    valid = {"selected_id": "node", "profiles": [{"id": "node", "dns_mode": "home", "mtu_policy": "auto"}]}
    private_json(store_path, valid)

    old_root = os.environ.get("HOMEVPN_ROOT")
    old_profile = os.environ.get("HOMEVPN_PROFILE_ID")
    os.environ["HOMEVPN_ROOT"] = str(root)
    os.environ["HOMEVPN_PROFILE_ID"] = "node"
    try:
        dns = load("router_vpn_dns_profile_fail_closed", "dns-policy.py")
        mtu = load("router_vpn_mtu_profile_fail_closed", "mtu-policy.py")
        multihop = load("router_vpn_multihop_profile_fail_closed", "multihop.py")
        orchestrate = load("router_vpn_orchestrate_profile_fail_closed", "orchestrate.py")
        tuner = load("router_vpn_mtu_tuner_profile_fail_closed", "mtu-throughput-tuner.py")

        assert dns.load_profile()["id"] == "node"
        assert mtu.load_store(mtu.root_dir())[1]["id"] == "node"
        assert multihop.profile(multihop.read_store(multihop.root_dir()), "node", "test")["id"] == "node"
        assert orchestrate.selected_profile()["id"] == "node"
        assert tuner.load_profile(tuner.root_dir())[1]["id"] == "node"

        store_path.write_text("{broken\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(store_path, 0o600)
        for label, call in (
            ("dns", dns.load_profile),
            ("mtu", lambda: mtu.load_store(mtu.root_dir())),
            ("multihop", lambda: multihop.read_store(multihop.root_dir())),
            ("orchestrate", orchestrate.selected_profile),
            ("mtu-tuner", lambda: tuner.load_profile(tuner.root_dir())),
        ):
            try:
                call()
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"{label} silently fell back after profile-store corruption")

        private_json(store_path, {"selected_id": "missing", "profiles": [{"id": "other"}]})
        for label, call in (
            ("dns", dns.load_profile),
            ("mtu", lambda: mtu.load_store(mtu.root_dir())),
            ("multihop", lambda: multihop.profile(multihop.read_store(multihop.root_dir()), "missing", "test")),
            ("orchestrate", orchestrate.selected_profile),
            ("mtu-tuner", lambda: tuner.load_profile(tuner.root_dir())),
        ):
            try:
                call()
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"{label} silently selected another profile after selected-id loss")

        if os.name != "nt":
            real = root / "real-routers.json"
            private_json(real, valid)
            store_path.unlink()
            store_path.symlink_to(real)
            for label, call in (
                ("dns", dns.load_profile),
                ("mtu", lambda: mtu.load_store(mtu.root_dir())),
                ("multihop", lambda: multihop.read_store(multihop.root_dir())),
                ("orchestrate", orchestrate.selected_profile),
            ("mtu-tuner", lambda: tuner.load_profile(tuner.root_dir())),
            ):
                try:
                    call()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError(f"{label} followed a symlink profile store")
    finally:
        if old_root is None:
            os.environ.pop("HOMEVPN_ROOT", None)
        else:
            os.environ["HOMEVPN_ROOT"] = old_root
        if old_profile is None:
            os.environ.pop("HOMEVPN_PROFILE_ID", None)
        else:
            os.environ["HOMEVPN_PROFILE_ID"] = old_profile

print("Runtime profile-store fail-closed consumer tests: OK")
