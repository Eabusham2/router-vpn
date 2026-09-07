#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from network_context import GeneratedProfileSafetyError


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = load("router_vpn_mtu_policy_fail_closed", "mtu-policy.py")
TUNER = load("router_vpn_mtu_tuner_fail_closed", "mtu-throughput-tuner.py")


def require_safety_failure(label: str, call) -> None:
    try:
        call()
    except GeneratedProfileSafetyError:
        return
    except Exception as exc:
        raise AssertionError(f"{label} raised the wrong exception type: {type(exc).__name__}: {exc}") from exc
    raise AssertionError(f"{label} swallowed unsafe generated-profile state")


def main() -> None:
    if os.name == "nt":
        print("Generated profile fingerprint fail-closed test: SKIP symlink case on Windows")
        return
    with tempfile.TemporaryDirectory(prefix="router-vpn-generated-fingerprint-") as td:
        root = Path(td)
        outside = root / "outside"
        outside.mkdir()
        (outside / "sing-box.json").write_text('{"server":"203.0.113.10","server_port":8388}\n')
        generated = root / "generated" / "node"
        generated.mkdir(parents=True)
        (generated / "shadowsocks").symlink_to(outside, target_is_directory=True)

        old = {key: os.environ.get(key) for key in (
            "HOMEVPN_PROFILE_ID", "HOMEVPN_MODE", "HOMEVPN_LOGICAL_MODE",
            "HOMEVPN_BASE", "HOMEVPN_IP_FAMILY", "HOMEVPN_NETWORK_CONTEXT",
        )}
        os.environ.update({
            "HOMEVPN_PROFILE_ID": "node",
            "HOMEVPN_MODE": "shadowsocks",
            "HOMEVPN_LOGICAL_MODE": "shadowsocks",
            "HOMEVPN_BASE": "wg",
            "HOMEVPN_IP_FAMILY": "4",
            "HOMEVPN_NETWORK_CONTEXT": "test-network",
        })
        try:
            require_safety_failure(
                "pre-connect MTU policy",
                lambda: POLICY.path_context(root, "203.0.113.10", "shadowsocks"),
            )
            require_safety_failure(
                "post-connect MTU throughput tuner",
                lambda: TUNER.path_context(
                    {"id": "node", "endpoint": "203.0.113.10", "mtu_policy": "auto"},
                    root,
                ),
            )
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    print("Generated profile fingerprint fail-closed tests: OK")


if __name__ == "__main__":
    main()
