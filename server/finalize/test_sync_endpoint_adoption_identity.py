#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

SCRIPT = Path(__file__).with_name("sync-endpoint.py")
SPEC = importlib.util.spec_from_file_location("router_vpn_sync_endpoint_identity", SCRIPT)
assert SPEC and SPEC.loader
SYNC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SYNC
SPEC.loader.exec_module(SYNC)


def private_file(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    os.chmod(path, 0o600)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-sync-endpoint-identity-") as td:
        base = Path(td)
        wg = base / "client-bundle/generated/wg/wg.conf"
        awg = base / "client-bundle/generated/awg2-fast/awg.conf"
        private_file(wg, b"[Peer]\nEndpoint = old.example:51820\n")
        private_file(awg, b"[Peer]\nEndpoint = old.example:51822\n")

        endpoint, rendered = SYNC.parse_endpoint("203.0.113.9")
        changes = SYNC.build_changes(base, endpoint, rendered)
        assert len(changes) >= 2
        first = changes[0]
        foreign = first.path.with_name(first.path.name + ".foreign-immediate")
        foreign_body = b"[Peer]\nEndpoint = foreign-immediate.example:59999\n"
        private_file(foreign, foreign_body)
        real_replace = SYNC.os.replace
        swapped = False

        def replace_then_immediate_foreign_swap(src, dst):
            nonlocal swapped
            result = real_replace(src, dst)
            if Path(dst) == first.path and not swapped:
                swapped = True
                real_replace(foreign, first.path)
            return result

        with mock.patch.object(SYNC.os, "replace", side_effect=replace_then_immediate_foreign_swap):
            try:
                SYNC.apply_transaction(changes)
            except RuntimeError as exc:
                text = str(exc)
                assert "identity changed before verification" in text
                assert "rollback was incomplete" in text
            else:
                raise AssertionError("endpoint sync accepted a foreign post-rename replacement")

        assert first.path.read_bytes() == foreign_body
        for change in changes[1:]:
            assert change.path.read_bytes() == change.before
        assert not list(first.path.parent.glob(f".{first.path.name}.endpoint-*"))

    print("Endpoint sync adoption identity test: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
