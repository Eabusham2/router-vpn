#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_all_result", HERE / "all-result.py")
assert SPEC and SPEC.loader
ALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ALL)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-all-result-") as td:
        root = Path(td)
        target = root / "state" / "selected"

        # Relative result paths are rooted at HOMEVPN_ROOT, independent of cwd.
        ALL.publish(str(root), "state/selected", "max-tls-wg")
        assert target.read_text() == "max-tls-wg\n"
        if os.name != "nt":
            assert target.stat().st_mode & 0o777 == 0o600
        assert not list(target.parent.glob(".selected.all-*"))

        ALL.prepare(str(root), "state/selected")
        assert not target.exists()

        # A failed rename must preserve the prior complete selection.
        ALL.publish(str(root), "state/selected", "max-quic-awg")
        original = target.read_bytes()
        with mock.patch.object(ALL.os, "replace", side_effect=OSError("injected ALL adoption failure")):
            try:
                ALL.publish(str(root), "state/selected", "max-tls-awg")
            except OSError:
                pass
            else:
                raise AssertionError("injected ALL adoption failure did not fail")
        assert target.read_bytes() == original
        assert not list(target.parent.glob(".selected.all-*"))

        try:
            ALL.publish(str(root), "state/selected", "not-a-real-branch")
        except RuntimeError as exc:
            assert "unknown ALL runtime branch" in str(exc)
        else:
            raise AssertionError("ALL result accepted an unknown branch")

        outside = root.parent / (root.name + "-outside")
        outside.mkdir()
        try:
            ALL.publish(str(root), str(outside / "selected"), "max-tls-wg")
        except RuntimeError as exc:
            assert "inside HOMEVPN_ROOT" in str(exc)
        else:
            raise AssertionError("ALL result escaped HOMEVPN_ROOT")

        if os.name != "nt":
            real = root / "real-selected"
            real.write_text("keep\n")
            os.chmod(real, 0o600)
            link = root / "linked-selected"
            link.symlink_to(real)
            try:
                ALL.publish(str(root), str(link), "max-tls-wg")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("ALL result followed a symlink target")
            assert real.read_text() == "keep\n"

            real_dir = root / "real-state"
            real_dir.mkdir()
            linked_dir = root / "linked-state"
            linked_dir.symlink_to(real_dir, target_is_directory=True)
            try:
                ALL.publish(str(root), str(linked_dir / "selected"), "max-tls-wg")
            except RuntimeError as exc:
                assert "symlink" in str(exc) or "inside HOMEVPN_ROOT" in str(exc)
            else:
                raise AssertionError("ALL result followed a symlink ancestor")
            assert not (real_dir / "selected").exists()

    print("ALL runtime result publication tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
