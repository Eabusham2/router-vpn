#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_cleanup_private_runtime", HERE / "cleanup-private-runtime.py")
assert SPEC and SPEC.loader
CLEAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEAN)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-runtime-") as td:
        root = Path(td)
        run = root / "run"
        owned = run / "multihop"
        owned.mkdir(parents=True)
        (owned / "secret.json").write_text("private\n", encoding="utf-8")
        nested = owned / "nested"
        nested.mkdir()
        (nested / "state").write_text("private\n", encoding="utf-8")
        assert CLEAN.verify_directory(str(root), str(owned)) == owned
        CLEAN.cleanup(str(root), str(owned))
        assert not owned.exists()
        assert not list(run.glob(".router-vpn-cleanup-*"))

        session = run / "native-multihop" / "session-1"
        session.mkdir(parents=True)
        assert CLEAN.verify_directory(str(root), str(session)) == session
        CLEAN.cleanup(str(root), str(session))
        assert not session.exists()

        for category in ("native-node", "native-standard-exit", "openvpn-standard-exit"):
            standard = run / category / "session-1"
            standard.mkdir(parents=True)
            (standard / "secret").write_text("private\n", encoding="utf-8")
            assert CLEAN.verify_directory(str(root), str(standard)) == standard
            CLEAN.cleanup(str(root), str(standard))
            assert not standard.exists()

        # The single-node native launcher owns the category directory itself.
        native_node = run / "native-node"
        (native_node / "profile.json").write_text("private\n", encoding="utf-8")
        assert CLEAN.verify_directory(str(root), str(native_node)) == native_node
        CLEAN.cleanup(str(root), str(native_node))
        assert not native_node.exists()
        assert (run / "native-standard-exit").is_dir(), "another runtime owner was removed"

        # The Tor wrapper needs the same no-follow execution check, while its
        # controller retains exclusive deletion ownership after native drain.
        tor = run / "tor-bridge" / "session-captured"
        tor.mkdir(parents=True)
        private = tor / "tor-profile.json"
        private.write_text("captured private Tor input\n", encoding="utf-8")
        assert CLEAN.verify_directory(str(root), str(tor)) == tor
        for target in (tor, tor.parent):
            try:
                CLEAN.cleanup(str(root), str(target))
            except RuntimeError as exc:
                assert "unrelated" in str(exc)
            else:
                raise AssertionError("verification-only Tor workspace acquired generic deletion authority")
        assert private.read_text(encoding="utf-8") == "captured private Tor input\n"
        tor_deep = tor / "unowned-depth"
        tor_deep.mkdir()
        try:
            CLEAN.verify_directory(str(root), str(tor_deep))
        except RuntimeError as exc:
            assert "deep" in str(exc)
        else:
            raise AssertionError("Tor verification bypassed the existing depth bound")

        # First launch with no run directory is an intentional no-op.
        fresh = root / "fresh"
        fresh.mkdir()
        CLEAN.cleanup(str(fresh), str(fresh / "run" / "multihop"))

        unrelated = run / "wg"
        unrelated.mkdir()
        try:
            CLEAN.cleanup(str(root), str(unrelated))
        except RuntimeError as exc:
            assert "unrelated" in str(exc)
        else:
            raise AssertionError("cleanup accepted unrelated runtime path")
        assert unrelated.is_dir()

        too_deep = run / "multihop" / "one" / "two"
        try:
            CLEAN.cleanup(str(root), str(too_deep))
        except RuntimeError as exc:
            assert "deep" in str(exc)
        else:
            raise AssertionError("cleanup accepted unexpectedly deep runtime path")

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-tor-verify-links-") as td:
            root = Path(td)
            run = root / "run"
            category = run / "tor-bridge"
            category.mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep").write_text("retained\n", encoding="utf-8")
            session = category / "session-linked"
            session.symlink_to(outside, target_is_directory=True)
            for target in (session, category / "session-linked" / "child"):
                try:
                    CLEAN.verify_directory(str(root), str(target))
                except RuntimeError as exc:
                    assert "symlink" in str(exc) or "deep" in str(exc)
                else:
                    raise AssertionError("Tor verification followed a linked/deep runtime")
            session.unlink()
            category.rmdir()
            category.symlink_to(outside, target_is_directory=True)
            try:
                CLEAN.verify_directory(str(root), str(category / "session-linked"))
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("Tor verification followed a linked category")
            assert (outside / "keep").read_text(encoding="utf-8") == "retained\n"

        with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-leaf-link-") as td:
            root = Path(td)
            run = root / "run"
            run.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep").write_text("keep\n", encoding="utf-8")
            owned = run / "multihop"
            owned.symlink_to(outside, target_is_directory=True)
            try:
                CLEAN.verify_directory(str(root), str(owned))
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("runtime execution validator followed an owned symlink leaf")
            CLEAN.cleanup(str(root), str(owned))
            assert not owned.exists(), "owned symlink leaf survived cleanup"
            assert (outside / "keep").read_text(encoding="utf-8") == "keep\n"
            assert not list(run.glob(".router-vpn-cleanup-*"))

        with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-child-link-") as td:
            root = Path(td)
            run = root / "run"
            owned = run / "native-multihop"
            owned.mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep").write_text("keep\n", encoding="utf-8")
            (owned / "outside-link").symlink_to(outside, target_is_directory=True)
            (owned / "owned").write_text("delete\n", encoding="utf-8")
            CLEAN.cleanup(str(root), str(owned))
            assert not owned.exists()
            assert (outside / "keep").read_text(encoding="utf-8") == "keep\n"

        with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-run-link-") as td:
            root = Path(td)
            outside = root / "outside"
            outside.mkdir()
            (outside / "keep").write_text("keep\n", encoding="utf-8")
            (root / "run").symlink_to(outside, target_is_directory=True)
            try:
                CLEAN.cleanup(str(root), str(root / "run" / "multihop"))
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("cleanup followed a symlinked run directory")
            assert (outside / "keep").read_text(encoding="utf-8") == "keep\n"

    native = (HERE / "native-multihop-darwin.sh").read_text(encoding="utf-8")
    assert 'cleanup-private-runtime.py" verify-dir' in native
    assert "os.path.realpath" not in native
    assert '[[ -f "$CONFIG" && ! -L "$CONFIG" ]]' in native

    print("Private runtime no-follow cleanup tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
