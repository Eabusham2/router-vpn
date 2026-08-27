#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("router_vpn_runtime_pids", HERE / "runtime-pids.py")
assert SPEC and SPEC.loader
PIDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PIDS)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-pids-") as td:
        root = Path(td)
        mode = "reality-vision"
        assert PIDS.run_dir(str(root)) == root / "run"
        PIDS.init(str(root), mode)
        path = root / "run" / f"{mode}.pids"
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        PIDS.record(str(root), mode, str(os.getpid()))
        assert os.getpid() in PIDS.verified(str(root))
        assert os.getpid() in PIDS.verified_mode(str(root), mode)
        PIDS.init(str(root), "other-mode")
        assert PIDS.verified_mode(str(root), "other-mode") == []
        assert os.getpid() in PIDS.verified_mode(str(root), mode)
        records = PIDS.read_registry(path)
        assert len(records) == 1 and records[0]["pid"] == os.getpid()
        assert records[0]["command_sha256"], records

        # A stale/reused PID record with the wrong start identity is never
        # returned as kill input even though the numeric PID is currently alive.
        stale = dict(records[0])
        stale["start"] = "wrong-start-token"
        PIDS.atomic_write(path, [stale])
        assert os.getpid() not in PIDS.verified(str(root))

        # An exec/replacement that keeps the same PID and start time but changes
        # command identity must also lose Router VPN ownership.
        wrong_command = dict(records[0])
        wrong_command["command_sha256"] = "0" * 64
        PIDS.atomic_write(path, [wrong_command])
        assert os.getpid() not in PIDS.verified(str(root))

        # Legacy plain numeric PID files are intentionally untrusted.
        path.write_text(f"{os.getpid()}\n", encoding="utf-8")
        os.chmod(path, 0o600)
        assert os.getpid() not in PIDS.verified(str(root))

        # A failed atomic replacement preserves the prior complete registry.
        PIDS.init(str(root), mode)
        PIDS.record(str(root), mode, str(os.getpid()))
        original = path.read_bytes()
        with mock.patch.object(PIDS.os, "replace", side_effect=OSError("injected PID adoption failure")):
            try:
                PIDS.record(str(root), mode, str(os.getppid()))
            except OSError:
                pass
            else:
                # Parent may have already exited in unusual test harnesses. In
                # that case process_start fails before the injected replace.
                pass
        assert path.read_bytes() == original
        assert not list(path.parent.glob(f".{path.name}.pid-*"))

        # Replacing a tracked registry with another regular file while a new
        # version is staged must fail before adoption and preserve the foreign
        # replacement instead of overwriting it.
        foreign = path.parent / "foreign.pids"
        foreign_body = b'{"version":1,"pid":999999,"start":"foreign","command_sha256":"deadbeef"}\n'
        foreign.write_bytes(foreign_body)
        os.chmod(foreign, 0o600)
        real_mkstemp = PIDS.tempfile.mkstemp

        def mkstemp_then_swap(*args, **kwargs):
            fd, name = real_mkstemp(*args, **kwargs)
            os.replace(foreign, path)
            return fd, name

        with mock.patch.object(PIDS.tempfile, "mkstemp", side_effect=mkstemp_then_swap):
            try:
                PIDS.atomic_write(path, records)
            except RuntimeError as exc:
                assert "target identity changed" in str(exc)
            else:
                raise AssertionError("runtime PID replacement race was accepted")
        assert path.read_bytes() == foreign_body
        assert not list(path.parent.glob(f".{path.name}.pid-*"))

        PIDS.clear(str(root))
        assert not path.exists()

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-pids-link-") as td:
            root = Path(td)
            run = root / "run"
            run.mkdir()
            real = root / "real.pids"
            real.write_text("keep\n")
            os.chmod(real, 0o600)
            link = run / "wg.pids"
            link.symlink_to(real)
            try:
                PIDS.record(str(root), "wg", str(os.getpid()))
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("runtime PID registry followed a symlink target")
            assert real.read_text() == "keep\n"
            assert os.getpid() not in PIDS.verified(str(root))
            PIDS.clear(str(root))
            assert not link.exists() and real.read_text() == "keep\n"

        with tempfile.TemporaryDirectory(prefix="router-vpn-runtime-pids-parent-") as td:
            root = Path(td)
            outside = root / "outside"
            outside.mkdir()
            (root / "run").symlink_to(outside, target_is_directory=True)
            try:
                PIDS.init(str(root), "wg")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("runtime PID registry followed a symlink run directory")
            assert not list(outside.iterdir())

    # Darwin transient platform runners must resolve the same verified run
    # directory and must not exec away the EXIT cleanup trap.
    platform_runner = (HERE / "run-platform.sh").read_text(encoding="utf-8")
    assert 'runtime-pids.py" run-dir' in platform_runner
    assert 'bash "$TMP" "$@"' in platform_runner
    assert 'exec bash "$TMP" "$@"' not in platform_runner
    assert 'trap cleanup EXIT INT TERM' in platform_runner

    # Native macOS multihop uses the same birth+command-verified registry;
    # raw numeric PID files are not an ownership boundary.
    native_multihop = (HERE / "native-multihop-darwin.sh").read_text(encoding="utf-8")
    assert 'runtime-pids.py' in native_multihop
    assert 'verified-mode "$ROOT" "$PID_MODE"' in native_multihop
    assert 'record "$ROOT" "$PID_MODE" "$child"' in native_multihop
    assert "native-multihop.pid" not in native_multihop
    assert "PID_FILE" not in native_multihop

    # Every launcher that records background processes must use the verified
    # JSON PID registry. Raw numeric .pids files can target unrelated reused
    # processes after a crash/restart and are forbidden.
    for runner_name in ("run-mode.sh", "run-max.sh", "run-pq.sh", "run-xhttp.sh", "run-combined.sh"):
        runner = (HERE / runner_name).read_text(encoding="utf-8")
        assert 'runtime-pids.py" init' in runner, runner_name
        assert 'runtime-pids.py" record' in runner, runner_name
        assert ': >"$RUN/$MODE.pids"' not in runner, runner_name
        assert 'echo $! >>"$RUN/$MODE.pids"' not in runner, runner_name

    print("Verified runtime PID registry tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
