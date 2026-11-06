#!/usr/bin/env python3
from __future__ import annotations

import os
import select
import signal
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
STOP = HERE / "stop-mode.sh"
PIDS = HERE / "runtime-pids.py"


def install_sudo_shim(bindir: Path, log: Path) -> None:
    sudo = bindir / "sudo"
    sudo.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$ROUTER_VPN_TEST_SUDO_LOG\"\n"
        "if [ \"${1:-}\" = kill ]; then shift; /bin/kill \"$@\" 2>/dev/null || true; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    sudo.chmod(0o755)


def run_stop(root: Path, bindir: Path, log: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["HOMEVPN_ROOT"] = str(root)
    env["HOMEVPN_KILLSWITCH_HOLD"] = "1"
    env["ROUTER_VPN_TEST_SUDO_LOG"] = str(log)
    return subprocess.run(
        ["bash", str(STOP)],
        cwd=HERE,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
    )


def owned_ready_child(*, stubborn: bool = False) -> subprocess.Popen[bytes]:
    # The stop fixture owns this exact child's lifetime. A timer cannot retire
    # it before registration, and the readiness byte is emitted only after its
    # requested signal behavior is installed. Production registration still
    # proves the original birth identity and nonempty command hash itself.
    child = subprocess.Popen(
        [sys.executable, "-c",
         "import os,signal,sys; "
         "signal.signal(signal.SIGTERM, signal.SIG_IGN if sys.argv[1]=='ignore' else signal.SIG_DFL); "
         "os.write(1,b'I' if signal.getsignal(signal.SIGTERM)==signal.SIG_IGN else b'T'); "
         "os.read(0,1)",
         "ignore" if stubborn else "terminate"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    try:
        assert child.stdout is not None
        readable, _, _ = select.select([child.stdout], [], [], 5)
        assert readable and child.stdout.read(1) == (b"I" if stubborn else b"T"), "owned child did not acknowledge installed signal behavior"
        assert child.poll() is None, "owned child exited before registration"
        return child
    except BaseException:
        retire_child(child)
        raise


def retire_child(child: subprocess.Popen[bytes]) -> None:
    try:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
    finally:
        if child.stdin is not None:
            child.stdin.close()
        if child.stdout is not None:
            child.stdout.close()


def main() -> int:
    source = STOP.read_text(encoding="utf-8")
    assert 'runtime-pids.py' in source
    assert 'verified-strict "$ROOT"' in source
    assert 'clear "$ROOT"' in source
    assert 'wait_for_owned_exit' in source
    assert 'kill -TERM' in source
    assert 'kill -KILL' in source
    assert 'retaining PID ownership registry for recovery' in source
    assert 'cat "$RUN"/*.pids' not in source
    assert "pkill -f" not in source

    with tempfile.TemporaryDirectory(prefix="router-vpn-stop-pids-") as td:
        root = Path(td) / "root"
        root.mkdir()
        mode = "test-owned"
        child = owned_ready_child()
        try:
            subprocess.run(["python3", str(PIDS), "init", str(root), mode], check=True)
            subprocess.run(["python3", str(PIDS), "record", str(root), mode, str(child.pid)], check=True)

            bindir = Path(td) / "bin"
            bindir.mkdir()
            log = Path(td) / "sudo.log"
            install_sudo_shim(bindir, log)

            proc = run_stop(root, bindir, log)
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert child.wait(timeout=5) == -signal.SIGTERM, "owned child did not retire through TERM"
            calls = log.read_text(encoding="utf-8").splitlines()
            kill_calls = [line for line in calls if line.startswith("kill ")]
            assert kill_calls == [f"kill -TERM {child.pid}"], kill_calls
            assert not list((root / "run").glob("*.pids"))
        finally:
            retire_child(child)

    with tempfile.TemporaryDirectory(prefix="router-vpn-stop-malformed-") as td:
        root = Path(td) / "root"
        root.mkdir()
        mode = "test-owned"
        child = owned_ready_child()
        try:
            subprocess.run(["python3", str(PIDS), "init", str(root), mode], check=True)
            subprocess.run(["python3", str(PIDS), "record", str(root), mode, str(child.pid)], check=True)
            legacy = root / "run" / "legacy.pids"
            legacy.write_text("999999\n", encoding="utf-8")
            os.chmod(legacy, 0o600)
            bindir = Path(td) / "bin"
            bindir.mkdir()
            log = Path(td) / "sudo.log"
            install_sudo_shim(bindir, log)

            proc = run_stop(root, bindir, log)
            assert proc.returncode != 0, proc.stdout + proc.stderr
            assert "retaining ownership metadata" in proc.stderr
            assert child.poll() is None, "strict failure must not guess at process ownership"
            calls = log.read_text(encoding="utf-8").splitlines()
            assert all(not line.startswith("kill ") for line in calls), calls
            assert legacy.exists(), "malformed registry was erased after failed ownership proof"
            assert (root / "run" / f"{mode}.pids").exists(), "valid registry was erased beside malformed peer"
        finally:
            retire_child(child)

    with tempfile.TemporaryDirectory(prefix="router-vpn-stop-stubborn-") as td:
        root = Path(td) / "root"
        root.mkdir()
        mode = "test-stubborn"
        child = owned_ready_child(stubborn=True)
        try:
            subprocess.run(["python3", str(PIDS), "init", str(root), mode], check=True)
            subprocess.run(["python3", str(PIDS), "record", str(root), mode, str(child.pid)], check=True)
            bindir = Path(td) / "bin"
            bindir.mkdir()
            log = Path(td) / "sudo.log"
            install_sudo_shim(bindir, log)

            proc = run_stop(root, bindir, log)
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert child.wait(timeout=5) == -signal.SIGKILL, "stubborn child did not retire through KILL"
            calls = log.read_text(encoding="utf-8").splitlines()
            kill_calls = [line for line in calls if line.startswith("kill ")]
            assert kill_calls == [f"kill -TERM {child.pid}", f"kill -KILL {child.pid}"], kill_calls
            assert not list((root / "run").glob("*.pids"))
        finally:
            retire_child(child)

    print("Verified central stop-mode PID ownership tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
