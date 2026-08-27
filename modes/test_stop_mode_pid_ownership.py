#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
STOP = HERE / "stop-mode.sh"
PIDS = HERE / "runtime-pids.py"


def main() -> int:
    source = STOP.read_text(encoding="utf-8")
    assert 'runtime-pids.py' in source
    assert 'verified "$ROOT"' in source
    assert 'clear "$ROOT"' in source
    assert 'cat "$RUN"/*.pids' not in source
    assert "pkill -f" not in source

    with tempfile.TemporaryDirectory(prefix="router-vpn-stop-pids-") as td:
        root = Path(td) / "root"
        root.mkdir()
        mode = "test-owned"
        subprocess.run(["python3", str(PIDS), "init", str(root), mode], check=True)
        subprocess.run(["python3", str(PIDS), "record", str(root), mode, str(os.getpid())], check=True)

        # A legacy/raw PID registry is deliberately malformed and must never be
        # converted into kill input by central disconnect.
        legacy = root / "run" / "legacy.pids"
        legacy.write_text("999999\n", encoding="utf-8")
        os.chmod(legacy, 0o600)

        bindir = Path(td) / "bin"
        bindir.mkdir()
        log = Path(td) / "sudo.log"
        sudo = bindir / "sudo"
        sudo.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$ROUTER_VPN_TEST_SUDO_LOG\"\n"
            "exit 0\n",
            encoding="utf-8",
        )
        sudo.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        env["HOMEVPN_ROOT"] = str(root)
        env["HOMEVPN_KILLSWITCH_HOLD"] = "1"
        env["ROUTER_VPN_TEST_SUDO_LOG"] = str(log)
        proc = subprocess.run(
            ["bash", str(STOP)],
            cwd=HERE,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        calls = log.read_text(encoding="utf-8").splitlines()
        kill_calls = [line for line in calls if line.startswith("kill ")]
        assert kill_calls == [f"kill -TERM {os.getpid()}"], kill_calls
        assert all("999999" not in line for line in calls)
        assert not list((root / "run").glob("*.pids"))

    print("Verified central stop-mode PID ownership tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
