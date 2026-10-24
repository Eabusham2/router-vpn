#!/usr/bin/env python3
"""Execute both shipping Unix wrappers with local engines and policy doubles."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent


def wait_for(predicate, process=None):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if predicate():
            return
        if process is not None and process.poll() is not None:
            raise AssertionError("wrapper exited before its owned child was ready")
        time.sleep(0.02)
    raise AssertionError("timed out waiting for owned test process")


def run_wrapper(script: str):
    with tempfile.TemporaryDirectory(prefix="router-vpn-wrapper-") as temporary:
        base = Path(temporary)
        modes = base / "modes"
        modes.mkdir()
        root = base / "private"
        runtime = root / "run" / "native-node" / "one"
        runtime.mkdir(parents=True)
        (runtime / "sing-box.json").write_text("{}")
        marker = runtime / "owned.marker"
        marker.write_text("original")
        for name in (script, "runtime-pids.py", "cleanup-private-runtime.py", "native-wrapper-owner.py"):
            shutil.copy2(HERE / name, modes / name)
        core = base / "core"
        core.write_text("#!/usr/bin/env python3\n" + '''import os, signal, sys, time
from pathlib import Path
if sys.argv[1] == "check":
    raise SystemExit(int(os.environ.get("CHECK_RESULT", "0")))
if os.environ.get("EARLY_EXIT"):
    raise SystemExit(23)
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
Path(os.environ["CHILD_OBSERVER"]).write_text(str(os.getpid()))
while True: time.sleep(.02)
''')
        core.chmod(0o700)
        (modes / "select-standard-engine.sh").write_text('router_vpn_standard_engine() { printf "%s\\n" "$TEST_CORE"; }\n')
        policy = base / "policy.log"
        (modes / "kill-switch-platform.py").write_text('import os,sys\nfrom pathlib import Path\np=Path(os.environ["POLICY_OBSERVER"])\nwith p.open("a") as f: f.write(sys.argv[1]+"\\n")\n')
        observer = base / "child.pid"
        env = dict(os.environ, HOMEVPN_ROOT=str(root), HOMEVPN_PROFILE_ID="entry", HOMEVPN_POLICY_PROFILE_ID="exit", HOMEVPN_STANDARD_ENGINE="native", HOMEVPN_EXTERNAL_SESSION="e" * 32, TEST_CORE=str(core), POLICY_OBSERVER=str(policy), CHILD_OBSERVER=str(observer), PYTHONDONTWRITEBYTECODE="1")
        command = ["bash", str(modes / script), "check", str(runtime), "203.0.113.20", "router-vpn"]
        for code in (0, 19):
            result = subprocess.run(command, env=dict(env, CHECK_RESULT=str(code)), capture_output=True, text=True, timeout=8)
            assert (result.returncode == 0) == (code == 0), result.stderr
            assert not policy.exists(), "check changed firewall ownership"
            assert marker.read_text() == "original" and (runtime / "sing-box.json").exists(), "check deleted the prepared runtime"
            assert not list((root / "run").glob("*.pids")), "check changed PID registry"
        # External down may not consume whichever process/directory now exists
        # at an older pathname, including when the caller retries teardown.
        command[2] = "down"
        assert subprocess.run(command, env=env, capture_output=True, timeout=8).returncode == 0
        assert marker.exists() and not policy.exists()
        command[2] = "up"
        wrapper = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        replacement = None
        try:
            mode = "native-standard-exit-linux" if "linux" in script else "native-multihop-darwin"
            registry_path = root / "run" / (mode + ".pids")
            wait_for(lambda: observer.exists() and registry_path.exists(), wrapper)
            first = int(observer.read_text())
            # Register a later owner while the earlier wrapper is still alive.
            replacement = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            registered = subprocess.run([sys.executable, str(modes / "runtime-pids.py"), "record", str(root), mode, str(replacement.pid)], env=env, capture_output=True, timeout=8)
            assert registered.returncode == 0, registered.stderr
            before = registry_path.read_bytes()
            retired = runtime.with_name("retired")
            runtime.rename(retired)
            runtime.mkdir()
            (runtime / "replacement.marker").write_text("replacement")
            wrapper.send_signal(signal.SIGTERM)
            wrapper.communicate(timeout=8)
            assert replacement.poll() is None, "retired wrapper stopped the replacement process"
            assert registry_path.read_bytes() == before, "retired wrapper erased replacement PID ownership"
            assert (runtime / "replacement.marker").read_text() == "replacement", "retired wrapper deleted replacement workspace"
            assert retired.joinpath("owned.marker").exists(), "trap retired a directory outside the controller transaction"
            assert policy.read_text().splitlines() == ["apply"], "wrapper released fail-closed protection"
            assert subprocess.run([sys.executable, str(modes / "runtime-pids.py"), "verified-mode", str(root), mode], env=env, capture_output=True, text=True, timeout=8).stdout.split() == [str(replacement.pid)], "captured child did not stop or replacement identity was lost"
            assert first != replacement.pid
        finally:
            if wrapper.poll() is None:
                wrapper.kill()
                wrapper.wait(timeout=8)
            if replacement is not None:
                replacement.terminate()
                replacement.wait(timeout=8)
        # A core exiting during startup must fail without deleting the
        # workspace or releasing the controller's protection.
        (runtime / "sing-box.json").write_text("{}")
        result = subprocess.run(command, env=dict(env, EARLY_EXIT="1"), capture_output=True, text=True, timeout=8)
        assert result.returncode != 0, "early native exit reported successful startup"
        assert (runtime / "replacement.marker").exists()
        assert "release" not in policy.read_text().splitlines()


def signal_reproof():
    spec = importlib.util.spec_from_file_location("native_wrapper_owner_fixture", HERE / "native-wrapper-owner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    record = {"version": 1, "pid": 12345, "start": "captured-birth", "command_sha256": "a" * 64}
    checks = iter((True, True, False))
    calls = []
    module.matches = lambda _: next(checks)
    module.os = SimpleNamespace(kill=lambda pid, kind: calls.append((pid, kind)))
    module.stop(record)
    assert calls == [(12345, signal.SIGINT)], "replacement identity received the later TERM signal"
    module.matches = lambda _: False
    module.stop(record)
    assert len(calls) == 1, "retired process identity was signalled"


if __name__ == "__main__":
    for script in ("native-standard-exit-linux.sh", "native-multihop-darwin.sh"):
        run_wrapper(script)
        print("PASS shipping " + script + ": check, failed check, replacement ownership, native early exit", flush=True)
    signal_reproof()
    print("PASS captured identity reproof before later signals", flush=True)
