#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import pty
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "configure-ai-help.sh"
BATCH = HERE / "atomic-private-batch.py"
READER = HERE / "verified-regular-read.py"


def private_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)


def run_tty(script: Path, config: Path, args: list[str], input_text: str) -> subprocess.CompletedProcess[str]:
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(
            ["sh", str(script), *args],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "ROUTER_VPN_CONFIG_DIR": str(config)},
        )
        os.close(slave)
        slave = -1
        os.write(master, input_text.encode())
        stdout, stderr = proc.communicate(timeout=15)
        return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)


def assert_private(path: Path, expected: str) -> None:
    assert path.read_text(encoding="utf-8") == expected
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600, (path, oct(path.stat().st_mode & 0o777))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-ai-state-") as td:
        root = Path(td)
        config = root / "config"
        config.mkdir(mode=0o700)
        private_write(config / "openai-model", "legacy-model\n")
        private_write(config / "openai-api.key", "legacy-secret-key-material\n")

        proc = run_tty(
            SCRIPT,
            config,
            ["configure", "local", "router-local-model"],
            "http://127.0.0.1:8000/v1\n\n",
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert_private(config / "ai-provider", "local\n")
        assert_private(config / "ai-model", "router-local-model\n")
        assert_private(config / "ai-web-access", "off\n")
        assert_private(config / "ai-base-url", "http://127.0.0.1:8000/v1\n")
        assert not (config / "ai-api.key").exists()
        assert not (config / "openai-model").exists()
        assert not (config / "openai-api.key").exists()

        status = subprocess.run(
            ["sh", str(SCRIPT), "status"],
            env={**os.environ, "ROUTER_VPN_CONFIG_DIR": str(config)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        assert status.returncode == 0, (status.stdout, status.stderr)
        assert "provider: local" in status.stdout
        assert "API key: not set" in status.stdout
        assert "127.0.0.1" not in status.stdout, "status leaked the configured private base URL"

        # A symlinked status field must fail closed and must not print the target.
        model = config / "ai-model"
        model.unlink()
        secret_target = root / "unrelated-secret"
        private_write(secret_target, "DO-NOT-PRINT\n")
        if os.name != "nt":
            model.symlink_to(secret_target)
            poisoned = subprocess.run(
                ["sh", str(SCRIPT), "status"],
                env={**os.environ, "ROUTER_VPN_CONFIG_DIR": str(config)},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            assert poisoned.returncode != 0, poisoned.stdout
            assert "DO-NOT-PRINT" not in poisoned.stdout + poisoned.stderr
            model.unlink()
        private_write(model, "router-local-model\n")

        disabled = subprocess.run(
            ["sh", str(SCRIPT), "disable"],
            env={**os.environ, "ROUTER_VPN_CONFIG_DIR": str(config)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        assert disabled.returncode == 0, (disabled.stdout, disabled.stderr)
        for name in (
            "ai-provider", "ai-model", "ai-api.key", "ai-base-url", "ai-web-access",
            "openai-model", "openai-api.key",
        ):
            assert not (config / name).exists(), name

    # Prove configure has no file-at-a-time commit edge before the batch helper:
    # use a helper that can validate/create the parent when imported but always
    # fails when invoked as the transaction command.
    with tempfile.TemporaryDirectory(prefix="router-vpn-ai-state-fault-") as td:
        root = Path(td)
        tools = root / "tools"
        tools.mkdir()
        config = root / "config"
        config.mkdir(mode=0o700)
        copied_script = tools / "configure-ai-help.sh"
        shutil.copyfile(SCRIPT, copied_script)
        shutil.copyfile(READER, tools / "verified-regular-read.py")
        (tools / "atomic-private-batch.py").write_text(
            """#!/usr/bin/env python3
from pathlib import Path

def ensure_private_parent(path, create=True):
    parent = Path(path).parent
    if create:
        parent.mkdir(parents=True, exist_ok=True)
    if not parent.is_dir():
        raise RuntimeError("unsafe parent")

if __name__ == "__main__":
    raise SystemExit("injected transaction failure")
""",
            encoding="utf-8",
        )
        private_write(config / "ai-provider", "openai\n")
        private_write(config / "ai-model", "old-model\n")
        private_write(config / "ai-web-access", "on\n")
        private_write(config / "ai-api.key", "old-provider-key-123456\n")

        before = {p.name: p.read_bytes() for p in config.iterdir()}
        failed = run_tty(
            copied_script,
            config,
            ["configure", "local", "new-model"],
            "http://127.0.0.1:9000/v1\n\n",
        )
        assert failed.returncode != 0
        after = {p.name: p.read_bytes() for p in config.iterdir() if ".input." not in p.name}
        assert after == before, (before, after)

        failed_disable = subprocess.run(
            ["sh", str(copied_script), "disable"],
            env={**os.environ, "ROUTER_VPN_CONFIG_DIR": str(config)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        assert failed_disable.returncode != 0
        after_disable = {p.name: p.read_bytes() for p in config.iterdir() if ".input." not in p.name}
        assert after_disable == before

    print("AI Help private configuration transaction tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
