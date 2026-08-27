#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "configure-portainer-update.sh"


def write_exe(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def fake_tools(root: Path) -> Path:
    bindir = root / "bin"
    bindir.mkdir()
    write_exe(
        bindir / "id",
        "#!/bin/sh\n"
        "if [ \"$1\" = -u ]; then echo 0; else /usr/bin/id \"$@\"; fi\n",
    )
    write_exe(bindir / "stty", "#!/bin/sh\nexit 0\n")
    write_exe(
        bindir / "curl",
        "#!/bin/sh\nprintf 200\n",
    )
    write_exe(
        bindir / "openssl",
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  s_client) printf 'fake-local-portainer-certificate\\n' ;;\n"
        "  x509) cat ;;\n"
        "  dgst) cat >/dev/null; printf '%064d *stdin\\n' 0 ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
    )
    return bindir


def run(script_root: Path, base: Path, key: str) -> subprocess.CompletedProcess[str]:
    bindir = fake_tools(script_root)
    env = os.environ.copy()
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["BASE"] = str(base)
    env["PORTAINER_HOST"] = "127.0.0.1"
    env["PORTAINER_PORT"] = "9443"
    return subprocess.run(
        ["sh", str(SCRIPT)],
        input=key + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=HERE.parents[1],
    )


def main() -> int:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "atomic-private-batch.py" in source
    assert ".tmp.$$" not in source
    assert 'mv -f "$KEY_TMP" "$KEY_FILE"' not in source
    assert 'mv -f "$PIN_TMP" "$PIN_FILE"' not in source

    with tempfile.TemporaryDirectory(prefix="router-vpn-portainer-config-") as td:
        root = Path(td)
        base = root / "state"
        key = "private-portainer-api-key-0123456789"
        proc = run(root / "tools1", base, key)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert key not in proc.stdout and key not in proc.stderr
        config = base / "config"
        key_path = config / "portainer-api.key"
        pin_path = config / "portainer-tls.sha256"
        assert key_path.read_text(encoding="utf-8") == key + "\n"
        assert pin_path.read_text(encoding="utf-8") == "0" * 64 + "\n"
        if os.name != "nt":
            assert config.stat().st_mode & 0o777 == 0o700
            assert key_path.stat().st_mode & 0o777 == 0o600
            assert pin_path.stat().st_mode & 0o777 == 0o600
        assert not list(config.glob(".portainer-*.input.*"))

        # Reconfiguration replaces key + pin as one private publication and does
        # not leak either credential into output.
        key2 = "second-private-portainer-key-abcdefgh"
        proc = run(root / "tools2", base, key2)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert key2 not in proc.stdout and key2 not in proc.stderr
        assert key_path.read_text(encoding="utf-8") == key2 + "\n"
        assert pin_path.read_text(encoding="utf-8") == "0" * 64 + "\n"

    if os.name != "nt":
        with tempfile.TemporaryDirectory(prefix="router-vpn-portainer-parent-") as td:
            root = Path(td)
            base = root / "state"
            outside = root / "outside"
            base.mkdir()
            outside.mkdir()
            (base / "config").symlink_to(outside, target_is_directory=True)
            proc = run(root / "tools", base, "private-portainer-api-key-0123456789")
            assert proc.returncode != 0
            assert not list(outside.iterdir()), "symlinked Portainer config parent received credentials"

    print("Portainer update credential transaction tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
