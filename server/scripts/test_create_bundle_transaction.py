#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "create-bundle-json.py"


def private_write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    os.chmod(path, 0o600)


def seed(base: Path) -> None:
    private_write(
        base / "config/router-agent.json",
        json.dumps({"token": "router-token", "wan_interface": "eth0"}) + "\n",
    )
    private_write(
        base / "client-bundle/generated/wg/wg.conf",
        "[Interface]\nPrivateKey = client-private\n[Peer]\nPublicKey = stable-router-public-key\n",
    )
    private_write(
        base / "client-bundle/generated/reality-vision/xray.json",
        '{"outbounds":[]}\n',
    )
    private_write(base / "client-bundle/modes.json", "[]\n")
    private_write(base / "client-bundle/logical-modes.json", "[]\n")


def run(base: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(base),
            "vpn.example",
            "router-token",
            "http://192.168.50.133:8787",
            "192.168.50.133",
            "",
            "",
        ],
        cwd=HERE.parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def canonical(base: Path) -> dict[str, bytes]:
    bundle = base / "client-bundle"
    return {
        name: (bundle / name).read_bytes()
        for name in ("client.json", "routers.json", "router-vpn-bundle.json")
    }


def assert_private_outputs(base: Path) -> None:
    for name in ("client.json", "routers.json", "router-vpn-bundle.json"):
        path = base / "client-bundle" / name
        assert path.is_file() and not path.is_symlink()
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-create-bundle-") as td:
        base = Path(td) / "state"
        seed(base)
        proc = run(base)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert_private_outputs(base)
        before = canonical(base)

        if os.name != "nt":
            outside = Path(td) / "outside-mode"
            outside.mkdir()
            private_write(outside / "secret.json", '{"outside":"secret"}\n')
            evil = base / "client-bundle/generated/evil"
            evil.symlink_to(outside, target_is_directory=True)
            proc = run(base)
            assert proc.returncode != 0
            assert "symlink generated profile entry" in (proc.stdout + proc.stderr)
            assert canonical(base) == before
            evil.unlink()

            target = base / "client-bundle/generated/reality-vision/xray.json"
            real = Path(td) / "outside-file"
            private_write(real, '{"outside":"file"}\n')
            target.unlink()
            target.symlink_to(real)
            proc = run(base)
            assert proc.returncode != 0
            assert "symlink" in (proc.stdout + proc.stderr)
            assert canonical(base) == before
            target.unlink()
            private_write(target, '{"outbounds":[]}\n')

        logical = base / "client-bundle/logical-modes.json"
        private_write(logical, "{broken-json\n")
        proc = run(base)
        assert proc.returncode != 0
        assert "invalid JSON bundle source" in (proc.stdout + proc.stderr)
        assert canonical(base) == before

    print("Verified transactional private bundle generation tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
