#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

base = Path(sys.argv[1] if len(sys.argv) > 1 else "/opt/router-vpn")
root = base / "client-bundle" / "generated"
helper = Path(__file__).with_name("atomic-private-batch.py")

branches = {
    "max-tls-wg": ("wg-pq", "10.77.0.1"),
    "max-quic-wg": ("wg-pq", "10.77.0.1"),
    "max-tls-awg": ("awg2-pq", "10.78.0.1"),
    "max-quic-awg": ("awg2-pq", "10.78.0.1"),
}
files = [
    "rosenpass.toml",
    "rosenpass.env",
    "rosenpass-client-public",
    "rosenpass-client-secret",
    "rosenpass-server-public",
]


def regular_nonempty(path: Path, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise RuntimeError(f"missing/unsafe {label}: {path}")


def main() -> int:
    tmp_root = Path(tempfile.mkdtemp(prefix=".max-pq-", dir=root))
    batch_args = [sys.executable, str(helper)]
    try:
        for branch, (source_name, tunnel_host) in branches.items():
            src = root / source_name
            dst = root / branch
            if not dst.is_dir() or dst.is_symlink():
                raise RuntimeError(f"missing/unsafe MAX branch: {branch}")
            regular_nonempty(dst / "chain.env", "MAX chain metadata")
            staged = tmp_root / branch
            staged.mkdir()
            for name in files:
                source = src / name
                regular_nonempty(source, "Rosenpass prerequisite")
                shutil.copy2(source, staged / name)
                os.chmod(staged / name, 0o600)

            toml = staged / "rosenpass.toml"
            text = toml.read_text(encoding="utf-8")
            text, count = re.subn(
                r'(?m)^endpoint\s*=\s*["\'][^"\']+["\']\s*$',
                f'endpoint = "{tunnel_host}:51822"',
                text,
            )
            if count != 1:
                raise RuntimeError(f"expected one Rosenpass endpoint in {src / 'rosenpass.toml'}, found {count}")
            toml.write_text(text, encoding="utf-8")
            os.chmod(toml, 0o600)

            chain = (dst / "chain.env").read_text(encoding="utf-8")
            if "PQ_BASE=" not in chain:
                chain += "PQ_BASE=1\n"
            else:
                chain = re.sub(r"(?m)^PQ_BASE=.*$", "PQ_BASE=1", chain)
            chain, count = re.subn(
                r"(?m)^CHAIN_LAYERS=(.*)$",
                lambda match: "CHAIN_LAYERS=rosenpass-pq>" + match.group(1)
                if not match.group(1).startswith("rosenpass-pq>")
                else match.group(0),
                chain,
            )
            if count != 1:
                raise RuntimeError(f"expected one CHAIN_LAYERS entry in {dst / 'chain.env'}, found {count}")
            staged_chain = staged / "chain.env"
            staged_chain.write_text(chain, encoding="utf-8")
            os.chmod(staged_chain, 0o600)

            for name in files + ["chain.env"]:
                batch_args.append(f"{dst / name}={staged / name}")

        subprocess.run(batch_args, check=True)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    print("added live Rosenpass PQ exchange inside all MAX WG/AWG TLS/QUIC branches as one private transaction")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc)) from exc
