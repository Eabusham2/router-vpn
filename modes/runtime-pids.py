#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MAX_FILE = 64 << 10
MAX_RECORDS = 128
VERSION = 1


def run_dir(root_text: str) -> Path:
    root = Path(root_text).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("Router VPN root is not a directory")
    run = root / "run"
    try:
        info = run.lstat()
    except FileNotFoundError:
        run.mkdir(mode=0o700)
        info = run.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink runtime PID directory: {run}")
    try:
        os.chmod(run, 0o700)
    except OSError:
        pass
    return run


def mode_file(root_text: str, mode: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", mode):
        raise RuntimeError("invalid runtime PID mode")
    return run_dir(root_text) / f"{mode}.pids"


def process_start(pid: int) -> str:
    if pid <= 1:
        raise RuntimeError("invalid runtime PID")
    proc = Path(f"/proc/{pid}/stat")
    if proc.is_file():
        text = proc.read_text(encoding="utf-8", errors="strict")
        close = text.rfind(")")
        if close < 0:
            raise RuntimeError("invalid /proc stat")
        fields = text[close + 2 :].split()
        if len(fields) <= 19:
            raise RuntimeError("short /proc stat")
        return "linux:" + fields[19]
    try:
        out = subprocess.check_output(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"cannot identify runtime PID {pid}") from exc
    if not out:
        raise RuntimeError(f"cannot identify runtime PID {pid}")
    return "ps:" + out


def process_command_hash(pid: int) -> str:
    proc = Path(f"/proc/{pid}/cmdline")
    try:
        body = proc.read_bytes() if proc.is_file() else subprocess.check_output(
            ["ps", "-o", "command=", "-p", str(pid)], stderr=subprocess.DEVNULL, timeout=2
        )
    except Exception:
        body = b""
    return hashlib.sha256(body[:8192]).hexdigest() if body else ""


def read_registry(path: Path) -> list[dict]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return []
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"refusing non-regular/symlink runtime PID registry: {path}")
    if info.st_size < 0 or info.st_size > MAX_FILE:
        raise RuntimeError(f"runtime PID registry exceeds safety limit: {path}")
    if os.name != "nt" and info.st_mode & 0o077:
        raise RuntimeError(f"runtime PID registry must be private 0600: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"runtime PID registry changed during open: {path}")
        body = os.read(fd, MAX_FILE + 1)
    finally:
        os.close(fd)
    if len(body) > MAX_FILE:
        raise RuntimeError(f"runtime PID registry exceeds safety limit: {path}")
    if not body:
        return []
    records: list[dict] = []
    for raw in body.decode("utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"runtime PID registry contains legacy/untrusted record: {path}") from exc
        if not isinstance(value, dict) or value.get("version") != VERSION:
            raise RuntimeError(f"runtime PID registry contains unsupported record: {path}")
        records.append(value)
    if len(records) > MAX_RECORDS:
        raise RuntimeError(f"runtime PID registry has too many records: {path}")
    return records


def atomic_write(path: Path, records: list[dict]) -> None:
    if len(records) > MAX_RECORDS:
        raise RuntimeError("too many runtime PID records")
    body = b"".join((json.dumps(x, sort_keys=True, separators=(",", ":")) + "\n").encode() for x in records)
    if len(body) > MAX_FILE:
        raise RuntimeError("runtime PID registry exceeds safety limit")
    run = path.parent
    before = run.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise RuntimeError("runtime PID parent is unsafe")
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if current is not None and (stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)):
        raise RuntimeError(f"refusing non-regular/symlink runtime PID target: {path}")
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.pid-", dir=run)
    tmp = Path(name)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        after = run.lstat()
        if stat.S_ISLNK(after.st_mode) or not stat.S_ISDIR(after.st_mode) or not os.path.samestat(before, after):
            raise RuntimeError("runtime PID parent changed before adoption")
        try:
            target = path.lstat()
        except FileNotFoundError:
            target = None
        if target is not None and (stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode)):
            raise RuntimeError("runtime PID target changed before adoption")
        os.replace(tmp, path)
        committed = True
        try:
            dfd = os.open(run, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if not committed:
            tmp.unlink(missing_ok=True)


def init(root: str, mode: str) -> None:
    atomic_write(mode_file(root, mode), [])


def record(root: str, mode: str, pid_text: str) -> None:
    try:
        pid = int(pid_text)
    except ValueError as exc:
        raise RuntimeError("invalid runtime PID") from exc
    start = process_start(pid)
    command_hash = process_command_hash(pid)
    if not command_hash:
        raise RuntimeError(f"cannot identify runtime PID {pid} command")
    path = mode_file(root, mode)
    records = read_registry(path)
    if any(
        int(x.get("pid") or 0) == pid
        and str(x.get("start") or "") == start
        and str(x.get("command_sha256") or "") == command_hash
        for x in records
    ):
        return
    records.append({
        "version": VERSION,
        "pid": pid,
        "start": start,
        "command_sha256": command_hash,
    })
    atomic_write(path, records)


def verified(root: str) -> list[int]:
    run = run_dir(root)
    out: list[int] = []
    for path in sorted(run.glob("*.pids")):
        try:
            records = read_registry(path)
        except RuntimeError:
            # Never turn a malformed/stale PID file into sudo kill input.
            continue
        for item in records:
            try:
                pid = int(item.get("pid") or 0)
                expected_start = str(item.get("start") or "")
                expected_command = str(item.get("command_sha256") or "")
                if (
                    expected_start
                    and expected_command
                    and process_start(pid) == expected_start
                    and process_command_hash(pid) == expected_command
                ):
                    out.append(pid)
            except (RuntimeError, ValueError, TypeError):
                continue
    return sorted(set(out))


def clear(root: str) -> None:
    run = run_dir(root)
    for path in sorted(run.glob("*.pids")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            path.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "init":
            init(argv[2], argv[3]); return 0
        if len(argv) == 5 and argv[1] == "record":
            record(argv[2], argv[3], argv[4]); return 0
        if len(argv) == 3 and argv[1] == "verified":
            for pid in verified(argv[2]):
                print(pid)
            return 0
        if len(argv) == 3 and argv[1] == "clear":
            clear(argv[2]); return 0
        raise RuntimeError("usage: runtime-pids.py init ROOT MODE | record ROOT MODE PID | verified ROOT | clear ROOT")
    except (OSError, RuntimeError) as exc:
        print(f"runtime PID error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
