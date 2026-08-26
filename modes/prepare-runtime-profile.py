#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import tempfile

MAX_FILE = 16 << 20
MAX_TOTAL = 64 << 20


def require_dir(path: Path, label: str) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink {label}: {path}")
    return info


def ensure_child(root: Path, path: Path, label: str) -> Path:
    root = root.resolve(strict=True)
    candidate = Path(os.path.abspath(path))
    try:
        rel = candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"{label} escapes Router VPN root") from exc
    current = root
    for part in rel.parts[:-1]:
        current = current / part
        require_dir(current, f"{label} ancestor")
    return candidate


def ensure_run_dir(root: Path) -> Path:
    root = root.resolve(strict=True)
    run = root / "run"
    try:
        info = run.lstat()
    except FileNotFoundError:
        run.mkdir(mode=0o700)
        info = run.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"refusing non-directory/symlink runtime directory: {run}")
    try:
        os.chmod(run, 0o700)
    except OSError:
        pass
    return run


def read_regular(path: Path) -> tuple[bytes, int]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"runtime profile contains non-regular/symlink file: {path}")
    if before.st_size < 0 or before.st_size > MAX_FILE:
        raise RuntimeError(f"runtime profile file exceeds safety limit: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(opened, current):
            raise RuntimeError(f"runtime profile file changed during open: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1 << 20, MAX_FILE + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_FILE:
                raise RuntimeError(f"runtime profile file exceeds safety limit: {path}")
        return b"".join(chunks), opened.st_mode
    finally:
        os.close(fd)


def patch_json(obj, endpoint: str, final_root: Path) -> None:
    if isinstance(obj, dict):
        outbounds = obj.get("outbounds")
        if isinstance(outbounds, list):
            for outbound in outbounds:
                if not isinstance(outbound, dict):
                    continue
                if outbound.get("tag") in ("proxy", "outer", "transport") and isinstance(outbound.get("server"), str):
                    outbound["server"] = endpoint
                settings = outbound.get("settings")
                if isinstance(settings, dict):
                    vnext_list = settings.get("vnext") if isinstance(settings.get("vnext"), list) else []
                    for vnext in vnext_list:
                        if isinstance(vnext, dict) and "address" in vnext:
                            vnext["address"] = endpoint
        for key, value in list(obj.items()):
            if key in ("endpoint", "remote_address") and isinstance(value, str):
                obj[key] = endpoint
            elif key in ("certificate_path", "key_path") and isinstance(value, str) and not value.startswith("/"):
                obj[key] = str(final_root / value)
            else:
                patch_json(value, endpoint, final_root)
    elif isinstance(obj, list):
        for value in obj:
            patch_json(value, endpoint, final_root)


def patch_text(body: str, endpoint: str) -> str:
    host = f"[{endpoint}]" if ":" in endpoint else endpoint
    body = re.sub(
        r"(?m)^(Endpoint\s*=\s*).*:(\d+)\s*$",
        lambda m: f"{m.group(1)}{host}:{m.group(2)}",
        body,
    )

    def repl(match: re.Match[str]) -> str:
        prefix, old, quote = match.group(1), match.group(2), match.group(3)
        port = re.search(r":(\d+)$", old)
        return f"{prefix}{host}:{port.group(1)}{quote}" if port else f"{prefix}{endpoint}{quote}"

    return re.sub(r"(?m)^(endpoint\s*=\s*[\"'])(.*?)([\"'])", repl, body)


def transform(rel: Path, body: bytes, endpoint: str, final_root: Path) -> bytes:
    if rel.suffix.lower() == ".json":
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return body
        patch_json(value, endpoint, final_root)
        return (json.dumps(value, indent=2) + "\n").encode("utf-8")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    return patch_text(text, endpoint).encode("utf-8")


def copy_profile(source: Path, stage: Path, final_root: Path, endpoint: str) -> None:
    require_dir(source, "runtime profile source")
    total = 0
    for path in sorted(source.rglob("*")):
        rel = path.relative_to(source)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"runtime profile source contains symlink: {path}")
        target = stage / rel
        if stat.S_ISDIR(info.st_mode):
            target.mkdir(mode=0o700)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"runtime profile source contains non-regular entry: {path}")
        body, mode = read_regular(path)
        body = transform(rel, body, endpoint, final_root)
        total += len(body)
        if total > MAX_TOTAL:
            raise RuntimeError("runtime profile tree exceeds safety limit")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fchmod(fd, 0o700 if mode & 0o111 else 0o600)
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)


def sync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def adopt(run: Path, stage: Path, dest: Path) -> None:
    require_dir(run, "runtime directory")
    backup: Path | None = None
    committed = False
    try:
        try:
            info = dest.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RuntimeError(f"refusing non-directory/symlink prior runtime profile: {dest}")
            backup = run / f".{dest.name}.backup-{secrets.token_hex(8)}"
            os.rename(dest, backup)
        try:
            os.rename(stage, dest)
            committed = True
        except Exception:
            if backup is not None and backup.exists() and not dest.exists():
                os.rename(backup, dest)
                backup = None
            raise
        sync_dir(run)
        # New runtime tree is authoritative after rename. Old-tree cleanup must
        # never be reported as a false post-commit failure.
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
            backup = None
    finally:
        if not committed and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        if not committed and backup is not None and backup.exists() and not dest.exists():
            try:
                os.rename(backup, dest)
            except OSError:
                pass


def prepare(root_text: str, profile_id: str, mode: str, endpoint: str) -> Path:
    root = Path(root_text).resolve(strict=True)
    run = ensure_run_dir(root)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", profile_id):
        raise RuntimeError("invalid runtime profile id")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", mode):
        raise RuntimeError("invalid runtime mode id")
    endpoint = endpoint.strip().strip("[]")
    if not endpoint or any(ch in endpoint for ch in "\r\n\x00"):
        raise RuntimeError("invalid runtime endpoint")

    dest = ensure_child(root, run / f"profile-{profile_id}-{mode}", "runtime profile destination")
    stage = Path(tempfile.mkdtemp(prefix=f".{dest.name}.stage-", dir=run))
    os.chmod(stage, 0o700)
    adopted = False
    try:
        if mode != "all":
            primary = root / "generated" / profile_id / mode
            fallback = root / "generated" / mode
            source = primary if primary.is_dir() else fallback
            source = ensure_child(root, source, "runtime profile source")
            copy_profile(source, stage, dest, endpoint)
        sync_dir(stage)
        adopt(run, stage, dest)
        adopted = True
        return dest
    finally:
        if not adopted and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 5:
            raise RuntimeError("usage: prepare-runtime-profile.py ROOT PROFILE_ID MODE ENDPOINT")
        print(prepare(argv[1], argv[2], argv[3], argv[4]))
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"runtime profile staging error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
