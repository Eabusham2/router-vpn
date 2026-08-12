#!/usr/bin/env python3
"""Fail CI if a public generic Router VPN package contains linked-node material."""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile


def _check_name(name: str) -> None:
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or any(part in ("", ".", "..") for part in p.parts):
        raise ValueError(f"unsafe packaged path: {name}")


def _check_member(name: str, data: bytes) -> None:
    _check_name(name)
    p = PurePosixPath(name.replace("\\", "/"))
    if p.name == "router-vpn-bundle.json":
        raise ValueError(f"generic package contains private bundle: {name}")
    if "generated" in p.parts and data:
        raise ValueError(f"generic package contains generated per-node material: {name}")
    if p.name == "routers.json" and data:
        obj = json.loads(data.decode("utf-8"))
        if obj.get("selected_id") not in (None, "") or obj.get("profiles") not in (None, []):
            raise ValueError(f"generic package contains linked router profiles: {name}")


def scan_zip(path: Path) -> None:
    saw_license = False
    with zipfile.ZipFile(path) as zf:
        for item in zf.infolist():
            if item.is_dir():
                _check_name(item.filename.rstrip("/"))
                continue
            data = zf.read(item)
            _check_member(item.filename, data)
            if PurePosixPath(item.filename).name == "LICENSE":
                saw_license = True
    if not saw_license:
        raise ValueError(f"package does not ship LICENSE: {path.name}")


def scan_tgz(path: Path) -> None:
    saw_license = False
    with tarfile.open(path, "r:gz") as tf:
        for item in tf.getmembers():
            _check_name(item.name.rstrip("/"))
            if not item.isfile():
                continue
            f = tf.extractfile(item)
            data = f.read() if f else b""
            _check_member(item.name, data)
            if PurePosixPath(item.name).name == "LICENSE":
                saw_license = True
    if not saw_license:
        raise ValueError(f"package does not ship LICENSE: {path.name}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("package_dir")
    args = ap.parse_args()
    root = Path(args.package_dir)
    archives = sorted(root.glob("RouterVPN-*.zip")) + sorted(root.glob("RouterVPN-*.tar.gz"))
    if not archives:
        raise SystemExit("no generic Router VPN packages found to scan")
    for path in archives:
        if path.suffix == ".zip":
            scan_zip(path)
        else:
            scan_tgz(path)
        print(f"secret-free package OK: {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
