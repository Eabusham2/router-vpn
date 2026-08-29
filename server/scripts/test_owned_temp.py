#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import runpy
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
OWNED = runpy.run_path(str(HERE / "owned-temp.py"))
create_owned_temp = OWNED["create_owned_temp"]
mark_owned_temp = OWNED["mark_owned_temp"]
is_owned_temp = OWNED["is_owned_temp"]
cleanup_owned_temp = OWNED["cleanup_owned_temp"]
MARKER_NAME = OWNED["MARKER_NAME"]
MARKER_BODY = OWNED["MARKER_BODY"]


def remove_manual(path: Path) -> None:
    if path.is_symlink():
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path, ignore_errors=True)


def main() -> int:
    owned = create_owned_temp("router-vpn-request-")
    try:
        assert is_owned_temp(owned)
        marker = owned / MARKER_NAME
        assert marker.read_bytes() == MARKER_BODY
        if os.name != "nt":
            assert owned.stat().st_mode & 0o777 == 0o700
            assert marker.stat().st_mode & 0o777 == 0o600
        assert cleanup_owned_temp(owned) is True
        assert not owned.exists()
    finally:
        remove_manual(owned)

    foreign = Path(tempfile.mkdtemp(prefix="router-vpn-job-"))
    try:
        os.chmod(foreign, 0o700)
        sentinel = foreign / "foreign.txt"
        sentinel.write_text("keep\n", encoding="utf-8")
        assert not is_owned_temp(foreign)
        assert cleanup_owned_temp(foreign) is False
        assert sentinel.read_text(encoding="utf-8") == "keep\n"
    finally:
        remove_manual(foreign)

    if os.name != "nt":
        target = Path(tempfile.mkdtemp(prefix="not-router-vpn-owned-"))
        link = Path(tempfile.gettempdir()) / ("router-vpn-job-link-" + next(tempfile._get_candidate_names()))
        try:
            sentinel = target / "sentinel"
            sentinel.write_text("keep\n", encoding="utf-8")
            link.symlink_to(target, target_is_directory=True)
            assert cleanup_owned_temp(link) is False
            assert link.is_symlink()
            assert sentinel.read_text(encoding="utf-8") == "keep\n"
        finally:
            remove_manual(link)
            remove_manual(target)

        forged = Path(tempfile.mkdtemp(prefix="router-vpn-one-package-"))
        outside = Path(tempfile.mkstemp(prefix="router-vpn-marker-target-")[1])
        try:
            os.chmod(forged, 0o700)
            outside.write_bytes(MARKER_BODY)
            os.chmod(outside, 0o600)
            (forged / MARKER_NAME).symlink_to(outside)
            assert cleanup_owned_temp(forged) is False
            assert forged.exists()
            assert outside.read_bytes() == MARKER_BODY
        finally:
            remove_manual(forged)
            outside.unlink(missing_ok=True)

        broad = create_owned_temp("router-vpn-request-")
        try:
            os.chmod(broad, 0o755)
            assert cleanup_owned_temp(broad) is False
            assert broad.exists()
        finally:
            remove_manual(broad)

    print("Owned Router VPN temporary-root tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
