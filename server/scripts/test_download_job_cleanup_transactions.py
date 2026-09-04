#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import threading

SCRIPT_DIR = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("router_vpn_download_jobs_cleanup", SCRIPT_DIR / "download_jobs.py")


def seed(manager, job_id: str, **extra) -> None:
    row = {
        "id": job_id,
        "name": "router-vpn-test.zip",
        "status": "queued",
        "phase": "queued",
        "progress": 5,
        "phase_history": ["queued"],
        "source": "",
        "size": 0,
        "bytes_sent": 0,
        "bytes_total": 0,
        "delivery_attempts": 0,
        "error_code": "",
        "error": "",
        "created_at": "",
        "updated_at": "",
        "updated_epoch": 0.0,
        "retention_deadline_epoch": 0.0,
        "cancel_requested": False,
        "work_dir": "",
        "path": "",
    }
    row.update(extra)
    with manager.lock:
        manager.jobs[job_id] = row


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-cleanup-transaction-") as td:
        base = Path(td)

        def never_build(_base, _name, _work, progress=None):
            raise AssertionError("pre-cancelled job must never invoke the builder")

        manager = m.DownloadJobManager(
            base, never_build, lambda _n: "application/zip",
            threading.BoundedSemaphore(1), {"router-vpn-test.zip"}, max_active=8,
        )
        try:
            # A job cancelled before its worker starts must return without even
            # allocating a temporary workspace. This prevents a terminal
            # cancelled row from later acquiring hidden files behind the API.
            seed(manager, "pre-cancel", status="cancelled", phase="cancelled", cancel_requested=True)
            created = []
            original_create = m.create_owned_temp
            try:
                m.create_owned_temp = lambda prefix: created.append(prefix) or original_create(prefix)
                manager._run("pre-cancel")
            finally:
                m.create_owned_temp = original_create
            assert created == [], "pre-cancelled worker created a workspace after terminal cancellation"
            with manager.lock:
                pre = dict(manager.jobs["pre-cancel"])
            assert pre["status"] == "cancelled" and not pre["work_dir"] and not pre["path"]

            # READY adoption is one atomic lock-owned decision. A cancellation
            # that wins first must prevent the package from becoming retained.
            ready_work = base / "ready-race"
            ready_work.mkdir()
            package = ready_work / "router-vpn-test.zip"
            package.write_bytes(b"race")
            seed(manager, "ready-race", status="building", phase="packaging",
                 cancel_requested=True, work_dir=str(ready_work))
            assert manager._adopt_ready("ready-race", package, "test", package.stat().st_size) is False
            with manager.lock:
                race = dict(manager.jobs["ready-race"])
            assert race["status"] == "building" and race.get("path", "") == ""
            manager._finish_cleanup("ready-race", str(ready_work), "cancelled", "cancelled", "cancelled", "cancelled before READY")
            with manager.lock:
                race = dict(manager.jobs["ready-race"])
            assert race["status"] == "cancelled" and not race["work_dir"] and not race["path"]
            assert not ready_work.exists()

            # A failed cleanup must never publish failed/cancelled/expired. It
            # stays cleanup-pending with the intended terminal result hidden
            # until a later owned cleanup actually succeeds.
            seed(manager, "cleanup-fail", status="building", phase="building",
                 work_dir="/owned/work", path="/owned/work/package.zip")
            original_cleanup = manager._cleanup_dir
            manager._cleanup_dir = lambda _value: False
            try:
                manager._finish_cleanup("cleanup-fail", "/owned/work", "failed", "failed", "build_failed", "builder failed")
            finally:
                manager._cleanup_dir = original_cleanup
            with manager.lock:
                pending = dict(manager.jobs["cleanup-fail"])
            assert pending["status"] == "cleanup-pending"
            assert pending["status"] not in m.CLEAN_TERMINAL
            assert pending["cleanup_target_status"] == "failed"
            assert pending["work_dir"] == "/owned/work" and pending["path"] == "/owned/work/package.zip"

            manager._cleanup_dir = lambda _value: True
            try:
                assert manager.reap_expired() >= 1
            finally:
                manager._cleanup_dir = original_cleanup
            with manager.lock:
                finished = dict(manager.jobs["cleanup-fail"])
            assert finished["status"] == "failed"
            assert not finished["work_dir"] and not finished["path"]
            assert finished["error_code"] == "build_failed"

            # Global invariant: a clean terminal row never owns a workspace or
            # package path. cleanup-pending is intentionally nonterminal.
            with manager.lock:
                for row in manager.jobs.values():
                    if row.get("status") in m.CLEAN_TERMINAL:
                        assert not row.get("work_dir"), row
                        assert not row.get("path"), row
        finally:
            manager.close()

    print("Download cleanup transaction tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
