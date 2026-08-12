#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import threading
import time

SCRIPT_DIR = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("router_vpn_download_jobs", SCRIPT_DIR / "download_jobs.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load download_jobs.py")
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


def wait_terminal(manager, job_id: str, timeout: float = 3.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = manager.status(job_id)
        if s["status"] in ("ready", "failed", "cancelled", "delivered", "delivery-interrupted"):
            return s
        time.sleep(0.02)
    raise AssertionError("job did not reach terminal/ready state")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-job-test-base-") as td:
        base = Path(td)
        def fake_build(_base: Path, name: str, work: Path):
            out = work / name
            out.write_bytes(b"router-vpn-test-package")
            return out, "test-source"
        manager = m.DownloadJobManager(base, fake_build, lambda _n: "application/zip", threading.BoundedSemaphore(1), {"router-vpn-test.zip"}, max_active=2)
        try:
            created = manager.create("router-vpn-test.zip")
            assert created["status"] in ("queued", "building", "ready")
            job_id = created["id"]
            ready = wait_terminal(manager, job_id)
            assert ready["status"] == "ready", ready
            assert ready["progress"] == 100 and ready["source"] == "test-source"
            path, meta = manager.begin_delivery(job_id)
            assert path.read_bytes() == b"router-vpn-test-package"
            assert meta["content_type"] == "application/zip"
            work_parent = path.parent
            manager.finish_delivery(job_id, True)
            assert manager.status(job_id)["status"] == "delivered"
            assert not work_parent.exists(), "delivered job temp directory was not removed"

            second = manager.create("router-vpn-test.zip")
            second_id = second["id"]
            ready2 = wait_terminal(manager, second_id)
            assert ready2["status"] == "ready"
            path2, _ = manager.begin_delivery(second_id)
            parent2 = path2.parent
            manager.finish_delivery(second_id, False)
            assert manager.status(second_id)["status"] == "delivery-interrupted"
            assert not parent2.exists(), "interrupted delivery temp directory was not removed"

            try:
                manager.create("../escape.zip")
            except ValueError:
                pass
            else:
                raise AssertionError("unsupported/traversal package name accepted")
        finally:
            manager.close()
    print("download job/progress cleanup tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
