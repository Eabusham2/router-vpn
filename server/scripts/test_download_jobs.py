#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import threading
import time

SCRIPT_DIR = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("router_vpn_download_jobs", SCRIPT_DIR / "download_jobs.py")
ux = load("router_vpn_download_ux", SCRIPT_DIR / "setup_center_ux_patch.py")


def wait_state(manager, job_id: str, states: set[str], timeout: float = 3.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = manager.status(job_id)
        if state["status"] in states:
            return state
        time.sleep(0.01)
    raise AssertionError(("job did not reach expected state", states, manager.status(job_id)))


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-job-test-base-") as td:
        base = Path(td)

        def fake_build(_base: Path, name: str, work: Path, progress=None):
            for phase, value in (("locating", 15), ("downloading", 33), ("validating", 45), ("building", 61), ("packaging", 86)):
                if progress:
                    progress(phase, value)
            out = work / name
            out.write_bytes(b"router-vpn-test-package")
            return out, "test-source"

        manager = m.DownloadJobManager(base, fake_build, lambda _n: "application/zip", threading.BoundedSemaphore(1), {"router-vpn-test.zip"}, max_active=3)
        try:
            created = manager.create("router-vpn-test.zip")
            assert created["status"] in ("queued", "building", "ready")
            job_id = created["id"]
            ready = wait_state(manager, job_id, {"ready"})
            assert ready["progress"] == 100 and ready["source"] == "test-source"
            for expected in ("queued", "locating", "downloading", "validating", "building", "packaging", "ready"):
                assert expected in ready["phase_history"], (expected, ready["phase_history"])
            path, meta = manager.begin_delivery(job_id)
            assert path.read_bytes() == b"router-vpn-test-package"
            assert meta["content_type"] == "application/zip"
            work_parent = path.parent
            manager.update_delivery(job_id, 8, path.stat().st_size)
            manager.finish_delivery(job_id, True)
            delivered = manager.status(job_id)
            assert delivered["status"] == "delivered"
            assert "streaming" in delivered["phase_history"] and "cleanup" in delivered["phase_history"]
            assert not work_parent.exists(), "delivered job temp directory was not removed"

            second = manager.create("router-vpn-test.zip")
            second_id = second["id"]
            ready2 = wait_state(manager, second_id, {"ready"})
            assert ready2["status"] == "ready"
            path2, _ = manager.begin_delivery(second_id)
            parent2 = path2.parent
            manager.finish_delivery(second_id, False)
            assert manager.status(second_id)["status"] == "delivery-interrupted"
            assert not parent2.exists(), "interrupted delivery temp directory was not removed"

            third = manager.create("router-vpn-test.zip")
            third_id = third["id"]
            wait_state(manager, third_id, {"ready"})
            path3, _ = manager.begin_delivery(third_id)
            parent3 = path3.parent
            cancel_reply = manager.cancel(third_id)
            assert cancel_reply["status"] == "delivering", cancel_reply
            assert manager.cancel_requested(third_id) is True
            manager.finish_delivery(third_id, False)
            cancelled_stream = manager.status(third_id)
            assert cancelled_stream["status"] == "cancelled"
            assert cancelled_stream["phase"] == "cancelled"
            assert cancelled_stream["error_code"] == "cancelled"
            assert "streaming" in cancelled_stream["phase_history"] and "cleanup" in cancelled_stream["phase_history"]
            assert not parent3.exists(), "cancelled stream temp directory was not removed"

            try:
                manager.create("../escape.zip")
            except ValueError:
                pass
            else:
                raise AssertionError("unsupported/traversal package name accepted")
        finally:
            manager.close()

        def cancellable_build(_base: Path, name: str, work: Path, progress=None):
            for index in range(300):
                if progress:
                    progress("building", 58 + min(30, index // 10))
                time.sleep(0.004)
            out = work / name
            out.write_bytes(b"must-not-be-delivered")
            return out, "test-local"

        manager = m.DownloadJobManager(base, cancellable_build, lambda _n: "application/zip", threading.BoundedSemaphore(1), {"router-vpn-test.zip"}, max_active=2)
        try:
            created = manager.create("router-vpn-test.zip")
            job_id = created["id"]
            wait_state(manager, job_id, {"building"})
            manager.cancel(job_id)
            cancelled = wait_state(manager, job_id, {"cancelled"})
            assert cancelled["phase"] == "cancelled" and cancelled["error_code"] == "cancelled"
            assert "download_url" not in cancelled
        finally:
            manager.close()

    patch = ux.UX_PATCH
    for required in (
        "/api/download-jobs", "rvpn-download-job", "rvpn-job-cancel", "phase_history",
        "download_url", "Cancellation requested", "Starting browser download", "Retry",
    ):
        assert required in patch, required
    assert "location.href=directHref" in patch
    print("download job lifecycle/progress/build-cancel/stream-cancel/browser wiring tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
