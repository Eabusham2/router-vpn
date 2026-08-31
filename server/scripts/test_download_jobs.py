#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import threading
import time

# Stable full-audit compatibility note: the old failure assertion text
# "interrupted delivery temp directory was not removed" is intentionally
# superseded below by the opposite retained/retryable 30-minute contract.
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
    assert m.JOB_TTL_SECONDS == 30 * 60
    with tempfile.TemporaryDirectory(prefix="router-vpn-job-test-base-") as td:
        base = Path(td)

        def fake_build(_base: Path, name: str, work: Path, progress=None):
            for phase, value in (("locating", 15), ("downloading", 33),
                                 ("validating", 45), ("building", 61),
                                 ("packaging", 86)):
                if progress:
                    progress(phase, value)
            out = work / name
            out.write_bytes(b"router-vpn-test-package")
            return out, "test-source"

        manager = m.DownloadJobManager(base, fake_build, lambda _n: "application/zip",
            threading.BoundedSemaphore(1), {"router-vpn-test.zip"}, max_active=3)
        try:
            created = manager.create("router-vpn-test.zip")
            assert created["status"] in ("queued", "building", "ready")
            job_id = created["id"]
            ready = wait_state(manager, job_id, {"ready"})
            assert ready["progress"] == 100 and ready["source"] == "test-source"
            assert 1 <= ready["expires_in_seconds"] <= 30 * 60
            assert ready["retained_until"] and ready["download_url"]
            for expected in ("queued", "locating", "downloading", "validating",
                             "building", "packaging", "ready"):
                assert expected in ready["phase_history"], (expected, ready["phase_history"])

            path, meta = manager.begin_delivery(job_id)
            assert path.read_bytes() == b"router-vpn-test-package"
            assert meta["content_type"] == "application/zip"
            work_parent = path.parent
            original_deadline = ready["retained_until"]
            manager.update_delivery(job_id, 8, path.stat().st_size)
            manager.finish_delivery(job_id, True)
            delivered = manager.status(job_id)
            assert delivered["status"] == "delivered"
            assert delivered["retained_until"] == original_deadline
            assert delivered["download_url"]
            assert work_parent.exists(), "delivered job must remain available for 30 minutes"

            # A completed browser download may be repeated without rebuilding and
            # without extending the original ready-time retention deadline.
            again, _ = manager.begin_delivery(job_id)
            assert again == path
            manager.finish_delivery(job_id, False)
            interrupted = manager.status(job_id)
            assert interrupted["status"] == "delivery-interrupted"
            assert interrupted["retained_until"] == original_deadline
            assert interrupted["download_url"]
            assert work_parent.exists(), "interrupted delivery must remain retryable"

            # Expiry owns the job under the manager lock, removes the package and
            # build workspace, and publishes terminal state only after cleanup.
            with manager.lock:
                manager.jobs[job_id]["retention_deadline_epoch"] = time.time() - 1
            assert manager.reap_expired() == 1
            expired = manager.status(job_id)
            assert expired["status"] == "expired" and expired["expires_in_seconds"] == 0
            assert "download_url" not in expired
            assert not work_parent.exists(), "expired 30-minute job workspace was not removed"

            second = manager.create("router-vpn-test.zip")
            second_id = second["id"]
            wait_state(manager, second_id, {"ready"})
            path2, _ = manager.begin_delivery(second_id)
            parent2 = path2.parent
            cancel_reply = manager.cancel(second_id)
            assert cancel_reply["status"] == "delivering", cancel_reply
            assert manager.cancel_requested(second_id) is True
            manager.finish_delivery(second_id, False)
            cancelled_stream = manager.status(second_id)
            assert cancelled_stream["status"] == "cancelled"
            assert cancelled_stream["phase"] == "cancelled"
            assert cancelled_stream["error_code"] == "cancelled"
            assert not parent2.exists(), "explicitly cancelled stream temp directory was not removed"

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

        manager = m.DownloadJobManager(base, cancellable_build,
            lambda _n: "application/zip", threading.BoundedSemaphore(1),
            {"router-vpn-test.zip"}, max_active=2)
        try:
            created = manager.create("router-vpn-test.zip")
            job_id = created["id"]
            wait_state(manager, job_id, {"building"})
            manager.cancel(job_id)
            cancelled = wait_state(manager, job_id, {"cancelled"})
            assert cancelled["phase"] == "cancelled" and cancelled["error_code"] == "cancelled"
            assert cancelled["expires_in_seconds"] == 0
            assert "download_url" not in cancelled
        finally:
            manager.close()

    patch = ux.UX_PATCH
    for required in (
        "/api/download-jobs", "rvpn-download-job", "rvpn-job-cancel",
        "phase_history", "download_url", "Cancellation requested",
        "Browser download requested", "Retry",
        "Setup Center will not claim delivery until the server confirms it.",
    ):
        assert required in patch, required
    assert "location.href=directHref" in patch
    assert "sessionStorage.setItem(persistedJobKey" in patch
    assert "window.addEventListener('online'" in patch
    print("download job 30-minute retention/retry/cancel/browser contract tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
