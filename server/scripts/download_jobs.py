#!/usr/bin/env python3
"""Bounded asynchronous download jobs for the Router VPN Setup Center broker."""
from __future__ import annotations

import inspect
import math
from pathlib import Path
import runpy
import secrets
import threading
import time
from typing import Callable

_OWNED_TEMP = runpy.run_path(str(Path(__file__).with_name("owned-temp.py")))
create_owned_temp = _OWNED_TEMP["create_owned_temp"]
cleanup_owned_temp = _OWNED_TEMP["cleanup_owned_temp"]

# Completed packages and their owned build workspaces stay available for thirty
# minutes from READY. Delivery/retry does not extend the deadline. Explicit
# cancellation and service shutdown still remove them immediately.
JOB_TTL_SECONDS = 30 * 60
PACKAGE_RETENTION_SECONDS = JOB_TTL_SECONDS
REAPER_INTERVAL_SECONDS = 15
MAX_HISTORY = 64
RETAINED = {"ready", "delivered", "delivery-interrupted"}
CLEAN_TERMINAL = {"failed", "cancelled", "expired"}


class DownloadCancelled(RuntimeError):
    """Raised cooperatively when an authenticated Setup Center job is cancelled."""


class DownloadJobManager:
    def __init__(self, base: Path, build_func: Callable, content_type_func: Callable,
                 build_slots: threading.BoundedSemaphore, allowed_names: set[str],
                 max_active: int = 8):
        self.base = Path(base)
        self.build_func = build_func
        self.content_type_func = content_type_func
        self.build_slots = build_slots
        self.allowed_names = set(allowed_names)
        self.max_active = max_active
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}
        self.closed = threading.Event()
        try:
            params = inspect.signature(build_func).parameters
            self.build_accepts_progress = "progress" in params or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
        except (TypeError, ValueError):
            self.build_accepts_progress = False
        self.reaper = threading.Thread(target=self._reaper_loop,
            name="router-vpn-download-job-reaper", daemon=True)
        self.reaper.start()

    @staticmethod
    def _remaining(job: dict, now: float | None = None) -> int:
        if str(job.get("status") or "") in CLEAN_TERMINAL | {"cleaning", "cleanup-pending"}:
            return 0
        deadline = float(job.get("retention_deadline_epoch") or 0)
        if deadline <= 0:
            return PACKAGE_RETENTION_SECONDS
        return max(0, math.ceil(deadline - (time.time() if now is None else now)))

    def _public(self, job: dict) -> dict:
        hidden = {"work_dir", "path", "cancel_requested", "retention_deadline_epoch",
                  "cleanup_target_status", "cleanup_target_phase",
                  "cleanup_error_code", "cleanup_error"}
        out = {k: v for k, v in job.items() if k not in hidden}
        out["status_url"] = f"/api/download-jobs/{job['id']}"
        out["expires_in_seconds"] = self._remaining(job)
        deadline = float(job.get("retention_deadline_epoch") or 0)
        if deadline > 0:
            out["retained_until"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(deadline))
        if job.get("status") in RETAINED and out["expires_in_seconds"] > 0 and job.get("path"):
            out["download_url"] = f"/api/download-jobs/{job['id']}/file"
        return out

    def _trim_history_locked(self) -> None:
        terminal = [j for j in self.jobs.values()
                    if j.get("status") in CLEAN_TERMINAL and not j.get("work_dir")]
        terminal.sort(key=lambda j: float(j.get("updated_epoch", 0)))
        while len(self.jobs) > MAX_HISTORY and terminal:
            self.jobs.pop(terminal.pop(0)["id"], None)

    def create(self, name: str) -> dict:
        if name not in self.allowed_names:
            raise ValueError("unsupported download")
        now = time.time()
        with self.lock:
            occupied = {"queued", "building", "ready", "delivering", "delivered",
                        "delivery-interrupted", "cleanup-pending", "cleaning"}
            if sum(j.get("status") in occupied for j in self.jobs.values()) >= self.max_active:
                raise RuntimeError("download queue is full")
            job_id = secrets.token_urlsafe(12)
            while job_id in self.jobs:
                job_id = secrets.token_urlsafe(12)
            self.jobs[job_id] = {
                "id": job_id, "name": name, "status": "queued", "phase": "queued",
                "progress": 5, "phase_history": ["queued"], "source": "", "size": 0,
                "bytes_sent": 0, "bytes_total": 0, "delivery_attempts": 0,
                "error_code": "", "error": "",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "updated_epoch": now, "retention_deadline_epoch": 0.0,
                "cancel_requested": False, "work_dir": "", "path": "",
            }
            self._trim_history_locked()
        threading.Thread(target=self._run, args=(job_id,),
            name=f"router-vpn-download-{job_id[:8]}", daemon=True).start()
        return self.status(job_id)

    def _update(self, job_id: str, **changes) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            phase = changes.get("phase")
            if isinstance(phase, str) and phase and phase != job.get("phase"):
                history = job.setdefault("phase_history", [])
                if not history or history[-1] != phase:
                    history.append(phase)
                    if len(history) > 32:
                        del history[:-32]
            job.update(changes)
            now = time.time()
            job["updated_epoch"] = now
            job["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    def _progress_callback(self, job_id: str):
        floors = {"locating": 15, "downloading": 28, "validating": 42,
                  "building": 58, "packaging": 78}
        def report(phase: str, progress: int | None = None) -> None:
            if self._cancelled(job_id):
                raise DownloadCancelled("download job cancelled")
            phase = str(phase or "building").strip().lower()
            floor = floors.get(phase, 25)
            value = floor if progress is None else max(floor, min(94, int(progress)))
            self._update(job_id, status="building", phase=phase, progress=value)
        return report

    def _cancelled(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            return not job or bool(job.get("cancel_requested")) or self.closed.is_set()

    def cancel_requested(self, job_id: str) -> bool:
        """Safe build/delivery-loop cancellation probe for the HTTP server."""
        return self._cancelled(job_id)

    def _cleanup_dir(self, value: str) -> bool:
        if not value:
            return True
        path = Path(value)
        try:
            cleanup_owned_temp(path)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return not path.exists()

    def _finish_cleanup(self, job_id: str, work: str, status: str, phase: str,
                        code: str, message: str) -> None:
        self._update(job_id, status="cleaning", phase="cleanup", progress=100)
        removed = self._cleanup_dir(work)
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            now = time.time()
            if removed:
                job.update(work_dir="", path="", status=status, phase=phase,
                           progress=100 if status == "delivered" else 0,
                           error_code=code, error=message, retention_deadline_epoch=0.0)
                for key in ("cleanup_target_status", "cleanup_target_phase",
                            "cleanup_error_code", "cleanup_error"):
                    job.pop(key, None)
                if not job.get("phase_history") or job["phase_history"][-1] != phase:
                    job.setdefault("phase_history", []).append(phase)
            else:
                job.update(status="cleanup-pending", phase="cleanup", progress=100,
                           error_code="cleanup_failed",
                           error="temporary output cleanup failed and will be retried",
                           cleanup_target_status=status, cleanup_target_phase=phase,
                           cleanup_error_code=code, cleanup_error=message)
            job["updated_epoch"] = now
            job["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            self._trim_history_locked()

    def _adopt_ready(self, job_id: str, package: Path, source: str, size: int) -> bool:
        """Atomically publish READY only if cancellation still does not own the job."""
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job.get("cancel_requested") or self.closed.is_set():
                return False
            now = time.time()
            if not job.get("phase_history") or job["phase_history"][-1] != "ready":
                job.setdefault("phase_history", []).append("ready")
            job.update(status="ready", phase="ready", progress=100,
                       source=source, size=size, bytes_total=size, path=str(package),
                       retention_deadline_epoch=now + PACKAGE_RETENTION_SECONDS,
                       updated_epoch=now,
                       updated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))
            return True

    def _run(self, job_id: str) -> None:
        work = ""
        acquired = False
        retained = False
        terminal_status = "failed"
        terminal_code = "cleanup_without_result"
        terminal_message = "download job ended without a deliverable package"
        try:
            # Register the owned workspace while holding the job lock. A queued
            # cancellation therefore either wins before any workspace exists or
            # sees the exact workspace and drives it through cleanup-pending.
            with self.lock:
                job = self.jobs.get(job_id)
                if not job or job.get("cancel_requested") or self.closed.is_set():
                    return
                work = str(create_owned_temp("router-vpn-job-"))
                job["work_dir"] = work
                now = time.time()
                job["updated_epoch"] = now
                job["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            if self._cancelled(job_id):
                raise DownloadCancelled("download job cancelled")
            self._update(job_id, status="queued", phase="waiting-for-build-slot", progress=10)
            acquired = self.build_slots.acquire(timeout=30)
            if not acquired:
                raise RuntimeError("download builder is busy")
            if self._cancelled(job_id):
                raise DownloadCancelled("download job cancelled")
            report = self._progress_callback(job_id)
            report("locating", 15)
            with self.lock:
                job = self.jobs.get(job_id)
                if not job:
                    return
                name = str(job["name"])
            if self.build_accepts_progress:
                package, source = self.build_func(self.base, name, Path(work), progress=report)
            else:
                report("building", 58)
                package, source = self.build_func(self.base, name, Path(work))
                report("packaging", 85)
            if self._cancelled(job_id):
                raise DownloadCancelled("download job cancelled")
            if not package.is_file() or package.stat().st_size <= 0:
                raise RuntimeError("package creation returned an empty file")
            size = package.stat().st_size
            if not self._adopt_ready(job_id, package, source, size):
                raise DownloadCancelled("download job cancelled before READY adoption")
            retained = True
        except DownloadCancelled:
            terminal_status, terminal_code, terminal_message = "cancelled", "cancelled", "download job cancelled"
        except TimeoutError:
            terminal_status, terminal_code, terminal_message = "failed", "timeout", "package generation timed out"
        except Exception as exc:
            terminal_status = "failed"
            terminal_code = "builder_busy" if "builder is busy" in str(exc).lower() else "build_failed"
            terminal_message = str(exc)[:500]
        finally:
            if acquired:
                self.build_slots.release()
            if not retained:
                self._finish_cleanup(job_id, work, terminal_status, terminal_status,
                                     terminal_code, terminal_message)

    def status(self, job_id: str) -> dict:
        self.reap_expired()
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            return self._public(dict(job))

    def begin_delivery(self, job_id: str) -> tuple[Path, dict]:
        self.reap_expired()
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            status = str(job.get("status") or "")
            if status not in RETAINED:
                raise RuntimeError(f"download job is {status}")
            if self._remaining(job) <= 0:
                raise RuntimeError("download job retention expired")
            path = Path(str(job.get("path") or ""))
            if not path.is_file():
                raise RuntimeError("download job output is missing")
            job["status"] = "delivering"
            if not job.get("phase_history") or job["phase_history"][-1] != "streaming":
                job.setdefault("phase_history", []).append("streaming")
            job.update(phase="streaming", progress=0, bytes_sent=0,
                       bytes_total=path.stat().st_size,
                       delivery_attempts=int(job.get("delivery_attempts") or 0) + 1,
                       updated_epoch=time.time())
            meta = self._public(dict(job))
            meta["content_type"] = self.content_type_func(str(job["name"]))
            return path, meta

    def update_delivery(self, job_id: str, sent: int, total: int) -> None:
        total = max(0, int(total))
        sent = max(0, min(int(sent), total if total else int(sent)))
        progress = min(99, int(sent * 100 / total)) if total else 0
        self._update(job_id, status="delivering", phase="streaming", progress=progress,
                     bytes_sent=sent, bytes_total=total)

    def finish_delivery(self, job_id: str, success: bool) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            work = str(job.get("work_dir") or "")
            cancelled = bool(job.get("cancel_requested"))
        if cancelled:
            self._finish_cleanup(job_id, work, "cancelled", "cancelled", "cancelled",
                                 "download delivery cancelled; temporary output was deleted")
            return
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            final = "delivered" if success else "delivery-interrupted"
            if not job.get("phase_history") or job["phase_history"][-1] != final:
                job.setdefault("phase_history", []).append(final)
            if success:
                job.update(status=final, phase=final, progress=100,
                           bytes_sent=job.get("bytes_total", 0), error_code="",
                           error="temporary package retained for repeat download until its 30-minute deadline")
            else:
                job.update(status=final, phase=final, progress=0,
                           error_code="client_disconnected",
                           error="delivery interrupted; temporary package retained for retry until its 30-minute deadline")
            now = time.time()
            job["updated_epoch"] = now
            job["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    def cancel(self, job_id: str) -> dict:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            job["cancel_requested"] = True
            status = str(job.get("status") or "")
            cleanup = status in {"queued", "ready", "delivered", "delivery-interrupted", "cleanup-pending"}
            work = str(job.get("work_dir") or "") if cleanup else ""
            if cleanup:
                job.update(status="cleaning", phase="cleanup", progress=100)
            result = self._public(dict(job))
        if cleanup:
            self._finish_cleanup(job_id, work, "cancelled", "cancelled", "cancelled",
                                 "download job cancelled; temporary output was deleted")
            return self.status(job_id)
        return result

    def reap_expired(self, now: float | None = None) -> int:
        current = time.time() if now is None else float(now)
        doomed: list[tuple[str, str, str, str, str, str]] = []
        with self.lock:
            for job_id, job in self.jobs.items():
                status = str(job.get("status") or "")
                if status == "cleanup-pending":
                    doomed.append((job_id, str(job.get("work_dir") or ""),
                        str(job.get("cleanup_target_status") or "expired"),
                        str(job.get("cleanup_target_phase") or "expired"),
                        str(job.get("cleanup_error_code") or "expired"),
                        str(job.get("cleanup_error") or "temporary package expired after 30 minutes")))
                elif status in RETAINED:
                    deadline = float(job.get("retention_deadline_epoch") or 0)
                    if deadline > 0 and current >= deadline:
                        # Claim the job under the lock so a repeat download cannot
                        # begin between expiry selection and owned cleanup.
                        job.update(status="cleaning", phase="cleanup", progress=100)
                        doomed.append((job_id, str(job.get("work_dir") or ""),
                            "expired", "expired", "expired",
                            "temporary package and build workspace deleted after 30 minutes"))
            self._trim_history_locked()
        for item in doomed:
            self._finish_cleanup(*item)
        return len(doomed)

    def _reaper_loop(self) -> None:
        while not self.closed.wait(REAPER_INTERVAL_SECONDS):
            self.reap_expired()

    def close(self) -> None:
        self.closed.set()
        with self.lock:
            work_dirs = [str(j.get("work_dir") or "") for j in self.jobs.values()]
            for job in self.jobs.values():
                job["cancel_requested"] = True
        for work in work_dirs:
            self._cleanup_dir(work)
