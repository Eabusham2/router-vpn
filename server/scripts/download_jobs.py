#!/usr/bin/env python3
"""Bounded asynchronous download jobs for the Router VPN Setup Center broker."""
from __future__ import annotations

import inspect
import secrets
from pathlib import Path
import runpy
import shutil
import threading
import time
from typing import Callable


_OWNED_TEMP = runpy.run_path(str(Path(__file__).with_name("owned-temp.py")))
create_owned_temp = _OWNED_TEMP["create_owned_temp"]
cleanup_owned_temp = _OWNED_TEMP["cleanup_owned_temp"]

JOB_TTL_SECONDS = 15 * 60
MAX_HISTORY = 64


class DownloadCancelled(RuntimeError):
    """Raised cooperatively when an authenticated Setup Center job is cancelled."""


class DownloadJobManager:
    def __init__(self, base: Path, build_func: Callable, content_type_func: Callable, build_slots: threading.BoundedSemaphore, allowed_names: set[str], max_active: int = 8):
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
            self.build_accepts_progress = "progress" in params or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
        except (TypeError, ValueError):
            self.build_accepts_progress = False
        self.reaper = threading.Thread(target=self._reaper_loop, name="router-vpn-download-job-reaper", daemon=True)
        self.reaper.start()

    def _public(self, job: dict) -> dict:
        out = {k: v for k, v in job.items() if k not in ("work_dir", "path", "cancel_requested")}
        out["status_url"] = f"/api/download-jobs/{job['id']}"
        if job.get("status") == "ready":
            out["download_url"] = f"/api/download-jobs/{job['id']}/file"
        return out

    def _trim_history_locked(self) -> None:
        terminal = [j for j in self.jobs.values() if j.get("status") in ("failed", "cancelled", "delivered", "delivery-interrupted", "expired")]
        terminal.sort(key=lambda j: float(j.get("updated_epoch", 0)))
        while len(self.jobs) > MAX_HISTORY and terminal:
            old = terminal.pop(0)
            self.jobs.pop(old["id"], None)

    def create(self, name: str) -> dict:
        if name not in self.allowed_names:
            raise ValueError("unsupported download")
        now = time.time()
        with self.lock:
            active = sum(1 for j in self.jobs.values() if j.get("status") in ("queued", "building", "ready", "delivering"))
            if active >= self.max_active:
                raise RuntimeError("download queue is full")
            job_id = secrets.token_urlsafe(12)
            while job_id in self.jobs:
                job_id = secrets.token_urlsafe(12)
            job = {
                "id": job_id,
                "name": name,
                "status": "queued",
                "phase": "queued",
                "progress": 5,
                "phase_history": ["queued"],
                "source": "",
                "size": 0,
                "bytes_sent": 0,
                "bytes_total": 0,
                "error_code": "",
                "error": "",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "expires_in_seconds": JOB_TTL_SECONDS,
                "updated_epoch": now,
                "cancel_requested": False,
                "work_dir": "",
                "path": "",
            }
            self.jobs[job_id] = job
            self._trim_history_locked()
        threading.Thread(target=self._run, args=(job_id,), name=f"router-vpn-download-{job_id[:8]}", daemon=True).start()
        return self.status(job_id)

    def _update(self, job_id: str, **changes) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            new_phase = changes.get("phase")
            if isinstance(new_phase, str) and new_phase and new_phase != job.get("phase"):
                history = job.setdefault("phase_history", [])
                if not history or history[-1] != new_phase:
                    history.append(new_phase)
                    if len(history) > 32:
                        del history[:-32]
            job.update(changes)
            now = time.time()
            job["updated_epoch"] = now
            job["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    def _progress_callback(self, job_id: str):
        allowed = {
            "locating": 15,
            "downloading": 28,
            "validating": 42,
            "building": 58,
            "packaging": 78,
        }
        def report(phase: str, progress: int | None = None) -> None:
            if self._cancelled(job_id):
                raise DownloadCancelled("download job cancelled")
            phase = str(phase or "building").strip().lower()
            floor = allowed.get(phase, 25)
            value = floor if progress is None else max(floor, min(94, int(progress)))
            self._update(job_id, status="building", phase=phase, progress=value)
        return report

    def _cancelled(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            return not job or bool(job.get("cancel_requested")) or self.closed.is_set()

    def cancel_requested(self, job_id: str) -> bool:
        """Safe delivery-loop cancellation probe for the threaded HTTP server."""
        return self._cancelled(job_id)

    def _cleanup_dir(self, path: str) -> None:
        if not path:
            return
        try:
            cleanup_owned_temp(Path(path))
        except FileNotFoundError:
            pass
        except OSError:
            pass

    def _run(self, job_id: str) -> None:
        work = str(create_owned_temp("router-vpn-job-"))
        self._update(job_id, work_dir=work)
        acquired = False
        try:
            if self._cancelled(job_id):
                self._update(job_id, status="cancelled", phase="cancelled", progress=0, error_code="cancelled", error="download job cancelled")
                return
            self._update(job_id, status="queued", phase="waiting-for-build-slot", progress=10)
            acquired = self.build_slots.acquire(timeout=30)
            if not acquired:
                raise RuntimeError("download builder is busy")
            if self._cancelled(job_id):
                self._update(job_id, status="cancelled", phase="cancelled", progress=0, error_code="cancelled", error="download job cancelled")
                return
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
            self._update(job_id, status="ready", phase="ready", progress=100, source=source, size=size, bytes_total=size, path=str(package), expires_in_seconds=JOB_TTL_SECONDS)
            work = ""
        except DownloadCancelled:
            self._update(job_id, status="cancelled", phase="cancelled", progress=0, error_code="cancelled", error="download job cancelled")
        except TimeoutError:
            self._update(job_id, status="failed", phase="failed", progress=0, error_code="timeout", error="package generation timed out")
        except Exception as exc:
            code = "builder_busy" if "builder is busy" in str(exc).lower() else "build_failed"
            self._update(job_id, status="failed", phase="failed", progress=0, error_code=code, error=str(exc)[:500])
        finally:
            if acquired:
                self.build_slots.release()
            if work:
                with self.lock:
                    job = self.jobs.get(job_id)
                    terminal_status = str(job.get("status") or "") if job else ""
                self._update(job_id, phase="cleanup", progress=100)
                self._cleanup_dir(work)
                if terminal_status in ("cancelled", "failed"):
                    self._update(job_id, work_dir="", path="", phase=terminal_status, progress=0)
                else:
                    self._update(job_id, work_dir="", path="", status="failed", phase="failed", progress=0, error_code="cleanup_without_result", error="download job ended without a deliverable package")

    def status(self, job_id: str) -> dict:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            return self._public(dict(job))

    def begin_delivery(self, job_id: str) -> tuple[Path, dict]:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            if job.get("status") != "ready":
                raise RuntimeError(f"download job is {job.get('status')}")
            path = Path(str(job.get("path") or ""))
            if not path.is_file():
                raise RuntimeError("download job output is missing")
            job["status"] = "delivering"
            if not job.get("phase_history") or job["phase_history"][-1] != "streaming":
                job.setdefault("phase_history", []).append("streaming")
            job["phase"] = "streaming"
            job["progress"] = 0
            job["bytes_sent"] = 0
            job["bytes_total"] = path.stat().st_size
            job["updated_epoch"] = time.time()
            meta = self._public(dict(job))
            meta["content_type"] = self.content_type_func(str(job["name"]))
            return path, meta

    def update_delivery(self, job_id: str, sent: int, total: int) -> None:
        total = max(0, int(total))
        sent = max(0, min(int(sent), total if total else int(sent)))
        progress = min(99, int((sent * 100) / total)) if total else 0
        self._update(job_id, status="delivering", phase="streaming", progress=progress, bytes_sent=sent, bytes_total=total)

    def finish_delivery(self, job_id: str, success: bool) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            work = str(job.get("work_dir") or "")
            cancelled = bool(job.get("cancel_requested"))
        self._update(job_id, status="delivering", phase="cleanup", progress=100)
        self._cleanup_dir(work)
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job["work_dir"] = ""
            job["path"] = ""
            if success:
                final_status = "delivered"
                final_phase = "delivered"
            elif cancelled:
                final_status = "cancelled"
                final_phase = "cancelled"
            else:
                final_status = "delivery-interrupted"
                final_phase = "delivery-interrupted"
            job["status"] = final_status
            if not job.get("phase_history") or job["phase_history"][-1] != final_phase:
                job.setdefault("phase_history", []).append(final_phase)
            job["phase"] = final_phase
            job["progress"] = 100 if success else 0
            if success:
                job["bytes_sent"] = job.get("bytes_total", 0)
                job["error_code"] = ""
                job["error"] = ""
            elif cancelled:
                job["error_code"] = "cancelled"
                job["error"] = "download delivery cancelled; temporary output was deleted"
            else:
                job["error_code"] = "client_disconnected"
                job["error"] = "download delivery was interrupted; temporary output was deleted"
            job["updated_epoch"] = time.time()

    def cancel(self, job_id: str) -> dict:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            job["cancel_requested"] = True
            work = ""
            if job.get("status") in ("queued", "ready"):
                work = str(job.get("work_dir") or "")
                job["work_dir"] = ""
                job["path"] = ""
                job["status"] = "cancelled"
                job["phase"] = "cancelled"
                if not job.get("phase_history") or job["phase_history"][-1] != "cancelled":
                    job.setdefault("phase_history", []).append("cancelled")
                job["progress"] = 0
                job["error_code"] = "cancelled"
                job["error"] = "download job cancelled"
                job["updated_epoch"] = time.time()
            out = self._public(dict(job))
        self._cleanup_dir(work)
        return out

    def _reaper_loop(self) -> None:
        while not self.closed.wait(30):
            cutoff = time.time() - JOB_TTL_SECONDS
            doomed: list[tuple[str, str]] = []
            with self.lock:
                for job_id, job in self.jobs.items():
                    if job.get("status") == "ready" and float(job.get("updated_epoch", 0)) < cutoff:
                        work = str(job.get("work_dir") or "")
                        job["work_dir"] = ""
                        job["path"] = ""
                        job["status"] = "expired"
                        job["phase"] = "expired"
                        job.setdefault("phase_history", []).append("expired")
                        job["progress"] = 0
                        job["error_code"] = "expired"
                        job["error"] = "download job expired before delivery"
                        job["updated_epoch"] = time.time()
                        doomed.append((job_id, work))
                self._trim_history_locked()
            for _, work in doomed:
                self._cleanup_dir(work)

    def close(self) -> None:
        self.closed.set()
        with self.lock:
            work_dirs = [str(j.get("work_dir") or "") for j in self.jobs.values()]
            for job in self.jobs.values():
                job["cancel_requested"] = True
        for work in work_dirs:
            self._cleanup_dir(work)