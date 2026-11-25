#!/usr/bin/env python3
"""Bounded asynchronous download jobs for the Router VPN Setup Center broker."""
from __future__ import annotations

import hashlib
import inspect
import math
import os
from pathlib import Path
import runpy
import secrets
import threading
import time
from typing import BinaryIO, Callable

_OWNED_TEMP = runpy.run_path(str(Path(__file__).with_name("owned-temp.py")))
create_owned_temp = _OWNED_TEMP["create_owned_temp"]
cleanup_owned_temp = _OWNED_TEMP["cleanup_owned_temp"]
owned_temp_identity = _OWNED_TEMP["owned_temp_identity"]
package_file_identity = _OWNED_TEMP["package_file_identity"]
PACKAGE_CHUNK = _OWNED_TEMP["PACKAGE_CHUNK"]

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


class DownloadCleanupPending(RuntimeError):
    """Shutdown still owns a worker, stream or directory that must be retried."""


class DownloadJobManager:
    def __init__(self, base: Path, build_func: Callable, content_type_func: Callable,
                 build_slots: threading.BoundedSemaphore, allowed_names: set[str],
                 max_active: int = 8, require_verified_output: bool = False):
        self.base = Path(base)
        self.build_func = build_func
        self.content_type_func = content_type_func
        self.build_slots = build_slots
        self.allowed_names = set(allowed_names)
        self.max_active = max_active
        self.require_verified_output = require_verified_output
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}
        self.closed = threading.Event()
        self.wake_reaper = threading.Event()
        self.workers: dict[str, threading.Thread] = {}
        self.deliveries: dict[str, tuple[Callable, threading.Event]] = {}
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
        hidden = {"work_dir", "work_identity", "work_fd", "path", "package_identity", "package_sha256", "chunk_hashes", "ready_ctime_ns", "ready_file", "cancel_requested", "retention_deadline_epoch",
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
            if self.closed.is_set():
                raise RuntimeError("download service is closing")
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
            worker = threading.Thread(target=self._run, args=(job_id,),
                name=f"router-vpn-download-{job_id[:8]}", daemon=True)
            self.workers[job_id] = worker
            try:
                worker.start()
            except RuntimeError:
                del self.workers[job_id], self.jobs[job_id]
                raise
        return self.status(job_id)

    def _update(self, job_id: str, **changes) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            if changes.get("status") in {"queued", "building"} and job.get("cancel_requested"):
                raise DownloadCancelled("download job cancelled")
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
        def verified_output(path, identity, digest):
            with self.lock:
                job = self.jobs[job_id]
                if Path(path) == Path(job["work_dir"]) / job["name"]:
                    job.update(package_identity=tuple(identity), package_sha256=digest)
        with self.lock:
            report.work_identity = self.jobs[job_id]["work_identity"]
        report.verified_output = verified_output
        return report

    def _cancelled(self, job_id: str) -> bool:
        with self.lock:
            job = self.jobs.get(job_id)
            return not job or bool(job.get("cancel_requested")) or self.closed.is_set()

    def cancel_requested(self, job_id: str) -> bool:
        """Safe build/delivery-loop cancellation probe for the HTTP server."""
        return self._cancelled(job_id)

    def _cleanup_dir(self, value: str, identity, work_fd) -> bool:
        if not value:
            return True
        if identity is None:
            return False
        path = Path(value)
        try:
            if work_fd is not None and os.fstat(work_fd).st_nlink == 0:
                # The original directory was removed independently. A new
                # directory at its old name does not belong to this job.
                return True
            if not cleanup_owned_temp(path, expected=identity):
                return False
        except FileNotFoundError:
            pass  # A missing descendant alone does not prove the root was removed.
        except OSError:
            return False
        try:
            path.lstat()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return False

    def _claim_cleanup_locked(self, job, work, status, phase, code, message):
        if job["status"] in CLEAN_TERMINAL or job["status"] == "cleaning":
            return None
        job.update(status="cleaning", phase="cleanup", progress=100)
        job.update(cleanup_target_status=status, cleanup_target_phase=phase,
                   cleanup_error_code=code, cleanup_error=message)
        return job["id"], work, job.get("work_identity"), job.get("work_fd"), self.deliveries.get(job["id"])

    def _complete_cleanup(self, claim) -> None:
        if claim is None:
            return
        job_id, work, work_identity, work_fd, delivery = claim
        joined = True
        if delivery is not None:
            abort, finished = delivery
            try:
                abort()  # Wake a writer blocked in sendall() before unlinking its input.
            except OSError:
                pass
            joined = finished.wait(1)
        if joined:
            with self.lock:
                ready = self.jobs[job_id].pop("ready_file", None)
            if ready is not None:
                ready.close()
        removed = joined and self._cleanup_dir(work, work_identity, work_fd)
        with self.lock:
            job = self.jobs[job_id]
            now = time.time()
            if removed:
                if work_fd is not None:
                    os.close(job.pop("work_fd"))
                job.pop("chunk_hashes", None)
                status = job.pop("cleanup_target_status")
                phase = job.pop("cleanup_target_phase")
                job.update(work_dir="", path="", status=status, phase=phase,
                           progress=0, error_code=job.pop("cleanup_error_code"),
                           error=job.pop("cleanup_error"), retention_deadline_epoch=0.0)
                if not job["phase_history"] or job["phase_history"][-1] != phase:
                    job["phase_history"].append(phase)
            else:
                job.update(status="cleanup-pending", phase="cleanup", progress=100,
                           error_code="cleanup_failed",
                           error="temporary output cleanup failed and will be retried")
            job["updated_epoch"] = now
            job["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            self._trim_history_locked()

    def _finish_cleanup(self, job_id: str, work: str, status: str, phase: str,
                        code: str, message: str) -> None:
        with self.lock:
            claim = self._claim_cleanup_locked(self.jobs[job_id], work, status, phase, code, message)
        self._complete_cleanup(claim)

    def _adopt_ready(self, job_id: str, package: Path, source: str) -> bool:
        """Atomically publish READY only if cancellation still does not own the job."""
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job.get("cancel_requested") or self.closed.is_set():
                return False
            if package != Path(job["work_dir"]) / job["name"]:
                raise RuntimeError("builder returned a package outside its original job")
            expected = job.get("package_sha256")
            if self.require_verified_output and ("package_identity" not in job or not expected):
                raise RuntimeError("package producer omitted its verified file identity")
            ready, identity = self._open_package(job, package)
        retained = False
        try:
            # Bind every outbound buffer to the original producer's whole-file
            # hash. Other jobs and authenticated Cancel remain available here.
            initial_ctime = os.fstat(ready.fileno()).st_ctime_ns
            digest = hashlib.sha256()
            chunks = []
            remaining = identity[2]
            while remaining:
                if self._cancelled(job_id):
                    return False
                length = min(PACKAGE_CHUNK, remaining)
                chunk = ready.read(length)
                if len(chunk) != length:
                    raise RuntimeError("package output changed during READY verification")
                digest.update(chunk)
                chunks.append(hashlib.sha256(chunk).digest())
                remaining -= length
            actual = digest.hexdigest()
            if ready.read(1) or (expected is not None and actual != expected):
                raise RuntimeError("package output differs from its verified producer digest")
            with self.lock:
                if job["cancel_requested"] or self.closed.is_set():
                    return False
                info = os.fstat(ready.fileno())
                if (info.st_ctime_ns != initial_ctime or package_file_identity(info) != identity or
                        package_file_identity(package.lstat()) != identity or
                        owned_temp_identity(package.parent) != job["work_identity"]):
                    raise RuntimeError("package source changed before READY")
                now = time.time()
                if not job.get("phase_history") or job["phase_history"][-1] != "ready":
                    job.setdefault("phase_history", []).append("ready")
                job.update(ready_file=ready, package_identity=identity, ready_ctime_ns=initial_ctime,
                           package_sha256=actual, chunk_hashes=tuple(chunks),
                           status="ready", phase="ready", progress=100,
                           source=source, size=identity[2], bytes_total=identity[2], path=str(package),
                           retention_deadline_epoch=now + PACKAGE_RETENTION_SECONDS,
                           updated_epoch=now,
                           updated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))
                retained = True
                self.wake_reaper.set()
                return True
        finally:
            if not retained:
                ready.close()

    def _run(self, job_id: str) -> None:
        work = ""
        acquired = False
        retained = False
        should_finalize = False
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
                should_finalize = True
                folder, identity = create_owned_temp("router-vpn-job-", capture_identity=True)
                work = str(folder)
                job.update(work_dir=work, work_identity=identity)
                if hasattr(os, "O_DIRECTORY"):
                    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
                    info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) != identity[2:]:
                        os.close(fd)
                        raise RuntimeError("newly allocated package workspace changed")
                    job["work_fd"] = fd
                if owned_temp_identity(folder) != identity:
                    raise RuntimeError("could not capture the newly allocated package workspace")
                now = time.time()
                job["updated_epoch"] = now
                job["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            if self._cancelled(job_id):
                raise DownloadCancelled("download job cancelled")
            self._update(job_id, status="queued", phase="waiting-for-build-slot", progress=10)
            until = time.monotonic() + 30
            while not acquired:
                if self._cancelled(job_id):
                    raise DownloadCancelled("download job cancelled")
                remaining = until - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("download builder is busy")
                acquired = self.build_slots.acquire(timeout=min(0.2, remaining))
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
            if not self._adopt_ready(job_id, package, source):
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
            if should_finalize and not retained:
                self._finish_cleanup(job_id, work, terminal_status, terminal_status,
                                     terminal_code, terminal_message)
            with self.lock:
                self.workers.pop(job_id, None)
            if self.closed.is_set():
                self.wake_reaper.set()

    def status(self, job_id: str) -> dict:
        self.reap_expired()
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            return self._public(dict(job))

    @staticmethod
    def _open_package(job, path: Path):
        if not job.get("work_identity") or owned_temp_identity(path.parent) != job["work_identity"]:
            raise RuntimeError("download job workspace changed")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        try:
            stream = os.fdopen(os.open(path, flags), "rb")
            try:
                info = os.fstat(stream.fileno())
                identity = package_file_identity(info)
                if (package_file_identity(path.lstat()) != identity or
                        job.get("ready_ctime_ns", info.st_ctime_ns) != info.st_ctime_ns or
                        job.get("package_identity", identity) != identity or
                        owned_temp_identity(path.parent) != job["work_identity"]):
                    raise RuntimeError("download job output changed")
                return stream, identity
            except BaseException:
                stream.close()
                raise
        except OSError as exc:
            raise RuntimeError("download job output is unavailable") from exc

    def begin_delivery(self, job_id: str, abort: Callable | None = None) -> tuple[BinaryIO, dict]:
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
            history = list(job["phase_history"])
            if not history or history[-1] != "streaming":
                history.append("streaming")
            changes = dict(status="delivering", phase="streaming", phase_history=history,
                           progress=0, bytes_sent=0, bytes_total=job["size"],
                           delivery_attempts=int(job.get("delivery_attempts") or 0) + 1,
                           updated_epoch=time.time())
            # Formatting may fail. Install a writer only when this call can
            # return its attempt to the handler that will join it.
            meta = self._public({**job, **changes})
            meta["content_type"] = self.content_type_func(str(job["name"]))
            meta["verified_sha256"] = job["package_sha256"]
            meta["chunk_hashes"] = job["chunk_hashes"]
            stream, _ = self._open_package(job, path)
            if abort is not None:
                self.deliveries[job_id] = (abort, threading.Event())
            job.update(changes)
            return stream, meta

    def update_delivery(self, job_id: str, sent: int, total: int, attempt: int | None = None) -> None:
        total = max(0, int(total))
        sent = max(0, min(int(sent), total if total else int(sent)))
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or job["status"] != "delivering" or (attempt is not None and job["delivery_attempts"] != attempt):
                return
            job.update(progress=min(99, int(sent * 100 / total)) if total else 0,
                       bytes_sent=sent, bytes_total=total)

    def finish_delivery(self, job_id: str, success: bool, attempt: int | None = None) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job or (attempt is not None and job["delivery_attempts"] != attempt):
                return
            delivery = self.deliveries.pop(job_id, None)
            if delivery:
                delivery[1].set()
            if job["status"] != "delivering":
                self.wake_reaper.set()
                return
            if self._remaining(job) <= 0:
                self.wake_reaper.set()
                return
            if success:
                # The pathname can disappear during an admitted download. The
                # pinned inode must still have its complete original contents.
                try:
                    success = package_file_identity(os.fstat(job["ready_file"].fileno())) == job["package_identity"]
                except (OSError, RuntimeError):
                    success = False
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
            claim = None
            # A running builder owns its process group and directory until it joins.
            if job["status"] in RETAINED | {"delivering"} or (job["status"] == "queued" and not job["work_dir"]):
                claim = self._claim_cleanup_locked(job, job["work_dir"], "cancelled", "cancelled", "cancelled",
                    "download job cancelled; temporary output was deleted")
        self._complete_cleanup(claim)
        with self.lock:
            return self._public(dict(job))

    def reap_expired(self, now: float | None = None) -> int:
        current = time.time() if now is None else float(now)
        doomed = []
        with self.lock:
            for job in self.jobs.values():
                status = job["status"]
                if status == "cleanup-pending":
                    doomed.append(self._claim_cleanup_locked(job, job["work_dir"],
                        job["cleanup_target_status"], job["cleanup_target_phase"],
                        job["cleanup_error_code"], job["cleanup_error"]))
                elif status in RETAINED | {"delivering"} and 0 < job["retention_deadline_epoch"] <= current:
                    job["cancel_requested"] = True
                    doomed.append(self._claim_cleanup_locked(job, job["work_dir"], "expired", "expired",
                        "expired", "temporary package and build workspace deleted after 30 minutes"))
        for claim in doomed:
            self._complete_cleanup(claim)
        return len(doomed)

    def _reaper_loop(self) -> None:
        while True:
            self.wake_reaper.clear()
            self.reap_expired()
            with self.lock:
                if self.closed.is_set() and not self.workers and all(j["status"] in CLEAN_TERMINAL for j in self.jobs.values()):
                    return
                deadlines = [j["retention_deadline_epoch"] for j in self.jobs.values() if j["status"] in RETAINED | {"delivering"}]
            delay = REAPER_INTERVAL_SECONDS
            if deadlines:
                delay = min(delay, max(0, min(deadlines) - time.time()))
            self.wake_reaper.wait(delay)

    def close(self, timeout: float = 10) -> None:
        self.closed.set()
        with self.lock:
            ids = list(self.jobs)
        for job_id in ids:
            try:
                self.cancel(job_id)
            except KeyError:
                pass  # A concurrent successful cleanup trimmed this terminal history row.
        deadline = time.monotonic() + timeout
        self.wake_reaper.set()
        while self.reaper.is_alive():
            self.reap_expired()
            self.wake_reaper.set()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DownloadCleanupPending("download cleanup pending; original owners retained for retry")
            self.reaper.join(min(remaining, 0.2))
