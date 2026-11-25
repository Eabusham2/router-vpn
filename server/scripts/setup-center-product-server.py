#!/usr/bin/env python3
"""Final authenticated Setup Center composition: admin + guide + device UX + AI + release status."""
from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
FORWARDING_EXTENSION_BASE = "http://127.0.0.1:8791"
FORWARDING_EXTENSION_PREFIX = "/api/admin/forwarding-extension"
SERVER_CONTROL_BASE = "http://127.0.0.1:8792"
SERVER_CONTROL_PREFIX = "/api/admin/server-control"
UPDATE_BASE = "http://127.0.0.1:8793"
UPDATE_PREFIX = "/api/admin/update"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_ai = _load("routervpn_setup_center_ai_composition", "setup-center-ai-server.py")
_release = _load("routervpn_setup_center_release_status", "setup_center_release_status.py")
_verified = _load("routervpn_setup_center_verified_onboarding", "setup_center_verified_onboarding.py")
_server_control = _load("routervpn_setup_center_server_control", "setup_center_server_control.py")
_update = _load("routervpn_setup_center_update", "setup_center_update.py")
_exact_release = _load("routervpn_exact_sha_release_download", "exact_sha_release_download.py")


def _adopt_orphaned_build_children() -> None:
    # On Linux, an exiting builder may orphan a compiler before the broker
    # can join it. Each job reaps only children in its own new process group.
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))


def _builder_group_alive(proc: subprocess.Popen) -> bool:
    if proc.poll() is not None:
        try:
            while os.waitpid(-proc.pid, os.WNOHANG)[0] > 0:
                pass
        except ChildProcessError:
            pass
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        return False
    return True


def _terminate_builder(proc: subprocess.Popen) -> None:
    if os.name != "posix":
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        return
    if not _builder_group_alive(proc):
        return
    sig = signal.SIGTERM
    while _builder_group_alive(proc):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if not _builder_group_alive(proc):
                return
            time.sleep(0.025)
        # The build thread keeps its original workspace until OS retirement.
        sig = signal.SIGKILL
    proc.wait()


def _cancellable_run_builder(base: Path, name: str, temp: Path, source: Path | None, progress=None) -> Path:
    """Production fallback builder that remains bounded and responds to job cancel."""
    broker = _ai._core._broker
    output = temp / name
    args = [
        "python3", str(broker.BUILDER_PATH), "--base", str(base),
        "--source-root", os.environ.get("ROUTER_VPN_FALLBACK_ROOT", "/src"),
        "--name", name, "--output", str(output), "--job-workspace",
    ]
    if source is not None:
        args += ["--source-archive", str(source)]
    if progress:
        progress("building", 58)
    _adopt_orphaned_build_children()
    # Compilers and their helper processes also create system temporary files.
    # Their scratch space must retire with the same job after forced shutdown.
    env = broker._owned_temp.workspace_child_environment(temp, progress)
    scratch = tempfile.mkdtemp(prefix="builder-tmp-", dir=temp)
    env.update(dict.fromkeys(("TMPDIR", "TMP", "TEMP", "GOTMPDIR"), scratch))
    with tempfile.TemporaryFile(dir=scratch) as receipt:
        proc = subprocess.Popen(args, stdout=receipt, env=env,
                                start_new_session=(os.name == "posix"))
        deadline = time.monotonic() + broker.PACKAGE_TIMEOUT
        try:
            while True:
                code = proc.poll()
                if code is not None:
                    if code != 0:
                        raise subprocess.CalledProcessError(code, args)
                    break
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(args, broker.PACKAGE_TIMEOUT)
                if progress:
                    progress("building", 58)
                time.sleep(0.20)
        finally:
            # The leader may have exited before a compiler grandchild. The job
            # cannot publish READY or release its files until the group is gone.
            _terminate_builder(proc)
        receipt.seek(0)
        identity, digest = json.loads(receipt.read(256))
    broker._owned_temp.verify_package_output(output, identity, progress, digest)
    if progress:
        progress("packaging", 84)
    return output


# Use the same verified Release and Actions implementations in a child whose
# DNS lookup, TLS handshake or response read can be stopped and joined.
_release_download = _exact_release._download_release_asset
_actions_download = _ai._core._broker.fetch_artifact_member


def _fetch_job_source(mode, workspace, output_name, *source):
    broker = _ai._core._broker
    temp = Path(workspace)
    if (not temp.is_absolute() or temp.resolve() != temp or
            not temp.name.startswith(("router-vpn-request-", "router-vpn-job-"))):
        raise ValueError("source download requires its original parent broker workspace")
    broker._owned_temp.require_parent_workspace(temp)
    expected = broker._safe_selected_output(temp, output_name)
    last = None
    verified = None

    def record(path, identity, digest):
        nonlocal verified
        if path != expected:
            raise RuntimeError("GitHub source produced an unexpected path")
        verified = (identity, digest)

    def report(phase, value):
        nonlocal last
        current = (phase, value)
        if current != last:
            print(json.dumps(["progress", phase, value]), flush=True)
            last = current

    report.verified_output = record
    if mode == "release" and len(source) == 1:
        output = _release_download(broker, source[0], temp, output_name, progress=report)
    elif mode == "actions" and len(source) == 2:
        output = _actions_download(*source, temp, output_name, progress=report)
    else:
        raise ValueError("unknown GitHub source operation")
    if output != expected or verified is None:
        raise RuntimeError("GitHub source did not return the original output path")
    broker._owned_temp.verify_package_output(output, verified[0])
    print(json.dumps(["ready", *verified]), flush=True)


def _cancellable_fetch(mode, temp, output_name, source, progress):
    phase, value = "locating", 15
    if progress:
        progress(phase, value)
    command = [sys.executable, __file__, "--fetch-job-source", mode, str(temp), output_name, *source]
    _adopt_orphaned_build_children()
    env = _ai._core._broker._owned_temp.workspace_child_environment(temp, progress)
    with subprocess.Popen(command, stdout=subprocess.PIPE, env=env, start_new_session=(os.name == "posix")) as proc:
        seen = 0
        record = None
        try:
            while True:
                try:
                    output, _ = proc.communicate(timeout=0.2)
                    finished = True
                except subprocess.TimeoutExpired as timeout:
                    output, finished = timeout.output or b"", False
                # The child emits only changed progress values and one final
                # file identity. Ignore an unfinished write until the next read.
                lines = output.split(b"\n")[:-1]
                for line in lines[seen:]:
                    record = json.loads(line)
                    if record[0] == "progress":
                        phase, value = record[1:]
                        if progress:
                            progress(phase, value)
                seen = len(lines)
                if progress:
                    progress(phase, value)
                if finished:
                    break
        finally:
            _terminate_builder(proc)
        if proc.returncode or not lines:
            raise RuntimeError(f"exact-SHA {mode} source worker failed ({proc.returncode})")
    package = temp / output_name
    if not isinstance(record, list) or len(record) != 3 or record[0] != "ready":
        raise RuntimeError("GitHub source omitted its verified file identity")
    _ai._core._broker._owned_temp.verify_package_output(package, record[1], progress, record[2])
    return package


def _job_release_asset(broker, name, temp, output_name, progress=None):
    return _cancellable_fetch("release", temp, output_name, (name,), progress)


def _job_actions_member(artifact, wanted, temp, output_name, progress=None):
    return _cancellable_fetch("actions", temp, output_name, (artifact, wanted), progress)


# Product delivery uses a cancellable local builder and the exact source order:
# immutable exact-SHA GitHub Release asset, exact-SHA Actions artifact, then one
# bounded router-local desktop/Portable build. Mobile stays GitHub-only.
_ai._core._broker._run_builder = _cancellable_run_builder
_ai._core._broker.fetch_artifact_member = _job_actions_member
_exact_release._download_release_asset = _job_release_asset
_exact_release.install(_ai._core._broker)


class Handler(_ai.Handler):
    def _inject_product_ui(self, text: str) -> str:
        # Full generated Setup Center pages carry both the start tab and legacy
        # wizard seam. Reconcile those pages strictly. Tiny unit-test/alternate
        # fixture HTML may omit both, so it can still exercise the independent
        # release/admin composition layers without being mistaken for production.
        if 'data-tab="start"' in text or "startWizard(false)" in text or "startWizard(true)" in text:
            enriched = _verified.reconcile_setup_text(text)
        else:
            enriched = text
        enriched = super()._inject_product_ui(enriched)
        if 'data-tab="release-status"' not in enriched:
            enriched = self._before_body(enriched, _release.RELEASE_PANEL)
        if 'id="rvpn-verified-onboarding"' not in enriched:
            enriched = self._before_body(enriched, _verified.VERIFIED_ONBOARDING_PANEL)
        if 'id="rvpn-server-control-script"' not in enriched:
            enriched = self._before_body(enriched, _server_control.SERVER_CONTROL_PANEL)
        if 'id="rvpn-update-script"' not in enriched:
            enriched = self._before_body(enriched, _update.UPDATE_PANEL)
        return enriched

    def _dynamic(self, name: str) -> None:
        """Route direct package links through the same retained async job."""
        try:
            job = self.server.jobs.create(name)
        except ValueError:
            self.send_error(404, "unsupported package")
            return
        except RuntimeError:
            self.send_error(503, "download queue is full; retry shortly")
            return

        job_id = str(job["id"])
        deadline = time.monotonic() + _ai._core._broker.PACKAGE_TIMEOUT + 35
        while time.monotonic() < deadline:
            try:
                state = self.server.jobs.status(job_id)
            except KeyError:
                self.send_error(404, "download job disappeared")
                return
            status = str(state.get("status") or "")
            if status in {"ready", "delivered", "delivery-interrupted"}:
                self._job_file(job_id)
                return
            if status in {"failed", "cancelled", "expired"}:
                self.send_error(503, "requested package could not be generated")
                return
            time.sleep(0.10)

        try:
            self.server.jobs.cancel(job_id)
        except KeyError:
            pass
        self.send_error(504, "package generation timed out")

    def _proxy_forwarding_extension(self, method: str) -> bool:
        path = urlparse(self.path).path
        if not (path == FORWARDING_EXTENSION_PREFIX or path.startswith(FORWARDING_EXTENSION_PREFIX + "/")):
            return False
        if not self._require_auth():
            return True
        self._proxy_admin(FORWARDING_EXTENSION_BASE, path, method)
        return True

    def _proxy_server_control(self, method: str) -> bool:
        path = urlparse(self.path).path
        if not (path == SERVER_CONTROL_PREFIX or path.startswith(SERVER_CONTROL_PREFIX + "/")):
            return False
        if not self._require_auth():
            return True
        self._proxy_admin(SERVER_CONTROL_BASE, path, method)
        return True

    def _proxy_update(self, method: str) -> bool:
        path = urlparse(self.path).path
        if not (path == UPDATE_PREFIX or path.startswith(UPDATE_PREFIX + "/")):
            return False
        if not self._require_auth():
            return True
        self._proxy_admin(UPDATE_BASE, path, method)
        return True

    def do_GET(self) -> None:
        if self._proxy_update("GET"):
            return
        if self._proxy_server_control("GET"):
            return
        if self._proxy_forwarding_extension("GET"):
            return
        if urlparse(self.path).path == "/api/release-status":
            if not self._require_auth():
                return
            self._send_ai_json(200, _release.release_status(Path(self.server.base_dir)))
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self._proxy_update("POST"):
            return
        if self._proxy_server_control("POST"):
            return
        if self._proxy_forwarding_extension("POST"):
            return
        super().do_POST()

    def do_PUT(self) -> None:
        if self._proxy_server_control("PUT"):
            return
        if self._proxy_forwarding_extension("PUT"):
            return
        super().do_PUT()

    def do_DELETE(self) -> None:
        if self._proxy_server_control("DELETE"):
            return
        if self._proxy_forwarding_extension("DELETE"):
            return
        super().do_DELETE()


class Server(_ai.Server):
    require_verified_output = True

    def server_close(self):
        while True:
            try:
                return super().server_close()
            except _ai._core._broker._jobs.DownloadCleanupPending as exc:
                # The listener has closed. Keep this broker and its original
                # process-group and directory owners alive until cleanup joins.
                print(f"setup center: {exc}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/opt/router-vpn")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8786)
    args = ap.parse_args()
    base = _ai._core._broker.validate_private_directory(Path(args.base).resolve())
    static = _ai._core._broker.validate_private_directory(base / "downloads")
    _ai._core._broker.cleanup_stale_temp()
    server = Server((args.bind, args.port), Handler, base, static)
    print(
        f"Router VPN Setup Center on {args.bind}:{args.port}; authenticated admin/downloads + exact-SHA Release-first delivery + one-package local fallback + 30-minute retained package retry + Full Guide + verified onboarding + device UX + Stop/Emergency/Resume server control + exact-SHA Portainer update + forwarding ownership/Protected DMZ + release/recovery status + server-side AI Help",
        flush=True,
    )
    def terminate(_signum, _frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            server.server_close()
        finally:
            signal.signal(signal.SIGTERM, previous)
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fetch-job-source"]:
        _fetch_job_source(*sys.argv[2:])
    else:
        raise SystemExit(main())
