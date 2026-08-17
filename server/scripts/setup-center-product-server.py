#!/usr/bin/env python3
"""Final authenticated Setup Center composition: admin + guide + device UX + AI + release status."""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
FORWARDING_EXTENSION_BASE = "http://127.0.0.1:8791"
FORWARDING_EXTENSION_PREFIX = "/api/admin/forwarding-extension"


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


def _terminate_builder(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def _cancellable_run_builder(base: Path, name: str, temp: Path, source: Path | None, progress=None) -> Path:
    """Production fallback builder that remains bounded and responds to job cancel."""
    broker = _ai._core._broker
    output = temp / name
    args = [
        "python3", str(broker.BUILDER_PATH), "--base", str(base),
        "--source-root", os.environ.get("ROUTER_VPN_FALLBACK_ROOT", "/src"),
        "--name", name, "--output", str(output),
    ]
    if source is not None:
        args += ["--source-archive", str(source)]
    if progress:
        progress("building", 58)
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL)
    deadline = time.monotonic() + broker.PACKAGE_TIMEOUT
    try:
        while True:
            code = proc.poll()
            if code is not None:
                if code != 0:
                    raise subprocess.CalledProcessError(code, args)
                break
            if time.monotonic() >= deadline:
                _terminate_builder(proc)
                raise subprocess.TimeoutExpired(args, broker.PACKAGE_TIMEOUT)
            if progress:
                try:
                    # DownloadJobManager's progress callback is also the
                    # cooperative cancellation checkpoint. Rechecking while the
                    # subprocess is alive makes Cancel terminate a local build
                    # instead of waiting for the full package timeout.
                    progress("building", 58)
                except Exception:
                    _terminate_builder(proc)
                    raise
            time.sleep(0.20)
    except BaseException:
        _terminate_builder(proc)
        raise
    if progress:
        progress("packaging", 84)
    return output


# build_package resolves _run_builder through the broker module globals, so this
# replaces only the final authenticated product's local fallback runner. GitHub
# same-SHA artifact selection/validation remains unchanged.
_ai._core._broker._run_builder = _cancellable_run_builder


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
        return enriched

    def _job_file(self, job_id: str) -> None:
        """Stream a ready package while honoring authenticated DELETE cancellation."""
        try:
            package, meta = self.server.jobs.begin_delivery(job_id)
        except KeyError:
            self._json(404, {"ok": False, "error_code": "not_found", "error": "download job not found"})
            return
        except RuntimeError as exc:
            self._json(409, {"ok": False, "error_code": "not_ready", "error": str(exc)})
            return

        success = False
        try:
            size = package.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", str(meta["content_type"]))
            self.send_header("Content-Disposition", f'attachment; filename="{meta["name"]}"')
            self.send_header("Content-Length", str(size))
            self.send_header("X-Router-VPN-Source", str(meta.get("source") or ""))
            self.send_header("X-Router-VPN-Job", job_id)
            self.end_headers()
            sent = 0
            with package.open("rb") as f:
                while True:
                    if self.server.jobs.cancel_requested(job_id):
                        break
                    chunk = f.read(_ai._core._broker.CHUNK)
                    if not chunk:
                        success = not self.server.jobs.cancel_requested(job_id)
                        break
                    self.wfile.write(chunk)
                    sent += len(chunk)
                    self.server.jobs.update_delivery(job_id, sent, size)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            print(f"setup center: delivery failed {job_id}: {type(exc).__name__}: {exc}", flush=True)
        finally:
            self.server.jobs.finish_delivery(job_id, success)

    def _proxy_forwarding_extension(self, method: str) -> bool:
        path = urlparse(self.path).path
        if not (path == FORWARDING_EXTENSION_PREFIX or path.startswith(FORWARDING_EXTENSION_PREFIX + "/")):
            return False
        if not self._require_auth():
            return True
        self._proxy_admin(FORWARDING_EXTENSION_BASE, path, method)
        return True

    def do_GET(self) -> None:
        if self._proxy_forwarding_extension("GET"):
            return
        if urlparse(self.path).path == "/api/release-status":
            if not self._require_auth():
                return
            self._send_ai_json(200, _release.release_status(Path(self.server.base_dir)))
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self._proxy_forwarding_extension("POST"):
            return
        super().do_POST()

    def do_PUT(self) -> None:
        if self._proxy_forwarding_extension("PUT"):
            return
        super().do_PUT()

    def do_DELETE(self) -> None:
        if self._proxy_forwarding_extension("DELETE"):
            return
        super().do_DELETE()


class Server(_ai.Server):
    pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/opt/router-vpn")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8786)
    args = ap.parse_args()
    base = Path(args.base).resolve()
    static = base / "downloads"
    static.mkdir(parents=True, exist_ok=True)
    _ai._core._broker.cleanup_stale_temp()
    server = Server((args.bind, args.port), Handler, base, static)
    print(
        f"Router VPN Setup Center on {args.bind}:{args.port}; authenticated admin/downloads + Full Guide + verified onboarding + device UX + forwarding ownership/Protected DMZ + release/recovery status + server-side AI Help",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
