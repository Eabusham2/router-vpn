#!/usr/bin/env python3
"""Ephemeral Setup Center download broker.

Large platform packages are never cached in /opt/router-vpn.  Each request tries
the newest matching GitHub Actions build first, overlays this node's private
profiles in a temporary directory, streams the result, and deletes it.  If the
GitHub artifact is unavailable, only the requested package is assembled from
the prebuilt fallback binaries shipped in this image and is likewise deleted.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import functools
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from importlib.util import module_from_spec, spec_from_file_location

SCRIPT_DIR = Path(__file__).resolve().parent
BUILDER_PATH = SCRIPT_DIR / "build-download-on-demand.py"
_spec = spec_from_file_location("router_vpn_one_package", BUILDER_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"cannot load {BUILDER_PATH}")
_builder = module_from_spec(_spec)
_spec.loader.exec_module(_builder)
PACKAGE_MAP = _builder.PACKAGE_MAP

MAX_GITHUB_ARTIFACT = 768 * 1024 * 1024
CHUNK = 1024 * 1024
BUILD_SLOTS = threading.BoundedSemaphore(value=2)


def _api_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "router-vpn-setup-center/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _urlopen(url: str, timeout: int = 12):
    return urllib.request.urlopen(urllib.request.Request(url, headers=_api_headers()), timeout=timeout)


def _read_limited_json(url: str) -> dict:
    with _urlopen(url) as r:
        raw = r.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError("GitHub artifact metadata response is too large")
    return json.loads(raw)


def _download_limited(url: str, path: Path) -> None:
    total = 0
    with _urlopen(url, timeout=25) as r, path.open("wb") as w:
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_GITHUB_ARTIFACT:
                raise RuntimeError("GitHub artifact exceeds safety limit")
            w.write(chunk)
    if total == 0:
        raise RuntimeError("GitHub returned an empty artifact")


def _pick_member(zf: zipfile.ZipFile, wanted: str) -> zipfile.ZipInfo:
    matches = []
    for item in zf.infolist():
        p = PurePosixPath(item.filename.replace("\\", "/"))
        if p.name == wanted and not item.is_dir():
            matches.append(item)
    if len(matches) != 1:
        raise RuntimeError(f"GitHub artifact contains {len(matches)} copies of {wanted}")
    item = matches[0]
    if item.file_size > MAX_GITHUB_ARTIFACT:
        raise RuntimeError("selected GitHub package exceeds safety limit")
    return item


def fetch_github_package(home_name: str, temp: Path) -> Path:
    if os.environ.get("ROUTER_VPN_GITHUB_DISABLE", "").lower() in ("1", "true", "yes"):
        raise RuntimeError("GitHub artifact use disabled")
    generic = _builder.generic_name(home_name)
    if not generic:
        raise RuntimeError("this download has no generic GitHub package")

    repo = os.environ.get("ROUTER_VPN_GITHUB_REPO", "Eabusham2/router-vpn").strip()
    branch = os.environ.get("ROUTER_VPN_GITHUB_BRANCH", "main").strip()
    artifact_name = os.environ.get("ROUTER_VPN_GITHUB_ARTIFACT", "RouterVPN-client-desktop-unix-ci").strip()
    if "/" not in repo or not artifact_name:
        raise RuntimeError("invalid GitHub artifact configuration")

    q = urllib.parse.urlencode({"name": artifact_name, "per_page": 100})
    meta = _read_limited_json(f"https://api.github.com/repos/{repo}/actions/artifacts?{q}")
    candidates = []
    for item in meta.get("artifacts", []):
        if item.get("expired") or item.get("name") != artifact_name:
            continue
        run = item.get("workflow_run") or {}
        if branch and run.get("head_branch") != branch:
            continue
        candidates.append(item)
    if not candidates:
        raise RuntimeError(f"no unexpired {artifact_name} artifact for {branch}")
    candidates.sort(key=lambda x: (x.get("created_at", ""), int(x.get("id", 0))), reverse=True)

    outer = temp / "github-actions-artifact.zip"
    _download_limited(candidates[0]["archive_download_url"], outer)
    selected = temp / generic
    with zipfile.ZipFile(outer) as zf:
        item = _pick_member(zf, generic)
        with zf.open(item) as r, selected.open("wb") as w:
            shutil.copyfileobj(r, w, CHUNK)
    outer.unlink(missing_ok=True)
    if not selected.is_file() or selected.stat().st_size == 0:
        raise RuntimeError("selected GitHub package is empty")
    return selected


def build_package(base: Path, name: str, temp: Path) -> tuple[Path, str]:
    output = temp / name
    source = None
    source_label = "local-fallback"
    try:
        source = fetch_github_package(name, temp)
        source_label = "github"
    except Exception as exc:
        # Do not include credentials in logs; none are placed in URLs or argv.
        print(f"download broker: GitHub build unavailable for {name}: {type(exc).__name__}: {exc}", flush=True)

    args = [
        "python3", str(BUILDER_PATH),
        "--base", str(base),
        "--source-root", os.environ.get("ROUTER_VPN_FALLBACK_ROOT", "/src"),
        "--name", name,
        "--output", str(output),
    ]
    if source is not None:
        args += ["--source-archive", str(source)]
    try:
        subprocess.run(args, check=True, timeout=120, stdout=subprocess.DEVNULL)
    except Exception:
        # A GitHub artifact can be stale/incompatible with the current private
        # bundle. Retry once from this image's already-built binaries.
        if source is None:
            raise
        print(f"download broker: GitHub package customization failed for {name}; using local fallback", flush=True)
        output.unlink(missing_ok=True)
        subprocess.run(args[:-2], check=True, timeout=120, stdout=subprocess.DEVNULL)
        source_label = "local-fallback"
    return output, source_label


@contextmanager
def request_temp():
    with tempfile.TemporaryDirectory(prefix="router-vpn-request-") as td:
        path = Path(td)
        os.chmod(path, 0o700)
        yield path


def cleanup_stale_temp() -> None:
    temp = Path(tempfile.gettempdir())
    for path in temp.glob("router-vpn-request-*"):
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        except OSError:
            pass


class Handler(SimpleHTTPRequestHandler):
    server_version = "RouterVPNSetupCenter/1"

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz":
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/download-policy":
            body = json.dumps({
                "mode": "on-demand",
                "preferred_source": "github-actions",
                "fallback": "prebuilt-local-image",
                "server_cache": False,
                "github_artifact_retention_days": 1,
            }, separators=(",", ":")).encode() + b"\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        name = path.lstrip("/")
        if "/" not in name and name in PACKAGE_MAP:
            self._dynamic(name)
            return
        super().do_GET()

    def _dynamic(self, name: str) -> None:
        acquired = BUILD_SLOTS.acquire(timeout=30)
        if not acquired:
            self.send_error(503, "download builder is busy; retry shortly")
            return
        try:
            with request_temp() as temp:
                try:
                    package, source = build_package(Path(self.server.base_dir), name, temp)
                except subprocess.TimeoutExpired:
                    self.send_error(504, "package generation timed out")
                    return
                except Exception as exc:
                    print(f"download broker: failed {name}: {type(exc).__name__}: {exc}", flush=True)
                    self.send_error(503, "requested package could not be generated")
                    return
                size = package.stat().st_size
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                self.send_header("Content-Length", str(size))
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.send_header("X-Router-VPN-Source", source)
                self.end_headers()
                try:
                    with package.open("rb") as f:
                        shutil.copyfileobj(f, self.wfile, CHUNK)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                # TemporaryDirectory removes the package and any downloaded
                # GitHub artifact immediately on success, error, or disconnect.
        finally:
            BUILD_SLOTS.release()

    def translate_path(self, path: str) -> str:
        # SimpleHTTPRequestHandler handles normalization; pin it to the static
        # downloads directory rather than the process working directory.
        original = self.directory
        try:
            self.directory = str(self.server.static_dir)
            return super().translate_path(path)
        finally:
            self.directory = original

    def log_message(self, fmt: str, *args) -> None:
        print("download broker:", fmt % args, flush=True)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, base_dir: Path, static_dir: Path):
        super().__init__(address, handler)
        self.base_dir = base_dir
        self.static_dir = static_dir


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/opt/router-vpn")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8786)
    args = ap.parse_args()

    base = Path(args.base).resolve()
    static = base / "downloads"
    static.mkdir(parents=True, exist_ok=True)
    cleanup_stale_temp()
    server = Server((args.bind, args.port), Handler, base, static)
    print(f"Router VPN Setup Center on {args.bind}:{args.port}; packages are ephemeral", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
