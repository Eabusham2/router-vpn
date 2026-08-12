#!/usr/bin/env python3
"""Ephemeral private Setup Center download broker.

Generic desktop/Portable packages prefer the matching same-SHA GitHub Actions
artifact. If unavailable, the Linux/ARM64 home node compiles only the requested
GENERIC Go application package. Node linking/private profiles are delivered as a
separate router-vpn-client-bundle.zip operation and are never baked into public
application packages.

Android and iOS remain same-SHA GitHub-backed and never pretend the Linux home
node can reproduce platform-specific mobile/Xcode build pipelines.

Both direct-download compatibility URLs and typed asynchronous download jobs are
supported. Job outputs live only in private /tmp directories until first delivery,
cancellation, failure, or TTL expiry.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
import threading
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

_jobs_spec = spec_from_file_location("router_vpn_download_jobs", SCRIPT_DIR / "download_jobs.py")
if _jobs_spec is None or _jobs_spec.loader is None:
    raise RuntimeError("cannot load download_jobs.py")
_jobs = module_from_spec(_jobs_spec)
_jobs_spec.loader.exec_module(_jobs)

DIRECT_ARTIFACTS = {
    "router-vpn-android.apk": {
        "artifact": "RouterVPN-Android-CI",
        "member": "app-debug.apk",
        "content_type": "application/vnd.android.package-archive",
    },
    "router-vpn-ios-preview.ipa": {
        "artifact": "RouterVPN-iOS-Preview-CI",
        "member": "RouterVPN-preview-unsigned-resignable.ipa",
        "content_type": "application/octet-stream",
    },
}

MAX_GITHUB_ARTIFACT = 768 * 1024 * 1024
MAX_MEMBER = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
CHUNK = 1024 * 1024
REQUEST_SLOTS = threading.BoundedSemaphore(value=8)
BUILD_SLOTS = threading.BoundedSemaphore(value=1)
PACKAGE_TIMEOUT = 720
ALLOWED_DOWNLOADS = set(PACKAGE_MAP) | set(DIRECT_ARTIFACTS)


def _api_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "router-vpn-setup-center/3",
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


def _safe_artifact_name(name: str) -> None:
    normalized = urllib.parse.unquote(name.replace("\\", "/"))
    p = PurePosixPath(normalized)
    if p.is_absolute() or any(part in ("", ".", "..") for part in p.parts) or (p.parts and p.parts[0].endswith(":")):
        raise RuntimeError("GitHub artifact contains an unsafe member path")


def _pick_member(zf: zipfile.ZipFile, wanted: str) -> zipfile.ZipInfo:
    matches = []
    for item in zf.infolist():
        _safe_artifact_name(item.filename.rstrip("/"))
        mode = (item.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise RuntimeError("GitHub artifact contains a symlink")
        if item.file_size > MAX_MEMBER:
            raise RuntimeError("GitHub artifact member exceeds safety limit")
        if item.compress_size > 0 and item.file_size > 8 * 1024 * 1024:
            if item.file_size / item.compress_size > MAX_COMPRESSION_RATIO:
                raise RuntimeError("GitHub artifact member compression ratio is unsafe")
        p = PurePosixPath(item.filename.replace("\\", "/"))
        if p.name == wanted and not item.is_dir():
            matches.append(item)
    if len(matches) != 1:
        raise RuntimeError(f"GitHub artifact contains {len(matches)} copies of {wanted}")
    return matches[0]


def _github_scope() -> tuple[str, str, str]:
    repo = os.environ.get("ROUTER_VPN_GITHUB_REPO", "Eabusham2/router-vpn").strip()
    branch = os.environ.get("ROUTER_VPN_GITHUB_BRANCH", "main").strip()
    head_sha = os.environ.get("ROUTER_VPN_GITHUB_SHA", "").strip().lower()
    if "/" not in repo:
        raise RuntimeError("invalid GitHub repository")
    if head_sha and (len(head_sha) != 40 or any(ch not in "0123456789abcdef" for ch in head_sha)):
        raise RuntimeError("ROUTER_VPN_GITHUB_SHA must be a full 40-character commit SHA")
    return repo, branch, head_sha


def _artifact_candidates(meta: dict, artifact_name: str, branch: str, head_sha: str) -> list[dict]:
    candidates: list[dict] = []
    for item in meta.get("artifacts", []):
        if item.get("expired") or item.get("name") != artifact_name:
            continue
        run = item.get("workflow_run") or {}
        if branch and run.get("head_branch") != branch:
            continue
        if head_sha and run.get("head_sha") != head_sha:
            continue
        candidates.append(item)
    candidates.sort(key=lambda x: (x.get("created_at", ""), int(x.get("id", 0))), reverse=True)
    return candidates


def fetch_artifact_member(artifact_name: str, wanted: str, temp: Path, output_name: str) -> Path:
    if os.environ.get("ROUTER_VPN_GITHUB_DISABLE", "").lower() in ("1", "true", "yes"):
        raise RuntimeError("GitHub artifact use disabled")
    repo, branch, head_sha = _github_scope()
    if not artifact_name:
        raise RuntimeError("invalid GitHub artifact name")

    q = urllib.parse.urlencode({"name": artifact_name, "per_page": 100})
    meta = _read_limited_json(f"https://api.github.com/repos/{repo}/actions/artifacts?{q}")
    candidates = _artifact_candidates(meta, artifact_name, branch, head_sha)
    if not candidates:
        scope = branch or "any branch"
        if head_sha:
            scope += f" at {head_sha}"
        raise RuntimeError(f"no unexpired {artifact_name} artifact for {scope}")

    outer = temp / (artifact_name + "-artifact.zip")
    _download_limited(candidates[0]["archive_download_url"], outer)
    selected = temp / output_name
    with zipfile.ZipFile(outer) as zf:
        item = _pick_member(zf, wanted)
        with zf.open(item) as r, selected.open("wb") as w:
            shutil.copyfileobj(r, w, CHUNK)
    outer.unlink(missing_ok=True)
    if not selected.is_file() or selected.stat().st_size == 0:
        raise RuntimeError("selected GitHub package is empty")
    return selected


def fetch_github_package(home_name: str, temp: Path) -> Path:
    generic = _builder.generic_name(home_name)
    if not generic:
        raise RuntimeError("this download has no generic GitHub package")
    artifact_name = os.environ.get("ROUTER_VPN_GITHUB_ARTIFACT", "RouterVPN-client-desktop-unix-ci").strip()
    return fetch_artifact_member(artifact_name, generic, temp, generic)


def fetch_direct_mobile(name: str, temp: Path) -> Path:
    spec = DIRECT_ARTIFACTS[name]
    try:
        return fetch_artifact_member(spec["artifact"], spec["member"], temp, name)
    except Exception as exc:
        raise RuntimeError(
            f"{name} requires its same-SHA GitHub mobile artifact; the Linux home node does not fake a platform-specific mobile build fallback: {exc}"
        ) from exc


def _run_builder(base: Path, name: str, temp: Path, source: Path | None) -> Path:
    output = temp / name
    args = [
        "python3", str(BUILDER_PATH),
        "--base", str(base),
        "--source-root", os.environ.get("ROUTER_VPN_FALLBACK_ROOT", "/src"),
        "--name", name,
        "--output", str(output),
    ]
    if source is not None:
        args += ["--source-archive", str(source)]
    subprocess.run(args, check=True, timeout=PACKAGE_TIMEOUT, stdout=subprocess.DEVNULL)
    return output


def build_package(base: Path, name: str, temp: Path) -> tuple[Path, str]:
    if name in DIRECT_ARTIFACTS:
        return fetch_direct_mobile(name, temp), "github"
    if name == "router-vpn-client-bundle.zip":
        return _run_builder(base, name, temp, None), "private-node-bundle"

    source = None
    try:
        source = fetch_github_package(name, temp)
    except Exception as exc:
        print(
            f"download broker: GitHub build unavailable for {name}: {type(exc).__name__}: {exc}; compiling requested generic package locally",
            flush=True,
        )

    if source is not None:
        try:
            return _run_builder(base, name, temp, source), "github"
        except Exception as exc:
            print(
                f"download broker: GitHub package validation/repack failed for {name}: {type(exc).__name__}: {exc}; compiling requested generic package locally",
                flush=True,
            )
    return _run_builder(base, name, temp, None), "router-local-generic-build"


@contextmanager
def request_temp():
    with tempfile.TemporaryDirectory(prefix="router-vpn-request-") as td:
        path = Path(td)
        os.chmod(path, 0o700)
        yield path


def cleanup_stale_temp() -> None:
    temp = Path(tempfile.gettempdir())
    for pattern in ("router-vpn-request-*", "router-vpn-job-*", "router-vpn-one-package-*"):
        for path in temp.glob(pattern):
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            except OSError:
                pass


def content_type_for(name: str) -> str:
    if name in DIRECT_ARTIFACTS:
        return str(DIRECT_ARTIFACTS[name]["content_type"])
    return "application/zip"


def _job_route(path: str) -> tuple[str, str] | None:
    prefix = "/api/download-jobs/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix):]
    if not rest:
        return None
    parts = rest.split("/")
    if len(parts) == 1:
        return parts[0], "status"
    if len(parts) == 2 and parts[1] == "file":
        return parts[0], "file"
    return None


class Handler(SimpleHTTPRequestHandler):
    server_version = "RouterVPNSetupCenter/3"

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def _json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, separators=(",", ":")).encode() + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_body_json(self, limit: int = 4096) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length <= 0 or length > limit:
            raise ValueError("request body size is invalid")
        raw = self.rfile.read(length)
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path != "/api/download-jobs":
            self.send_error(404)
            return
        try:
            body = self._read_body_json()
            name = str(body.get("name") or "")
            job = self.server.jobs.create(name)
        except ValueError as exc:
            self._json(400, {"ok": False, "error_code": "bad_request", "error": str(exc)})
            return
        except RuntimeError as exc:
            self._json(503, {"ok": False, "error_code": "queue_full", "error": str(exc)})
            return
        self._json(202, {"ok": True, "job": job})

    def do_DELETE(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        route = _job_route(path)
        if not route or route[1] != "status":
            self.send_error(404)
            return
        job_id, _ = route
        try:
            job = self.server.jobs.cancel(job_id)
        except KeyError:
            self._json(404, {"ok": False, "error_code": "not_found", "error": "download job not found"})
            return
        self._json(200, {"ok": True, "job": job})

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
            self._json(200, {
                "mode": "on-demand",
                "preferred_source": "github-actions",
                "fallback": "router-local-generic-build",
                "server_cache": False,
                "generic_packages_secret_free": True,
                "node_linking": "separate-bundle-or-pairing",
                "local_build_scope": "requested-generic-package-only",
                "local_build_platforms": "go-desktop-portable",
                "mobile_artifacts": "same-sha-github-only",
                "max_parallel_package_requests": 8,
                "local_build_slots": 1,
                "download_jobs": {
                    "create": "POST /api/download-jobs {name}",
                    "status": "GET /api/download-jobs/{job_id}",
                    "cancel": "DELETE /api/download-jobs/{job_id}",
                    "file": "GET /api/download-jobs/{job_id}/file",
                    "ready_ttl_seconds": _jobs.JOB_TTL_SECONDS,
                },
                "github_artifact_retention_days": 1,
                "github_sha": os.environ.get("ROUTER_VPN_GITHUB_SHA", "").strip(),
            })
            return

        route = _job_route(path)
        if route:
            job_id, action = route
            if action == "status":
                try:
                    job = self.server.jobs.status(job_id)
                except KeyError:
                    self._json(404, {"ok": False, "error_code": "not_found", "error": "download job not found"})
                    return
                self._json(200, {"ok": True, "job": job})
                return
            if action == "file":
                self._job_file(job_id)
                return

        name = path.lstrip("/")
        if "/" not in name and name in ALLOWED_DOWNLOADS:
            self._dynamic(name)
            return
        super().do_GET()

    def _job_file(self, job_id: str) -> None:
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
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("X-Router-VPN-Source", str(meta.get("source") or ""))
            self.send_header("X-Router-VPN-Job", job_id)
            self.end_headers()
            with package.open("rb") as f:
                shutil.copyfileobj(f, self.wfile, CHUNK)
            success = True
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            print(f"download broker: delivery failed {job_id}: {type(exc).__name__}: {exc}", flush=True)
        finally:
            self.server.jobs.finish_delivery(job_id, success)

    def _dynamic(self, name: str) -> None:
        if not REQUEST_SLOTS.acquire(timeout=1):
            self.send_error(503, "download queue is full; retry shortly")
            return
        try:
            if not BUILD_SLOTS.acquire(timeout=30):
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
                    self.send_header("Content-Type", content_type_for(name))
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
            finally:
                BUILD_SLOTS.release()
        finally:
            REQUEST_SLOTS.release()

    def translate_path(self, path: str) -> str:
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
        self.jobs = _jobs.DownloadJobManager(base_dir, build_package, content_type_for, BUILD_SLOTS, ALLOWED_DOWNLOADS, max_active=8)

    def server_close(self) -> None:
        self.jobs.close()
        super().server_close()


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
    print(f"Router VPN Setup Center on {args.bind}:{args.port}; packages are ephemeral; typed download jobs enabled", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
