#!/usr/bin/env python3
"""Authenticated ephemeral Router VPN Setup Center/download broker.

Security boundaries:
- /healthz and generic policy metadata are public to the LAN/container healthcheck.
- Setup Center HTML/assets, build jobs, direct packages and pairing-code creation
  require the separate Setup Center access token stored only on the router.
- The Setup Center token is never included in client/node bundles.
- Pairing redemption is one-time, short-lived and LAN/local-network only.
- Generic application packages remain secret-free; private node data is a
  separate authenticated bundle/pairing operation.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from http import cookies
import hashlib
import hmac
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

_verified_spec = spec_from_file_location(
    "router_vpn_broker_verified_regular_read",
    SCRIPT_DIR / "verified-regular-read.py",
)
if _verified_spec is None or _verified_spec.loader is None:
    raise RuntimeError("cannot load verified-regular-read.py")
_verified = module_from_spec(_verified_spec)
_verified_spec.loader.exec_module(_verified)
read_verified_regular = _verified.read_verified_regular

_private_dir_spec = spec_from_file_location(
    "router_vpn_broker_private_directory",
    SCRIPT_DIR / "private-directory.py",
)
if _private_dir_spec is None or _private_dir_spec.loader is None:
    raise RuntimeError("cannot load private-directory.py")
_private_dir = module_from_spec(_private_dir_spec)
_private_dir_spec.loader.exec_module(_private_dir)
ensure_private_directory = _private_dir.ensure_private_directory

_owned_temp_spec = spec_from_file_location(
    "router_vpn_broker_owned_temp",
    SCRIPT_DIR / "owned-temp.py",
)
if _owned_temp_spec is None or _owned_temp_spec.loader is None:
    raise RuntimeError("cannot load owned-temp.py")
_owned_temp = module_from_spec(_owned_temp_spec)
_owned_temp_spec.loader.exec_module(_owned_temp)
create_owned_temp = _owned_temp.create_owned_temp
cleanup_owned_temp = _owned_temp.cleanup_owned_temp

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

_pair_spec = spec_from_file_location("router_vpn_pairing", SCRIPT_DIR / "pairing.py")
if _pair_spec is None or _pair_spec.loader is None:
    raise RuntimeError("cannot load pairing.py")
_pairing = module_from_spec(_pair_spec)
_pair_spec.loader.exec_module(_pairing)

_policy_spec = spec_from_file_location("router_vpn_native_artifact_policy", SCRIPT_DIR / "native_artifact_policy.py")
if _policy_spec is None or _policy_spec.loader is None:
    raise RuntimeError("cannot load native_artifact_policy.py")
_artifact_policy = module_from_spec(_policy_spec)
_policy_spec.loader.exec_module(_artifact_policy)
NATIVE_PACKAGE_ARTIFACTS = _artifact_policy.NATIVE_PACKAGE_ARTIFACTS
DIRECT_ARTIFACTS = _artifact_policy.DIRECT_ARTIFACTS
ARTIFACT_PRODUCER_WORKFLOWS = _artifact_policy.ARTIFACT_PRODUCER_WORKFLOWS

_mobile_provenance_spec = spec_from_file_location("router_vpn_mobile_artifact_provenance", SCRIPT_DIR / "mobile-artifact-provenance.py")
if _mobile_provenance_spec is None or _mobile_provenance_spec.loader is None:
    raise RuntimeError("cannot load mobile-artifact-provenance.py")
_mobile_provenance = module_from_spec(_mobile_provenance_spec)
_mobile_provenance_spec.loader.exec_module(_mobile_provenance)

MAX_GITHUB_ARTIFACT = 768 * 1024 * 1024
MAX_ARTIFACT_MEMBERS = 20_000
MAX_MEMBER = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_PAIR_BUNDLE = 64 * 1024 * 1024
CHUNK = 1024 * 1024
REQUEST_SLOTS = threading.BoundedSemaphore(value=8)
BUILD_SLOTS = threading.BoundedSemaphore(value=1)
PACKAGE_TIMEOUT = 720
ALLOWED_DOWNLOADS = set(PACKAGE_MAP) | set(DIRECT_ARTIFACTS)
COOKIE_NAME = "router_vpn_setup"


def _api_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "router-vpn-setup-center/4",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


class _SafeGitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(redirected.full_url)
        if new.scheme.lower() != "https":
            raise RuntimeError(f"refusing non-HTTPS GitHub redirect to {new.scheme or 'unknown'}")
        old_origin = (old.scheme.lower(), (old.hostname or "").lower(), old.port)
        new_origin = (new.scheme.lower(), (new.hostname or "").lower(), new.port)
        if new_origin != old_origin:
            # Python urllib copies arbitrary headers during redirects. Artifact
            # downloads intentionally redirect from api.github.com to GitHub's
            # blob storage, so strip credentials before the cross-origin hop.
            redirected.remove_header("Authorization")
            redirected.remove_header("Cookie")
        return redirected


_GITHUB_OPENER = urllib.request.build_opener(_SafeGitHubRedirect())


def _urlopen(url: str, timeout: int = 12):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() != "api.github.com":
        raise RuntimeError("authenticated GitHub requests must start at https://api.github.com")
    request = urllib.request.Request(url, headers=_api_headers())
    return _GITHUB_OPENER.open(request, timeout=timeout)


def _read_limited_json(url: str) -> dict:
    with _urlopen(url) as r:
        raw = r.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError("GitHub artifact metadata response is too large")
    return json.loads(raw)


def _download_limited(url: str, path: Path, progress=None) -> None:
    total = 0
    if progress:
        progress("downloading", 28)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    complete = False
    try:
        with _urlopen(url, timeout=25) as r, os.fdopen(fd, "wb", closefd=True) as w:
            try:
                expected = int(r.headers.get("Content-Length", "0") or 0)
            except ValueError:
                expected = 0
            if expected < 0 or expected > MAX_GITHUB_ARTIFACT:
                raise RuntimeError("GitHub artifact Content-Length exceeds safety limit")
            while True:
                chunk = r.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_GITHUB_ARTIFACT:
                    raise RuntimeError("GitHub artifact exceeds safety limit")
                w.write(chunk)
                if progress and expected > 0:
                    progress("downloading", min(39, 28 + int(11 * total / expected)))
            w.flush()
            os.fsync(w.fileno())
        if total == 0:
            raise RuntimeError("GitHub returned an empty artifact")
        if expected > 0 and total != expected:
            raise RuntimeError(
                f"GitHub artifact Content-Length mismatch: received {total}, expected {expected}"
            )
        complete = True
    finally:
        if not complete:
            try:
                os.close(fd)
            except OSError:
                pass
            path.unlink(missing_ok=True)


def _artifact_sha256(item: dict) -> str:
    raw = str(item.get("digest") or "").strip().lower()
    if not raw.startswith("sha256:"):
        raise RuntimeError("GitHub artifact metadata is missing a SHA-256 digest")
    digest = raw[len("sha256:"):]
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise RuntimeError("GitHub artifact metadata has an invalid SHA-256 digest")
    return digest


@contextmanager
def _verified_artifact_zip(path: Path, expected_sha256: str):
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError("downloaded GitHub artifact is not a regular file")
    if before.st_size <= 0 or before.st_size > MAX_GITHUB_ARTIFACT:
        raise RuntimeError("downloaded GitHub artifact has an unsafe size")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    stream = os.fdopen(fd, "rb", closefd=True)
    try:
        opened = os.fstat(stream.fileno())
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(before, opened)
            or not os.path.samestat(opened, current)
        ):
            raise RuntimeError("downloaded GitHub artifact changed during verification open")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_GITHUB_ARTIFACT:
                raise RuntimeError("downloaded GitHub artifact exceeds safety limit")
            digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            raise RuntimeError("GitHub artifact archive SHA-256 digest mismatch")
        after = path.lstat()
        if (
            stat.S_ISLNK(after.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or not os.path.samestat(opened, after)
            or after.st_size != total
        ):
            raise RuntimeError("downloaded GitHub artifact changed during digest verification")
        stream.seek(0)
        yield stream
    finally:
        stream.close()


def _safe_selected_output(temp: Path, output_name: str) -> Path:
    if not output_name or output_name in (".", "..") or Path(output_name).name != output_name:
        raise RuntimeError("invalid selected artifact output name")
    selected = temp / output_name
    try:
        info = selected.lstat()
    except FileNotFoundError:
        return selected
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("selected artifact output target is unsafe")
    raise RuntimeError("selected artifact output already exists before adoption")


def _require_selected_output_absent(selected: Path) -> None:
    try:
        selected.lstat()
    except FileNotFoundError:
        return
    raise RuntimeError("selected artifact output appeared before adoption")


def _safe_artifact_name(name: str) -> None:
    normalized = urllib.parse.unquote(name.replace("\\", "/"))
    p = PurePosixPath(normalized)
    if p.is_absolute() or any(part in ("", ".", "..") for part in p.parts) or (p.parts and p.parts[0].endswith(":")):
        raise RuntimeError("GitHub artifact contains an unsafe member path")


def _pick_member(zf: zipfile.ZipFile, wanted: str) -> zipfile.ZipInfo:
    matches = []
    items = zf.infolist()
    if len(items) > MAX_ARTIFACT_MEMBERS:
        raise RuntimeError("GitHub artifact contains too many members")
    for item in items:
        _safe_artifact_name(item.filename.rstrip("/"))
        mode = (item.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise RuntimeError("GitHub artifact contains a symlink")
        if item.flag_bits & 0x1:
            raise RuntimeError("GitHub artifact contains an encrypted member")
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
    if len(head_sha) != 40 or any(ch not in "0123456789abcdef" for ch in head_sha):
        raise RuntimeError("ROUTER_VPN_GITHUB_SHA is required and must be a full 40-character commit SHA for GitHub artifact retrieval")
    return repo, branch, head_sha


def _newest_meaningful_workflow_run(runs: list[dict], branch: str, head_sha: str) -> dict | None:
    matches = [
        run for run in runs
        if str(run.get("head_sha") or "").lower() == head_sha
        and str(run.get("head_branch") or "") == branch
    ]
    matches.sort(key=lambda run: int(run.get("id") or 0), reverse=True)
    for run in matches:
        # A newer exact-SHA producer that is queued/in-progress means artifact
        # evidence is unsettled. Never fall back to an older green producer.
        if str(run.get("status") or "") != "completed":
            return None
        conclusion = str(run.get("conclusion") or "")
        # Concurrency duplicates may be cancelled/skipped without invalidating
        # the newest meaningful completed producer.
        if conclusion in ("cancelled", "skipped"):
            continue
        return run
    return None


def _successful_producer_run_id(repo: str, artifact_name: str, branch: str, head_sha: str) -> int:
    workflow = ARTIFACT_PRODUCER_WORKFLOWS.get(artifact_name)
    if not workflow:
        raise RuntimeError(f"artifact {artifact_name} has no closed producer-workflow mapping")
    q = urllib.parse.urlencode({"branch": branch, "head_sha": head_sha, "per_page": 50})
    workflow_path = urllib.parse.quote(workflow, safe="")
    meta = _read_limited_json(f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_path}/runs?{q}")
    run = _newest_meaningful_workflow_run(list(meta.get("workflow_runs") or []), branch, head_sha)
    if not run or str(run.get("conclusion") or "") != "success":
        raise RuntimeError(
            f"artifact producer {workflow} has no settled successful exact-SHA run for {branch} at {head_sha}"
        )
    run_id = int(run.get("id") or 0)
    if run_id <= 0:
        raise RuntimeError(f"artifact producer {workflow} returned an invalid workflow run id")
    return run_id


def _artifact_candidates(meta: dict, artifact_name: str, branch: str, head_sha: str, producer_run_id: int) -> list[dict]:
    candidates: list[dict] = []
    for item in meta.get("artifacts", []):
        if item.get("expired") or item.get("name") != artifact_name:
            continue
        run = item.get("workflow_run") or {}
        if branch and run.get("head_branch") != branch:
            continue
        if str(run.get("head_sha") or "").lower() != head_sha:
            continue
        if int(run.get("id") or 0) != producer_run_id:
            continue
        candidates.append(item)
    candidates.sort(key=lambda x: (x.get("created_at", ""), int(x.get("id", 0))), reverse=True)
    return candidates


def fetch_artifact_member(artifact_name: str, wanted: str, temp: Path, output_name: str, progress=None) -> Path:
    if os.environ.get("ROUTER_VPN_GITHUB_DISABLE", "").lower() in ("1", "true", "yes"):
        raise RuntimeError("GitHub artifact use disabled")
    if progress:
        progress("locating", 15)
    selected = _safe_selected_output(temp, output_name)
    repo, branch, head_sha = _github_scope()
    if not artifact_name:
        raise RuntimeError("invalid GitHub artifact name")
    producer_run_id = _successful_producer_run_id(repo, artifact_name, branch, head_sha)
    q = urllib.parse.urlencode({"name": artifact_name, "per_page": 100})
    meta = _read_limited_json(
        f"https://api.github.com/repos/{repo}/actions/runs/{producer_run_id}/artifacts?{q}"
    )
    candidates = _artifact_candidates(meta, artifact_name, branch, head_sha, producer_run_id)
    if len(candidates) != 1:
        scope = branch or "any branch"
        scope += f" at {head_sha} producer run {producer_run_id}"
        raise RuntimeError(
            f"expected exactly one unexpired {artifact_name} artifact for {scope}; found {len(candidates)}"
        )
    artifact = candidates[0]
    expected_digest = _artifact_sha256(artifact)
    outer = temp / (artifact_name + "-artifact.zip")
    _download_limited(artifact["archive_download_url"], outer, progress=progress)
    if progress:
        progress("validating", 42)
    fd, staged_name = tempfile.mkstemp(prefix=f".{Path(output_name).name}.", suffix=".part", dir=temp)
    os.close(fd)
    staged = Path(staged_name)
    committed = False
    try:
        with _verified_artifact_zip(outer, expected_digest) as verified_outer:
            with zipfile.ZipFile(verified_outer) as zf:
                item = _pick_member(zf, wanted)
                with zf.open(item) as r, staged.open("wb") as w:
                    shutil.copyfileobj(r, w, CHUNK)
                    w.flush()
                    os.fsync(w.fileno())
        if staged.stat().st_size == 0:
            raise RuntimeError("selected GitHub package is empty")
        _require_selected_output_absent(selected)
        os.replace(staged, selected)
        committed = True
    finally:
        outer.unlink(missing_ok=True)
        if not committed:
            staged.unlink(missing_ok=True)
    if not selected.is_file() or selected.stat().st_size == 0:
        raise RuntimeError("selected GitHub package is empty")
    return selected


def _fetch_first_artifact(sources, temp: Path, output_name: str, progress=None) -> Path:
    failures = []
    for artifact_name, wanted in sources:
        try:
            return fetch_artifact_member(str(artifact_name), str(wanted), temp, output_name, progress=progress)
        except Exception as exc:
            failures.append(f"{artifact_name}: {type(exc).__name__}: {exc}")
    raise RuntimeError("; ".join(failures) if failures else "no GitHub artifact sources configured")


def _desktop_github_sources(home_name: str):
    generic = _builder.generic_name(home_name)
    if not generic:
        raise RuntimeError("this download has no generic GitHub package")
    override = os.environ.get("ROUTER_VPN_GITHUB_ARTIFACT", "").strip()
    if override:
        return ((override, generic),), generic
    return NATIVE_PACKAGE_ARTIFACTS.get(
        home_name, (("RouterVPN-client-desktop-unix-ci", generic),)
    ), generic


def fetch_github_package(home_name: str, temp: Path, progress=None) -> Path:
    # Retained for focused callers/tests that need only artifact extraction.
    # Product delivery uses build_github_package so each producer candidate is
    # provenance-validated/repacked before falling through to the next source.
    sources, generic = _desktop_github_sources(home_name)
    return _fetch_first_artifact(sources, temp, generic, progress=progress)


def build_github_package(base: Path, name: str, temp: Path, progress=None) -> Path:
    sources, generic = _desktop_github_sources(name)
    failures: list[str] = []
    for artifact_name, wanted in sources:
        source = temp / generic
        try:
            source.unlink(missing_ok=True)
            candidate = fetch_artifact_member(
                str(artifact_name), str(wanted), temp, generic, progress=progress
            )
            if progress:
                progress("validating", 48)
            # Validation/repack is part of candidate selection. A downloaded
            # artifact with wrong embedded source/family is not allowed to
            # suppress the next same-SHA native producer.
            return _run_builder(base, name, temp, candidate, progress=progress)
        except Exception as exc:
            failures.append(f"{artifact_name}: {type(exc).__name__}: {exc}")
        finally:
            source.unlink(missing_ok=True)
    raise RuntimeError("; ".join(failures) if failures else "no GitHub artifact sources configured")


def fetch_direct_mobile(name: str, temp: Path, progress=None) -> Path:
    spec = DIRECT_ARTIFACTS[name]
    failures = []
    try:
        repo, _, head_sha = _github_scope()
    except Exception as exc:
        raise RuntimeError(
            f"{name} requires its same-SHA GitHub mobile artifact; the Linux home node does not fake a platform-specific mobile build fallback: {exc}"
        ) from exc
    for artifact_name, wanted in spec["sources"]:
        selected = temp / name
        try:
            selected = fetch_artifact_member(str(artifact_name), str(wanted), temp, name, progress=progress)
            # Workflow metadata narrows discovery to the exact SHA, but the
            # binary itself is the final trust boundary. Verify each candidate
            # before accepting it so a corrupt preferred artifact can fall
            # through to the second same-SHA native producer safely.
            _mobile_provenance.verify(name, selected, head_sha, repo)
            return selected
        except Exception as exc:
            selected.unlink(missing_ok=True)
            failures.append(f"{artifact_name}: {type(exc).__name__}: {exc}")
    detail = "; ".join(failures) if failures else "no GitHub mobile artifact sources configured"
    raise RuntimeError(
        f"{name} requires its same-SHA GitHub mobile artifact; the Linux home node does not fake a platform-specific mobile build fallback: {detail}"
    )


def _run_builder(base: Path, name: str, temp: Path, source: Path | None, progress=None) -> Path:
    output = temp / name
    args = [
        "python3", str(BUILDER_PATH), "--base", str(base),
        "--source-root", os.environ.get("ROUTER_VPN_FALLBACK_ROOT", "/src"),
        "--name", name, "--output", str(output),
    ]
    if source is not None:
        args += ["--source-archive", str(source)]
    if progress:
        progress("building", 58)
    subprocess.run(args, check=True, timeout=PACKAGE_TIMEOUT, stdout=subprocess.DEVNULL)
    if progress:
        progress("packaging", 84)
    return output


def build_package(base: Path, name: str, temp: Path, progress=None) -> tuple[Path, str]:
    if progress:
        progress("locating", 15)
    if name in DIRECT_ARTIFACTS:
        result = fetch_direct_mobile(name, temp, progress=progress)
        if progress:
            progress("validating", 90)
        return result, "github"
    if name == "router-vpn-client-bundle.zip":
        if progress:
            progress("packaging", 70)
        return _run_builder(base, name, temp, None, progress=progress), "private-node-bundle"
    try:
        return build_github_package(base, name, temp, progress=progress), "github"
    except Exception as exc:
        print(
            f"download broker: all exact-SHA GitHub package candidates failed for {name}: "
            f"{type(exc).__name__}: {exc}; compiling requested generic package locally",
            flush=True,
        )
    if progress:
        progress("building", 58)
    return _run_builder(base, name, temp, None, progress=progress), "router-local-generic-build"


@contextmanager
def request_temp():
    path = create_owned_temp("router-vpn-request-")
    try:
        yield path
    finally:
        # If ownership evidence was tampered with, fail safe by leaving the
        # directory for manual/OS cleanup rather than deleting an unproved path.
        try:
            cleanup_owned_temp(path)
        except OSError:
            pass


def cleanup_stale_temp() -> None:
    temp = Path(tempfile.gettempdir())
    for pattern in ("router-vpn-request-*", "router-vpn-job-*", "router-vpn-one-package-*"):
        for path in temp.glob(pattern):
            try:
                cleanup_owned_temp(path)
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


def _verified_private_text(path: Path, limit: int, label: str) -> str:
    try:
        body = read_verified_regular(path, limit, private=True)
        return body.decode("utf-8", errors="strict")
    except Exception as exc:
        raise RuntimeError(f"cannot safely read {label}: {exc}") from exc


def _setup_token(path: Path) -> str:
    text = _verified_private_text(path, 4096, "Setup Center authentication token")
    lines = text.splitlines()
    if len(lines) != 1:
        raise RuntimeError("Setup Center authentication token must contain exactly one line")
    token = lines[0].strip()
    if (
        len(token) < 32
        or len(token) > 512
        or any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in token)
    ):
        raise RuntimeError("Setup Center authentication token is invalid")
    return token


def _pairing_bundle(base: Path) -> bytes:
    path = base / "client-bundle" / "router-vpn-bundle.json"
    try:
        data = read_verified_regular(path, MAX_PAIR_BUNDLE, private=True)
        value = json.loads(data)
    except Exception as exc:
        raise RuntimeError(f"private node bundle is unavailable or unsafe: {exc}") from exc
    if not isinstance(value, dict) or int(value.get("bundleVersion") or 0) < 1:
        raise RuntimeError("private node bundle is invalid")
    return data


class Handler(SimpleHTTPRequestHandler):
    server_version = "RouterVPNSetupCenter/4"

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, separators=(",", ":")).encode() + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body_json(self, limit: int = 4096, allow_empty: bool = False) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length == 0 and allow_empty:
            return {}
        if length <= 0 or length > limit:
            raise ValueError("request body size is invalid")
        raw = self.rfile.read(length)
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    def _presented_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        raw_cookie = self.headers.get("Cookie", "")
        if raw_cookie:
            jar = cookies.SimpleCookie()
            try:
                jar.load(raw_cookie)
                if COOKIE_NAME in jar:
                    return jar[COOKIE_NAME].value.strip()
            except cookies.CookieError:
                pass
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
        return str(query.get("token", [""])[0]).strip()

    def _authorized(self) -> bool:
        supplied = self._presented_token()
        expected = str(self.server.setup_token)
        return bool(supplied) and hmac.compare_digest(supplied, expected)

    def _bootstrap_cookie(self) -> bool:
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        supplied = str(query.get("token", [""])[0]).strip()
        if not supplied or not hmac.compare_digest(supplied, str(self.server.setup_token)):
            return False
        pairs = [(k, v) for k, values in query.items() if k != "token" for v in values]
        clean_query = urllib.parse.urlencode(pairs)
        clean = urllib.parse.urlunsplit(("", "", parts.path or "/", clean_query, parts.fragment))
        self.send_response(303)
        self.send_header("Location", clean)
        self.send_header("Set-Cookie", f"{COOKIE_NAME}={supplied}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400")
        self.end_headers()
        return True

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/api/") or path in ALLOWED_DOWNLOADS:
            self._json(401, {"ok": False, "error_code": "authentication_required", "error": "Setup Center authentication required"})
        else:
            body = (
                "<!doctype html><meta charset=utf-8><title>Router VPN authentication required</title>"
                "<body style='font-family:system-ui;background:#0b1020;color:#eef2ff;padding:32px'>"
                "<h1>Router VPN Setup Center</h1><p>Authentication is required because this page can contain private node setup material.</p>"
                "<p>Retrieve the local Setup Center token from <code>/opt/router-vpn/config/setup-center.token</code> on the AI Board, then open this page with <code>?token=...</code> once. The token is converted to an HttpOnly same-site session cookie and removed from the URL.</p></body>"
            ).encode()
            self.send_response(401)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        return False

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/pairing/redeem":
            self._redeem_pairing()
            return
        if not self._require_auth():
            return
        if path == "/api/download-jobs":
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
            return
        if path == "/api/pairing":
            try:
                body = self._read_body_json(4096, allow_empty=True)
                ttl = int(body.get("ttl_seconds") or _pairing.DEFAULT_TTL)
                pair = self.server.pairing.create(ttl)
            except (ValueError, RuntimeError) as exc:
                self._json(400, {"ok": False, "error_code": "pairing_unavailable", "error": str(exc)})
                return
            self._json(201, {"ok": True, "pairing": pair})
            return
        if path == "/api/auth/logout":
            self.send_response(204)
            self.send_header("Set-Cookie", f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            self.end_headers()
            return
        self.send_error(404)

    def _redeem_pairing(self) -> None:
        try:
            body = self._read_body_json()
            code = str(body.get("code") or "")
            data = self.server.pairing.redeem(
                code,
                str(self.client_address[0]),
                lambda: _pairing_bundle(Path(self.server.base_dir)),
            )
        except (ValueError, PermissionError) as exc:
            self._json(403, {"ok": False, "error_code": "pairing_rejected", "error": str(exc)})
            return
        except RuntimeError as exc:
            self._json(503, {"ok": False, "error_code": "pairing_unavailable", "error": str(exc)})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Router-VPN-Pairing", "one-time")
        self.end_headers()
        self.wfile.write(data)

    def do_DELETE(self) -> None:
        if not self._require_auth():
            return
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
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/download-policy":
            self._json(200, {
                "mode": "on-demand", "preferred_source": "github-actions",
                "fallback": "router-local-generic-build", "server_cache": False,
                "generic_packages_secret_free": True, "node_linking": "separate-bundle-or-pairing",
                "setup_center_auth": "required-for-private-ui-and-build-actions",
                "local_build_scope": "requested-generic-package-only",
                "local_build_platforms": ["windows-amd64", "windows-arm64", "windows-portable-amd64", "windows-portable-arm64"], "mobile_artifacts": "same-sha-github-only",
                "github_exact_sha_required": True,
                "max_parallel_package_requests": 8, "local_build_slots": 1,
                "download_jobs": {"create": "POST /api/download-jobs {name}", "status": "GET /api/download-jobs/{job_id}", "cancel": "DELETE /api/download-jobs/{job_id}", "file": "GET /api/download-jobs/{job_id}/file", "ready_ttl_seconds": _jobs.JOB_TTL_SECONDS},
                "github_artifact_retention_days": 1,
                "github_sha": os.environ.get("ROUTER_VPN_GITHUB_SHA", "").strip(),
            })
            return
        if path == "/api/pairing/policy":
            self._json(200, {
                "lan_only": True, "one_time": True, "default_ttl_seconds": _pairing.DEFAULT_TTL,
                "setup_auth_required_to_create": True,
                "apple_local_network_permission_required": True,
                "private_node_material_not_discoverable_without_pairing": True,
            })
            return
        if path == "/api/auth/status":
            self._json(200, {"authentication_required": True, "authenticated": self._authorized()})
            return
        if self._bootstrap_cookie():
            return
        if not self._require_auth():
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
            self.send_header("X-Router-VPN-Source", str(meta.get("source") or ""))
            self.send_header("X-Router-VPN-Job", job_id)
            self.end_headers()
            sent = 0
            with package.open("rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    sent += len(chunk)
                    self.server.jobs.update_delivery(job_id, sent, size)
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
                        print(f"download broker: failed {name}: {type(exc).__name__}: {exc}; requested package could not be generated", flush=True)
                        self.send_error(503, "requested package could not be generated")
                        return
                    size = package.stat().st_size
                    self.send_response(200)
                    self.send_header("Content-Type", content_type_for(name))
                    self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                    self.send_header("Content-Length", str(size))
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
        # Never pass the raw request line or query string to logs: the initial
        # authenticated browser bootstrap may arrive as /?token=... .
        print("download broker:", self.command, urllib.parse.urlsplit(self.path).path, flush=True)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, base_dir: Path, static_dir: Path):
        self.base_dir = ensure_private_directory(base_dir)
        self.static_dir = ensure_private_directory(static_dir)
        token_path = self.base_dir / "config" / "setup-center.token"
        self.setup_token = _setup_token(token_path)
        self.jobs = _jobs.DownloadJobManager(base_dir, build_package, content_type_for, BUILD_SLOTS, ALLOWED_DOWNLOADS, max_active=8)
        self.pairing = _pairing.PairingManager()
        super().__init__(address, handler)

    def server_close(self) -> None:
        self.jobs.close()
        super().server_close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/opt/router-vpn")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8786)
    args = ap.parse_args()
    base = Path(os.path.abspath(os.path.expanduser(args.base)))
    ensure_private_directory(base)
    static = ensure_private_directory(base / "downloads")
    cleanup_stale_temp()
    server = Server((args.bind, args.port), Handler, base, static)
    print(f"Router VPN Setup Center on {args.bind}:{args.port}; authenticated private UI, one-time LAN pairing, ephemeral packages", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
