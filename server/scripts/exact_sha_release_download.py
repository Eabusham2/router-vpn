#!/usr/bin/env python3
"""Exact-SHA GitHub Release delivery for the authenticated Setup Center.

Shipping order:

1. Exact-SHA GitHub Release asset published by the authoritative build-all run.
2. Exact-SHA GitHub Actions artifact from the mapped producer workflow.
3. A bounded router-local build of only the requested desktop/Portable package.

Mobile packages remain GitHub-only because a Linux home node cannot reproduce
Android/iOS platform builds or Apple packaging truthfully.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import urllib.parse
import urllib.request

_RELEASE_INSTALLED = "_router_vpn_exact_sha_release_delivery_installed"


def _release_metadata(broker):
    repo, _branch, head_sha = broker._github_scope()
    policy = broker._artifact_policy
    tag = f"{policy.EXACT_SHA_RELEASE_TAG_PREFIX}{head_sha}"
    encoded = urllib.parse.quote(tag, safe="")
    release = broker._read_limited_json(
        f"https://api.github.com/repos/{repo}/releases/tags/{encoded}"
    )
    if str(release.get("tag_name") or "") != tag:
        raise RuntimeError("exact-SHA GitHub Release tag mismatch")
    if bool(release.get("draft")):
        raise RuntimeError("exact-SHA GitHub Release is still a draft")
    target = str(release.get("target_commitish") or "").strip().lower()
    if target != head_sha:
        raise RuntimeError(
            f"exact-SHA GitHub Release target mismatch: expected {head_sha}, got {target or 'empty'}"
        )

    ref = broker._read_limited_json(
        f"https://api.github.com/repos/{repo}/git/ref/tags/{encoded}"
    )
    obj = ref.get("object") or {}
    if str(obj.get("type") or "") != "commit" or str(obj.get("sha") or "").lower() != head_sha:
        raise RuntimeError("exact-SHA GitHub Release tag does not point directly at the requested commit")
    return repo, head_sha, tag, release


def _release_asset(broker, request_name: str):
    policy = broker._artifact_policy
    asset_name = policy.EXACT_SHA_RELEASE_ASSETS.get(request_name)
    if not asset_name:
        raise RuntimeError(f"no exact-SHA release asset is mapped for {request_name}")
    _repo, _sha, _tag, release = _release_metadata(broker)
    matches = [
        item for item in list(release.get("assets") or [])
        if str(item.get("name") or "") == asset_name
        and str(item.get("state") or "uploaded") == "uploaded"
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one exact-SHA release asset named {asset_name}; found {len(matches)}"
        )
    asset = matches[0]
    size = int(asset.get("size") or 0)
    if size <= 0 or size > broker.MAX_GITHUB_ARTIFACT:
        raise RuntimeError("exact-SHA release asset has an unsafe size")
    url = str(asset.get("url") or "")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() != "api.github.com":
        raise RuntimeError("exact-SHA release asset API URL is unsafe")
    expected_digest = broker._artifact_sha256(asset)
    return asset_name, asset, size, expected_digest


def _download_release_asset(broker, request_name: str, temp: Path, output_name: str, progress=None) -> Path:
    if os.environ.get("ROUTER_VPN_GITHUB_DISABLE", "").lower() in ("1", "true", "yes"):
        raise RuntimeError("GitHub release use disabled")
    if progress:
        progress("locating", 12)
    selected = broker._safe_selected_output(temp, output_name)
    asset_name, asset, metadata_size, expected_digest = _release_asset(broker, request_name)
    if progress:
        progress("downloading", 22)

    headers = broker._api_headers()
    headers["Accept"] = "application/octet-stream"
    request = urllib.request.Request(str(asset["url"]), headers=headers)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(selected, flags, 0o600)
    complete = False
    digest = hashlib.sha256()
    total = 0
    opened = None
    try:
        with broker._GITHUB_OPENER.open(request, timeout=25) as response, os.fdopen(fd, "wb", closefd=True) as output:
            opened = os.fstat(output.fileno())
            try:
                content_length = int(response.headers.get("Content-Length", "0") or 0)
            except ValueError:
                content_length = 0
            if content_length < 0 or content_length > broker.MAX_GITHUB_ARTIFACT:
                raise RuntimeError("exact-SHA release Content-Length exceeds safety limit")
            while True:
                chunk = response.read(broker.CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > broker.MAX_GITHUB_ARTIFACT:
                    raise RuntimeError("exact-SHA release asset exceeds safety limit")
                output.write(chunk)
                digest.update(chunk)
                if progress and content_length > 0:
                    progress("downloading", min(40, 22 + int(18 * total / content_length)))
            output.flush()
            os.fsync(output.fileno())
        if total <= 0:
            raise RuntimeError("GitHub Release returned an empty asset")
        if metadata_size != total:
            raise RuntimeError(
                f"exact-SHA release asset size mismatch for {asset_name}: received {total}, metadata {metadata_size}"
            )
        if content_length > 0 and content_length != total:
            raise RuntimeError("exact-SHA release Content-Length mismatch")
        if digest.hexdigest() != expected_digest:
            raise RuntimeError("exact-SHA release asset SHA-256 digest mismatch")
        current = selected.lstat()
        if (
            opened is None
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
            or current.st_size != total
        ):
            raise RuntimeError("exact-SHA release asset changed during download verification")
        complete = True
    finally:
        if not complete:
            try:
                os.close(fd)
            except OSError:
                pass
            selected.unlink(missing_ok=True)
    if progress:
        progress("validating", 46)
    return selected


def _release_desktop_package(broker, base: Path, name: str, temp: Path, progress=None) -> Path:
    generic = broker._builder.generic_name(name)
    if not generic:
        raise RuntimeError("this desktop download has no generic release package")
    source = _download_release_asset(broker, name, temp, generic, progress=progress)
    try:
        return broker._run_builder(base, name, temp, source, progress=progress)
    finally:
        source.unlink(missing_ok=True)


def _release_mobile_package(broker, name: str, temp: Path, progress=None) -> Path:
    selected = _download_release_asset(broker, name, temp, name, progress=progress)
    try:
        repo, _branch, head_sha = broker._github_scope()
        broker._mobile_provenance.verify(name, selected, head_sha, repo)
        return selected
    except Exception:
        selected.unlink(missing_ok=True)
        raise


def install(broker) -> None:
    """Install release-first delivery into one loaded download-broker module."""
    if getattr(broker, _RELEASE_INSTALLED, False):
        return

    original_build_github_package = broker.build_github_package
    original_fetch_direct_mobile = broker.fetch_direct_mobile

    def release_first_build_package(base: Path, name: str, temp: Path, progress=None):
        if progress:
            progress("locating", 10)
        if name in broker.DIRECT_ARTIFACTS:
            try:
                return _release_mobile_package(broker, name, temp, progress=progress), "github-release"
            except Exception as release_error:
                print(
                    f"download broker: exact-SHA GitHub Release asset failed for {name}: "
                    f"{type(release_error).__name__}: {release_error}; trying exact-SHA Actions artifact",
                    flush=True,
                )
            return original_fetch_direct_mobile(name, temp, progress=progress), "github-actions"

        if name == "router-vpn-client-bundle.zip":
            if progress:
                progress("packaging", 70)
            return broker._run_builder(base, name, temp, None, progress=progress), "private-node-bundle"

        try:
            return _release_desktop_package(broker, base, name, temp, progress=progress), "github-release"
        except Exception as release_error:
            print(
                f"download broker: exact-SHA GitHub Release asset failed for {name}: "
                f"{type(release_error).__name__}: {release_error}; trying exact-SHA Actions artifact",
                flush=True,
            )
        try:
            return original_build_github_package(base, name, temp, progress=progress), "github-actions"
        except Exception as actions_error:
            print(
                f"download broker: exact-SHA Actions artifacts failed for {name}: "
                f"{type(actions_error).__name__}: {actions_error}; building only the requested package locally",
                flush=True,
            )
        return broker._run_builder(base, name, temp, None, progress=progress), "router-local-generic-build"

    broker.build_package = release_first_build_package
    setattr(broker, _RELEASE_INSTALLED, True)
