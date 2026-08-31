#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "router_vpn_exact_sha_release_download_tested",
    HERE / "exact_sha_release_download.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load exact_sha_release_download.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

SHA = "1" * 40
TAG = "router-vpn-sha-" + SHA


class FakeBroker:
    DIRECT_ARTIFACTS = {"router-vpn-android.apk": {}}
    _artifact_policy = SimpleNamespace(
        EXACT_SHA_RELEASE_TAG_PREFIX="router-vpn-sha-",
        EXACT_SHA_RELEASE_ASSETS={
            "router-vpn-windows-amd64.zip": "RouterVPN-Windows-amd64.zip",
            "router-vpn-android.apk": "app-debug.apk",
        },
    )

    def __init__(self):
        self.calls: list[str] = []
        self.build_package = lambda *args, **kwargs: None
        self.build_github_package = self._actions_desktop
        self.fetch_direct_mobile = self._actions_mobile
        self._run_builder = self._local_builder

    def _actions_desktop(self, base, name, temp, progress=None):
        self.calls.append("actions-desktop")
        output = temp / "actions-desktop"
        output.write_bytes(b"actions")
        return output

    def _actions_mobile(self, name, temp, progress=None):
        self.calls.append("actions-mobile")
        output = temp / "actions-mobile"
        output.write_bytes(b"mobile")
        return output

    def _local_builder(self, base, name, temp, source, progress=None):
        self.calls.append("local" if source is None else "repack")
        output = temp / name
        output.write_bytes(b"local")
        return output


def assert_delivery_order() -> None:
    original_desktop = release._release_desktop_package
    original_mobile = release._release_mobile_package
    try:
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            broker = FakeBroker()
            release._release_desktop_package = lambda *args, **kwargs: temp / "release-desktop"
            (temp / "release-desktop").write_bytes(b"release")
            release.install(broker)
            package, source = broker.build_package(temp, "router-vpn-windows-amd64.zip", temp)
            assert package.name == "release-desktop" and source == "github-release"
            assert broker.calls == [], broker.calls

        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            broker = FakeBroker()
            release._release_desktop_package = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no release"))
            release.install(broker)
            package, source = broker.build_package(temp, "router-vpn-windows-amd64.zip", temp)
            assert package.name == "actions-desktop" and source == "github-actions"
            assert broker.calls == ["actions-desktop"], broker.calls

        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            broker = FakeBroker()
            release._release_desktop_package = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no release"))
            broker.build_github_package = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no actions"))
            release.install(broker)
            package, source = broker.build_package(temp, "router-vpn-windows-amd64.zip", temp)
            assert package.name == "router-vpn-windows-amd64.zip" and source == "router-local-generic-build"
            assert broker.calls == ["local"], broker.calls

        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            broker = FakeBroker()
            release._release_mobile_package = lambda *args, **kwargs: temp / "release-mobile"
            (temp / "release-mobile").write_bytes(b"release")
            release.install(broker)
            package, source = broker.build_package(temp, "router-vpn-android.apk", temp)
            assert package.name == "release-mobile" and source == "github-release"
            assert broker.calls == [], broker.calls

        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            broker = FakeBroker()
            release._release_mobile_package = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no release"))
            release.install(broker)
            package, source = broker.build_package(temp, "router-vpn-android.apk", temp)
            assert package.name == "actions-mobile" and source == "github-actions"
            assert broker.calls == ["actions-mobile"], broker.calls

        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            broker = FakeBroker()
            release._release_mobile_package = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no release"))
            broker.fetch_direct_mobile = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no actions"))
            release.install(broker)
            try:
                broker.build_package(temp, "router-vpn-android.apk", temp)
            except RuntimeError as exc:
                assert "no actions" in str(exc)
            else:
                raise AssertionError("mobile delivery incorrectly used a local Linux fallback")
            assert broker.calls == [], broker.calls

        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            broker = FakeBroker()
            release.install(broker)
            package, source = broker.build_package(temp, "router-vpn-client-bundle.zip", temp)
            assert package.name == "router-vpn-client-bundle.zip" and source == "private-node-bundle"
            assert broker.calls == ["local"], broker.calls
    finally:
        release._release_desktop_package = original_desktop
        release._release_mobile_package = original_mobile


def assert_exact_release_identity() -> None:
    calls: list[str] = []

    class MetadataBroker:
        _artifact_policy = SimpleNamespace(EXACT_SHA_RELEASE_TAG_PREFIX="router-vpn-sha-")

        @staticmethod
        def _github_scope():
            return "Eabusham2/router-vpn", "main", SHA

        @staticmethod
        def _read_limited_json(url: str):
            calls.append(url)
            if "/releases/tags/" in url:
                return {"tag_name": TAG, "target_commitish": SHA, "draft": False, "assets": []}
            return {"object": {"type": "commit", "sha": SHA}}

    repo, sha, tag, _metadata = release._release_metadata(MetadataBroker())
    assert (repo, sha, tag) == ("Eabusham2/router-vpn", SHA, TAG)
    assert len(calls) == 2
    assert all("releases/latest" not in value for value in calls)


assert_delivery_order()
assert_exact_release_identity()
source = (HERE / "exact_sha_release_download.py").read_text(encoding="utf-8")
assert "/releases/latest" not in source
assert "exact-SHA GitHub Release" in source
assert "router-local-generic-build" in source
print("Exact-SHA Release-first Setup Center delivery: PASS")
