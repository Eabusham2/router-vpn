from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/materialize-production-compose.py"
VERIFY_PATH = ROOT / "server/scripts/verify-production-compose.py"
SOURCE = ROOT / "server/portainer-current.yaml"
TARGET = "a" * 40


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROD = load("router_vpn_materialize_production_compose", SCRIPT)
VERIFY = load("router_vpn_verify_production_compose", VERIFY_PATH)


def test_exact_sha_materialization() -> None:
    original = SOURCE.read_bytes()
    with tempfile.TemporaryDirectory(prefix="router-vpn-production-compose-") as td:
        output = Path(td) / f"RouterVPN-Portainer-{TARGET}.yaml"
        subprocess.run(
            [sys.executable, str(SCRIPT), "--sha", TARGET, "--input", str(SOURCE), "--output", str(output)],
            cwd=ROOT,
            check=True,
        )
        rendered = output.read_text(encoding="utf-8")
        assert rendered.startswith("# GENERATED exact-SHA Router VPN production compose: " + TARGET)
        assert "# Generated from server/portainer-current.yaml" in rendered
        assert "ghcr.io/sagernet/sing-box:v1.13.12" in rendered
        assert "ghcr.io/xtls/xray-core:26.7.11" in rendered
        assert "ghcr.io/eabusham2/router-vpn-updater:" + TARGET in rendered
        assert "ROUTER_VPN_UPDATE_LISTEN: 127.0.0.1:8793" in rendered
        assert "ROUTER_VPN_GITHUB_SHA: " + TARGET in rendered
        assert "/var/run/docker.sock" not in rendered
        assert not any(tag in rendered for tag in (":latest", ":main", ":arm64-main"))
        assert VERIFY.verify(output) == TARGET
        assert SOURCE.read_bytes() == original, "materializer mutated tracked baseline"

        try:
            VERIFY.verify(SOURCE)
        except SystemExit:
            pass
        else:
            raise AssertionError("tracked baseline was accepted as a generated exact-SHA compose")

        bad = subprocess.run(
            [sys.executable, str(SCRIPT), "--sha", "not-a-sha", "--input", str(SOURCE), "--output", str(output)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert bad.returncode != 0


def test_template_and_output_identity_guards() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-compose-read-identity-") as td:
        root = Path(td)
        source = root / "source.yaml"
        source.write_text("services:\n  owned: {}\n", encoding="utf-8")
        foreign = root / "foreign.yaml"
        foreign.write_text("services:\n  foreign: {}\n", encoding="utf-8")
        real_read = PROD.os.read
        swapped = False

        def read_then_swap(fd: int, count: int) -> bytes:
            nonlocal swapped
            chunk = real_read(fd, count)
            if not swapped:
                swapped = True
                os.replace(foreign, source)
            return chunk

        with mock.patch.object(PROD.os, "read", side_effect=read_then_swap):
            try:
                PROD.read_regular_text(source)
            except RuntimeError as exc:
                assert "changed during read" in str(exc)
            else:
                raise AssertionError("compose reader accepted a foreign replacement")

    with tempfile.TemporaryDirectory(prefix="router-vpn-compose-write-identity-") as td:
        root = Path(td)
        output = root / "production.yaml"
        PROD.atomic_write(output, "services:\n  old: {}\n")
        foreign = root / "foreign.yaml"
        foreign_body = "services:\n  foreign: {}\n"
        foreign.write_text(foreign_body, encoding="utf-8")
        os.chmod(foreign, 0o644)
        real_replace = PROD.os.replace
        swapped = False

        def replace_then_swap(src, dst):
            nonlocal swapped
            result = real_replace(src, dst)
            if Path(dst) == output and not swapped:
                swapped = True
                real_replace(foreign, output)
            return result

        with mock.patch.object(PROD.os, "replace", side_effect=replace_then_swap):
            try:
                PROD.atomic_write(output, "services:\n  new: {}\n")
            except RuntimeError as exc:
                assert "identity changed before verification" in str(exc)
            else:
                raise AssertionError("compose writer accepted a foreign post-rename replacement")
        assert output.read_text(encoding="utf-8") == foreign_body
        assert not list(root.glob(".production.yaml.compose-*"))


def test_release_workflow_contract() -> None:
    workflow = (ROOT / ".github/workflows/production-release-compose.yml").read_text(encoding="utf-8")
    for marker in (
        "materialize-production-compose.py --sha \"$GITHUB_SHA\"",
        "verify-production-compose.py",
        "RouterVPN-production-compose-${{ github.sha }}",
        "ghcr.io/eabusham2/router-vpn-updater:${GITHUB_SHA}",
        "ROUTER_VPN_GITHUB_SHA",
    ):
        assert marker in workflow, marker
    assert "--no-build" not in workflow, "production release workflow must materialize an image-only artifact, not deploy/build"
    assert "/var/run/docker.sock" in workflow, "workflow must explicitly prove Docker socket absence"


def main() -> int:
    test_exact_sha_materialization()
    test_template_and_output_identity_guards()
    test_release_workflow_contract()
    source = SCRIPT.read_text(encoding="utf-8")
    for marker in (
        "GENERATED exact-SHA Router VPN production compose",
        "server/portainer-current.yaml",
        '"updater": 1',
        "ROUTER_VPN_UPDATE_LISTEN: 127.0.0.1:8793",
        "ROUTER_VPN_GITHUB_SHA",
        "read_regular_text",
        "tempfile.mkstemp",
        "os.fsync(stream.fileno())",
        "os.replace(tmp, path)",
        "os.path.samestat(staged, current)",
    ):
        assert marker in source, marker
    print("production release compose materializer tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
