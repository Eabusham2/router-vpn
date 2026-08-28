#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/materialize-production-compose.py"
VERIFY = ROOT / "server/scripts/verify-production-compose.py"
VERIFY_SPEC = importlib.util.spec_from_file_location("routervpn_production_compose_verify_test", VERIFY)
assert VERIFY_SPEC and VERIFY_SPEC.loader
VERIFY_MOD = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY_MOD)
SOURCE = ROOT / "server/portainer-current.yaml"
TARGET = "a" * 40
DOCS = [
    ROOT / "README.md",
    ROOT / "START-HERE.md",
    ROOT / "START-CURRENT.md",
    ROOT / "USE-CURRENT.md",
    ROOT / "docs/CURRENT-GUIDE.md",
    ROOT / "docs/INSTALL-PORTAINER.md",
    ROOT / "docs/INSTALL-SSH.md",
]
ACTIVE_ONBOARDING = [
    ROOT / "server/scripts/setup_center_guide.py",
    ROOT / "server/scripts/generate-setup-assets.py",
    ROOT / "ios/RouterVPN/App/ContentView.swift",
    ROOT / "android/app/src/main/java/com/eabusham/routervpn/MainActivity.java",
]
UNSAFE_ONBOARDING = [
    "Create a stack from the Router VPN repository using <code>server/portainer-current.yaml</code>",
    "Compose path: server/portainer-current.yaml",
    "Compose: <code>server/portainer-current.yaml</code>",
    "and use server/portainer-current.yaml",
    "Deploy the home node with server/portainer-current.yaml",
]


def main() -> int:
    original = SOURCE.read_bytes()
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / f"portainer-{TARGET}.yaml"
        subprocess.run(
            [sys.executable, str(SCRIPT), "--sha", TARGET, "--input", str(SOURCE), "--output", str(out)],
            cwd=ROOT,
            check=True,
        )
        rendered = out.read_text(encoding="utf-8")
        assert TARGET in rendered
        assert "GENERATED exact-SHA Router VPN production compose: " + TARGET in rendered
        assert "ghcr.io/sagernet/sing-box:v1.13.12" in rendered
        assert "ghcr.io/xtls/xray-core:26.7.11" in rendered
        assert "ghcr.io/eabusham2/router-vpn-updater:" + TARGET in rendered
        assert "ROUTER_VPN_UPDATE_LISTEN: 127.0.0.1:8793" in rendered
        assert "/var/run/docker.sock" not in rendered
        assert "ROUTER_VPN_GITHUB_SHA: " + TARGET in rendered
        assert SOURCE.read_bytes() == original, "materializer mutated tracked template"

        verified = subprocess.run(
            [sys.executable, str(VERIFY), str(out)], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE
        )
        assert verified.stdout.strip() == TARGET
        baseline = subprocess.run(
            [sys.executable, str(VERIFY), str(SOURCE)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        assert baseline.returncode != 0, "tracked baseline was accepted as a generated release compose"

        if os.name != "nt":
            link = Path(td) / "compose-link.yaml"
            link.symlink_to(out)
            linked = subprocess.run(
                [sys.executable, str(VERIFY), str(link)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            assert linked.returncode != 0, "symlinked production compose was accepted"

            unsafe_target = Path(td) / "unsafe-target.yaml"
            unsafe_target.write_text("keep\n", encoding="utf-8")
            unsafe_output = Path(td) / "unsafe-output.yaml"
            unsafe_output.symlink_to(unsafe_target)
            unsafe = subprocess.run(
                [sys.executable, str(SCRIPT), "--sha", TARGET, "--input", str(SOURCE), "--output", str(unsafe_output)],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            assert unsafe.returncode != 0, "materializer followed a symlink output target"
            assert unsafe_target.read_text(encoding="utf-8") == "keep\n"

        replacement = Path(td) / "replacement.yaml"
        replacement.write_text(rendered, encoding="utf-8")
        real_open = VERIFY_MOD.os.open
        swapped = False
        def swap_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if Path(path) == out and not swapped:
                swapped = True
                os.replace(replacement, out)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(VERIFY_MOD.os, "open", side_effect=swap_before_open):
            try:
                VERIFY_MOD.verify(out)
            except SystemExit as exc:
                assert "changed identity during open" in str(exc)
            else:
                raise AssertionError("production compose replacement race was accepted")
        assert swapped

        for path in DOCS:
            text = path.read_text(encoding="utf-8")
            assert "Exact-SHA production compose" in text, f"{path} omits exact-SHA release workflow"
            assert "PRODUCTION-RELEASE.md" in text, f"{path} omits production release contract"
            assert "tracked" in text and "template" in text, f"{path} does not distinguish tracked template"

        for path in ACTIVE_ONBOARDING:
            text = path.read_text(encoding="utf-8")
            assert "Exact-SHA production compose" in text, f"{path} omits exact-SHA release workflow"
            assert "server/portainer-current.yaml" in text and "template/baseline" in text, f"{path} does not label tracked compose as baseline"
            for unsafe in UNSAFE_ONBOARDING:
                assert unsafe not in text, f"{path} revives unsafe baseline deployment wording: {unsafe}"

        bad = subprocess.run(
            [sys.executable, str(SCRIPT), "--sha", "not-a-sha", "--input", str(SOURCE), "--output", str(out)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert bad.returncode != 0, bad
    print("production release compose materializer tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
