#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MATERIALIZER_PATH = ROOT / "deploy" / "materialize-production-compose.py"
VERIFIER_PATH = ROOT / "server" / "scripts" / "verify-production-compose.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROD = load_module("router_vpn_materialize_production_compose", MATERIALIZER_PATH)
VERIFY = load_module("router_vpn_verify_production_compose", VERIFIER_PATH)


VALID_VALUES = {
    "TZ": "America/Chicago",
    "WG_PORT": "51820",
    "AWG2_PORT": "51822",
    "XRAY_PQ_PORT": "18443",
    "XRAY_XHTTP_PORT": "17443",
    "OPENVPN_PORT": "1194",
    "SERVER_INTERNAL_CIDR": "172.28.0.0/24",
    "SERVER_INTERNAL_GATEWAY": "172.28.0.1",
    "ROUTER_LAN_CIDR": "192.168.50.0/24",
    "CLIENT_EXTERNAL_PORT": "8788",
    "CLIENT_LISTEN": "0.0.0.0:8788",
    "SETUP_CENTER_EXTERNAL_PORT": "8090",
    "SETUP_CENTER_LISTEN": "0.0.0.0:8090",
    "ROUTER_AGENT_EXTERNAL_PORT": "8787",
    "ROUTER_AGENT_LISTEN": "0.0.0.0:8787",
    "SETUP_BASE_URL": "http://192.168.50.133:8090",
    "PUBLIC_ENDPOINT": "vpn.example.test",
}


def compose_template() -> str:
    lines = ["services:", "  router-vpn-client:", "    image: ghcr.io/eabusham2/router-vpn-client:current", "    environment:"]
    for key in PROD.REQUIRED:
        lines.append(f"      {key}: ${{{key}}}")
    lines.extend(
        [
            "    ports:",
            '      - "${CLIENT_EXTERNAL_PORT}:8788"',
            "  router-vpn-setup-center:",
            "    image: ghcr.io/eabusham2/router-vpn-setup-center:current",
            "    ports:",
            '      - "${SETUP_CENTER_EXTERNAL_PORT}:8090"',
            "  router-vpn-agent:",
            "    image: ghcr.io/eabusham2/router-vpn-router-agent:current",
            "    ports:",
            '      - "${ROUTER_AGENT_EXTERNAL_PORT}:8787"',
            "networks:",
            "  routervpn:",
            "    ipam:",
            "      config:",
            '        - subnet: "${SERVER_INTERNAL_CIDR}"',
            '          gateway: "${SERVER_INTERNAL_GATEWAY}"',
        ]
    )
    return "\n".join(lines) + "\n"


def test_materialization() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-production-compose-") as td:
        tmp = Path(td)
        env_path = tmp / "production.env"
        env_path.write_text("\n".join(f"{key}={VALID_VALUES[key]}" for key in PROD.REQUIRED) + "\n")
        values = PROD.load_env(env_path)
        assert values == VALID_VALUES
        rendered = PROD.materialize(compose_template(), values)
        assert "${" not in rendered
        assert "router.invalid" not in rendered
        assert '8788:8788' in rendered
        assert '8090:8090' in rendered
        assert '8787:8787' in rendered
        assert VERIFY.collect_errors(rendered, "vpn.example.test") == []
        output = tmp / "portainer-production.yaml"
        PROD.atomic_write(output, rendered)
        assert output.read_text() == rendered
        if os.name != "nt":
            assert output.stat().st_mode & 0o777 == 0o644


def test_materializer_rejects_unknown_and_missing_values() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-production-compose-env-") as td:
        tmp = Path(td)
        missing = tmp / "missing.env"
        missing.write_text("TZ=America/Chicago\n")
        try:
            PROD.load_env(missing)
        except SystemExit as exc:
            assert "missing required production values" in str(exc)
        else:
            raise AssertionError("missing production values were accepted")

        unknown = tmp / "unknown.env"
        unknown.write_text(
            "\n".join(f"{key}={VALID_VALUES[key]}" for key in PROD.REQUIRED)
            + "\nUNEXPECTED=value\n"
        )
        try:
            PROD.load_env(unknown)
        except SystemExit as exc:
            assert "unknown production values" in str(exc)
        else:
            raise AssertionError("unknown production value was accepted")


def test_materializer_rejects_unresolved_or_placeholder_compose() -> None:
    try:
        PROD.materialize("services:\n  x: ${UNKNOWN}\n", VALID_VALUES)
    except SystemExit as exc:
        assert "unresolved compose variables" in str(exc)
    else:
        raise AssertionError("unresolved compose variable was accepted")

    bad_values = dict(VALID_VALUES)
    bad_values["PUBLIC_ENDPOINT"] = "router.invalid"
    try:
        PROD.materialize(compose_template(), bad_values)
    except SystemExit as exc:
        assert "placeholder" in str(exc)
    else:
        raise AssertionError("placeholder materialization was accepted")


def test_verifier_rejects_repo_relative_build_context() -> None:
    rendered = PROD.materialize(compose_template(), VALID_VALUES)
    rendered = rendered.replace(
        "    image: ghcr.io/eabusham2/router-vpn-client:current\n",
        "    image: ghcr.io/eabusham2/router-vpn-client:current\n    build: .\n",
        1,
    )
    errors = VERIFY.collect_errors(rendered, "vpn.example.test")
    assert any("repo-relative Docker build context" in error for error in errors)


def test_source_has_durable_atomic_write() -> None:
    source = MATERIALIZER_PATH.read_text()
    for marker in (
        "read_regular_text",
        "tempfile.mkstemp",
        "os.fchmod(fd, PUBLIC_MODE)",
        "os.fsync(stream.fileno())",
        "os.replace(tmp, path)",
        "os.path.samestat(staged, current)",
        "os.fsync(dfd)",
    ):
        assert marker in source, marker


def test_source_read_replacement_is_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-compose-read-identity-") as td:
        root = Path(td)
        source = root / "source.env"
        source.write_text("TZ=America/Chicago\n")
        foreign = root / "foreign.env"
        foreign.write_text("TZ=UTC\n")
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
        assert source.read_text() == "TZ=UTC\n"


def test_output_post_rename_replacement_is_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-compose-write-identity-") as td:
        root = Path(td)
        output = root / "portainer-production.yaml"
        PROD.atomic_write(output, "services:\n  old: {}\n")
        foreign = root / "foreign.yaml"
        foreign_body = "services:\n  foreign: {}\n"
        foreign.write_text(foreign_body)
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
        assert output.read_text() == foreign_body
        assert not list(root.glob(".portainer-production.yaml.compose-*"))


def test_release_workflow_builds_each_repository_path_once() -> None:
    workflow = (ROOT / ".github/workflows/production-release-compose.yml").read_text()
    for marker in (
        "materialize-production-compose.py",
        "verify-production-compose.py",
        "docker compose",
        "--no-build",
    ):
        assert marker in workflow, marker
    assert workflow.count("docker compose") == 1
    assert "--template server/portainer-current.yaml" in workflow
    assert "portainer-production.yaml" in workflow


def test_deployment_docs_use_generated_compose() -> None:
    docs = (ROOT / "docs/PRODUCTION-RELEASE.md").read_text()
    assert "portainer-production.yaml" in docs
    assert "Server &gt; Stacks &gt; Add stack" in docs
    assert "one production compose file" in docs.lower()


def main() -> int:
    test_materialization()
    test_materializer_rejects_unknown_and_missing_values()
    test_materializer_rejects_unresolved_or_placeholder_compose()
    test_verifier_rejects_repo_relative_build_context()
    test_source_has_durable_atomic_write()
    test_source_read_replacement_is_rejected()
    test_output_post_rename_replacement_is_rejected()
    test_release_workflow_builds_each_repository_path_once()
    test_deployment_docs_use_generated_compose()
    print(json.dumps({"ok": True, "tests": 9}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
