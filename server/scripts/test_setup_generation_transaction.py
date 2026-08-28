#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


generator = load("router_vpn_setup_generation_transaction", HERE / "generate-setup-assets.py")
normalizer = load("router_vpn_setup_normalization_transaction", HERE / "normalize-setup-imports.py")


def seed_live(base: Path) -> tuple[Path, Path]:
    bundle = base / "client-bundle"
    bundle.mkdir(parents=True)
    assets = bundle / "setup-assets.json"
    html = bundle / "router-vpn-device-setup.html"
    assets.write_text('{"old":true}\n', encoding="utf-8")
    html.write_text("<html>old</html>\n", encoding="utf-8")
    os.chmod(assets, 0o600)
    os.chmod(html, 0o600)
    return assets, html


def fail_batch(*_args, **_kwargs):
    raise RuntimeError("injected private batch failure")


def assert_unchanged(assets: Path, html: Path) -> None:
    assert assets.read_text(encoding="utf-8") == '{"old":true}\n'
    assert html.read_text(encoding="utf-8") == "<html>old</html>\n"


def test_generator_failure_keeps_previous_pair() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-setup-generate-") as td:
        base = Path(td)
        assets, html = seed_live(base)
        old_argv = generator.sys.argv
        generator.sys.argv = ["generate-setup-assets.py", str(base), "router.invalid", "192.168.50.133"]
        try:
            with mock.patch.object(generator.subprocess, "run", side_effect=fail_batch):
                try:
                    generator.main()
                except RuntimeError as exc:
                    assert "injected private batch failure" in str(exc)
                else:
                    raise AssertionError("generator unexpectedly succeeded after injected batch failure")
        finally:
            generator.sys.argv = old_argv
        assert_unchanged(assets, html)
        assert not list((base / "client-bundle").glob(".setup-assets.*"))


def test_normalizer_failure_keeps_previous_pair() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-setup-normalize-") as td:
        base = Path(td)
        assets, html = seed_live(base)
        # Normalization needs a structurally valid generated data object. Build
        # one in memory, publish it as the current pair, then inject failure only
        # at the final private batch adoption.
        data = {
            "warning": "private",
            "endpoint": "router.invalid",
            "socksHost": "192.168.50.133",
            "devices": {},
            "methods": [],
            "modes": [],
            "downloads": [],
        }
        import json
        assets.write_text(json.dumps(data) + "\n", encoding="utf-8")
        html.write_text("<html>old-normalized</html>\n", encoding="utf-8")
        before_assets = assets.read_bytes()
        before_html = html.read_bytes()

        old_argv = normalizer.sys.argv
        normalizer.sys.argv = ["normalize-setup-imports.py", str(base)]
        try:
            with mock.patch.object(normalizer.subprocess, "run", side_effect=fail_batch):
                try:
                    normalizer.main()
                except RuntimeError as exc:
                    assert "injected private batch failure" in str(exc)
                else:
                    raise AssertionError("normalizer unexpectedly succeeded after injected batch failure")
        finally:
            normalizer.sys.argv = old_argv

        assert assets.read_bytes() == before_assets
        assert html.read_bytes() == before_html
        assert not list((base / "client-bundle").glob(".normalize-setup.*"))


def main() -> int:
    test_generator_failure_keeps_previous_pair()
    test_normalizer_failure_keeps_previous_pair()
    print("Setup Center generation/normalization transaction tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
