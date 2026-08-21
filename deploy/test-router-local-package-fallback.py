#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "server" / "scripts" / "build-download-on-demand.py"
spec = importlib.util.spec_from_file_location("routervpn_local_fallback_test", BUILDER_PATH)
assert spec and spec.loader
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def write(path: Path, data: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def fake_source(root: Path) -> None:
    write(root / "modes" / "run-wg.sh", "#!/bin/sh\nexit 0\n")
    write(root / "client" / "RouterVPN-Windows-App.ps1", "# native WPF product\n")
    write(root / "client" / "install-windows.ps1", "# install native Windows app\n")
    write(root / "client" / "Setup-Windows-Runtime.ps1", "# setup runtime\n")
    write(root / "configs" / "client" / "client.json.example", "{}\n")
    write(root / "configs" / "client" / "modes.json", "[]\n")
    write(root / "configs" / "client" / "logical-modes.json", "[]\n")
    write(root / "docs" / "MODES.md")
    write(root / "docs" / "CLIENT.md")
    write(root / "SECURITY.md")
    write(root / "LICENSE", "MIT\n")
    icon = root / "deploy" / "materialize-desktop-icons.py"
    write(
        icon,
        "#!/usr/bin/env python3\n"
        "import argparse,pathlib\n"
        "p=argparse.ArgumentParser();p.add_argument('--png');p.add_argument('--ico');a=p.parse_args()\n"
        "pathlib.Path(a.png).write_bytes(b'\\x89PNG\\r\\n\\x1a\\n'+b'P'*5000)\n"
        "pathlib.Path(a.ico).write_bytes(b'\\x00\\x00\\x01\\x00\\x01\\x00'+b'I'*128)\n",
    )
    dist = root / "dist"
    for arch in ("amd64", "arm64"):
        for name in (
            f"router-vpn-client-windows-{arch}.exe",
            f"router-vpn-dns-windows-{arch}.exe",
            f"RouterVPN-{arch}.exe",
            f"RouterVPNPortable-{arch}.exe",
            f"RouterVPNSetupRuntime-{arch}.exe",
        ):
            write(dist / name, "fake executable\n")


def require(root: Path, *names: str) -> None:
    for name in names:
        path = root / name
        assert path.is_file(), f"missing complete fallback component: {path}"


def assert_blank_store(path: Path) -> None:
    store = json.loads(path.read_text(encoding="utf-8"))
    assert store.get("schema_version") == 4, store
    assert store.get("selected_id") == "" and store.get("profiles") == [], store


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-local-fallback-") as td:
        td = Path(td)
        src = td / "src"
        base = td / "base"
        base.mkdir()
        fake_source(src)

        # Same-image prebuilt components must be preferred over a router-local
        # compile when the requested complete Windows/Portable set already exists.
        assert builder.compile_requested(td / "compile-win", "router-vpn-windows-amd64.zip", src) == src
        assert builder.compile_requested(td / "compile-portable", "router-vpn-windows-portable-arm64.zip", src) == src

        win = builder.build_local(td / "work-win", "router-vpn-windows-amd64.zip", src, src, base)
        require(
            win,
            "RouterVPN.exe",
            "RouterVPN.ico",
            "RouterVPN.png",
            "router-vpn-client.exe",
            "router-vpn-dns.exe",
            "install-windows.ps1",
            "Setup-Windows-Runtime.ps1",
            "client/RouterVPN-Windows-App.ps1",
            "routers.json",
        )
        assert_blank_store(win / "routers.json")
        builder.assert_generic_tree(win)

        portable = builder.build_local(td / "work-portable", "router-vpn-windows-portable-arm64.zip", src, src, base)
        require(
            portable,
            "RouterVPNPortable.exe",
            "RouterVPNSetupRuntime.exe",
            "Setup-Windows-Runtime.ps1",
            "App/RouterVPN/RouterVPN.ico",
            "App/RouterVPN/RouterVPN.png",
            "App/RouterVPN/client/RouterVPN-Windows-App.ps1",
            "App/RouterVPN/router-vpn-client.exe",
            "Data/routers.json",
        )
        assert_blank_store(portable / "App/RouterVPN/routers.json")
        assert_blank_store(portable / "Data/routers.json")
        builder.assert_generic_tree(portable)

        for request, platform in (
            ("router-vpn-macos-arm64.zip", "AppKit"),
            ("router-vpn-linux-arm64.zip", "GTK"),
        ):
            try:
                builder.compile_requested(td / ("compile-" + platform), request, src)
            except RuntimeError as exc:
                text = str(exc)
                assert "same-SHA native GitHub artifact is required" in text and platform in text, text
            else:
                raise AssertionError(f"{request} incorrectly allowed a controller-only local fallback")

    print("Router-local complete-package fallback tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
