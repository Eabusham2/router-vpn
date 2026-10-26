#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "server" / "scripts" / "build-download-on-demand.py"
spec = importlib.util.spec_from_file_location("routervpn_local_fallback_test", BUILDER_PATH)
assert spec and spec.loader
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
ENGINES = builder._desktop_runtime_builders()
spec = importlib.util.spec_from_file_location("routervpn_local_fallback_pe", ROOT / "deploy" / "test_desktop_native_dependencies.py")
assert spec and spec.loader
PE_FIXTURE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PE_FIXTURE)
METADATA_READS = []
METADATA_OVERLAY = b"\nROUTER_VPN_TEST_GO_METADATA\n"


def fixture_metadata(command, *, cwd=None, env=None, timeout=None):
    """Double only Go's executable metadata reader, not receipt verification.

    Real host-built engines are exercised by the native bundle/package gate.
    These tiny fixtures keep the source fallback tests independent of a cross
    compiler while still running the shipping target/tag/pin checks unchanged.
    """
    assert [str(value) for value in command[:3]] == ["go", "version", "-m"], command
    assert len(command) == 4 and cwd is None, command
    assert env["GOTOOLCHAIN"] == "local" and env["GOPROXY"] == "off", env
    binary = Path(command[3])
    header = json.loads(binary.read_bytes().split(METADATA_OVERLAY, 1)[1].split(b"\n", 1)[0])
    system, arch = header["target"].split("/")
    METADATA_READS.append((str(binary), header["target"]))
    return (str(binary) + ": " + header["toolchain"] + "\n"
            "build\tGOOS=" + system + "\n"
            "build\tGOARCH=" + arch + "\n"
            "build\tCGO_ENABLED=" + header["cgo"] + "\n"
            "build\t-tags=" + header["tags"] + "\n"
            "dep\tgithub.com/amnezia-vpn/amneziawg-go/v3\t" + header["amnezia"] + "\n"
            "dep\tgithub.com/xtls/xray-core\t" + header["xray"] + "\n")


def write(path: Path, data: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def sealed_runtime_fixtures(root: Path, arch: str) -> None:
    target = "windows/" + arch
    for kind, source in (("native", "native-runtime"), ("amnezia", "amnezia")):
        module = ENGINES[kind]
        directory = root / "dist" / source / ("windows-" + arch)
        policy = module.digest()
        header = {"target": target, "toolchain": module.TOOLCHAIN,
                  "cgo": "1" if kind == "native" else "0",
                  "tags": ",".join(module.tags(target)) if kind == "native" else module.TAGS,
                  "amnezia": module.POLICY.AMNEZIA.VERSION,
                  "xray": module.POLICY.XRAY_VERSION}
        binary = "sing-box-routervpn.exe" if kind == "native" else "sing-box-amnezia.exe"
        directory.mkdir(parents=True, exist_ok=True)
        # Real PE headers and import tables reach the shipping dependency
        # parser. Only Go's unrelated build-info reader uses this test overlay.
        (directory / binary).write_bytes(PE_FIXTURE.image(target) + METADATA_OVERLAY
                                        + (json.dumps(header) + "\n" + module.marker(policy) + "\n").encode())
        raw = (directory / binary).read_bytes()
        if kind == "native":
            for name in module.expected_names(target) - {binary}:
                if name == module.library_name(target):
                    (directory / name).write_bytes(PE_FIXTURE.image(target))
                elif name == module.PT_NOTICES:
                    (directory / name).write_bytes(module.EXTERNAL.desktop_pt_notices())
                else:
                    write(directory / name, "same-image " + name + "\n")
            files = {name: module.payload((directory / name).read_bytes())
                     for name in module.expected_names(target)}
            receipt = {**module.receipt_fields(target, policy), **files[binary], "files": files}
            write(directory / "NATIVE-RUNTIME.json", json.dumps(receipt))
        else:
            receipt = {"schema_version": 1, "runtime": "sing-box-amnezia", "version": module.VERSION,
                       "upstream_revision": module.PIN, "amnezia_version": module.POLICY.AMNEZIA.VERSION,
                       "amnezia_sum": module.POLICY.AMNEZIA.SUM, "policy_sha256": policy,
                       "target": target, "toolchain": module.TOOLCHAIN,
                       "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            write(directory / "AMNEZIA-RUNTIME.json", json.dumps(receipt))
            for name in ("SING-BOX-LICENSE", "AMNEZIA-LICENSE"):
                write(directory / name, "same-image " + name + "\n")


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
    for relative in ("deploy/build-dnsproxy.py", "cmd/dnsproxy/go.mod", "cmd/dnsproxy/go.sum", "cmd/dnsproxy/THIRD-PARTY-NOTICES.json"):
        write(root / relative, (ROOT / relative).read_text(encoding="utf-8"))
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
        sealed_runtime_fixtures(root, arch)
        runtime = dist / "xray" / f"windows-{arch}"
        write(runtime / "xray.exe", "authenticated bundled Xray fixture\n")
        write(runtime / "XRAY-RUNTIME.json", "{}\n")
        write(runtime / "XRAY-LICENSE", "fixture license\n")
        for name in (
            f"router-vpn-client-windows-{arch}.exe",
            f"router-vpn-dns-windows-{arch}.exe",
            f"router-vpn-start-layer-relay-windows-{arch}.exe",
            f"router-vpn-update-windows-{arch}.exe",
            f"RouterVPN-{arch}.exe",
            f"RouterVPNPortable-{arch}.exe",
            f"RouterVPNPortableCore-{arch}.exe",
            f"RouterVPNSetupRuntime-{arch}.exe",
        ):
            write(dist / name, "fake executable\n")


def require(root: Path, *names: str) -> None:
    app = root / "App/RouterVPN" if (root / "App/RouterVPN").is_dir() else root
    require_notice = app / "DNS-PROXY-NOTICES.json"
    assert require_notice.read_bytes() == (ROOT / "cmd/dnsproxy/THIRD-PARTY-NOTICES.json").read_bytes(), "fallback package lost the exact DNS proxy notices"
    for name in names:
        path = root / name
        assert path.is_file(), f"missing complete fallback component: {path}"


def assert_blank_store(path: Path) -> None:
    store = json.loads(path.read_text(encoding="utf-8"))
    assert store.get("schema_version") == 4, store
    assert store.get("selected_id") == "" and store.get("profiles") == [], store


def assert_archived_runtimes(root: Path, source: Path, arch: str, work: Path, portable: bool) -> None:
    archive = work / "complete.zip"
    builder.zip_dir(root, archive)
    unpack = work / "unpack"
    builder.safe_extract_zip(archive, unpack)
    packaged = builder.one_root(unpack)
    app = packaged / "App/RouterVPN" if portable else packaged
    for kind, folder in (("native", "native-runtime"), ("amnezia", "amnezia")):
        expected = builder._verify_desktop_runtime(source / "dist" / folder / ("windows-" + arch), "windows/" + arch, kind)
        actual = builder._verify_desktop_runtime(app / "runtime" / kind, "windows/" + arch, kind)
        assert actual == expected, "archived runtime differs from the exact same-image input"


def reject_before_compile(work: Path, source: Path, label: str, expected_error: str | None = None) -> None:
    with mock.patch.object(builder, "_go_build", side_effect=AssertionError(label + " compiled before native verification")):
        try:
            builder.compile_requested(work / label, "router-vpn-windows-amd64.zip", source)
        except (ValueError, RuntimeError, OSError) as error:
            if expected_error is not None:
                assert expected_error in str(error), (label, error)
        else:
            raise AssertionError(label + " runtime was accepted for local fallback")


def runtime_rejection_controls(work: Path, source: Path, base: Path) -> int:
    # Make controller compilation necessary: every runtime rejection below must
    # happen first, rather than running Go/Rust or repairing a sealed payload.
    controller = source / "dist/router-vpn-client-windows-amd64.exe"
    saved_controller = controller.read_bytes()
    controller.unlink()
    native = source / "dist/native-runtime/windows-amd64"
    awg = source / "dist/amnezia/windows-amd64"
    count = 0
    try:
        for path, corruption in (
            (native / "libcronet.dll", None),
            (native / "sing-box-routervpn.exe", b"changed engine"),
            (native / "CRONET-LICENSE", b"changed license"),
            (native / "NATIVE-RUNTIME.json", b"{}"),
            (awg / "sing-box-amnezia.exe", None),
            (awg / "AMNEZIA-RUNTIME.json", b"{}"),
            (awg / "AMNEZIA-LICENSE", None),
        ):
            old = path.read_bytes()
            if corruption is None:
                path.unlink()
            else:
                path.write_bytes(corruption)
            reject_before_compile(work, source, "missing-or-changed-" + path.name)
            path.write_bytes(old)
            count += 1
        for directory in (native, awg):
            foreign = directory / "foreign.dll"
            foreign.write_bytes(b"unowned payload")
            reject_before_compile(work, source, "foreign-" + directory.parent.name)
            foreign.unlink()
            count += 1
        receipt_path = native / "NATIVE-RUNTIME.json"
        old_receipt = receipt_path.read_bytes()
        for field, value in (("policy_sha256", "0" * 64), ("target", "windows/arm64")):
            receipt = json.loads(old_receipt)
            receipt[field] = value
            receipt_path.write_text(json.dumps(receipt))
            reject_before_compile(work, source, "wrong-native-" + field)
            count += 1
        receipt_path.write_bytes(old_receipt)

        # A matching file hash and receipt target cannot hide an executable
        # compiled for the other architecture: shipping metadata checks run.
        binary = native / "sing-box-routervpn.exe"
        old_binary = binary.read_bytes()
        binary.write_bytes(old_binary.replace(b'"windows/amd64"', b'"windows/arm64"'))
        receipt = json.loads(old_receipt)
        payload = ENGINES["native"].payload(binary.read_bytes())
        receipt.update(payload)
        receipt["files"][binary.name] = payload
        receipt_path.write_text(json.dumps(receipt))
        reject_before_compile(work, source, "foreign-executable-metadata")
        binary.write_bytes(old_binary)
        receipt_path.write_bytes(old_receipt)
        count += 1

        # Receipts authenticate bytes but cannot make an undeclared compiler
        # DLL available on the user's host. Exercise both shipped PE payloads
        # and both kinds of import through the actual router fallback boundary.
        for filename in ("sing-box-routervpn.exe", "libcronet.dll"):
            path = native / filename
            original = path.read_bytes()
            overlay = METADATA_OVERLAY + original.split(METADATA_OVERLAY, 1)[1] if METADATA_OVERLAY in original else b""
            try:
                for delayed in (False, True):
                    raw = PE_FIXTURE.image("windows/amd64",
                                           ("KERNEL32.dll",) if delayed else ("libunwind.dll",),
                                           ("libunwind.dll",) if delayed else ())
                    path.write_bytes(raw + overlay)
                    receipt = json.loads(old_receipt)
                    payload = ENGINES["native"].payload(path.read_bytes())
                    receipt["files"][filename] = payload
                    if filename == "sing-box-routervpn.exe":
                        receipt.update(payload)
                    receipt_path.write_text(json.dumps(receipt))
                    reject_before_compile(work, source, "unowned-import-" + filename + str(delayed),
                                          "imports an unowned DLL: libunwind.dll")
                    count += 1
            finally:
                path.write_bytes(original)
                receipt_path.write_bytes(old_receipt)

        if os.name != "nt":
            original = native.parent / "owned-amd64"
            native.rename(original)
            native.symlink_to(original, target_is_directory=True)
            reject_before_compile(work, source, "linked-native-directory")
            native.unlink()
            original.rename(native)
            count += 1
        calls = []

        def bounded_controller(go, src, dist, build_work, system, arch, package, name, windows_gui=False):
            calls.append((system, arch, package, name))
            write(dist / name, "rebuilt requested controller only\n")

        with mock.patch.object(builder.shutil, "which", return_value="/installed/go"), \
                mock.patch.object(builder, "_go_build", side_effect=bounded_controller):
            rebuilt = builder.compile_requested(work / "missing-controller", "router-vpn-windows-amd64.zip", source)
        assert calls == [("windows", "amd64", "./cmd/client", controller.name)], calls
        assert (rebuilt / "dist" / controller.name).is_file()
        count += 1
    finally:
        controller.write_bytes(saved_controller)

    # Corruption after source validation must still be rejected by the copy's
    # readback check, including licenses missing from the older AWG receipt.
    original_copy = builder.copy_file
    for relative in ("runtime/native/libcronet.dll", "runtime/amnezia/AMNEZIA-LICENSE"):
        def corrupt_copy(src, dst, required=True):
            original_copy(src, dst, required)
            if dst.as_posix().endswith(relative):
                dst.write_bytes(b"changed during assembly")

        with mock.patch.object(builder, "copy_file", side_effect=corrupt_copy):
            try:
                builder.build_local(work / ("raced-" + str(count)), "router-vpn-windows-amd64.zip", source, source, base)
            except (ValueError, RuntimeError, OSError):
                pass
            else:
                raise AssertionError("changed copied runtime was published")
        count += 1
    return count


def main_with_metadata_fixture() -> int:
    with tempfile.TemporaryDirectory(prefix="router-vpn-local-fallback-") as td:
        td = Path(td)
        src = td / "src"
        base = td / "base"
        base.mkdir()
        fake_source(src)
        # The optional missing Windows DNS component must enter its pinned
        # nested-module builder with the same bounded workspace/toolchain.
        # Intercept only the actual subprocess boundary, not dispatch logic.
        with mock.patch.object(builder.subprocess, "run") as execute:
            execute.return_value.returncode = 0
            execute.return_value.stdout = ""
            builder._go_build("/installed/go", src, td / "dns-dist", td / "dns-work",
                              "windows", "arm64", "./cmd/dnsproxy", "router-vpn-dns.exe")
            arguments = execute.call_args.args[0]
            assert arguments == [builder.sys.executable, str(src / "deploy/build-dnsproxy.py"),
                                 "build", "windows/arm64", str(td / "dns-dist/router-vpn-dns.exe"), "--go", "/installed/go"], arguments
            assert execute.call_args.kwargs["cwd"] == src
            assert execute.call_args.kwargs["timeout"] == builder.LOCAL_BUILD_TIMEOUT
            assert execute.call_args.kwargs["env"]["GOMODCACHE"] == str(td / "dns-work/go-mod-cache")

        notice_path = src / "cmd/dnsproxy/THIRD-PARTY-NOTICES.json"
        valid_notice = notice_path.read_bytes()
        notice_path.write_bytes(valid_notice + b"\n")
        try:
            builder.copy_generic_runtime(src, td / "corrupt-dns-notice")
        except RuntimeError as exc:
            assert "pinned input changed" in str(exc), exc
        else:
            raise AssertionError("generic fallback copied an unverified DNS notice")
        finally:
            notice_path.write_bytes(valid_notice)

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
            "router-vpn-start-layer-relay.exe",
            "router-vpn-update.exe",
            "install-windows.ps1",
            "Setup-Windows-Runtime.ps1",
            "client/RouterVPN-Windows-App.ps1",
            "routers.json",
        )
        assert_blank_store(win / "routers.json")
        builder.assert_generic_tree(win)
        assert_archived_runtimes(win, src, "amd64", td / "archive-win", portable=False)

        portable = builder.build_local(td / "work-portable", "router-vpn-windows-portable-arm64.zip", src, src, base)
        require(
            portable,
            "RouterVPNPortable.exe",
            "RouterVPNPortableCore.exe",
            "RouterVPNSetupRuntime.exe",
            "Setup-Windows-Runtime.ps1",
            "App/RouterVPN/RouterVPN.ico",
            "App/RouterVPN/RouterVPN.png",
            "App/RouterVPN/client/RouterVPN-Windows-App.ps1",
            "App/RouterVPN/router-vpn-client.exe",
            "App/RouterVPN/router-vpn-start-layer-relay.exe",
            "App/RouterVPN/router-vpn-update.exe",
            "Data/routers.json",
        )
        assert_blank_store(portable / "App/RouterVPN/routers.json")
        assert_blank_store(portable / "Data/routers.json")
        builder.assert_generic_tree(portable)
        assert_archived_runtimes(portable, src, "arm64", td / "archive-portable", portable=True)

        for family, arch in (("windows", "arm64"), ("portable", "amd64")):
            request = "router-vpn-windows-" + ("portable-" if family == "portable" else "") + arch + ".zip"
            package = builder.build_local(td / (family + arch), request, src, src, base)
            assert_archived_runtimes(package, src, arch, td / ("archive-" + family + arch), family == "portable")
        rejected = runtime_rejection_controls(td / "controls", src, base)

        # A GitHub package is accepted only when its embedded source manifest
        # proves the exact expected commit and package family.
        prov_root = td / "provenance-package"
        prov_root.mkdir()
        builder._provenance.write_manifest(
            prov_root,
            "0123456789abcdef0123456789abcdef01234567",
            "windows-amd64",
        )
        archive = td / "provenance-package.zip"
        builder.zip_dir(prov_root, archive)
        checked = builder.build_from_github(
            td / "provenance-ok",
            archive,
            "0123456789abcdef0123456789abcdef01234567",
            "windows-amd64",
        )
        assert checked.name == "provenance-package"
        try:
            builder.build_from_github(
                td / "provenance-wrong-sha",
                archive,
                "89abcdef0123456789abcdef0123456789abcdef",
                "windows-amd64",
            )
        except RuntimeError as exc:
            assert "provenance mismatch" in str(exc)
        else:
            raise AssertionError("GitHub package with wrong embedded source SHA was accepted")
        try:
            builder.build_from_github(
                td / "provenance-wrong-family",
                archive,
                "0123456789abcdef0123456789abcdef01234567",
                "linux-amd64",
            )
        except RuntimeError as exc:
            assert "family mismatch" in str(exc)
        else:
            raise AssertionError("GitHub package with wrong embedded family was accepted")

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

    assert METADATA_READS and {target for _, target in METADATA_READS} == {"windows/amd64", "windows/arm64"}
    print(f"Router-local complete-package fallback tests: OK (4 archived packages, {rejected} native integrity/compile controls)")
    return 0


def main() -> int:
    with mock.patch.object(ENGINES["native"], "run", side_effect=fixture_metadata), \
            mock.patch.object(ENGINES["amnezia"], "run", side_effect=fixture_metadata):
        return main_with_metadata_fixture()


if __name__ == "__main__":
    raise SystemExit(main())
