#!/usr/bin/env python3
"""Build exactly one Router VPN download in a temporary path.

Desktop and Portable application packages are GENERIC and secret-free. Installing
Router VPN and linking a home/server node are separate operations. A matching
same-SHA GitHub Actions package can be supplied with --source-archive.

When that artifact is unavailable, the home node may assemble only the requested
package from same-image prebuilt components, with a bounded Go build only for a
missing supported Windows/Portable Go component. It must never return a
controller-only archive while claiming to be a finished native desktop app.
Native AppKit/GTK packages therefore require their same-SHA native artifact unless
a complete native component is actually present; this image intentionally does
not become a giant cross-platform SDK environment.

router-vpn-client-bundle.zip is the explicit private node-link bundle and is kept
separate from application packages. The caller owns the temporary output and is
expected to stream/delete it after the request.
"""
from __future__ import annotations

import argparse
import json
import os
import runpy
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.parse
import zipfile

PROVENANCE_PATH = Path(__file__).with_name("source_provenance.py")
_prov_spec = __import__("importlib.util").util.spec_from_file_location("router_vpn_source_provenance", PROVENANCE_PATH)
if _prov_spec is None or _prov_spec.loader is None:
    raise RuntimeError(f"cannot load {PROVENANCE_PATH}")
_provenance = __import__("importlib.util").util.module_from_spec(_prov_spec)
_prov_spec.loader.exec_module(_provenance)

MAX_UNPACKED = 768 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_MEMBER = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
LOCAL_BUILD_TIMEOUT = 300
PROFILE_SCHEMA_VERSION = 4

_VERIFIED = runpy.run_path(str(Path(__file__).with_name("verified-regular-read.py")))
parent_chain_snapshot = _VERIFIED["parent_chain_snapshot"]
verify_parent_chain = _VERIFIED["verify_parent_chain"]
_OWNED_TEMP = runpy.run_path(str(Path(__file__).with_name("owned-temp.py")))
create_owned_temp = _OWNED_TEMP["create_owned_temp"]
cleanup_owned_temp = _OWNED_TEMP["cleanup_owned_temp"]

PACKAGE_MAP = {
    "router-vpn-windows-amd64.zip": ("RouterVPN-Windows-amd64.zip", "windows", "amd64"),
    "router-vpn-windows-arm64.zip": ("RouterVPN-Windows-arm64.zip", "windows", "arm64"),
    "router-vpn-windows-portable-amd64.zip": ("RouterVPN-Portable-Windows-amd64.zip", "portable", "amd64"),
    "router-vpn-windows-portable-arm64.zip": ("RouterVPN-Portable-Windows-arm64.zip", "portable", "arm64"),
    "router-vpn-macos-amd64.zip": ("RouterVPN-darwin-amd64.tar.gz", "darwin", "amd64"),
    "router-vpn-macos-arm64.zip": ("RouterVPN-darwin-arm64.tar.gz", "darwin", "arm64"),
    "router-vpn-linux-amd64.zip": ("RouterVPN-linux-amd64.tar.gz", "linux", "amd64"),
    "router-vpn-linux-arm64.zip": ("RouterVPN-linux-arm64.tar.gz", "linux", "arm64"),
    "router-vpn-client-bundle.zip": (None, "bundle", "any"),
}


def generic_name(name: str) -> str | None:
    try:
        return PACKAGE_MAP[name][0]
    except KeyError as exc:
        raise ValueError(f"unsupported download: {name}") from exc


def _safe_rel(name: str) -> Path:
    normalized = name.replace("\\", "/")
    decoded = urllib.parse.unquote(normalized)
    p = PurePosixPath(decoded)
    if (
        p.is_absolute()
        or decoded.startswith("//")
        or any(part in ("", ".", "..") for part in p.parts)
        or (p.parts and p.parts[0].endswith(":"))
    ):
        raise ValueError(f"unsafe archive path: {name}")
    return Path(*p.parts)


def _safe_target(dst: Path, rel: Path) -> Path:
    base = dst.resolve()
    target = (dst / rel).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"archive path escapes destination: {rel}") from exc
    return target


def _check_zip_member(item: zipfile.ZipInfo) -> None:
    _safe_rel(item.filename.rstrip("/"))
    mode = (item.external_attr >> 16) & 0o170000
    if mode == stat.S_IFLNK:
        raise ValueError(f"archive symlink is not allowed: {item.filename}")
    if item.flag_bits & 0x1:
        raise ValueError(f"encrypted archive member is not allowed: {item.filename}")
    if item.file_size > MAX_MEMBER:
        raise ValueError(f"archive member exceeds safety limit: {item.filename}")
    if item.compress_size > 0 and item.file_size > 8 * 1024 * 1024:
        if item.file_size / item.compress_size > MAX_COMPRESSION_RATIO:
            raise ValueError(f"archive member compression ratio is unsafe: {item.filename}")


def safe_extract_zip(src: Path, dst: Path) -> None:
    total = 0
    seen: set[str] = set()
    with zipfile.ZipFile(src) as zf:
        items = zf.infolist()
        if len(items) > MAX_MEMBERS:
            raise ValueError("archive contains too many members")
        for item in items:
            clean = item.filename.rstrip("/")
            if not clean:
                continue
            _check_zip_member(item)
            total += item.file_size
            if total > MAX_UNPACKED:
                raise ValueError("archive expands beyond safety limit")
            rel = _safe_rel(clean)
            key = rel.as_posix()
            if key in seen:
                raise ValueError(f"archive contains duplicate normalized path: {key}")
            seen.add(key)
            target = _safe_target(dst, rel)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(item) as r, target.open("wb") as w:
                shutil.copyfileobj(r, w, 1024 * 1024)


def safe_extract_tar(src: Path, dst: Path) -> None:
    total = 0
    seen: set[str] = set()
    with tarfile.open(src, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError("archive contains too many members")
        for item in members:
            clean = item.name.rstrip("/")
            if not clean:
                continue
            rel = _safe_rel(clean)
            key = rel.as_posix()
            if key in seen:
                raise ValueError(f"archive contains duplicate normalized path: {key}")
            seen.add(key)
            _safe_target(dst, rel)
            if item.issym() or item.islnk() or item.isdev() or item.isfifo():
                raise ValueError(f"unsafe tar member: {item.name}")
            if item.isfile():
                if item.size > MAX_MEMBER:
                    raise ValueError(f"archive member exceeds safety limit: {item.name}")
                total += item.size
                if total > MAX_UNPACKED:
                    raise ValueError("archive expands beyond safety limit")
        for item in members:
            clean = item.name.rstrip("/")
            if not clean:
                continue
            target = _safe_target(dst, _safe_rel(clean))
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif item.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tf.extractfile(item)
                if source is None:
                    raise ValueError(f"cannot read tar member: {item.name}")
                with source, target.open("wb") as w:
                    shutil.copyfileobj(source, w, 1024 * 1024)
                if item.mode & 0o111:
                    target.chmod(target.stat().st_mode | 0o755)


def one_root(work: Path) -> Path:
    roots = [p for p in work.iterdir() if p.name != "__MACOSX" and not p.name.startswith(".")]
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError("client artifact must contain one package root directory")
    return roots[0]


def copy_file(src: Path, dst: Path, required: bool = True) -> None:
    try:
        before = src.lstat()
    except FileNotFoundError:
        if required:
            raise
        return
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"refusing to package non-regular/symlink file: {src}")
    if before.st_size < 0 or before.st_size > MAX_MEMBER:
        raise ValueError(f"package source exceeds safety limit: {src}")

    try:
        source_parents = parent_chain_snapshot(src)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"unsafe package source ancestry: {exc}") from exc
    src_fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    tmp: Path | None = None
    try:
        opened = os.fstat(src_fd)
        current = src.lstat()
        try:
            verify_parent_chain(source_parents)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"package source changed during open: {src}: {exc}") from exc
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
            or not os.path.samestat(opened, before)
        ):
            raise ValueError(f"package source changed during open: {src}")

        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() or dst.is_symlink():
            dest_info = dst.lstat()
            if stat.S_ISLNK(dest_info.st_mode) or not stat.S_ISREG(dest_info.st_mode):
                raise ValueError(f"refusing unsafe package destination: {dst}")
        fd, tmp_name = tempfile.mkstemp(prefix=f".{dst.name}.copy-", dir=dst.parent)
        tmp = Path(tmp_name)
        total = 0
        try:
            mode = stat.S_IMODE(opened.st_mode) & 0o777
            os.fchmod(fd, mode or 0o600)
            while True:
                chunk = os.read(src_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_MEMBER:
                    raise ValueError(f"package source exceeds safety limit while reading: {src}")
                view = memoryview(chunk)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

        final_source = src.lstat()
        try:
            verify_parent_chain(source_parents)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"package source changed during read: {src}: {exc}") from exc
        if (
            stat.S_ISLNK(final_source.st_mode)
            or not stat.S_ISREG(final_source.st_mode)
            or not os.path.samestat(opened, final_source)
            or total != opened.st_size
        ):
            raise ValueError(f"package source changed during read: {src}")
        os.replace(tmp, dst)
        tmp = None
    finally:
        os.close(src_fd)
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def copy_tree(src: Path, dst: Path, required: bool = True) -> None:
    try:
        before = src.lstat()
    except FileNotFoundError:
        if required:
            raise
        return
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ValueError(f"refusing to package non-directory/symlink tree: {src}")
    try:
        source_parents = parent_chain_snapshot(src)
        verify_parent_chain(source_parents)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"unsafe package tree ancestry: {exc}") from exc

    if dst.exists() or dst.is_symlink():
        info = dst.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"refusing unsafe package tree destination: {dst}")
    else:
        dst.mkdir(parents=True, mode=stat.S_IMODE(before.st_mode) & 0o777 or 0o700)

    for entry in sorted(os.scandir(src), key=lambda item: item.name):
        child = Path(entry.path)
        info = child.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"refusing to package symlink: {child}")
        target = dst / entry.name
        if stat.S_ISDIR(info.st_mode):
            copy_tree(child, target)
        elif stat.S_ISREG(info.st_mode):
            copy_file(child, target)
        else:
            raise ValueError(f"refusing to package special filesystem entry: {child}")

    current = src.lstat()
    verify_parent_chain(source_parents)
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise ValueError(f"package source directory changed during traversal: {src}")


def write_blank_routers(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"schema_version": PROFILE_SCHEMA_VERSION, "selected_id": "", "profiles": []}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def copy_generic_runtime(src_root: Path, root: Path) -> None:
    """Copy only public application/runtime assets; never node-specific material."""
    copy_tree(src_root / "modes", root / "modes")
    copy_tree(src_root / "client", root / "client")
    copy_file(src_root / "configs" / "client" / "client.json.example", root / "client.json")
    copy_file(src_root / "configs" / "client" / "modes.json", root / "modes.json")
    copy_file(src_root / "configs" / "client" / "logical-modes.json", root / "logical-modes.json")
    copy_file(src_root / "docs" / "MODES.md", root / "MODES.md", required=False)
    copy_file(src_root / "docs" / "CLIENT.md", root / "CLIENT.md", required=False)
    copy_file(src_root / "SECURITY.md", root / "SECURITY.md", required=False)
    copy_file(src_root / "LICENSE", root / "LICENSE")
    write_blank_routers(root / "routers.json")
    (root / "generated").mkdir(parents=True, exist_ok=True)


def assert_generic_tree(root: Path) -> None:
    """Fail closed if a supposedly generic package contains linked-node data."""
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"generic package contains symlink: {path.relative_to(root)}")
        if path.is_file() and path.name == "router-vpn-bundle.json":
            raise ValueError("generic package contains a private router-vpn-bundle.json")
        if path.is_file() and "generated" in path.relative_to(root).parts:
            raise ValueError("generic package contains generated per-node material")
        if path.is_file() and path.name == "routers.json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                raise ValueError(f"generic routers.json is invalid: {path}") from exc
            if data.get("selected_id") not in (None, "") or data.get("profiles") not in (None, []):
                raise ValueError("generic package contains linked router profiles")


def _output_target_snapshot(output: Path):
    try:
        info = output.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"refusing unsafe package output target: {output}")
    return info


def _require_output_target_unchanged(output: Path, before) -> None:
    try:
        current = output.lstat()
    except FileNotFoundError:
        if before is None:
            return
        raise ValueError(f"package output disappeared before adoption: {output}")
    if before is None:
        raise ValueError(f"package output appeared before adoption: {output}")
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or not os.path.samestat(before, current):
        raise ValueError(f"package output identity changed before adoption: {output}")


def zip_dir(root: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    parent_snapshot = parent_chain_snapshot(output)
    before = _output_target_snapshot(output)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{output.name}.archive-", dir=output.parent)
    tmp = Path(tmp_name)
    committed = False
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w+b", closefd=True) as stream:
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
                for path in sorted(root.rglob("*")):
                    if path.is_symlink():
                        raise ValueError(f"refusing to archive symlink: {path}")
                    rel = Path(root.name) / path.relative_to(root)
                    if path.is_dir():
                        info = zipfile.ZipInfo(rel.as_posix().rstrip("/") + "/")
                        info.external_attr = (0o40755 << 16) | 0x10
                        zf.writestr(info, b"")
                    elif path.is_file():
                        zf.write(path, rel.as_posix())
            stream.flush()
            os.fsync(stream.fileno())
        if tmp.stat().st_size <= 0:
            raise RuntimeError("staged package archive is empty")
        verify_parent_chain(parent_snapshot)
        _require_output_target_unchanged(output, before)
        os.replace(tmp, output)
        committed = True
        try:
            directory = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass
    finally:
        if not committed:
            try:
                os.close(fd)
            except OSError:
                pass
            tmp.unlink(missing_ok=True)


def require_dist(src_root: Path, name: str) -> Path:
    p = src_root / "dist" / name
    if not p.is_file():
        raise FileNotFoundError(f"requested local-build binary missing: {p}")
    return p


def build_private_bundle(work: Path, base: Path, src_root: Path) -> Path:
    bundle = base / "client-bundle"
    if not bundle.is_dir() or bundle.is_symlink():
        raise FileNotFoundError(f"missing/unsafe private client bundle: {bundle}")
    root = work / "router-vpn-client-bundle"
    copy_tree(bundle, root)

    # Persistent node state owns routers/client config and generated private
    # profiles only. Runtime code/catalogs come from the exact source tree for
    # this request so an interrupted server sync can never ship a mixed
    # old/new modes or client directory.
    for stale in ("modes", "client", "dist"):
        path = root / stale
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    copy_tree(src_root / "modes", root / "modes")
    copy_tree(src_root / "client", root / "client")
    copy_file(src_root / "configs" / "client" / "modes.json", root / "modes.json")
    copy_file(src_root / "configs" / "client" / "logical-modes.json", root / "logical-modes.json")
    copy_file(src_root / "LICENSE", root / "LICENSE")
    return root


def materialize_icons(src_root: Path, root: Path) -> None:
    generator = src_root / "deploy" / "materialize-desktop-icons.py"
    if not generator.is_file():
        raise FileNotFoundError("Router VPN desktop icon generator is missing")
    subprocess.run(
        ["python3", str(generator), "--png", str(root / "RouterVPN.png"), "--ico", str(root / "RouterVPN.ico")],
        cwd=src_root,
        check=True,
        timeout=30,
        stdout=subprocess.DEVNULL,
    )


def build_local(work: Path, name: str, src_root: Path, compiled_root: Path, base: Path) -> Path:
    _, family, arch = PACKAGE_MAP[name]
    if family == "bundle":
        return build_private_bundle(work, base, src_root)

    if family in {"darwin", "linux"}:
        platform = "AppKit" if family == "darwin" else "GTK"
        raise RuntimeError(
            f"{family}/{arch} requires its same-SHA native {platform} package artifact; "
            "router-local fallback intentionally does not ship a cross-platform native SDK or return a controller-only substitute"
        )

    if family == "portable":
        root = work / f"RouterVPNPortable-{arch}"
        app = root / "App" / "RouterVPN"
        data = root / "Data"
        data.mkdir(parents=True, exist_ok=True)
        copy_generic_runtime(src_root, app)
        copy_file(require_dist(compiled_root, f"router-vpn-client-windows-{arch}.exe"), app / "router-vpn-client.exe")
        copy_file(require_dist(compiled_root, f"router-vpn-dns-windows-{arch}.exe"), app / "router-vpn-dns.exe")
        copy_file(require_dist(compiled_root, f"RouterVPNPortable-{arch}.exe"), root / "RouterVPNPortable.exe")
        copy_file(require_dist(compiled_root, f"RouterVPNSetupRuntime-{arch}.exe"), root / "RouterVPNSetupRuntime.exe")
        copy_file(src_root / "client" / "Setup-Windows-Runtime.ps1", root / "Setup-Windows-Runtime.ps1")
        materialize_icons(src_root, app)
        write_blank_routers(data / "routers.json")
        (data / "generated").mkdir(parents=True, exist_ok=True)
        (root / "README.txt").write_text(
            f"Router VPN Portable {arch} — generic native Windows application package\n"
            "Double-click RouterVPNPortable.exe, then link/import one or more Router VPN nodes separately.\n"
            "The native WPF product and Router VPN icon are included under App/RouterVPN.\n"
            "No home/server node, token, or generated private profile is baked into this ZIP.\n"
            "Move the whole folder together; writable Router VPN state stays under Data.\n"
            "Router VPN is MIT-licensed open-source software; see App/RouterVPN/LICENSE.\n",
            encoding="utf-8",
        )
        assert_generic_tree(root)
        return root

    if family == "windows":
        root = work / f"RouterVPN-Windows-{arch}"
        copy_generic_runtime(src_root, root)
        copy_file(require_dist(compiled_root, f"router-vpn-client-windows-{arch}.exe"), root / "router-vpn-client.exe")
        copy_file(require_dist(compiled_root, f"router-vpn-dns-windows-{arch}.exe"), root / "router-vpn-dns.exe")
        copy_file(require_dist(compiled_root, f"RouterVPN-{arch}.exe"), root / "RouterVPN.exe")
        copy_file(src_root / "client" / "install-windows.ps1", root / "install-windows.ps1")
        copy_file(src_root / "client" / "Setup-Windows-Runtime.ps1", root / "Setup-Windows-Runtime.ps1")
        materialize_icons(src_root, root)
        (root / "README-WINDOWS.txt").write_text(
            f"Router VPN Windows {arch} — generic native application package\n"
            "Double-click RouterVPN.exe or run install-windows.ps1 for the normal Start Menu application.\n"
            "The package includes the native WPF daily-use app and Router VPN icon, not a browser/PWA substitute.\n"
            "No home/server node, token, or generated private profile is baked into this ZIP.\n"
            "Link/import Router VPN nodes separately after installation.\n"
            "Router VPN is MIT-licensed open-source software; see LICENSE.\n",
            encoding="utf-8",
        )
        assert_generic_tree(root)
        return root

    raise ValueError(f"unsupported package family: {family}")


def _go_build(go: str, src_root: Path, dist: Path, work: Path, goos: str, goarch: str,
              package: str, output_name: str, windows_gui: bool = False) -> None:
    env = os.environ.copy()
    env.update({
        "CGO_ENABLED": "0",
        "GOOS": goos,
        "GOARCH": goarch,
        "GOTOOLCHAIN": "local",
        "GOCACHE": str(work / "go-build-cache"),
        "GOMODCACHE": str(work / "go-mod-cache"),
    })
    ldflags = "-s -w" + (" -H=windowsgui" if windows_gui else "")
    proc = subprocess.run(
        [go, "build", "-trimpath", "-ldflags", ldflags, "-o", str(dist / output_name), package],
        cwd=src_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=LOCAL_BUILD_TIMEOUT,
    )
    if proc.returncode != 0:
        tail = (proc.stdout or "")[-6000:]
        raise RuntimeError(f"router-local go build failed for {package} ({goos}/{goarch}):\n{tail}")


def _supported_components(family: str, arch: str) -> list[tuple[str, str, bool]]:
    if family == "windows":
        return [
            (f"router-vpn-client-windows-{arch}.exe", "./cmd/client", False),
            (f"router-vpn-dns-windows-{arch}.exe", "./cmd/dnsproxy", False),
            (f"RouterVPN-{arch}.exe", "./cmd/windows-app-launcher", True),
        ]
    if family == "portable":
        return [
            (f"router-vpn-client-windows-{arch}.exe", "./cmd/client", False),
            (f"router-vpn-dns-windows-{arch}.exe", "./cmd/dnsproxy", False),
            (f"RouterVPNPortable-{arch}.exe", "./cmd/portable-launcher", True),
            (f"RouterVPNSetupRuntime-{arch}.exe", "./cmd/portable-runtime-setup", True),
        ]
    return []


def compile_requested(work: Path, name: str, src_root: Path) -> Path:
    _, family, arch = PACKAGE_MAP[name]
    if family == "bundle":
        return src_root
    if family in {"darwin", "linux"}:
        platform = "AppKit" if family == "darwin" else "GTK"
        raise RuntimeError(
            f"router-local fallback cannot build the finished native {platform} app for {family}/{arch}; "
            "a same-SHA native GitHub artifact is required"
        )
    if family not in {"windows", "portable"}:
        raise ValueError(f"unsupported router-local fallback family: {family}")

    components = _supported_components(family, arch)
    prebuilt_dist = src_root / "dist"
    if components and all((prebuilt_dist / filename).is_file() for filename, _, _ in components):
        return src_root

    go = shutil.which("go")
    if not go:
        raise FileNotFoundError("router-local fallback requires the bundled Go toolchain for a missing supported Windows component")
    compiled = work / "router-local-build"
    dist = compiled / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    for filename, package, windows_gui in components:
        source = prebuilt_dist / filename
        target = dist / filename
        if source.is_file():
            copy_file(source, target)
            continue
        _go_build(go, src_root, dist, work, "windows", arch, package, filename, windows_gui=windows_gui)
    return compiled


def provenance_family(family: str, arch: str) -> str:
    if family == "windows":
        return f"windows-{arch}"
    if family == "portable":
        return f"windows-portable-{arch}"
    if family == "darwin":
        return f"macos-{arch}"
    if family == "linux":
        return f"linux-{arch}"
    if family == "bundle":
        return "private-node-bundle"
    raise ValueError(f"unsupported provenance family: {family}")


def build_from_github(work: Path, source_archive: Path, expected_sha: str, expected_family: str) -> Path:
    unpack = work / "github"
    # Callers may pass a fresh per-request work path. Create the complete private
    # extraction parent here instead of relying on an unrelated caller side effect.
    unpack.mkdir(parents=True)
    if source_archive.name.endswith(".tar.gz"):
        safe_extract_tar(source_archive, unpack)
    else:
        safe_extract_zip(source_archive, unpack)
    root = one_root(unpack)
    assert_generic_tree(root)
    _provenance.verify_manifest(root, expected_sha, expected_family)
    return root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/opt/router-vpn")
    ap.add_argument("--source-root", default="/src")
    ap.add_argument("--name", required=True, choices=sorted(PACKAGE_MAP))
    ap.add_argument("--output", required=True)
    ap.add_argument("--source-archive")
    args = ap.parse_args()

    output = Path(args.output).resolve()
    base = Path(args.base).resolve()
    src_root = Path(args.source_root).resolve()
    _, family, arch = PACKAGE_MAP[args.name]
    try:
        expected_sha = _provenance.resolve_sha(root=src_root)
    except RuntimeError:
        # Unit/developer source roots may be synthetic; the checked-out script
        # tree is the final fallback. Production images still require the exact
        # ROUTER_VPN_GITHUB_SHA because /src intentionally has no .git metadata.
        expected_sha = _provenance.resolve_sha(root=Path(__file__).resolve().parents[2])
    expected_family = provenance_family(family, arch)

    work = create_owned_temp("router-vpn-one-package-")
    try:
        if args.source_archive:
            if family == "bundle":
                raise SystemExit("private node bundle cannot be sourced from a public generic artifact")
            root = build_from_github(work, Path(args.source_archive), expected_sha, expected_family)
        else:
            compiled_root = compile_requested(work, args.name, src_root)
            root = build_local(work, args.name, src_root, compiled_root, base)
            _provenance.write_manifest(root, expected_sha, expected_family)
        _provenance.verify_manifest(root, expected_sha, expected_family)
        zip_dir(root, output)
    finally:
        try:
            cleanup_owned_temp(work)
        except OSError:
            pass

    if not output.is_file() or output.is_symlink() or output.stat().st_size == 0:
        raise SystemExit("package creation returned an empty/unsafe file")
    if os.name != "nt" and output.stat().st_mode & 0o777 != 0o600:
        raise SystemExit("package output lost private 0600 mode")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())