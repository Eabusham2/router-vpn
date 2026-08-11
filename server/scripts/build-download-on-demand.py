#!/usr/bin/env python3
"""Build/customize exactly one Router VPN download in a temporary path.

The AI Board never persists platform archives. A generic GitHub Actions package
can be supplied with --source-archive; otherwise only the requested package is
assembled from prebuilt binaries already shipped in the server image. Private
node data is overlaid locally and the caller is responsible for streaming and
removing the resulting temporary ZIP.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile
import zipfile

MAX_UNPACKED = 768 * 1024 * 1024

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
    p = PurePosixPath(name.replace("\\", "/"))
    if p.is_absolute() or any(part in ("", ".", "..") for part in p.parts):
        raise ValueError(f"unsafe archive path: {name}")
    return Path(*p.parts)


def safe_extract_zip(src: Path, dst: Path) -> None:
    total = 0
    with zipfile.ZipFile(src) as zf:
        for item in zf.infolist():
            clean = item.filename.rstrip("/")
            if not clean:
                continue
            rel = _safe_rel(clean)
            mode = (item.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError(f"archive symlink is not allowed: {item.filename}")
            total += item.file_size
            if total > MAX_UNPACKED:
                raise ValueError("archive expands beyond safety limit")
            target = dst / rel
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(item) as r, target.open("wb") as w:
                shutil.copyfileobj(r, w, 1024 * 1024)


def safe_extract_tar(src: Path, dst: Path) -> None:
    total = 0
    with tarfile.open(src, "r:gz") as tf:
        members = tf.getmembers()
        for item in members:
            clean = item.name.rstrip("/")
            if not clean:
                continue
            _safe_rel(clean)
            if item.issym() or item.islnk() or item.isdev():
                raise ValueError(f"unsafe tar member: {item.name}")
            if item.isfile():
                total += item.size
                if total > MAX_UNPACKED:
                    raise ValueError("archive expands beyond safety limit")
        for item in members:
            clean = item.name.rstrip("/")
            if not clean:
                continue
            target = dst / _safe_rel(clean)
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
    if not src.is_file():
        if required:
            raise FileNotFoundError(src)
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def copy_tree(src: Path, dst: Path, required: bool = True) -> None:
    if not src.is_dir():
        if required:
            raise FileNotFoundError(src)
        return
    shutil.copytree(src, dst, dirs_exist_ok=True)


def overlay_private(root: Path, family: str, bundle: Path) -> None:
    if family == "portable":
        app = root / "App" / "RouterVPN"
        data = root / "Data"
        if not app.is_dir():
            raise ValueError("GitHub Portable ZIP has no App/RouterVPN payload")
        data.mkdir(parents=True, exist_ok=True)
        copy_file(bundle / "client.json", app / "client.json")
        copy_file(bundle / "routers.json", app / "routers.json")
        copy_file(bundle / "router-vpn-bundle.json", app / "router-vpn-bundle.json")
        copy_file(bundle / "routers.json", data / "routers.json")
        copy_tree(bundle / "generated", data / "generated")
        return
    for item in ("client.json", "routers.json", "router-vpn-bundle.json"):
        copy_file(bundle / item, root / item)
    copy_tree(bundle / "generated", root / "generated")


def zip_dir(root: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
        for path in sorted(root.rglob("*")):
            rel = Path(root.name) / path.relative_to(root)
            if path.is_dir():
                info = zipfile.ZipInfo(rel.as_posix().rstrip("/") + "/")
                info.external_attr = (0o40755 << 16) | 0x10
                zf.writestr(info, b"")
            elif path.is_file():
                zf.write(path, rel.as_posix())


def require_dist(src_root: Path, name: str) -> Path:
    p = src_root / "dist" / name
    if not p.is_file():
        raise FileNotFoundError(f"prebuilt fallback binary missing: {p}")
    return p


def copy_bundle_runtime(bundle: Path, root: Path) -> None:
    copy_tree(bundle / "modes", root / "modes")
    copy_tree(bundle / "client", root / "client")
    copy_tree(bundle / "generated", root / "generated")
    for name in ("client.json", "routers.json", "modes.json", "logical-modes.json", "router-vpn-bundle.json", "LICENSE"):
        copy_file(bundle / name, root / name, required=(name != "logical-modes.json"))
    helper = bundle / "router" / "asus-merlin-router-vpn-forwards.sh"
    if helper.is_file():
        copy_file(helper, root / "router" / helper.name)


def build_local(work: Path, name: str, bundle: Path, src_root: Path) -> Path:
    _, family, arch = PACKAGE_MAP[name]
    if family == "bundle":
        root = work / "router-vpn-client-bundle"
        copy_tree(bundle, root)
        return root

    if family == "portable":
        root = work / f"RouterVPNPortable-{arch}"
        app = root / "App" / "RouterVPN"
        data = root / "Data"
        data.mkdir(parents=True, exist_ok=True)
        copy_bundle_runtime(bundle, app)
        copy_file(require_dist(src_root, f"router-vpn-client-windows-{arch}.exe"), app / "router-vpn-client.exe")
        copy_file(require_dist(src_root, f"router-vpn-dns-windows-{arch}.exe"), app / "router-vpn-dns.exe")
        copy_file(require_dist(src_root, f"RouterVPNPortable-{arch}.exe"), root / "RouterVPNPortable.exe")
        copy_file(require_dist(src_root, f"RouterVPNSetupRuntime-{arch}.exe"), root / "RouterVPNSetupRuntime.exe")
        copy_file(bundle / "client" / "Setup-Windows-Runtime.ps1", root / "Setup-Windows-Runtime.ps1")
        copy_file(bundle / "routers.json", data / "routers.json")
        copy_tree(bundle / "generated", data / "generated")
        (root / "README.txt").write_text(
            f"Router VPN Portable {arch} — home-linked on-demand package\n"
            "Run Setup-Windows-Runtime.ps1 once for the WSL engine set, then RouterVPNPortable.exe.\n"
            "Data contains this node's private profiles. Move the whole folder together; do not share it.\n"
            "Router VPN is MIT-licensed open-source software; see App/RouterVPN/LICENSE.\n",
            encoding="utf-8",
        )
        return root

    if family == "windows":
        root = work / "router-vpn"
        copy_bundle_runtime(bundle, root)
        copy_file(require_dist(src_root, f"router-vpn-client-windows-{arch}.exe"), root / "router-vpn-client.exe")
        copy_file(require_dist(src_root, f"router-vpn-dns-windows-{arch}.exe"), root / "router-vpn-dns.exe")
        return root

    if family in ("darwin", "linux"):
        root = work / "router-vpn"
        copy_bundle_runtime(bundle, root)
        copy_file(require_dist(src_root, f"router-vpn-client-{family}-{arch}"), root / "router-vpn-client")
        copy_file(require_dist(src_root, f"router-vpn-dns-{family}-{arch}"), root / "router-vpn-dns")
        (root / "router-vpn-client").chmod(0o755)
        (root / "router-vpn-dns").chmod(0o755)
        return root

    raise ValueError(f"unsupported package family: {family}")


def build_from_github(work: Path, name: str, source_archive: Path, bundle: Path) -> Path:
    _, family, _ = PACKAGE_MAP[name]
    unpack = work / "github"
    unpack.mkdir()
    if source_archive.name.endswith(".tar.gz"):
        safe_extract_tar(source_archive, unpack)
    else:
        safe_extract_zip(source_archive, unpack)
    root = one_root(unpack)
    overlay_private(root, family, bundle)
    return root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="/opt/router-vpn")
    ap.add_argument("--source-root", default="/src")
    ap.add_argument("--name", required=True, choices=sorted(PACKAGE_MAP))
    ap.add_argument("--output", required=True)
    ap.add_argument("--source-archive")
    args = ap.parse_args()

    base = Path(args.base).resolve()
    bundle = base / "client-bundle"
    output = Path(args.output).resolve()
    if not bundle.is_dir():
        raise SystemExit(f"missing private client bundle: {bundle}")

    with tempfile.TemporaryDirectory(prefix="router-vpn-one-package-") as td:
        work = Path(td)
        if args.source_archive:
            root = build_from_github(work, args.name, Path(args.source_archive), bundle)
        else:
            root = build_local(work, args.name, bundle, Path(args.source_root).resolve())
        zip_dir(root, output)
    if not output.is_file() or output.stat().st_size == 0:
        raise SystemExit("package creation returned an empty file")
    os.chmod(output, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
