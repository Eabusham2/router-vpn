#!/usr/bin/env python3
"""Build the isolated TCP/UDP composite reference peers from pinned source.

These test executables are never packaged. The desktop gate imports their fresh
node assets through the real controller and executes the resulting graph with
the sealed production engine, including the actual authenticated Server lease.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORE = "1ac1a339cb1223e9c70eae14c44411c75033c02d"
XRAY = "50231eaff98ccc31b5cbd247a721c16e97fe5ec1"
TAGS = "with_quic,with_wireguard,with_gvisor"


def pinned(path, revision, module):
    if path.is_symlink() or subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip() != revision or not (path / "go.mod").read_text().startswith("module " + module + "\n"):
        raise SystemExit("Composite reference requires the exact pinned native sources")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--xray-output", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--race", action="store_true")
    args = parser.parse_args()
    core = args.core.absolute()
    pinned(core, CORE, "github.com/sagernet/sing-box")
    environment = os.environ.copy()
    environment.update(GOWORK="off", GOTOOLCHAIN="go1.26.3+auto", GOFLAGS="")
    if subprocess.check_output([args.go, "env", "GOVERSION"], env=environment, text=True).strip() != "go1.26.3":
        raise SystemExit("Composite reference requires the pinned native Go compiler")
    dependency = json.loads(subprocess.check_output(
        [args.go, "list", "-m", "-json", "github.com/xtls/xray-core"], cwd=core,
        env=environment, text=True))
    xray = Path(dependency.get("Dir", ""))
    pinned(xray, XRAY, "github.com/xtls/xray-core")
    directory = core / "protocol/routervpncomposite"
    if directory.is_symlink():
        raise SystemExit("Refusing a linked composite reference package")
    for source in sorted((ROOT / "mobile/composite").glob("*.tmpl")):
        target = directory / source.name.removesuffix(".tmpl")
        if target.is_symlink() or not target.is_file() or target.read_bytes() != source.read_bytes():
            raise SystemExit("Prepared composite reference differs from this exact source")
    runtime_source = core / "protocol/routervpnxray/outbound.go"
    if runtime_source.is_symlink() or runtime_source.read_bytes() != (ROOT / "mobile/applexray/outbound.go.tmpl").read_bytes():
        raise SystemExit("Composite reference lost the captured native Xray session owner")
    for output in (args.output.absolute(), args.xray_output.absolute()):
        if output.is_symlink():
            raise SystemExit("Refusing a linked reference executable destination")
        output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [args.go, "build", "-p=1", "-mod=readonly", "-ldflags=-checklinkname=0", "-o",
         str(args.xray_output.absolute()), "./main"],
        cwd=xray, env=environment, check=True, timeout=600,
    )
    subprocess.run(
        [args.go, "test", "-c", "-p=1", *(["-race"] if args.race else []),
         "-mod=readonly", "-ldflags=-checklinkname=0", "-tags", TAGS, "-o",
         str(args.output.absolute()), "./protocol/routervpncomposite"],
        cwd=core, env=environment, check=True, timeout=600,
    )
    print("Built isolated complete composite reference peers from exact native sources")


if __name__ == "__main__":
    main()
