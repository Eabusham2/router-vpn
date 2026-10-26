#!/usr/bin/env python3
"""Build only the isolated AWG test peer from an already prepared pinned core.

The resulting test binary accepts --config /absolute/private.json and emits one
readiness JSON object. It never changes the production endpoint or builds the
complete application engine. Ordinary invocation with -test.run executes the
native package tests instead.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORE = "1ac1a339cb1223e9c70eae14c44411c75033c02d"
TAGS = "with_wireguard,with_gvisor"
AWG_MODULE = "github.com/amnezia-vpn/amneziawg-go/v3"
AWG_VERSION = "v3.1.20260814"
AWG_SUM = "h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0="


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--race", action="store_true")
    args = parser.parse_args()
    core = args.core.absolute()
    if core.is_symlink() or subprocess.check_output(
        ["git", "-C", str(core), "rev-parse", "HEAD"], text=True
    ).strip() != CORE:
        raise SystemExit("AWG reference requires the exact prepared pinned core")
    directory = core / "protocol/routervpnamnezia"
    if directory.is_symlink() or not (directory / "endpoint.go").is_file():
        raise SystemExit("AWG reference requires the existing owned native endpoint")
    for source in sorted((ROOT / "mobile/amnezia").glob("*.tmpl")):
        name = source.name.removesuffix(".tmpl")
        target = directory / name
        if target.is_symlink():
            raise SystemExit("Refusing a linked reference source destination")
        if name == "desktop_reference_test.go":
            target.write_bytes(source.read_bytes())
        elif target.read_bytes() != source.read_bytes():
            raise SystemExit("Prepared reference dependencies differ from this source")
    output = args.output.absolute()
    if output.is_symlink():
        raise SystemExit("Refusing a linked reference executable destination")
    output.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(GOWORK="off", GOTOOLCHAIN="local", GOFLAGS="")
    if subprocess.check_output([args.go, "env", "GOVERSION"], env=environment, text=True).strip() != "go1.26.3":
        raise SystemExit("AWG reference requires the pinned native Go compiler")
    dependency = json.loads(subprocess.check_output(
        [args.go, "list", "-m", "-json", AWG_MODULE], cwd=core, env=environment, text=True))
    if dependency.get("Version") != AWG_VERSION or dependency.get("Sum") != AWG_SUM or dependency.get("Replace"):
        raise SystemExit("AWG reference requires the exact unmodified cryptographic dependency")
    subprocess.run(
        [args.go, "test", "-c", "-p=1", *( ["-race"] if args.race else []),
         "-mod=readonly", "-ldflags=-checklinkname=0", "-tags", TAGS, "-o", str(output),
         "./protocol/routervpnamnezia"],
        cwd=core, env=environment, check=True, timeout=600,
    )
    print("Built isolated AWG reference:", output)


if __name__ == "__main__":
    main()
