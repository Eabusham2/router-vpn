#!/usr/bin/env python3
"""Build/test the isolated, pinned raw-tunnel DNS helper and retain its notices."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "cmd/dnsproxy"
TOOLCHAIN = "go1.26.3"
NOTICE = "DNS-PROXY-NOTICES.json"
MAX_NOTICE = 256 << 10
INPUTS = {
    "go.mod": "043fc96ce9b2287b438366ed71649b153b7a7f9d9a5a4175bfade8e8bd8c842f",
    "go.sum": "2e2652ba0b595498093e5772a126afc0589a9a598816bd7863da9e77ec6cb14b",
    "THIRD-PARTY-NOTICES.json": "cbeab45ba6e9be856faccead9aa4a1c200b9e19725a3a6566c4b802b6aa115bd",
}
TARGETS = frozenset((
    "windows/amd64", "windows/arm64", "darwin/amd64", "darwin/arm64",
    "linux/amd64", "linux/arm64", "linux/arm", "freebsd/amd64", "freebsd/arm64",
    "openbsd/amd64", "openbsd/arm64", "netbsd/amd64", "netbsd/arm64",
    "dragonfly/amd64", "illumos/amd64",
))


def notices(module: Path = MODULE) -> bytes:
    for name, digest in INPUTS.items():
        path = module / name
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"DNS proxy pinned input is missing or linked: {name}")
        raw = path.read_bytes()
        if len(raw) > MAX_NOTICE or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError(f"DNS proxy pinned input changed: {name}")
    raw = (module / "THIRD-PARTY-NOTICES.json").read_bytes()
    data = json.loads(raw)
    if data["schema"] != 1 or data["component"] != "router-vpn-dns" or data["toolchain"] != TOOLCHAIN:
        raise RuntimeError("DNS proxy notice identity changed")
    return raw


def stage_notices(output: Path, module: Path = MODULE) -> None:
    raw = notices(module)
    output = output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("refusing linked/non-file DNS notice output")
    fd, name = tempfile.mkstemp(prefix=".dns-notices-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        os.chmod(name, 0o644)
        os.replace(name, output)
    finally:
        Path(name).unlink(missing_ok=True)


def environment(target: str | None, race: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    # Neither an ambient workspace nor a downloaded replacement toolchain may
    # change the isolated module. Keep caller-owned build/module caches.
    env.update(GOTOOLCHAIN="local", GOWORK="off", GOENV="off", GOFLAGS="",
               GOEXPERIMENT="", CGO_ENABLED="1" if race else "0",
               GOSUMDB="sum.golang.org", GOPRIVATE="", GONOSUMDB="", GONOPROXY="")
    for key in ("GOOS", "GOARCH", "GOARM", "GOAMD64", "GOARM64"):
        env.pop(key, None)
    if target:
        if target not in TARGETS:
            raise RuntimeError(f"unsupported DNS proxy target: {target}")
        env["GOOS"], env["GOARCH"] = target.split("/")
        if env["GOARCH"] == "arm":
            env["GOARM"] = "7"
    return env


def run(go: str, arguments: list[str], env: dict[str, str], module: Path = MODULE,
        timeout: int = 1200) -> str:
    result = subprocess.run([go, *arguments], cwd=module, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"DNS proxy {' '.join(arguments[:2])} failed:\n{result.stdout[-8000:]}{result.stderr[-8000:]}")
    return result.stdout


def verify_module(directory: Path, prefix: str, expected: str) -> None:
    # Go's documented h1 directory checksum: sorted slash-separated names,
    # each prefixed by the module path/version and its file-content SHA-256.
    # Verify only actual compiled dependencies; `go mod verify` also visits
    # the local Router VPN replacement, which has no module-cache zip hash.
    digest = hashlib.sha256()
    files = []
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("DNS module cache directory is linked or missing")
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("DNS module cache contains a link")
        if path.is_file():
            name = path.relative_to(directory).as_posix()
            if "\n" in name:
                raise RuntimeError("DNS module cache contains an invalid filename")
            files.append(name)
    for name in sorted(files):
        file_hash = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        digest.update(f"{file_hash}  {prefix}/{name}\n".encode())
    if "h1:" + base64.b64encode(digest.digest()).decode() != expected:
        raise RuntimeError(f"DNS dependency content differs from its pinned checksum: {prefix}")


def compiled_dependency_names(payload: dict, target: str) -> set[str]:
    names = {entry["path"] for entry in payload["modules"]}
    # quic-go's generic NetBSD ARM64 socket implementation does not compile
    # x/sys. Keep the complete notices while verifying this exact target's
    # actual module set; all other existing targets compile all six modules.
    if target == "netbsd/arm64":
        names.remove("golang.org/x/sys")
    return names


def prepare(go: str, env: dict[str, str], module: Path = MODULE) -> dict:
    payload = json.loads(notices(module))
    version = run(go, ["env", "GOVERSION"], env, module).strip()
    if version != TOOLCHAIN:
        raise RuntimeError(f"DNS proxy requires installed {TOOLCHAIN}; found {version}")
    # Enumerate the actual production package closure. A new dependency cannot
    # bypass the pinned notices simply because it is only used by one target.
    fmt = "{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Sum}}|{{.Module.Dir}}{{end}}"
    listing = run(go, ["list", "-mod=readonly", "-deps", "-f", fmt, "."], env, module)
    expected = {entry["path"]: entry for entry in payload["modules"]}
    seen = set()
    for line in listing.splitlines():
        if not line:
            continue
        name, version, checksum, directory = line.split("|", 3)
        if name in {"router-vpn", "router-vpn/cmd/dnsproxy"}:
            continue
        if name in seen:
            continue
        seen.add(name)
        entry = expected.get(name)
        if entry is None or (version, checksum) != (entry["version"], entry["sum"]):
            raise RuntimeError(f"unowned DNS proxy dependency: {name} {version}")
        verify_module(Path(directory), name + "@" + version, checksum)
        for license in entry["licenses"]:
            raw = (Path(directory) / license["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != license["sha256"] or raw.decode("utf-8") != license["text"]:
                raise RuntimeError(f"DNS proxy dependency notice changed: {name}/{license['path']}")
    target = env.get("GOOS", "") + "/" + env.get("GOARCH", "")
    if target == "/":
        target = "/".join(run(go, ["env", "GOOS", "GOARCH"], env, module).split())
    if seen != compiled_dependency_names(payload, target):
        raise RuntimeError("DNS proxy actual dependency closure differs from pinned notices")
    toolchain = Path(run(go, ["env", "GOROOT"], env, module).strip())
    for license in payload["toolchain_licenses"]:
        raw = (toolchain / license["path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != license["sha256"] or raw.decode("utf-8") != license["text"]:
            raise RuntimeError("Go toolchain notice differs from the pinned DNS notices")
    return payload


def build(go: str, target: str, output: Path) -> None:
    env = environment(target)
    payload = prepare(go, env)
    output = output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("refusing linked/non-file DNS binary output")
    # VCS metadata is retained when building a checkout. An exact-SHA source
    # archive uses the enclosing package's existing ROUTER-VPN-SOURCE manifest;
    # this helper never invents a checkout identity for an archive.
    run(go, ["build", "-mod=readonly", "-trimpath", "-buildvcs=auto", "-ldflags=-s -w", "-o", str(output), "."], env)
    metadata = run(go, ["version", "-m", str(output)], env)
    lines = [line.strip().split("\t") for line in metadata.splitlines()]
    deps = {line[1]: (line[2], line[3]) for line in lines if len(line) == 4 and line[0] == "dep"}
    settings = {line[1] for line in lines if len(line) == 2 and line[0] == "build"}
    compiled = compiled_dependency_names(payload, target)
    expected = {entry["path"]: (entry["version"], entry["sum"]) for entry in payload["modules"] if entry["path"] in compiled}
    actual = {name: value for name, value in deps.items() if name != "router-vpn"}
    system, arch = target.split("/")
    if not metadata.splitlines()[0].endswith(": " + TOOLCHAIN) or actual != expected or not {"CGO_ENABLED=0", "GOOS=" + system, "GOARCH=" + arch}.issubset(settings):
        output.unlink(missing_ok=True)
        raise RuntimeError("built DNS proxy does not match its pinned target/dependencies/toolchain")
    stage_notices(output.parent / NOTICE)
    print(f"DNS proxy built and verified: {target} ({TOOLCHAIN})")


def race_supported(system: str, arch: str) -> bool:
    # Matches Go1.26.3 src/internal/platform/supported.go.
    if system == "linux":
        return arch in {"amd64", "arm64", "loong64", "ppc64le", "riscv64", "s390x"}
    if system == "darwin":
        return arch in {"amd64", "arm64"}
    return system in {"freebsd", "netbsd", "windows"} and arch == "amd64"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compile = commands.add_parser("build")
    compile.add_argument("target", choices=sorted(TARGETS))
    compile.add_argument("output", type=Path)
    compile.add_argument("--go", default="go")
    test = commands.add_parser("test")
    test.add_argument("--go", default="go")
    test.add_argument("--without-race", action="store_true", help="only for native hosts where pinned Go has no race detector, such as Windows ARM64")
    notice = commands.add_parser("notices")
    notice.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "notices":
        stage_notices(args.output)
        return
    go = shutil.which(args.go)
    if not go:
        raise RuntimeError("installed Go1.26.3 is required; this helper never installs toolchains")
    if args.command == "build":
        build(go, args.target, args.output)
    else:
        env = environment(None, race=not args.without_race)
        if args.without_race:
            host = run(go, ["env", "GOHOSTOS", "GOHOSTARCH"], env).split()
            if len(host) != 2 or race_supported(*host):
                raise RuntimeError("--without-race cannot weaken a race-capable native host gate")
        prepare(go, env)
        arguments = ["test", "-mod=readonly", "-count=1", "./..."]
        if not args.without_race:
            arguments.insert(1, "-race")
        print(run(go, arguments, env), end="")


if __name__ == "__main__":
    main()
