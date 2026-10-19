#!/usr/bin/env python3
"""A real Linux Go/Clang host for native Tor and Cronet graph checks."""
from __future__ import annotations

import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
GO_VERSION = 'go1.26.3'
MIN_LLVM = 21


def inputs() -> list[Path]:
    return [Path(__file__).resolve(), ROOT/'deploy/test_native_tor_graph_host.py']


def _executable(value: str | Path, path: str) -> Path:
    found = shutil.which(str(value), path=path)
    if not found:
        raise ValueError('Native graph tool is unavailable: '+str(value))
    # Preserve frontend/driver names such as clang++ and ld.lld. Their symlink
    # targets can be multi-call binaries whose behavior depends on argv[0].
    return Path(found).absolute()


def _version(executable: Path, expression: str, env: dict[str, str]) -> int:
    output = subprocess.check_output([str(executable), '--version'], env=env, text=True, timeout=15)
    match = re.search(expression, output)
    if not match:
        raise ValueError('Native graph compiler version is unavailable')
    return int(match[1])


def _llvm(compiler: Path, env: dict[str, str]) -> tuple[Path, Path, Path]:
    compiler = compiler.resolve(strict=True)
    cxx = _executable(compiler.parent/'clang++', env.get('PATH', ''))
    linker = _executable(compiler.parent/'ld.lld', env.get('PATH', ''))
    versions = (_version(compiler, r'clang version (\d+)', env),
                _version(cxx, r'clang version (\d+)', env),
                _version(linker, r'LLD (\d+)', env))
    if min(versions) < MIN_LLVM or len(set(versions)) != 1:
        raise ValueError('Pinned Cronet requires matching Clang/Clang++/LLD 21 or newer')
    return compiler, cxx, linker


def environment(go: str, library: Path, clang: str | None = None,
                require_swift: bool = False) -> dict[str, str]:
    """Discard target flags before loading the verified host DSO with real engines.

    A supplied compiler is authoritative and must have matching sibling tools.
    Otherwise prefer the installed Swift toolchain, then clang-21 or clang.
    The linker path is explicit: an older ld.lld earlier in PATH cannot win.
    """
    if platform.system() != 'Linux':
        raise ValueError('Native Tor graph checks require the real Linux host package')
    env = os.environ.copy()
    target_options = {
        'GOOS', 'GOARCH', 'GOARM', 'GOARM64', 'GOAMD64', 'GOMIPS', 'GOMIPS64',
        'GOPPC64', 'GORISCV64', 'GOWASM', 'GOEXPERIMENT', 'GOFLAGS', 'GOWORK',
        'GOENV', 'GOTOOLCHAIN', 'CC', 'CXX', 'CPP', 'AR', 'AS', 'LD', 'RANLIB',
        'CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'SDKROOT', 'SDK_DIR',
        'MACOSX_DEPLOYMENT_TARGET', 'IPHONEOS_DEPLOYMENT_TARGET',
        'TVOS_DEPLOYMENT_TARGET', 'WATCHOS_DEPLOYMENT_TARGET',
        'XROS_DEPLOYMENT_TARGET', 'DEVELOPER_DIR', 'TOOLCHAINS',
        'ROUTERVPN_IOS_TOR_MISSING_ENGINE',
    }
    for name in list(env):
        if name in target_options or name.startswith('CGO_'):
            env.pop(name)
    env.update(GOTOOLCHAIN='local', GOENV='off', GOWORK='off', GOFLAGS='',
               CGO_ENABLED='1', PYTHONDONTWRITEBYTECODE='1')
    go_tool = _executable(go, env.get('PATH', ''))
    version = subprocess.check_output([str(go_tool), 'version'], env=env, text=True, timeout=15).split()
    if len(version) < 3 or version[2] != GO_VERSION:
        raise ValueError('Native Tor graph checks require Go 1.26.3')
    host = subprocess.check_output([str(go_tool), 'env', 'GOHOSTOS', 'GOHOSTARCH'],
                                   env=env, text=True, timeout=15).split()
    if len(host) != 2 or host[0] != 'linux':
        raise ValueError('Native graph parser must execute on the real Linux host')
    env.update(GOOS=host[0], GOARCH=host[1])

    swift = shutil.which('swiftc', path=env.get('PATH', ''))
    if require_swift and not swift:
        raise ValueError('Swift is required to execute the actual Apple profile compiler')
    if clang:
        compiler, cxx, linker = _llvm(_executable(clang, env.get('PATH', '')), env)
    else:
        candidates = []
        if swift:
            candidates.append(Path(swift).resolve().parent/'clang')
        for name in ('clang-21', 'clang'):
            found = shutil.which(name, path=env.get('PATH', ''))
            if found:
                candidates.append(Path(found).resolve())
        selected = None
        for candidate in dict.fromkeys(candidates):
            try:
                selected = _llvm(_executable(candidate, env.get('PATH', '')), env)
                break
            except (ValueError, OSError, subprocess.SubprocessError):
                continue
        if selected is None:
            raise ValueError('Pinned Cronet requires Clang/LLD 21 or newer; install clang-21 and lld-21 or supply --clang')
        compiler, cxx, linker = selected

    library = library.resolve(strict=True)
    if not library.is_file():
        raise ValueError('Native graph checks require the verified Tor host DSO')
    env['CC'] = shlex.quote(str(compiler))
    env['CXX'] = shlex.quote(str(cxx))
    env['PATH'] = os.pathsep.join((str(go_tool.parent), str(compiler.parent), env.get('PATH', '')))
    env['CGO_LDFLAGS'] = shlex.join([
        '-fuse-ld='+str(linker), '-L'+str(library.parent),
        '-Wl,-rpath,'+str(library.parent), '-lroutervpn_tor',
    ])
    return env
