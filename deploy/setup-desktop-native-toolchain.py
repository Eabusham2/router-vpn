#!/usr/bin/env python3
"""Prepare the exact Rust target and native compiler used by the desktop builder.

The desktop PQ builder owns the Rust version/target mapping. Windows compiler
downloads use the existing verified LLVM-MinGW installer. Native Linux/macOS
prerequisites come from the runner; this helper never installs system packages.
"""
from pathlib import Path
import argparse
import contextlib
import ctypes
import fnmatch
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


PQ = module('desktop_setup_pq', 'deploy/build-desktop-pq.py')
WINDOWS = module('desktop_setup_windows', 'deploy/install-desktop-windows-toolchain.py')


def host():
    system = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows'}.get(platform.system())
    arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'ARM64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if system is None or arch is None:
        raise ValueError('Unsupported native compiler host')
    return system, arch


def line(value):
    value = str(value)
    if not value or any(ord(char) < 32 for char in value):
        raise ValueError('Build environment values must be nonempty single lines')
    return value


def executable(name, env):
    found = shutil.which(str(name), path=env.get('PATH', ''))
    if not found:
        raise ValueError('Required native build tool is unavailable: '+str(name))
    # Keep the frontend basename: clang++ and rustup proxies can be multi-call
    # binaries, so resolving a symlink may change the selected program.
    return Path(found).absolute()


def run(command, env, timeout=60):
    result = subprocess.run([str(arg) for arg in command], env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Native toolchain command failed: '+str(command[0])+'\n'+result.stdout[-8000:])
    return result.stdout.strip()


def validate_libclang(library):
    """Load and exercise the host C API, rather than accepting a guessed path."""
    class CXString(ctypes.Structure):
        _fields_ = [('data', ctypes.c_void_p), ('private_flags', ctypes.c_uint)]
    with contextlib.ExitStack() as stack:
        if hasattr(os, 'add_dll_directory'):
            stack.enter_context(os.add_dll_directory(str(library.parent)))
        api = ctypes.CDLL(str(library))
        api.clang_createIndex.argtypes = [ctypes.c_int, ctypes.c_int]
        api.clang_createIndex.restype = ctypes.c_void_p
        api.clang_disposeIndex.argtypes = [ctypes.c_void_p]
        api.clang_disposeIndex.restype = None
        api.clang_getClangVersion.argtypes = []
        api.clang_getClangVersion.restype = CXString
        api.clang_getCString.argtypes = [CXString]
        api.clang_getCString.restype = ctypes.c_char_p
        api.clang_disposeString.argtypes = [CXString]
        api.clang_disposeString.restype = None
        version = api.clang_getClangVersion()
        try:
            text = (api.clang_getCString(version) or b'').decode('utf-8', errors='replace')
        finally:
            api.clang_disposeString(version)
        match = re.search(r'clang version (\d+)', text)
        if not match or int(match[1]) < 9:
            raise ValueError('Native bindgen requires libclang 9 or newer')
        index = api.clang_createIndex(0, 0)
        if not index:
            raise ValueError('Host libclang could not create a compiler index')
        api.clang_disposeIndex(index)
    return text


def libclang_candidates(system, compiler, env):
    explicit = env.get('LIBCLANG_PATH', '')
    if explicit:
        roots = [Path(line(explicit))]
    else:
        roots = [compiler.parent, compiler.parent.parent/'lib', compiler.parent.parent/'lib64']
        current = shutil.which('clang', path=env.get('PATH', ''))
        if current:
            roots.extend([Path(current).parent, Path(current).parent.parent/'lib'])
        if system == 'windows':
            for key in ('ProgramFiles', 'ProgramW6432'):
                if env.get(key):
                    roots.append(Path(env[key])/'LLVM/bin')
        elif system == 'linux':
            roots.extend(sorted(Path('/usr/lib').glob('llvm-*/lib'), reverse=True))
            roots.extend([Path('/usr/lib/x86_64-linux-gnu'), Path('/usr/lib/aarch64-linux-gnu'),
                          Path('/usr/lib64'), Path('/usr/lib'), Path('/usr/local/lib')])
        else:
            roots.extend([Path('/opt/homebrew/opt/llvm/lib'), Path('/usr/local/opt/llvm/lib'),
                          Path('/Library/Developer/CommandLineTools/usr/lib')])
    patterns = {'windows': ('libclang.dll', 'clang.dll'), 'darwin': ('libclang.dylib', 'libclang.*.dylib'),
                'linux': ('libclang.so', 'libclang.so.*', 'libclang-*.so', 'libclang-*.so.*')}[system]
    result, seen = [], set()
    for root in roots:
        candidates = [root] if root.is_file() else [p for pattern in patterns for p in sorted(root.glob(pattern))]
        for candidate in candidates:
            if (not candidate.is_file() or 'clang-cpp' in candidate.name
                    or not any(fnmatch.fnmatchcase(candidate.name.lower(), pattern) for pattern in patterns)):
                continue
            resolved = candidate.resolve(strict=True)
            if resolved not in seen:
                result.append(resolved)
                seen.add(resolved)
    return result


def find_libclang(system, compiler, env):
    errors = []
    for candidate in libclang_candidates(system, compiler, env):
        try:
            version = validate_libclang(candidate)
            return candidate, version
        except (AttributeError, OSError, ValueError) as error:
            errors.append(str(candidate)+': '+str(error))
    detail = '; '.join(errors[-3:])
    raise ValueError('A working host-architecture libclang C API is required; install the runner LLVM/libclang package'
                     +(' or correct LIBCLANG_PATH' if env.get('LIBCLANG_PATH') else '')
                     +(': '+detail if detail else ''))


def export_environment(values, paths, env):
    values = {line(key): line(value) for key, value in values.items()}
    paths = [line(path) for path in paths]
    if any(not re.fullmatch(r'[A-Z][A-Za-z0-9_]*', key) for key in values):
        raise ValueError('Invalid build environment variable')
    # Validate every record before writing either Actions file. Local callers
    # receive the same complete values in the JSON result below.
    for name in ('GITHUB_ENV', 'GITHUB_PATH'):
        if env.get(name):
            line(env[name])
    if env.get('GITHUB_ENV'):
        with open(env['GITHUB_ENV'], 'a', encoding='utf-8', newline='\n') as output:
            output.write(''.join(key+'='+value+'\n' for key, value in sorted(values.items())))
    if env.get('GITHUB_PATH'):
        with open(env['GITHUB_PATH'], 'a', encoding='utf-8', newline='\n') as output:
            output.write(''.join(path+'\n' for path in reversed(paths)))


def setup(target, output, environ=None):
    if target not in PQ.TARGETS:
        raise ValueError('Unsupported desktop native target')
    system, arch = host()
    wanted_system, wanted_arch = target.split('/')
    if wanted_system != 'windows' and (system, arch) != (wanted_system, wanted_arch):
        raise ValueError('Linux/macOS native targets require their matching runner architecture')
    if wanted_system == 'windows' and system not in ('linux', 'windows'):
        raise ValueError('Windows targets require a supported native LLVM-MinGW host')
    env = dict(os.environ if environ is None else environ)
    output = Path(line(output)).absolute()
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise ValueError('Native toolchain output must be an owned directory')
    rustup = executable('rustup', env)
    for name in ('cmake', 'ninja'):
        tool = executable(name, env)
        run([tool, '--version'], env)
    if wanted_system == 'windows':
        bin_dir = WINDOWS.install(output/'llvm-mingw')
        compiler_env = {**env, 'PATH': os.pathsep.join((str(bin_dir), env.get('PATH', '')))}
        prefix = 'x86_64' if wanted_arch == 'amd64' else 'aarch64'
        suffix = '.exe' if system == 'windows' else ''
        compiler = executable(bin_dir/(prefix+'-w64-mingw32-clang'+suffix), compiler_env)
        cxx = executable(bin_dir/(prefix+'-w64-mingw32-clang++'+suffix), compiler_env)
        ar = executable(bin_dir/('llvm-ar'+suffix), compiler_env)
    else:
        if system == 'darwin':
            xcrun = executable('xcrun', env)
            compiler = executable(run([xcrun, '--sdk', 'macosx', '--find', 'clang'], env), env)
            cxx = executable(run([xcrun, '--sdk', 'macosx', '--find', 'clang++'], env), env)
        else:
            compiler, cxx = executable('clang', env), executable('clang++', env)
        ar = executable('llvm-ar' if shutil.which('llvm-ar', path=env.get('PATH', '')) else 'ar', env)
        bin_dir = compiler.parent
    for compiler_tool in (compiler, cxx):
        if not re.search(r'clang version \d+', run([compiler_tool, '--version'], env)):
            raise ValueError('Native C and C++ compilers must be Clang frontends')
    library, library_version = find_libclang(system, compiler, env)
    # Keep rustup's proxy directory first so the exported exact toolchain also
    # governs bare cargo/rustc calls in the downstream native builder.
    paths = list(dict.fromkeys([str(rustup.parent), str(bin_dir)]))
    env.update(RUSTUP_TOOLCHAIN=PQ.RUST, PATH=os.pathsep.join([*paths, env.get('PATH', '')]))
    run([rustup, 'toolchain', 'install', PQ.RUST, '--profile', 'minimal', '--no-self-update'], env, 1200)
    triple = PQ.TARGETS[target]
    run([rustup, 'target', 'add', '--toolchain', PQ.RUST, triple], env, 600)
    for tool in ('rustc', 'cargo'):
        if not run([rustup, 'run', PQ.RUST, tool, '--version'], env).startswith(tool+' '+PQ.RUST+' '):
            raise ValueError('Installed '+tool+' differs from the exact desktop Rust pin')
    installed = run([rustup, 'target', 'list', '--installed', '--toolchain', PQ.RUST], env).splitlines()
    if triple not in installed:
        raise ValueError('Rust did not install the exact desktop target')
    suffix = triple.replace('-', '_')
    values = {'RUSTUP_TOOLCHAIN': PQ.RUST, 'LIBCLANG_PATH': str(library),
              'CC': str(compiler), 'CXX': str(cxx), 'AR': str(ar),
              'CC_'+suffix: str(compiler), 'CXX_'+suffix: str(cxx), 'AR_'+suffix: str(ar),
              'CARGO_TARGET_'+suffix.upper()+'_LINKER': str(compiler)}
    export_environment(values, paths, env)
    result = {'target': target, 'rust_target': triple, 'environment': values,
              'prepend_path': paths, 'libclang_version': library_version}
    print(json.dumps(result, sort_keys=True, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=PQ.TARGETS)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    setup(args.target, args.output)
