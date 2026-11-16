"""Project the original CONNECT/SS execution provider onto a Windows test host.

The explicit platform adapters use the original Windows private-runtime DACL
checks and captured machine environment in place of POSIX permissions. The original Manager, authenticated lease
handler, worker IPC/source owner, CONNECT, SS UoT and stream retirement remain
the shipping or shared reference implementations. The Windows physical helper
retains its own exact interface and aliases; it cannot admit a Linux/Darwin
transport capture.
"""
from pathlib import Path
import importlib.util
import json

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load('windows_execution_original_connect', 'deploy/windows_connect_node_chain_overlay.py')
PROJECTOR = load('windows_execution_original_ipc', 'deploy/prepare-desktop-imported-execution-test.py')
TAG = BASE.TAG
replace_once = BASE.BASE.BASE.replace_once
HEADER = "//go:build windows && " + TAG + "\n\n"
PRIVATE = ("cmd/client/private_runtime_permissions.go", "cmd/client/private_runtime_permissions_windows.go")
WORKER = ("mobile/server_chain/command.go.tmpl", "mobile/server_chain/native.go.tmpl")
overlay = BASE.overlay
EXTRA = {
    'mobile/desktop/node_chain_imported_execution_peer_test.go.tmpl': 'routervpn_windows_execution_peer_test.go',
    'mobile/desktop/node_chain_imported_execution_layers_peer_test.go.tmpl': 'routervpn_windows_execution_layers_peer_test.go',
    'mobile/desktop/node_chain_connect_execution_peer_test.go.tmpl': 'routervpn_windows_connect_execution_peer_test.go',
}
PLATFORM_FILES = {
    'deploy/fixtures/windows-connect-execution/peer.go': 'routervpn_windows_connect_execution_selector_test.go',
    'deploy/fixtures/windows-connect-execution/physical.go': 'routervpn_windows_connect_execution_physical_test.go',
    'deploy/fixtures/windows-connect-execution/security.go': 'routervpn_windows_connect_execution_security_test.go',
    'deploy/fixtures/windows-connect-execution/security_test.go': 'routervpn_windows_connect_execution_security_controls_test.go',
}


def windows_source(raw, source):
    header, body = raw.decode().split('\n', 1)
    if header not in ('//go:build linux && !android',
                      '//go:build (linux && !android) || (darwin && routervpn_darwin_node_chain)') or not body.startswith('\npackage routervpnamnezia\n'):
        raise ValueError('Original execution provider projection changed: ' + source)
    return ('//go:build windows && ' + TAG + '\n' + body).encode()



def original(name):
    path = ROOT / name
    if path.is_symlink() or not path.is_file():
        raise ValueError('Windows CONNECT fixture lost original source: ' + name)
    return path.read_text()


def security_sources(package):
    if package not in ('main', 'routervpnamnezia'):
        raise ValueError('Foreign Windows fixture security package')
    shared = original(PRIVATE[0])
    boundary = '// An active proof is read-only.'
    if shared.count(boundary) != 1:
        raise ValueError('Original private-runtime identity boundary changed')
    shared = shared[:shared.index(boundary)]
    shared = replace_once(shared, '\n\t"io"', '')
    shared = replace_once(shared, 'package main\n', 'package ' + package + '\n')
    native = original(PRIVATE[1])
    native = replace_once(native, '//go:build windows\n\n', '')
    native = replace_once(native, 'package main\n', 'package ' + package + '\n')
    return {'routervpn_windows_execution_private_identity.go': (HEADER + shared).encode(),
            'routervpn_windows_execution_private_dacl.go': (HEADER + native).encode()}


def peer_sources():
    result = BASE.peer_sources()
    for source, target in EXTRA.items():
        path = ROOT / source
        if path.is_symlink() or not path.is_file() or target in result:
            raise ValueError('Original execution provider missing or replaced: ' + source)
        raw = path.read_bytes()
        if source.endswith('node_chain_connect_execution_peer_test.go.tmpl'):
            if raw.count(b'connectExecutionPhysicalPeer(local, remote)') != 1:
                raise ValueError('Original CONNECT execution physical boundary changed')
        text = raw.decode()
        if source.endswith('node_chain_imported_execution_peer_test.go.tmpl'):
            text = replace_once(text, 'original, err := os.Lstat(dir)\n\tif err != nil {\n\t\treturn nil, err\n\t}',
                                'original, err := os.Lstat(dir)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n'
                                '\tif err := preparePrivateRuntimeDirectoryPermissions(dir, original); err != nil { return nil, err }')
            text = replace_once(text, 'command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "GORACE=atexit_sleep_ms=0"}',
                                'command.Env, err = windowsCONNECTExecutionWorkerEnvironment()\n\tif err != nil { return p, err }')
        if source.endswith(('node_chain_imported_execution_peer_test.go.tmpl', 'node_chain_connect_execution_peer_test.go.tmpl')):
            text = replace_once(text, 'if os.Chmod(runtimeDir, 0700) != nil {',
                                'runtimeInfo, runtimeErr := os.Lstat(runtimeDir)\n\tif runtimeErr != nil || preparePrivateRuntimeDirectoryPermissions(runtimeDir, runtimeInfo) != nil {')
        result[target] = windows_source(text.encode(), source)
    projected = PROJECTOR.copies()
    # The separate Linux lease fixture is deliberately excluded from Windows.
    # Require the complete known projector inventory before selecting its IPC body.
    if set(projected) != {PROJECTOR.TARGET, 'protocol/routervpnamnezia/routervpn_imported_execution_native_lease_linux_test.go'}:
        raise ValueError('Original execution worker IPC projection changed')
    text = projected[PROJECTOR.TARGET].decode()
    text = replace_once(text, ' || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0111 == 0', '')
    text = replace_once(text, 'if err != nil || !os.SameFile(before, actual) {',
                        'if err != nil || !os.SameFile(before, actual) || windowsCONNECTExecutionCodePermissions(file, actual) != nil {')
    result['routervpn_windows_imported_execution_process_test.go'] = windows_source(text.encode(), PROJECTOR.TARGET)
    for name, body in security_sources('routervpnamnezia').items():
        result[name.removesuffix('.go') + '_test.go'] = body
    # Exercise the exact projected worker reader in the native peer control gate.
    reader = worker_text('command')
    start = 'func routerVPNServerChainRead('
    if reader.count(start) != 1:
        raise ValueError('Original private worker reader changed')
    reader = reader[reader.index(start):].replace('routerVPNServerChainRead', 'windowsCONNECTExecutionRead')
    result['routervpn_windows_execution_reader_test.go'] = (HEADER + 'package routervpnamnezia\nimport ("errors"; "io"; "os"; "path/filepath")\n' + reader).encode()
    for source, target in PLATFORM_FILES.items():
        path = ROOT / source
        if path.is_symlink() or not path.is_file() or target in result:
            raise ValueError('Windows execution lost its exact physical selector')
        result[target] = path.read_bytes()
    return result


def peer_overlay(directory, workspace):
    directory, workspace = Path(directory).resolve(), Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    replacements = {}
    for name, raw in peer_sources().items():
        path = workspace / name
        path.write_bytes(raw)
        replacements[str(directory / name)] = str(path)
    manifest = workspace / 'overlay.json'
    manifest.write_text(json.dumps({'Replace': replacements}, sort_keys=True))
    return manifest


def worker_text(stem):
    if stem not in ("command", "native"):
        raise ValueError("Foreign worker source")
    raw = original("mobile/server_chain/" + stem + ".go.tmpl")
    if stem == 'command':
        raw = replace_once(raw, 'info.Mode().Perm() != 0700', 'validatePrivateRuntimePathPermissions(directory, info) != nil')
        raw = replace_once(raw, 'before.Mode().Perm() != 0600', 'validatePrivateRuntimePathPermissions(filepath.Join(root.Name(), name), before) != nil')
    else:
        raw = replace_once(raw, 'path.Mode().Perm() != 0700', 'validatePrivateRuntimePathPermissions(n.directory, path) != nil')
        raw = replace_once(raw, 'info.Mode().Perm() != 0600', 'validatePrivateRuntimePathPermissions(filepath.Join(n.directory, name), info) != nil')
        if '"path/filepath"' not in raw:
            raw = replace_once(raw, '\n\t"os"', '\n\t"os"\n\t"path/filepath"')
    return raw


def worker_sources(source):
    source = Path(source)
    result = {}
    for stem in ('command', 'native'):
        target = 'cmd/sing-box/routervpn_server_chain_' + stem + '.go'
        path = source / target
        if path.is_symlink() or not path.is_file() or path.read_text() != original('mobile/server_chain/' + stem + '.go.tmpl'):
            raise ValueError('Windows fixture worker differs from original prepared source: ' + target)
        result[target] = worker_text(stem).encode()
    for name, body in security_sources('main').items():
        result['cmd/sing-box/' + name] = body
    # Preserve the delivered worker's absolute library lookup and compiled seal.
    target = 'cmd/sing-box/routervpn_native_library.go'
    path, raw = source / target, original('mobile/desktop/native_library.go.tmpl').encode()
    if path.is_symlink() or path.exists() and (not path.is_file() or path.read_bytes() != raw):
        raise ValueError('Original worker native library owner changed')
    result[target] = raw
    return result


def worker_overlay(source, workspace):
    source, workspace = Path(source).resolve(), Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    replacements = {}
    for name, raw in worker_sources(source).items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        replacements[str(source / name)] = str(path)
    manifest = workspace / 'overlay.json'
    manifest.write_text(json.dumps({'Replace': replacements}, sort_keys=True))
    return manifest
