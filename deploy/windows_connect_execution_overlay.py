"""Project the original CONNECT/SS execution provider onto a Windows test host.

Only platform selection changes. The original Manager, authenticated lease
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
overlay = BASE.overlay
EXTRA = {
    'mobile/desktop/node_chain_imported_execution_peer_test.go.tmpl': 'routervpn_windows_execution_peer_test.go',
    'mobile/desktop/node_chain_imported_execution_layers_peer_test.go.tmpl': 'routervpn_windows_execution_layers_peer_test.go',
    'mobile/desktop/node_chain_connect_execution_peer_test.go.tmpl': 'routervpn_windows_connect_execution_peer_test.go',
}
PLATFORM_FILES = {
    'deploy/fixtures/windows-connect-execution/peer.go': 'routervpn_windows_connect_execution_selector_test.go',
    'deploy/fixtures/windows-connect-execution/physical.go': 'routervpn_windows_connect_execution_physical_test.go',
}


def windows_source(raw, source):
    header, body = raw.decode().split('\n', 1)
    if header not in ('//go:build linux && !android',
                      '//go:build (linux && !android) || (darwin && routervpn_darwin_node_chain)') or not body.startswith('\npackage routervpnamnezia\n'):
        raise ValueError('Original execution provider projection changed: ' + source)
    return ('//go:build windows && ' + TAG + '\n' + body).encode()


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
        result[target] = windows_source(raw, source)
    projected = PROJECTOR.copies()
    if set(projected) != {PROJECTOR.TARGET}:
        raise ValueError('Original execution worker IPC projection changed')
    result['routervpn_windows_imported_execution_process_test.go'] = windows_source(
        projected[PROJECTOR.TARGET], PROJECTOR.TARGET)
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
