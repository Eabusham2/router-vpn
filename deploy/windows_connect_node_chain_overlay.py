"""Project only the explicit Windows selector over the real CONNECT reference.

The original prefix/SOCKS peers and the existing captured-image WFP scope remain
byte-identical. No protocol, credential, traffic or ownership operation is
replaced; the shared TCP CONNECT and SS UoT-v2 implementations run unchanged.
"""
from pathlib import Path
import importlib.util
import json

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'connect_windows_original_scope', ROOT / 'deploy/windows_socks_node_chain_overlay.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
TAG, REPLACEMENTS, overlay = BASE.TAG, BASE.REPLACEMENTS, BASE.overlay
EXTRA = {
    'mobile/chain/connect_reference_test.go.tmpl': 'routervpn_windows_connect_reference_test.go',
    'mobile/desktop/node_chain_connect_peer_test.go.tmpl': 'routervpn_windows_connect_installed_peer_test.go',
}
WRAPPER = 'deploy/fixtures/windows-connect-node-chain/peer.go'


def peer_sources():
    result = BASE.peer_sources()
    for source, name in EXTRA.items():
        path = ROOT / source
        if path.is_symlink() or not path.is_file():
            raise ValueError('Windows CONNECT peer lost original encrypted source: ' + source)
        header, raw = path.read_text(encoding='utf-8').split('\n', 1)
        if header != '//go:build linux && !android' or not raw.startswith('\npackage routervpnamnezia\n'):
            raise ValueError('Windows CONNECT peer changed its explicit projection boundary: ' + source)
        if name in result:
            raise ValueError('Windows CONNECT peer would replace an original peer')
        result[name] = ('//go:build windows && ' + TAG + '\n' + raw).encode()
    path = ROOT / WRAPPER
    if path.is_symlink() or not path.is_file():
        raise ValueError('Windows CONNECT peer lost its original physical wrapper')
    result['routervpn_windows_connect_physical_test.go'] = path.read_bytes()
    return result


def peer_overlay(directory, workspace):
    directory, workspace = Path(directory).resolve(), Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    replacement = {}
    for name, raw in peer_sources().items():
        path = workspace / name
        path.write_bytes(raw)
        replacement[str(directory / name)] = str(path)
    manifest = workspace / 'overlay.json'
    manifest.write_text(json.dumps({'Replace': replacement}, sort_keys=True), encoding='utf-8')
    return manifest
