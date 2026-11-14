"""Windows typed full-path peer overlay; real crypto and retirement stay original."""
from pathlib import Path
import hashlib
import importlib.util
import json
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('socks_windows_original_scope', ROOT/'deploy/windows_candidate_prefix_overlay.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
TAG, REPLACEMENTS = BASE.TAG, BASE.REPLACEMENTS
EXTRA = ('node_chain_socks_middle_test.go.tmpl', 'node_chain_socks_process_test.go.tmpl', 'node_chain_socks_peer_test.go.tmpl')
overlay = BASE.overlay


def peer_sources():
    result = BASE.peer_sources()
    for name in EXTRA:
        path = ROOT/'mobile/desktop'/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Windows SOCKS peer lost its exact original encrypted source')
        header, raw = path.read_text().split('\n', 1)
        if header != '//go:build linux && !android' or not raw.startswith('\npackage routervpnamnezia\n'):
            raise ValueError('Windows SOCKS peer changed its original explicit projection boundary')
        if name == 'node_chain_socks_peer_test.go.tmpl':
            raw = BASE.replace_once(raw, ' if runtime.GOOS == "linux" {\n',
                ' if runtime.GOOS == "windows" {\n'
                '  if !desktopWindowsPrefixReferenceAddressPair(address, client) { return netip.Addr{}, netip.Addr{}, bad }\n'
                '  return netip.MustParseAddr(address), netip.MustParseAddr(client), nil\n'
                ' }\n if runtime.GOOS == "linux" {\n')
        result['routervpn_windows_socks_'+name.removesuffix('.tmpl')] = ('//go:build windows && '+TAG+'\n'+raw).encode()
    result['routervpn_windows_socks_reference_test.go'] = (ROOT/'deploy/fixtures/windows-socks-node-chain/peer.go').read_bytes()
    return result


def peer_overlay(directory, workspace):
    directory, workspace = Path(directory).resolve(), Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    replacement = {}
    for name, raw in peer_sources().items():
        path = workspace/name
        path.write_bytes(raw)
        replacement[str(directory/name)] = str(path)
    manifest = workspace/'overlay.json'
    manifest.write_text(json.dumps({'Replace': replacement}, sort_keys=True))
    return manifest
