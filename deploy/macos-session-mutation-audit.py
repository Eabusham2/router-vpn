#!/usr/bin/env python3
from pathlib import Path
import importlib.util, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[1]
TRANSFORM=ROOT/'client/macos/macos-session-mutation-transform.py'
BUILD=ROOT/'client/macos/build-native-app.sh'
PRODUCT=ROOT/'client/macos/RouterVPNMacProduct.swift'
UNIFIED=ROOT/'client/macos/RouterVPNMacUnifiedShell.swift'

spec=importlib.util.spec_from_file_location('mac_session_transform',TRANSFORM)
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
product=mod.transform(PRODUCT.read_text(encoding='utf-8'),'product')
unified=mod.transform(UNIFIED.read_text(encoding='utf-8'),'unified')

def need(body,*markers):
    missing=[m for m in markers if m not in body]
    if missing: raise SystemExit(f'macOS session mutation missing markers: {missing}')

need(product,
    'func mutationBusy(from status:', 'func mutationBusy() -> Bool', 'func requireMutationIdle', 'func ensureMutationIdle',
    '"connecting", "starting", "checking", "trying", "proving", "reasserting", "disconnecting", "stopping", "switching", "reconnecting"',
    'catch { return true }',
    'opening node pairing', 'redeeming the one-time pairing code', 'importing a linked node',
    'selecting another Router VPN node', 'committing the lowest-latency node selection',
    'removing a linked node', 'committing linked-node removal', 'saving DNS policy',
    'starting multihop', 'starting an external connection', 'starting AUTO', 'starting the selected mode')
need(unified,
    'Disconnect already in progress.', 'Disconnect requested.', 'Disconnecting…', 'Checking…',
    'changing the selected mode', 'editing CUSTOM presets', 'saving a CUSTOM preset', 'deleting a CUSTOM preset',
    'changing multihop selection', 'changing persistent kill-switch policy', 'changing DNS policy',
    'unified-kill-switch', 'unified-multihop-toggle', 'unified-mode-popup', 'unified-dns-popup',
    'as? NSControl', 'control.isEnabled = !busy', 'self.routerPopup.isEnabled = !busy', 'self.multihopEntryPopup.isEnabled = !busy',
    'button.isEnabled = !unknown && !disconnecting')

build=BUILD.read_text(encoding='utf-8')
need(build,
    'SESSION_MUTATION_TRANSFORM=',
    'python3 "$SESSION_MUTATION_TRANSFORM" "$SRC" "$HARDENED_SRC" product',
    'python3 "$SESSION_MUTATION_TRANSFORM" "$UNIFIED_SRC" "$HARDENED_UNIFIED_SRC" unified',
    '"$ADAPTIVE_SRC" "$HARDENED_UNIFIED_SRC"',
    'python3 - "$HARDENED_SRC" "$ADAPTIVE_SRC"')

with tempfile.TemporaryDirectory() as td:
    p=Path(td)
    pp=p/'product.swift'; uu=p/'unified.swift'; pp.write_text(product); uu.write_text(unified)
    subprocess.run(['swiftc','-parse',str(pp)],check=True)
    subprocess.run(['swiftc','-parse',str(uu),str(ROOT/'client/macos/RouterVPNProfileSettings.swift')],check=True)
print('macOS session mutation shipping audit: PASS')
