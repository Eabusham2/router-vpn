#!/usr/bin/env python3
from pathlib import Path
import importlib.util, tempfile
ROOT=Path(__file__).resolve().parents[1]

def require(path,*markers):
    body=(ROOT/path).read_text(encoding='utf-8')
    missing=[m for m in markers if m not in body]
    if missing: raise SystemExit(f'{path}: missing Linux session-mutation marker(s): {missing}')
    return body

transform=require('client/linux/apply-session-mutation.py',
    'Linux session mutation baseline drifted',
    'routervpn-gtk-product.c','routervpn-gtk-product-v3.c','routervpn-gtk-product-v4.c',
    'routervpn-profile-settings-v1.inc','routervpn-unified-shell-v8.inc',
    'routervpn_phase_busy','routervpn_mutation_busy','routervpn_require_mutation_idle',
    'opening node pairing','redeeming the one-time pairing code','committing linked-node import',
    'committing linked-node removal','selecting the lowest-latency node',
    'starting an external connection','starting an external via-entry connection',
    'Connected/transitioning: settings are read-only.','saving persistent node settings',
    'editing CUSTOM presets','deleting a CUSTOM preset','saving a CUSTOM preset',
    'changing the selected mode','changing persistent kill-switch policy','changing DNS policy',
    'Disconnecting…','Checking…','Controller/status unavailable • session mutation locked')

build=require('client/linux/build-native-app.sh',
    'SESSION_MUTATION="$ROOT/client/linux/apply-session-mutation.py"',
    'HARDENED_V4="$BUILD_DIR/routervpn-gtk-product-v4.c"',
    'HARDENED_V3="$BUILD_DIR/routervpn-gtk-product-v3.c"',
    'HARDENED_CORE="$BUILD_DIR/routervpn-gtk-product.c"',
    'HARDENED_SETTINGS="$BUILD_DIR/routervpn-profile-settings-v1.inc"',
    'HARDENED_UNIFIED="$BUILD_DIR/routervpn-unified-shell-v8.inc"',
    'python3 "$SESSION_MUTATION"',
    'python3 - "$HARDENED_V4" "$EMBEDDED_V4"',
    '-I"$BUILD_DIR" -I"$ROOT/client/linux"')
assert 'routervpn-profile-settings-v2.inc' not in build, 'canonical Linux builder switched to un-audited settings include'

# Execute the transformer against the canonical shipping baselines and verify
# the hardened output contains the exact session guards used by the build.
spec=importlib.util.spec_from_file_location('linux_session_transform',ROOT/'client/linux/apply-session-mutation.py')
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as td:
    td=Path(td)
    checks={
      'routervpn-gtk-product.c':('static gboolean routervpn_phase_busy','starting AUTO','selecting another Router VPN node'),
      'routervpn-gtk-product-v3.c':('opening node pairing','committing linked-node import','committing linked-node removal'),
      'routervpn-gtk-product-v4.c':('committing the lowest-latency node selection','starting an external via-entry connection'),
      'routervpn-profile-settings-v1.inc':('Connected/transitioning: settings are read-only.','saving persistent node settings'),
      'routervpn-unified-shell-v8.inc':('editing CUSTOM presets','changing DNS policy','Disconnecting…'),
    }
    for name,markers in checks.items():
        src=ROOT/'client/linux'/name; dst=td/name
        mod.apply(src,dst)
        body=dst.read_text(encoding='utf-8')
        for marker in markers:
            if marker not in body: raise SystemExit(f'transformed {name}: missing {marker!r}')

require('client/linux/routervpn-telemetry-v9.inc',
    'selecting/connecting a fastest Router VPN node',
    'gtk_widget_set_sensitive(t->fastest,!routervpn_mutation_busy(t->app))')
require('client/linux/routervpn-globe-v10.inc',
    'selecting a node from the VPN globe',
    'routervpn_require_mutation_idle(app')

print('Linux session mutation shipping audit: PASS')
