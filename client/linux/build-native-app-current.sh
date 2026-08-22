#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BASE="$ROOT/client/linux/build-native-app.sh"
REQ="$ROOT/client/linux/routervpn-auto-requirements-v11.inc"
[[ -s "$BASE" && -s "$REQ" ]] || { echo 'Missing Linux native base builder or AUTO requirements include.' >&2; exit 2; }
TMP=$(mktemp "$ROOT/client/linux/.build-native-current.XXXXXX.sh")
trap 'rm -f "$TMP"' EXIT
python3 - "$BASE" "$TMP" <<'PY'
from pathlib import Path
import sys
src, dst = map(Path, sys.argv[1:3])
text = src.read_text(encoding='utf-8')
changes = (
    (
        'SETTINGS_INC="$ROOT/client/linux/routervpn-profile-settings-v1.inc"\n',
        'SETTINGS_INC="$ROOT/client/linux/routervpn-profile-settings-v1.inc"\nAUTO_REQUIREMENTS_INC="$ROOT/client/linux/routervpn-auto-requirements-v11.inc"\n',
    ),
    (
        '"$HOME_INC" "$SETTINGS_INC" "$UNIFIED_INC"',
        '"$HOME_INC" "$SETTINGS_INC" "$AUTO_REQUIREMENTS_INC" "$UNIFIED_INC"',
    ),
    (
        'for source in "$ONBOARDING_INC" "$HOME_INC" "$SETTINGS_INC" "$UNIFIED_INC"',
        'for source in "$ONBOARDING_INC" "$HOME_INC" "$SETTINGS_INC" "$AUTO_REQUIREMENTS_INC" "$UNIFIED_INC"',
    ),
    (
        'include_new = \'#include "routervpn-gtk-product-v4-embedded.c"\\n#include "routervpn-home-summary-v1.inc"\\n#include "routervpn-profile-settings-v1.inc"\\n\'',
        'include_new = \'#include "routervpn-gtk-product-v4-embedded.c"\\n#include "routervpn-home-summary-v1.inc"\\n#include "routervpn-profile-settings-v1.inc"\\n#include "routervpn-auto-requirements-v11.inc"\\n\'',
    ),
    (
        'set_remembered_sensitive_v5(app, "router-vpn-advanced-settings-v7", has_node && !connected);\\n    set_remembered_sensitive_v5(app, "router-vpn-advanced-mtu-v5", connected);',
        'set_remembered_sensitive_v5(app, "router-vpn-advanced-settings-v7", has_node && !connected);\\n    set_remembered_sensitive_v5(app, "router-vpn-auto-requirements-v11", has_node && !connected);\\n    set_remembered_sensitive_v5(app, "router-vpn-advanced-mtu-v5", connected);',
    ),
    (
        'gtk_box_pack_start(GTK_BOX(advanced), settings_v7, FALSE, FALSE, 0);\\n    add_tab(tabs, advanced, "Advanced");\\n    remember_button_v5(app, advanced, "router-vpn-advanced-settings-v7", "Edit profile settings");',
        'gtk_box_pack_start(GTK_BOX(advanced), settings_v7, FALSE, FALSE, 0);\\n    GtkWidget *requirements_v11 = make_button("AUTO / SMART requirements", G_CALLBACK(on_linux_auto_requirements_v11), app);\\n    gtk_box_pack_start(GTK_BOX(advanced), requirements_v11, FALSE, FALSE, 0);\\n    add_tab(tabs, advanced, "Advanced");\\n    remember_button_v5(app, advanced, "router-vpn-advanced-settings-v7", "Edit profile settings");\\n    remember_button_v5(app, advanced, "router-vpn-auto-requirements-v11", "AUTO / SMART requirements");',
    ),
)
for old, new in changes:
    if text.count(old) != 1:
        raise SystemExit(f'Linux current builder seam drifted before AUTO requirements patch: {old}')
    text = text.replace(old, new, 1)
dst.write_text(text, encoding='utf-8')
PY
chmod 755 "$TMP"
for marker in 'routervpn-auto-requirements-v11.inc' 'AUTO / SMART requirements' 'G_CALLBACK(on_linux_auto_requirements_v11)' 'router-vpn-auto-requirements-v11'; do
  grep -Fq "$marker" "$TMP" || { echo "Linux current builder missing $marker" >&2; exit 2; }
done
for marker in '/api/profile/settings' 'auto_require_encrypted' 'auto_require_obfuscation' 'Require encrypted AUTO candidates' 'Require obfuscation for AUTO candidates'; do
  grep -Fq "$marker" "$REQ" || { echo "Linux AUTO requirements include missing $marker" >&2; exit 2; }
done
bash "$TMP" "$@"
