#!/usr/bin/env bash
set -euo pipefail

BASE=${1:-/opt/router-vpn}
BUNDLE="$BASE/client-bundle"
OUT="$BASE/downloads"
mkdir -p "$OUT"

copy_public(){
  local src=$1 name=${2:-$(basename "$1")}
  [[ -f "$src" ]] || return 0
  cp -f "$src" "$OUT/$name"
}

# Large packages are deliberately NOT published here. Remove files left by any
# older release so an upgrade immediately returns the space. The download broker
# creates only the requested archive under /tmp, streams it, then deletes it.
rm -f \
  "$OUT"/router-vpn-macos-*.zip \
  "$OUT"/router-vpn-linux-*.zip \
  "$OUT"/router-vpn-windows-*.zip \
  "$OUT"/router-vpn-portableapps-*.zip \
  "$OUT"/router-vpn-client-bundle.zip \
  "$OUT"/SHA256SUMS

# Tiny direct files remain static because keeping these saves work without
# meaningfully consuming storage.
copy_public "$BUNDLE/router-vpn-bundle.json"
copy_public "$BUNDLE/CREDENTIALS.txt"
copy_public "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "asus-merlin-router-vpn-forwards.sh"
copy_public "$BUNDLE/modes.json"
copy_public "$BUNDLE/logical-modes.json"

# Keep the same stable download URLs in the Setup Center. The broker intercepts
# these names and resolves them GitHub-build-first, local-prebuilt fallback.
python3 - "$BUNDLE/router-vpn-device-setup.html" "$BUNDLE/setup-assets.json" <<'PY'
from pathlib import Path
import json,sys
html=Path(sys.argv[1]); assets=Path(sys.argv[2])
text=html.read_text()
needle="['Linux x86-64','router-vpn-linux-amd64.zip','x86-64 Linux'],"
if 'router-vpn-windows-portable-amd64.zip' not in text:
    extra=(
      "['Windows x64','router-vpn-windows-amd64.zip','On-demand Windows x86-64 package'],"
      "['Windows ARM64','router-vpn-windows-arm64.zip','On-demand Windows ARM64 package'],"
      "['Portable Windows x64','router-vpn-windows-portable-amd64.zip','On-demand home-linked no-install portable folder'],"
      "['Portable Windows ARM64','router-vpn-windows-portable-arm64.zip','On-demand home-linked no-install portable folder'],"
      "['PortableApps 3.9 x64 source','router-vpn-portableapps-amd64.zip','On-demand home-linked PortableApps source; MIT open source'],"
      "['PortableApps 3.9 ARM64 source','router-vpn-portableapps-arm64.zip','On-demand home-linked PortableApps source; MIT open source'],"
    )
    if needle not in text:
        raise SystemExit('Setup Center download marker changed; refusing to publish broken download links')
    text=text.replace(needle, needle+''.join(extra), 1)

# Add one small, visible storage/source note without changing the generated UI
# structure. Repeated finalizers are idempotent.
if 'Packages are generated on demand' not in text:
    marker='</body>'
    note=(
      '<div style="max-width:980px;margin:8px auto 24px;padding:0 16px;opacity:.72;font-size:12px">'
      'Packages are generated on demand: GitHub CI build first, local prebuilt fallback. '
      'Private home profiles are added only for this download and the server copy is deleted after delivery.'
      '</div>'
    )
    if marker in text:
        text=text.replace(marker,note+marker,1)
html.write_text(text)

try:
    data=json.loads(assets.read_text())
except Exception:
    data={}
wanted=[
 'router-vpn-macos-arm64.zip','router-vpn-macos-amd64.zip',
 'router-vpn-linux-arm64.zip','router-vpn-linux-amd64.zip',
 'router-vpn-windows-amd64.zip','router-vpn-windows-arm64.zip',
 'router-vpn-windows-portable-amd64.zip','router-vpn-windows-portable-arm64.zip',
 'router-vpn-portableapps-amd64.zip','router-vpn-portableapps-arm64.zip',
 'router-vpn-client-bundle.zip'
]
arr=data.setdefault('downloads',[])
for item in wanted:
    if item not in arr: arr.append(item)
data['download_policy']={
  'mode':'on-demand',
  'preferred_source':'github-actions',
  'fallback':'prebuilt-local-image',
  'server_cache':False,
  'github_artifact_retention_days':1,
}
assets.write_text(json.dumps(data,indent=2)+'\n')
PY

copy_public "$BUNDLE/router-vpn-device-setup.html" "index.html"
copy_public "$BUNDLE/router-vpn-device-setup.html"
copy_public "$BUNDLE/setup-assets.json"

cat >"$OUT/download-policy.json" <<'JSON'
{
  "mode": "on-demand",
  "preferred_source": "github-actions",
  "fallback": "prebuilt-local-image",
  "server_cache": false,
  "github_artifact_retention_days": 1
}
JSON
chmod 0600 "$OUT"/* 2>/dev/null || true

echo 'Published lightweight Setup Center only; large client/Portable/PortableApps packages are ephemeral on-demand downloads.'
