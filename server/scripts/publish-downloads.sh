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
# older release, including retired PortableApps files, so upgrades reclaim space.
# The download broker creates only the requested package under /tmp, streams it,
# then deletes it.
rm -f \
  "$OUT"/router-vpn-macos-*.zip \
  "$OUT"/router-vpn-linux-*.zip \
  "$OUT"/router-vpn-windows-*.zip \
  "$OUT"/router-vpn-portableapps-*.zip \
  "$OUT"/router-vpn-client-bundle.zip \
  "$OUT"/router-vpn-android.apk \
  "$OUT"/router-vpn-ios-preview.ipa \
  "$OUT"/SHA256SUMS

# Tiny direct files remain static because keeping these saves work without
# meaningfully consuming storage. These are private node-link/setup files,
# separate from the secret-free generic application packages.
copy_public "$BUNDLE/router-vpn-bundle.json"
copy_public "$BUNDLE/CREDENTIALS.txt"
copy_public "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "asus-merlin-router-vpn-forwards.sh"
copy_public "$BUNDLE/modes.json"
copy_public "$BUNDLE/logical-modes.json"

# Normalize the generated Setup Center into typed import lanes. This is where
# legacy "QR = arbitrary config text" behavior is removed: QR remains only for
# actual interoperable import payloads (WireGuard, SIP002, Hysteria2, SSR).
if [[ -f "$BUNDLE/setup-assets.json" && -f "$BUNDLE/router-vpn-device-setup.html" ]]; then
  python3 /src/server/scripts/normalize-setup-imports.py "$BASE"
fi

# Keep stable on-demand URLs in the Setup Center. PortableApps was retired;
# Router VPN's own tested no-install Portable ZIP remains supported.
python3 - "$BUNDLE/router-vpn-device-setup.html" "$BUNDLE/setup-assets.json" <<'PY'
from pathlib import Path
import json,sys
html=Path(sys.argv[1]); assets=Path(sys.argv[2])
text=html.read_text()

for stale in (
  "['PortableApps 3.9 x64 source','router-vpn-portableapps-amd64.zip','On-demand home-linked PortableApps source; MIT open source'],",
  "['PortableApps 3.9 ARM64 source','router-vpn-portableapps-arm64.zip','On-demand home-linked PortableApps source; MIT open source'],",
):
    text=text.replace(stale,'')

needle="['Linux x86-64','router-vpn-linux-amd64.zip','x86-64 Linux'],"
extra=[]
if 'router-vpn-windows-amd64.zip' not in text:
    extra += [
      "['Windows x64','router-vpn-windows-amd64.zip','On-demand generic Windows x86-64 app; add nodes separately'],",
      "['Windows ARM64','router-vpn-windows-arm64.zip','On-demand generic Windows ARM64 app; add nodes separately'],",
      "['Portable Windows x64','router-vpn-windows-portable-amd64.zip','On-demand generic no-install portable app; add nodes separately'],",
      "['Portable Windows ARM64','router-vpn-windows-portable-arm64.zip','On-demand generic no-install portable app; add nodes separately'],",
    ]
if 'router-vpn-android.apk' not in text:
    extra += [
      "['Android APK','router-vpn-android.apk','Same-SHA GitHub-built generic Android controller/importer APK'],",
      "['iOS/iPadOS preview IPA','router-vpn-ios-preview.ipa','Unsigned re-signable same-SHA generic preview; Packet Tunnel engines are intentionally unavailable'],",
    ]
if extra:
    if needle not in text:
        raise SystemExit('Setup Center download marker changed; refusing to publish broken download links')
    text=text.replace(needle, needle+''.join(extra), 1)
text=text.replace(
    "['Checksums','SHA256SUMS','Verify direct downloads before bypassing OS security warnings']",
    "['Static-file checksums','SHA256SUMS','SHA-256 for private node-link/helper/Setup Center files; on-demand app packages are generated per request']",
)

if 'Generic application packages are generated on demand' not in text:
    marker='</body>'
    note=(
      '<div style="max-width:980px;margin:8px auto 24px;padding:0 16px;opacity:.72;font-size:12px">'
      'Generic application packages are generated on demand and never contain linked-node secrets. Desktop/Portable: matching same-SHA GitHub CI artifact first, then router-side build of only the requested generic Go client package if unavailable. '
      'Android/iOS: matching same-SHA GitHub mobile artifact; the Linux home node does not fake platform-specific mobile builds. '
      'Add home/server nodes separately by private bundle import or pairing. Private bundle builds and all temporary package files are deleted after delivery. '
      'The broker also exposes typed asynchronous download jobs so clients can show queued/building/ready progress and cancel safely.'
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
 'router-vpn-android.apk','router-vpn-ios-preview.ipa',
 'router-vpn-client-bundle.zip'
]
arr=[x for x in data.get('downloads',[]) if 'portableapps' not in str(x).lower()]
for item in wanted:
    if item not in arr: arr.append(item)
data['downloads']=arr
data['download_policy']={
  'mode':'on-demand',
  'preferred_source':'github-actions',
  'fallback':'router-local-generic-build',
  'local_build_scope':'requested-generic-package-only',
  'local_build_platforms':'go-desktop-portable',
  'generic_packages_secret_free':True,
  'node_linking':'separate-bundle-or-pairing',
  'mobile_artifacts':'same-sha-github-only',
  'server_cache':False,
  'max_parallel_package_requests':8,
  'local_build_slots':1,
  'download_jobs':{
    'create':'POST /api/download-jobs {name}',
    'status':'GET /api/download-jobs/{job_id}',
    'cancel':'DELETE /api/download-jobs/{job_id}',
    'file':'GET /api/download-jobs/{job_id}/file',
    'ready_ttl_seconds':900,
  },
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
  "fallback": "router-local-generic-build",
  "local_build_scope": "requested-generic-package-only",
  "local_build_platforms": "go-desktop-portable",
  "generic_packages_secret_free": true,
  "node_linking": "separate-bundle-or-pairing",
  "mobile_artifacts": "same-sha-github-only",
  "server_cache": false,
  "max_parallel_package_requests": 8,
  "local_build_slots": 1,
  "download_jobs": {
    "create": "POST /api/download-jobs {name}",
    "status": "GET /api/download-jobs/{job_id}",
    "cancel": "DELETE /api/download-jobs/{job_id}",
    "file": "GET /api/download-jobs/{job_id}/file",
    "ready_ttl_seconds": 900
  },
  "github_artifact_retention_days": 1
}
JSON

# This is intentionally the checksum manifest for lightweight static files only.
# On-demand packages may be generated per request and are not pre-listed here.
(
  cd "$OUT"
  for f in \
    router-vpn-bundle.json CREDENTIALS.txt asus-merlin-router-vpn-forwards.sh \
    modes.json logical-modes.json index.html router-vpn-device-setup.html \
    setup-assets.json download-policy.json; do
      [[ -f "$f" ]] && sha256sum "$f"
  done
) >"$OUT/SHA256SUMS"

chmod 0600 "$OUT"/* 2>/dev/null || true

echo 'Published lightweight Setup Center only; typed imports and async download jobs enabled; generic desktop/Portable apps are ephemeral, private node linking is separate, and mobile downloads are same-SHA GitHub-backed.'
