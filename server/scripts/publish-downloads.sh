#!/usr/bin/env bash
set -euo pipefail

BASE=${1:-/opt/router-vpn}
BUNDLE="$BASE/client-bundle"
OUT="$BASE/downloads"
mkdir -p "$OUT"

copy_static(){
  local src=$1 name=${2:-$(basename "$1")}
  [[ -f "$src" ]] || return 0
  cp -f "$src" "$OUT/$name"
}

# Large packages and private node material are never persistently published.
# Remove files left by older releases so upgrades reclaim space and cannot keep
# leaking node credentials on the LAN. The authenticated broker creates private
# bundles and generic application packages only on demand under /tmp.
rm -f \
  "$OUT"/router-vpn-macos-*.zip \
  "$OUT"/router-vpn-linux-*.zip \
  "$OUT"/router-vpn-windows-*.zip \
  "$OUT"/router-vpn-portableapps-*.zip \
  "$OUT"/router-vpn-client-bundle.zip \
  "$OUT"/router-vpn-android.apk \
  "$OUT"/router-vpn-ios-preview.ipa \
  "$OUT"/router-vpn-ios.ipa \
  "$OUT"/router-vpn-bundle.json \
  "$OUT"/CREDENTIALS.txt \
  "$OUT"/SHA256SUMS

# These lightweight files contain no long-lived Setup Center credential. The
# generated Setup Center HTML/setup-assets may contain private import material,
# so the broker requires authentication before serving them.
copy_static "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "asus-merlin-router-vpn-forwards.sh"
copy_static "$BUNDLE/modes.json"
copy_static "$BUNDLE/logical-modes.json"

# Normalize Setup Center methods into typed import lanes. QR remains only for
# real interoperable payloads (WireGuard, SIP002, Hysteria2, SSR), never random
# JSON/text or a made-up SOCKS QR.
if [[ -f "$BUNDLE/setup-assets.json" && -f "$BUNDLE/router-vpn-device-setup.html" ]]; then
  python3 /src/server/scripts/normalize-setup-imports.py "$BASE"
fi

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
      "['Android APK','router-vpn-android.apk','Same-SHA native Android VpnService app'],",
      "['iOS/iPadOS native WireGuard IPA','router-vpn-ios.ipa','Unsigned re-signable same-SHA native WireGuard PacketTunnel build'],",
    ]
if extra:
    if needle not in text:
        raise SystemExit('Setup Center download marker changed; refusing to publish broken download links')
    text=text.replace(needle, needle+''.join(extra), 1)
text=text.replace(
    "['Checksums','SHA256SUMS','Verify direct downloads before bypassing OS security warnings']",
    "['Static-file checksums','SHA256SUMS','SHA-256 for authenticated Setup Center/helper metadata; packages are generated per request']",
)
if 'Generic application packages are generated on demand' not in text:
    marker='</body>'
    note=(
      '<div style="max-width:980px;margin:8px auto 24px;padding:0 16px;opacity:.72;font-size:12px">'
      'This Setup Center is authenticated because it can contain private node setup material. Generic application packages are generated on demand and never contain linked-node secrets. '
      'Windows x64/ARM64 installed/Portable: matching same-SHA release/native GitHub artifact first, then the bounded router-local Windows fallback if unavailable. macOS/Linux require a real same-SHA native artifact; Android/iOS require same-SHA native GitHub artifacts only. '
      'Add nodes separately by authenticated private-bundle import or one-time LAN pairing. Pairing codes are short-lived and one-use; Apple-family clients must grant local-network permission before LAN pairing. '
      'Private bundle builds and all temporary package files are deleted after delivery. Typed asynchronous download jobs expose queued/building/ready progress and cancellation.'
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
 'router-vpn-android.apk','router-vpn-ios.ipa','router-vpn-client-bundle.zip'
]
arr=[x for x in data.get('downloads',[]) if 'portableapps' not in str(x).lower()]
for item in wanted:
    if item not in arr: arr.append(item)
data['downloads']=arr
data['download_policy']={
  'mode':'on-demand','preferred_source':'github-actions','fallback':'router-local-generic-build',
  'local_build_scope':'requested-generic-package-only','local_build_platforms':['windows-amd64','windows-arm64','windows-portable-amd64','windows-portable-arm64'],
  'generic_packages_secret_free':True,'node_linking':'separate-bundle-or-pairing',
  'setup_center_auth':'required-for-private-ui-and-build-actions',
  'mobile_artifacts':'same-sha-github-only','github_exact_sha_required':True,'server_cache':False,
  'max_parallel_package_requests':8,'local_build_slots':1,
  'download_jobs':{'create':'POST /api/download-jobs {name}','status':'GET /api/download-jobs/{job_id}','cancel':'DELETE /api/download-jobs/{job_id}','file':'GET /api/download-jobs/{job_id}/file','ready_ttl_seconds':900},
  'pairing':{'create':'POST /api/pairing (Setup Center auth required)','redeem':'POST /api/pairing/redeem','lan_only':True,'one_time':True,'default_ttl_seconds':300,'apple_local_network_permission_required':True},
  'github_artifact_retention_days':1,
}
assets.write_text(json.dumps(data,indent=2)+'\n')
PY

copy_static "$BUNDLE/router-vpn-device-setup.html" "index.html"
copy_static "$BUNDLE/router-vpn-device-setup.html"
copy_static "$BUNDLE/setup-assets.json"

cat >"$OUT/download-policy.json" <<'JSON'
{
  "mode": "on-demand",
  "preferred_source": "github-actions",
  "fallback": "router-local-generic-build",
  "local_build_scope": "requested-generic-package-only",
  "local_build_platforms": ["windows-amd64", "windows-arm64", "windows-portable-amd64", "windows-portable-arm64"],
  "generic_packages_secret_free": true,
  "node_linking": "separate-bundle-or-pairing",
  "setup_center_auth": "required-for-private-ui-and-build-actions",
  "mobile_artifacts": "same-sha-github-only",
  "github_exact_sha_required": true,
  "server_cache": false,
  "max_parallel_package_requests": 8,
  "local_build_slots": 1,
  "download_jobs": {"create":"POST /api/download-jobs {name}","status":"GET /api/download-jobs/{job_id}","cancel":"DELETE /api/download-jobs/{job_id}","file":"GET /api/download-jobs/{job_id}/file","ready_ttl_seconds":900},
  "pairing": {"create":"POST /api/pairing","redeem":"POST /api/pairing/redeem","lan_only":true,"one_time":true,"default_ttl_seconds":300,"apple_local_network_permission_required":true},
  "github_artifact_retention_days": 1
}
JSON

# Static checksums intentionally exclude private node bundle/CREDENTIALS because
# those files are not copied into the LAN-served static directory.
(
  cd "$OUT"
  for f in asus-merlin-router-vpn-forwards.sh modes.json logical-modes.json index.html router-vpn-device-setup.html setup-assets.json download-policy.json; do
    [[ -f "$f" ]] && sha256sum "$f"
  done
) >"$OUT/SHA256SUMS"

chmod 0600 "$OUT"/* 2>/dev/null || true

echo 'Published authenticated Setup Center metadata only; no static node credentials, one-time LAN pairing enabled, generic apps remain ephemeral/secret-free.'
