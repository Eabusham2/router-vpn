#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE=${1:-/opt/router-vpn}
BUNDLE="$BASE/client-bundle"
OUT="$BASE/downloads"
PRIVATE_DIR=/src/server/scripts/private-directory.py
PRIVATE_WRITE=/src/server/scripts/atomic-private-write.py
PRIVATE_BATCH=/src/server/scripts/atomic-private-batch.py

# Validate the private roots before *any* deletion, staging or publication. In
# particular, never let an old/malicious downloads symlink turn rm/copy into a
# write outside Router VPN's owned tree.
python3 "$PRIVATE_DIR" "$BUNDLE"
python3 "$PRIVATE_DIR" "$OUT"

WORK=$(mktemp -d "$BUNDLE/.publish-downloads.XXXXXX")
trap 'rm -rf "${WORK:-}"' EXIT
chmod 0700 "$WORK"
python3 "$PRIVATE_DIR" "$WORK/normalized/client-bundle"
python3 "$PRIVATE_DIR" "$WORK/patched"
python3 "$PRIVATE_DIR" "$WORK/out"

# Large packages and private node material are never persistently published.
# Remove files left by older releases only after the downloads root is proven to
# be a real private directory. The authenticated broker creates private bundles
# and generic application packages on demand under its private temporary tree.
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

# Normalize Setup Center metadata on a private staging copy. normalize-setup-
# imports.py may use ordinary writes because this tree is not served and is
# discarded on failure; only a completely generated pair is batch-adopted into
# the canonical client bundle.
if [[ -e "$BUNDLE/setup-assets.json" ]]; then
  python3 "$PRIVATE_BATCH" \
    "$WORK/normalized/client-bundle/setup-assets.json=$BUNDLE/setup-assets.json"
  python3 /src/server/scripts/normalize-setup-imports.py "$WORK/normalized"
  python3 "$PRIVATE_BATCH" \
    "$BUNDLE/setup-assets.json=$WORK/normalized/client-bundle/setup-assets.json" \
    "$BUNDLE/router-vpn-device-setup.html=$WORK/normalized/client-bundle/router-vpn-device-setup.html"
fi

# Apply download-policy/UI augmentation to private staging copies too. Parse
# failure is fatal: never replace current authenticated Setup Center metadata
# with an empty/default object because the previous generation was unreadable.
python3 "$PRIVATE_BATCH" \
  "$WORK/patched/router-vpn-device-setup.html=$BUNDLE/router-vpn-device-setup.html" \
  "$WORK/patched/setup-assets.json=$BUNDLE/setup-assets.json"
python3 - "$WORK/patched/router-vpn-device-setup.html" "$WORK/patched/setup-assets.json" <<'PY'
from pathlib import Path
import json,sys
html=Path(sys.argv[1]); assets=Path(sys.argv[2])
text=html.read_text(encoding='utf-8')
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
    if marker not in text:
        raise SystemExit('Setup Center HTML lost </body> marker')
    text=text.replace(marker,note+marker,1)
html.write_text(text, encoding='utf-8')
data=json.loads(assets.read_text(encoding='utf-8'))
if not isinstance(data,dict):
    raise SystemExit('setup-assets.json must remain an object')
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
assets.write_text(json.dumps(data,indent=2)+'\n', encoding='utf-8')
PY
chmod 0600 "$WORK/patched/router-vpn-device-setup.html" "$WORK/patched/setup-assets.json"
python3 "$PRIVATE_BATCH" \
  "$BUNDLE/router-vpn-device-setup.html=$WORK/patched/router-vpn-device-setup.html" \
  "$BUNDLE/setup-assets.json=$WORK/patched/setup-assets.json"

# Stage the complete static generation. Every source read goes through the
# private batch helper, which validates regular files/ancestors and re-checks
# identity during read. Nothing is copied directly into the served directory.
stage_static(){
  local src=$1 name=${2:-$(basename "$1")}
  if [[ ! -e "$src" ]]; then return 0; fi
  python3 "$PRIVATE_BATCH" "$WORK/out/$name=$src"
}
stage_static "$BUNDLE/router/asus-merlin-router-vpn-forwards.sh" "asus-merlin-router-vpn-forwards.sh"
stage_static "$BUNDLE/modes.json"
stage_static "$BUNDLE/logical-modes.json"
stage_static "$BUNDLE/router-vpn-device-setup.html" "index.html"
stage_static "$BUNDLE/router-vpn-device-setup.html"
stage_static "$BUNDLE/setup-assets.json"

cat <<'JSON' | python3 "$PRIVATE_WRITE" "$WORK/out/download-policy.json"
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
# those files are not copied into the LAN-served static directory. Compute the
# checksum manifest over one staged generation, then publish all files from that
# generation through the same private batch primitive.
(
  cd "$WORK/out"
  for f in asus-merlin-router-vpn-forwards.sh modes.json logical-modes.json index.html router-vpn-device-setup.html setup-assets.json download-policy.json; do
    [[ -f "$f" ]] && sha256sum "$f"
  done
) | python3 "$PRIVATE_WRITE" "$WORK/out/SHA256SUMS"

publish=( )
for f in asus-merlin-router-vpn-forwards.sh modes.json logical-modes.json index.html router-vpn-device-setup.html setup-assets.json download-policy.json SHA256SUMS; do
  [[ -f "$WORK/out/$f" ]] && publish+=("$OUT/$f=$WORK/out/$f")
done
(( ${#publish[@]} > 0 )) || { echo 'No Setup Center metadata was staged for publication.' >&2; exit 1; }
python3 "$PRIVATE_BATCH" "${publish[@]}"

rm -rf "$WORK"
WORK=
trap - EXIT

echo 'Published one validated authenticated Setup Center metadata generation; no static node credentials, one-time LAN pairing enabled, generic apps remain ephemeral/secret-free.'
