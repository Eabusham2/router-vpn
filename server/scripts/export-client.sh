#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.'; exit 1; }
BASE=/opt/router-vpn
[[ -d $BASE/client-bundle ]] || { echo 'Client bundle not found. Run server/install.sh first.'; exit 1; }
cd "$BASE/client-bundle"
rm -f "$BASE/router-vpn-client-bundle.zip"
zip -qr "$BASE/router-vpn-client-bundle.zip" .
echo "$BASE/router-vpn-client-bundle.zip"
