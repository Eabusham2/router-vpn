#!/usr/bin/env bash
set -euo pipefail

BASE=${ROUTER_VPN_BASE:-/opt/router-vpn}
cleanup_private_archives() {
  rm -f \
    "$BASE/downloads/router-vpn-client-bundle.zip" \
    "$BASE/router-vpn-client-bundle.zip"
}
trap cleanup_private_archives EXIT

# Keep the proven initializer unchanged, but never retain a credential-bearing
# client ZIP after it finishes. The Setup Center broker creates the private node
# bundle only for the active request and deletes its temporary output afterward.
/bin/bash /usr/local/bin/router-vpn-init "$@"
