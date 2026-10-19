#!/usr/bin/env bash
# Exercise the actual compiled dispatcher, independent encrypted lanes and
# nested per-node Xray sessions before either shipping Libbox is packaged.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR=${1:?prepared exact native core required}
[[ $(git -C "$VENDOR" rev-parse HEAD) == 1ac1a339cb1223e9c70eae14c44411c75033c02d ]]
XRAY=$(cd "$VENDOR" && go list -mod=readonly -m -f '{{.Dir}}' github.com/xtls/xray-core)
[[ $(git -C "$XRAY" rev-parse HEAD) == 50231eaff98ccc31b5cbd247a721c16e97fe5ec1 ]]
export GOTOOLCHAIN=go1.26.3+auto
python3 "$ROOT/deploy/prepare-mobile-buffers.py" "$VENDOR"
FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$FIXTURE_DIR"' EXIT
(cd "$XRAY" && go build -mod=readonly -ldflags=-checklinkname=0 -o "$FIXTURE_DIR/xray-fixture" ./main)
export ROUTER_VPN_XRAY_TEST_BINARY="$FIXTURE_DIR/xray-fixture"
# Prove that the observed nested-session defect remains caught by encrypted
# traffic, restoring only our exact generated source before the positive gate.
python3 - "$ROOT" "$VENDOR" <<'PY'
from pathlib import Path
import subprocess
import sys
root, core = map(Path, sys.argv[1:])
source = core/'protocol/routervpnxray/outbound.go'
original = source.read_bytes()
if source.is_symlink() or original != (root/'mobile/applexray/outbound.go.tmpl').read_bytes():
    raise SystemExit('Nested-session negative control requires exact owned source')
fixed = b'ctx = nativeRequestContext(request.Context, h.binding)'
if original.count(fixed) != 2:
    raise SystemExit('Nested-session boundary changed')
try:
    source.write_bytes(original.replace(fixed, b'ctx = request.Context'))
    result = subprocess.run(['go','test','-race','-mod=readonly','-ldflags=-checklinkname=0','-tags','with_quic,with_wireguard,with_gvisor','-count=1','-timeout=60s','-v','./protocol/routervpncomposite','-run','^TestNativeCompositeEncryptedEntryAndExitBothLanes$/^split$/^split$'], cwd=core, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
finally:
    source.write_bytes(original)
if result.returncode != 1 or 'encrypted native payload or UDP reassembly tcp' not in result.stdout:
    print(result.stdout)
    raise SystemExit('Original shared Xray session did not fail the encrypted nested-hop regression')
print('Verified negative control: shared Xray session overwrites the encrypted exit destination')
PY
(cd "$VENDOR" && go test -race -mod=readonly -ldflags=-checklinkname=0 -tags with_quic,with_wireguard,with_gvisor -count=1 -timeout=180s -v ./protocol/routervpncomposite)
# Shipping low-memory packet buffers must preserve fragmented nested UDP too.
(cd "$VENDOR" && go test -race -mod=readonly -ldflags=-checklinkname=0 -tags with_quic,with_wireguard,with_gvisor,with_low_memory -count=1 -timeout=180s ./protocol/routervpncomposite)
