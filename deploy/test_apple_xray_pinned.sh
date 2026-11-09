#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VENDOR=${1:?prepared pinned sing-box checkout}
XRAY=${2:?prepared pinned Xray checkout}
[[ $(git -C "$VENDOR" rev-parse HEAD) == 1ac1a339cb1223e9c70eae14c44411c75033c02d ]]
[[ $(git -C "$XRAY" rev-parse HEAD) == 50231eaff98ccc31b5cbd247a721c16e97fe5ec1 ]]
export GOTOOLCHAIN=go1.26.3+auto
FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$FIXTURE_DIR"' EXIT
# Full native packet tests require the same corrected dependency buffers as apps.
python3 "$ROOT/deploy/prepare-mobile-buffers.py" "$VENDOR"
# A listening socket precedes the pinned REALITY detector's completion. Reuse
# the original captured detector receipt before starting bounded authentication
# exchanges. This separately built fixture never changes a shipping engine.
python3 - "$ROOT" "$VENDOR" "$XRAY" "$FIXTURE_DIR" <<'PY'
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root, vendor, expected_xray, workspace = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location(
    "apple_xray_reference", root / "deploy/test_mobile_imported_socks_xray.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
compiler = shutil.which("go")
if not compiler:
    raise ValueError("native Xray fixture requires the pinned Go compiler")
env = dict(os.environ)
env.update(json.loads(subprocess.check_output(
    [compiler, "env", "-json", "GOOS", "GOARCH"], text=True)))
source, _, binary, _, _, _ = gate.build_reference(compiler, vendor, workspace, env)
if source.resolve() != expected_xray.resolve():
    raise ValueError("native Xray fixture changed its original prepared source")
(workspace / "reference-binary-path").write_text(str(binary), encoding="utf-8")
PY
ROUTER_VPN_XRAY_TEST_BINARY="$(cat "$FIXTURE_DIR/reference-binary-path")"
export ROUTER_VPN_XRAY_TEST_BINARY
export ROUTER_VPN_XRAY_REFERENCE_DETECTOR_READY=1
(cd "$XRAY" && go test -race -ldflags=-checklinkname=0 -count=1 -run 'TestRouterVPN' ./transport/internet/splithttp)
(cd "$XRAY" && go test -race -ldflags=-checklinkname=0 -count=1 -run 'TestRouterVPNScoped' ./transport/internet)
(
 cd "$VENDOR"
 go test -race -count=1 ./experimental/libbox/routervpn/applexray
 go test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor -count=1 -timeout=180s -v ./protocol/routervpnxray
 go test -ldflags=-checklinkname=0 -tags with_quic,with_wireguard,with_gvisor ./experimental/libbox -run 'TestRouterXray' -count=1
)

bash "$ROOT/deploy/test_xray_start_layer_pinned.sh" "$VENDOR"
