#!/usr/bin/env bash
# Focused encrypted-return gate; it supplements, never replaces, native releases.
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PIN=1ac1a339cb1223e9c70eae14c44411c75033c02d
git -C "$WORK" init -q core
git -C "$WORK/core" remote add origin https://github.com/SagerNet/sing-box.git
git -C "$WORK/core" fetch -q --depth=1 origin "$PIN"
git -C "$WORK/core" checkout -q --detach FETCH_HEAD
test "$(git -C "$WORK/core" rev-parse HEAD)" = "$PIN"
python3 - "$ROOT" "$WORK/core" <<'PY'
from pathlib import Path
import sys
source,core=map(Path,sys.argv[1:])
packages=('awgpolicy','routechoice','multihoprelay','mobilemultihop')
for package in packages:
    target=core/'experimental/libbox/routervpn'/package
    target.mkdir(parents=True,exist_ok=True)
    for path in (source/'internal'/package).glob('*.go'):
        if path.name.endswith('_test.go'):continue
        text=path.read_text()
        for name in packages:
            text=text.replace('"router-vpn/internal/'+name+'"','"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"')
        (target/path.name).write_text(text)
PY
python3 "$ROOT/deploy/prepare-mobile-amnezia.py" "$WORK/core"
(
 cd "$WORK/core"
 go mod tidy
 python3 "$ROOT/deploy/prepare-mobile-amnezia.py" --verify-dependency "$WORK/core"
 go test -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor -count=2 -timeout=120s -v ./protocol/routervpnamnezia -run 'TestNativeTun|TestActualAmnezia(EntryUDPReturn|NestedReturnBoundaries|ExitOverRetainedAmneziaEntry)$'
)
