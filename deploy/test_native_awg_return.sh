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
packages=('awgpolicy','routechoice','multihoprelay','mobilemultihop', 'applexray','startwhitening')
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
 # On ARM64, prove that the original dependency fails the direct regression.
 # Restore the owned copy even on compiler/test errors; never edit module cache.
 python3 - "$ROOT" "$WORK/core" <<'PYPROOF'
from pathlib import Path
import importlib.util
import subprocess
import sys
source, core = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('scheduler_proof', source/'deploy/prepare-gvisor-scheduler.py')
SCHEDULER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SCHEDULER)
if subprocess.check_output(['go', 'env', 'GOARCH'], text=True).strip() == 'arm64':
    path = core/SCHEDULER.COPY/SCHEDULER.ASSEMBLY
    fixed = path.read_bytes()
    try:
        path.write_bytes(SCHEDULER.original(fixed))
        control = subprocess.run(['go', 'test', '-race', '-ldflags=-checklinkname=0', '-tags', 'with_wireguard,with_gvisor', '-count=1', '-timeout=20s', './protocol/routervpnamnezia', '-run', '^TestNativeTunSchedulerAtomicCAS$'], cwd=core, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    finally:
        path.write_bytes(fixed)
    if control.returncode != 1 or 'scheduler CAS failed to install replacement' not in control.stdout:
        print(control.stdout)
        raise SystemExit('Original ARM64 scheduler did not fail the expected atomic regression')
    print('Verified ARM64 negative control: original pinned scheduler fails the atomic regression')
SCHEDULER.verify(core)
PYPROOF
 result=0
 go test -cpuprofile="$WORK/awg.cpu" -race -ldflags=-checklinkname=0 -tags with_wireguard,with_gvisor -count=2 -timeout=120s -v ./protocol/routervpnamnezia -run 'TestNativeTun|TestActualAmnezia(EntryUDPReturn|NestedReturnBoundaries|ExitOverRetainedAmneziaEntry)$' || result=$?
 # Function-level CPU attribution contains no generated keys or packet data.
 # Preserve the test's failure status; diagnostics can never make it pass.
 if [[ -s "$WORK/awg.cpu" ]]; then
   go tool pprof -top -nodecount=20 "$WORK/awg.cpu" || true
 fi
 exit "$result"
)
