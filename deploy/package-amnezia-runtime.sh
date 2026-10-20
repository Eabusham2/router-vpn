#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=${1:?native target required}
PACKAGE=${2:?package staging directory required}
POLICY=$(python3 - "$ROOT" <<'PY'
from pathlib import Path
import importlib.util,sys
spec=importlib.util.spec_from_file_location('amnezia_build',Path(sys.argv[1])/'deploy/build-amnezia-runtime.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
print(module.digest())
PY
)
CACHE="$ROOT/dist/engines/amnezia/$POLICY/${TARGET//\//-}"
python3 "$ROOT/deploy/build-amnezia-runtime.py" "$TARGET" "$CACHE"
mkdir -p "$PACKAGE/runtime/amnezia"
cp -a "$CACHE/." "$PACKAGE/runtime/amnezia/"
