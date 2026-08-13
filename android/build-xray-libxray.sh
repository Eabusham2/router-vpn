#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998
XRAY_VERSION=26.7.11
XRAY_COMMIT=50231eaff98c
MOBILE_VERSION=v0.0.0-20260709172247-6129f5bee9d5
NDK_VERSION=28.0.13004108
VENDOR="$ROOT/.vendor/libXray"
LIBDIR="$ROOT/app/libs"
AAR="$LIBDIR/libxray.aar"
STAMP="$LIBDIR/libxray.commit"
LICENSE_OUT="$LIBDIR/libxray-LICENSE.txt"

verify_aar() {
  test -s "$AAR"
  unzip -tq "$AAR" >/dev/null
  unzip -l "$AAR" | grep -q 'classes.jar' || { echo 'libXray AAR is missing classes.jar' >&2; return 1; }
  for abi in armeabi-v7a arm64-v8a x86 x86_64; do
    unzip -l "$AAR" | grep -q "jni/$abi/libgojni\\.so" || { echo "libXray AAR is missing jni/$abi/libgojni.so" >&2; return 1; }
  done
}

if [[ -s "$AAR" && -f "$STAMP" && $(tr -d '\r\n' <"$STAMP") == "$LIBXRAY_COMMIT" ]]; then
  verify_aar
  printf 'Pinned libXray already built: Xray %s (%s) wrapper %s\n' "$XRAY_VERSION" "$XRAY_COMMIT" "$LIBXRAY_COMMIT"
  exit 0
fi

command -v git >/dev/null || { echo 'git is required to build pinned libXray' >&2; exit 1; }
command -v go >/dev/null || { echo 'Go with toolchain download support is required to build pinned libXray' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is required to build pinned libXray' >&2; exit 1; }
command -v java >/dev/null || { echo 'Java 17 is required to build pinned libXray' >&2; exit 1; }

SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
if [[ -z "$SDK_ROOT" || ! -x "$SDKMANAGER" ]]; then
  echo 'Android sdkmanager was not found under ANDROID_HOME/ANDROID_SDK_ROOT' >&2
  exit 1
fi

yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
"$SDKMANAGER" "ndk;$NDK_VERSION" >/dev/null
export ANDROID_NDK_HOME="$SDK_ROOT/ndk/$NDK_VERSION"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export GOTOOLCHAIN=go1.26.3+auto
export PATH="$(go env GOPATH)/bin:$PATH"

rm -rf "$VENDOR"
mkdir -p "$(dirname "$VENDOR")" "$LIBDIR"
clone_ok=0
for attempt in 1 2 3; do
  echo "Fetching pinned libXray $LIBXRAY_COMMIT (attempt $attempt/3)..."
  rm -rf "$VENDOR"
  if git clone --filter=blob:none --no-checkout https://github.com/XTLS/libXray.git "$VENDOR" && \
     git -C "$VENDOR" fetch --depth 1 origin "$LIBXRAY_COMMIT" && \
     git -C "$VENDOR" checkout --detach FETCH_HEAD; then
    clone_ok=1
    break
  fi
  sleep $((attempt * 3))
done
[[ $clone_ok == 1 ]] || { echo 'Unable to fetch pinned libXray source after 3 attempts' >&2; exit 1; }
ACTUAL=$(git -C "$VENDOR" rev-parse HEAD)
[[ "$ACTUAL" == "$LIBXRAY_COMMIT" ]] || { echo "libXray source commit mismatch: expected $LIBXRAY_COMMIT got $ACTUAL" >&2; exit 1; }

grep -q 'github.com/xtls/xray-core v1.260327.1-0.20260711155151-50231eaff98c' "$VENDOR/go.mod" || {
  echo 'Pinned libXray no longer references the expected Xray-core v26.7.11 commit' >&2
  exit 1
}

# Upstream historical build.py resolved golang.org/x/mobile@latest. Replace only
# that moving resolver with the exact mobile revision current for this wrapper,
# while preserving the rest of the official Android build path.
python3 - "$VENDOR/build/app/build.py" "$MOBILE_VERSION" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
version = sys.argv[2]
text = path.read_text()
old = '''        result = subprocess.run(\n            [\n                "go",\n                "list",\n                "-m",\n                "-f",\n                "{{.Version}}",\n                "golang.org/x/mobile@latest",\n            ],\n            capture_output=True,\n            text=True,\n        )\n        version = result.stdout.strip()\n        if result.returncode != 0 or not version:\n            raise Exception("resolve latest gomobile version failed")\n'''
new = f'''        version = "{version}"\n'''
if old not in text:
    raise SystemExit('libXray gomobile resolver shape changed; refusing unreviewed build')
path.write_text(text.replace(old, new, 1))
PY

(
  cd "$VENDOR"
  python3 build/main.py android
)
SOURCE_AAR="$VENDOR/libXray.aar"
[[ -s "$SOURCE_AAR" ]] || { echo 'Pinned libXray build did not produce libXray.aar' >&2; exit 1; }
install -m 0644 "$SOURCE_AAR" "$AAR"
install -m 0644 "$VENDOR/LICENSE" "$LICENSE_OUT"
printf '%s\n' "$LIBXRAY_COMMIT" >"$STAMP"
verify_aar
printf 'Built pinned libXray wrapper %s with Xray-core %s (%s)\n' "$LIBXRAY_COMMIT" "$XRAY_VERSION" "$XRAY_COMMIT"
