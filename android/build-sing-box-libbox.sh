#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=1.13.12
COMMIT=1086ab2563320e0da0c23b3a491d8dfa0939dff4
NDK_VERSION=28.0.13004108
VENDOR="$ROOT/.vendor/sing-box"
LIBDIR="$ROOT/app/libs"
AAR="$LIBDIR/libbox.aar"
STAMP="$LIBDIR/libbox.commit"
LICENSE_OUT="$LIBDIR/libbox-LICENSE.txt"

verify_aar() {
  test -s "$AAR"
  unzip -tq "$AAR" >/dev/null
  unzip -l "$AAR" | grep -q 'classes.jar' || { echo 'libbox AAR is missing classes.jar' >&2; return 1; }
  unzip -l "$AAR" | grep -Eq 'jni/(arm64-v8a|x86_64)/libbox\.so' || { echo 'libbox AAR is missing Android native libbox.so' >&2; return 1; }
}

if [[ -s "$AAR" && -f "$STAMP" && $(tr -d '\r\n' <"$STAMP") == "$COMMIT" ]]; then
  verify_aar
  printf 'Pinned sing-box libbox already built: %s (%s)\n' "$VERSION" "$COMMIT"
  exit 0
fi

command -v git >/dev/null || { echo 'git is required to build pinned sing-box libbox' >&2; exit 1; }
command -v go >/dev/null || { echo 'Go is required to build sing-box libbox (upstream requires Go 1.24.7+)' >&2; exit 1; }
command -v java >/dev/null || { echo 'Java 17 is required to build sing-box libbox' >&2; exit 1; }

SDKMANAGER="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}/cmdline-tools/latest/bin/sdkmanager"
if [[ ! -x "$SDKMANAGER" ]]; then
  echo 'Android sdkmanager was not found under ANDROID_HOME/ANDROID_SDK_ROOT' >&2
  exit 1
fi

yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
"$SDKMANAGER" "ndk;$NDK_VERSION" >/dev/null
export ANDROID_NDK_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT}}/ndk/$NDK_VERSION"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export GOTOOLCHAIN=auto

rm -rf "$VENDOR"
mkdir -p "$(dirname "$VENDOR")" "$LIBDIR"

clone_ok=0
for attempt in 1 2 3; do
  echo "Fetching sing-box $VERSION at pinned commit $COMMIT (attempt $attempt/3)..."
  rm -rf "$VENDOR"
  if git clone --filter=blob:none --no-checkout https://github.com/SagerNet/sing-box.git "$VENDOR" && \
     git -C "$VENDOR" fetch --depth 1 origin "$COMMIT" && \
     git -C "$VENDOR" checkout --detach FETCH_HEAD; then
    clone_ok=1
    break
  fi
  sleep $((attempt * 3))
done
[[ $clone_ok == 1 ]] || { echo 'Unable to fetch pinned sing-box source after 3 attempts' >&2; exit 1; }

ACTUAL=$(git -C "$VENDOR" rev-parse HEAD)
[[ "$ACTUAL" == "$COMMIT" ]] || { echo "sing-box source commit mismatch: expected $COMMIT got $ACTUAL" >&2; exit 1; }
# The official mobile builder reads the git tag to embed the version. The
# immutable commit above is the trust anchor; this local tag only makes the
# generated Libbox.version() report the matching release instead of unknown.
git -C "$VENDOR" tag -f "v$VERSION" "$COMMIT" >/dev/null

(
  cd "$VENDOR"
  go run ./cmd/internal/build_libbox -target android
)

SOURCE_AAR="$VENDOR/libbox.aar"
[[ -s "$SOURCE_AAR" ]] || { echo 'Pinned sing-box build did not produce libbox.aar' >&2; exit 1; }
install -m 0644 "$SOURCE_AAR" "$AAR"
install -m 0644 "$VENDOR/LICENSE" "$LICENSE_OUT"
printf '%s\n' "$COMMIT" >"$STAMP"
verify_aar
printf 'Built pinned sing-box libbox %s at %s\n' "$VERSION" "$COMMIT"
