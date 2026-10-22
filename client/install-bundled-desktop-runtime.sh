#!/usr/bin/env bash
# Promote the complete, verified Linux desktop engines without private state.
set -euo pipefail
SOURCE=${1:?source application root required}
DESTINATION=${2:?destination application root required}
[[ -d "$SOURCE" && ! -L "$SOURCE" && -d "$DESTINATION" && ! -L "$DESTINATION" ]] || { echo 'Unsafe application root' >&2; exit 1; }
SOURCE=$(cd "$SOURCE" && pwd -P)
DESTINATION=$(cd "$DESTINATION" && pwd -P)
[[ "$SOURCE" != "$DESTINATION" ]] || { echo 'Source and installation must differ' >&2; exit 1; }
[[ -d "$SOURCE/runtime" && ! -L "$SOURCE/runtime" && ! -L "$DESTINATION/runtime" ]] || { echo 'Unsafe runtime root' >&2; exit 1; }

verify() {
  "$SOURCE/router-vpn-client" --verify-native-runtime "$1" >/dev/null
  "$SOURCE/router-vpn-client" --verify-amnezia-runtime "$1" >/dev/null
  python3 "$SOURCE/client/verify-bundled-xray.py" "$1/runtime/xray" >/dev/null
}

verify "$SOURCE"
mkdir -p "$DESTINATION/runtime"
for engine in xray amnezia native; do
  [[ -d "$SOURCE/runtime/$engine" && ! -L "$SOURCE/runtime/$engine" && ! -L "$DESTINATION/runtime/$engine" ]] || { echo 'Unsafe packaged or installed runtime' >&2; exit 1; }
done

STAGE=$(mktemp -d "$DESTINATION/.runtime-install.XXXXXX")
mkdir -p "$STAGE/new/runtime" "$STAGE/previous"
promoted=()
committed=false
cleanup() {
  local result=$?
  if ! $committed; then
    for engine in "${promoted[@]}"; do
      rm -rf -- "$DESTINATION/runtime/$engine"
    done
    for engine in xray amnezia native; do
      if [[ -d "$STAGE/previous/$engine" ]]; then
        mv -- "$STAGE/previous/$engine" "$DESTINATION/runtime/$engine" || result=1
      fi
    done
  fi
  # A rollback failure keeps its previous bytes for recovery.
  if [[ -z "$(find "$STAGE/previous" -mindepth 1 -maxdepth 1 -print -quit)" ]] || $committed; then
    rm -rf -- "$STAGE"
  else
    echo "Previous runtime retained for recovery: $STAGE/previous" >&2
  fi
  return "$result"
}
trap cleanup EXIT
for engine in xray amnezia native; do
  cp -a -- "$SOURCE/runtime/$engine" "$STAGE/new/runtime/$engine"
done
verify "$STAGE/new"
for engine in xray amnezia native; do
  [[ ! -L "$DESTINATION/runtime/$engine" ]] || { echo 'Runtime destination changed during installation' >&2; exit 1; }
  if [[ -e "$DESTINATION/runtime/$engine" ]]; then
    mv -- "$DESTINATION/runtime/$engine" "$STAGE/previous/$engine"
  fi
  mv -- "$STAGE/new/runtime/$engine" "$DESTINATION/runtime/$engine"
  promoted+=("$engine")
done
verify "$DESTINATION"
committed=true
echo 'Installed verified Xray, AmneziaWG and complete native runtimes.'
