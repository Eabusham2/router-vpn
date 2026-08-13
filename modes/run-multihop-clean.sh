#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
RUN="$ROOT/run/multihop"
child=''
cleanup(){
  status=$?
  trap - EXIT INT TERM HUP
  if [[ -n ${child:-} ]]; then
    kill -TERM "$child" >/dev/null 2>&1 || true
    wait "$child" >/dev/null 2>&1 || true
  fi
  HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" "$RUN" >/dev/null 2>&1 || true
  exit "$status"
}
forward(){
  sig=$1
  if [[ -n ${child:-} ]]; then kill -"$sig" "$child" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
trap 'forward INT' INT
trap 'forward TERM' TERM
trap 'forward HUP' HUP
bash "$SCRIPT_DIR/run-multihop.sh" "$@" &
child=$!
wait "$child"
status=$?
child=''
exit "$status"
