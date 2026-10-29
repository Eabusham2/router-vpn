#!/usr/bin/env bash
set -euo pipefail

ACTION=${1:-}
RUNTIME_DIR=${2:-}
BRIDGE_ENDPOINT=${3:-}
SOCKS_PORT=${4:-}
TOR_BIN=${5:-}
NATIVE_BIN=${6:-}
ROOT=${HOMEVPN_ROOT:-/opt/router-vpn-client}
PROFILE_ID=${HOMEVPN_PROFILE_ID:-}
POLICY_PROFILE_ID=${HOMEVPN_POLICY_PROFILE_ID:-}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

[[ "$ACTION" == check || "$ACTION" == up || "$ACTION" == down ]] || { echo 'usage: native-tor-bridge.sh check|up|down RUNTIME_DIR BRIDGE_IP SOCKS_PORT TOR_BIN NATIVE_BIN' >&2; exit 2; }
[[ -n "$RUNTIME_DIR" && "$PROFILE_ID" =~ ^[A-Za-z0-9_-]{1,64}$ && "$POLICY_PROFILE_ID" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo 'Tor requires its captured private profiles' >&2; exit 2; }
[[ "$SOCKS_PORT" =~ ^[0-9]+$ ]] && (( SOCKS_PORT >= 1024 && SOCKS_PORT <= 65535 )) || { echo 'invalid captured Tor SOCKS port' >&2; exit 2; }
[[ ${HOMEVPN_STANDARD_ENGINE:-} == native && ${HOMEVPN_TOR_SESSION:-} =~ ^[a-f0-9]{32}$ ]] || { echo 'Tor requires its captured native session' >&2; exit 2; }
for field in HOMEVPN_TOR_SOURCE_SHA256 HOMEVPN_TOR_PROFILE_SHA256 HOMEVPN_TOR_CAPTURE_SHA256 HOMEVPN_TOR_TORRC_SHA256 HOMEVPN_TOR_DEFAULTS_SHA256 HOMEVPN_TOR_CONFIG_SHA256; do
  [[ ${!field:-} =~ ^[a-f0-9]{64}$ ]] || { echo 'Tor launch is missing an exact input digest' >&2; exit 2; }
done
# Disconnect has already requested and checked native drain. The controller
# retains the exact private directory handle and performs all final cleanup.
if [[ "$ACTION" == down ]]; then exit 0; fi

# This trap exists only in the un-replaced wrapper. A successful exec discards
# it, so neither a running native child nor its crash can receive a no-work
# witness. Signal exits remain ambiguous and retain the controller's owner.
tor_prelaunch_failed() {
  local result=${1:-$?}
  trap - EXIT
  if (( result > 0 && result < 128 )) && [[ -f "$SCRIPT_DIR/tor-prelaunch-witness.py" && ! -L "$SCRIPT_DIR/tor-prelaunch-witness.py" ]]; then
    HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/tor-prelaunch-witness.py" "$RUNTIME_DIR" >/dev/null 2>&1 || :
  fi
  exit "$result"
}
if [[ "$ACTION" == up ]]; then trap tor_prelaunch_failed EXIT; fi

for helper in cleanup-private-runtime.py tor-prelaunch-witness.py select-standard-engine.sh kill-switch-platform.py; do
  [[ -f "$SCRIPT_DIR/$helper" && ! -L "$SCRIPT_DIR/$helper" ]] || { echo 'Tor native safety helper is missing or unsafe' >&2; exit 1; }
done
RUNTIME_DIR=$(HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/cleanup-private-runtime.py" verify-dir "$RUNTIME_DIR") || { echo 'Tor private runtime directory is unsafe' >&2; exit 1; }
for input in torrc tor-defaults tor-profile.json tor-capture.json sing-box.json; do
  [[ -f "$RUNTIME_DIR/$input" && ! -L "$RUNTIME_DIR/$input" ]] || { echo 'captured Tor native input is missing or unsafe' >&2; exit 1; }
done
if [[ -n "$TOR_BIN" ]]; then
  [[ "$TOR_BIN" == /* && -f "$TOR_BIN" && ! -L "$TOR_BIN" && -x "$TOR_BIN" ]] || { echo 'captured standalone Tor executable is missing or unsafe' >&2; exit 1; }
fi
export HOMEVPN_ENDPOINT=${HOMEVPN_ENDPOINT:-$BRIDGE_ENDPOINT}
HOMEVPN_ROOT="$ROOT" python3 "$SCRIPT_DIR/tor-prelaunch-witness.py" --validate "$RUNTIME_DIR" "$BRIDGE_ENDPOINT" "$TOR_BIN" || { echo 'Tor launch differs from its captured physical policy' >&2; exit 1; }
source "$SCRIPT_DIR/select-standard-engine.sh"
VERIFIED_NATIVE=$(router_vpn_standard_engine) || { echo 'Tor native engine failed its complete package verification' >&2; exit 1; }
[[ "$VERIFIED_NATIVE" == "$NATIVE_BIN" && -f "$NATIVE_BIN" && ! -L "$NATIVE_BIN" && -x "$NATIVE_BIN" ]] || { echo 'Tor native engine changed after capture' >&2; exit 1; }
"$NATIVE_BIN" routervpn-tor --help >/dev/null
"$NATIVE_BIN" check -D "$RUNTIME_DIR" -c "$RUNTIME_DIR/sing-box.json" >/dev/null
if [[ "$ACTION" == check ]]; then exit 0; fi

# Install the captured client protection before the native TUN or Tor starts.
# Fixed Darwin captures retain their established route watcher. Dynamic
# captures use only the native guardian's retained actual utun descriptor.
# A dynamic Direct Unix capture installs only the deny baseline here. Its
# native Initialize factory later starts the privileged socket guardian, whose
# exact isolated-UID/full-tuple permits never become host-wide exemptions.
HOMEVPN_ROOT="$ROOT" HOMEVPN_PROFILE_ID="$PROFILE_ID" HOMEVPN_POLICY_PROFILE_ID="$POLICY_PROFILE_ID" HOMEVPN_ENDPOINT="$HOMEVPN_ENDPOINT" \
  python3 "$SCRIPT_DIR/kill-switch-platform.py" apply

# The native command replaces this shell, so the controller owns and joins the
# actual native process. Local owns its disabled Tor child and authenticated
# control; Server owns the exact private Router lease without a local Tor child.
# Both start/prove the selected TUN/DNS path and publish captured receipts.
# No external PT process or log marker
# can substitute for bootstrap/proof; no asynchronous trap deletes a pathname.
# exec can discard EXIT traps even when replacement fails. Only its failure
# return can take the explicit no-work branch; successful exec never returns.
# Bash's errexit can still exit inside this special builtin, so handle its
# failure explicitly after every required preflight/protection check passed.
shopt -s execfail
set +e
if [[ -n "$TOR_BIN" ]]; then
  exec "$NATIVE_BIN" routervpn-tor --runtime-dir "$RUNTIME_DIR" --session "$HOMEVPN_TOR_SESSION" --tor-binary "$TOR_BIN" || tor_prelaunch_failed "$?"
else
  exec "$NATIVE_BIN" routervpn-tor --runtime-dir "$RUNTIME_DIR" --session "$HOMEVPN_TOR_SESSION" || tor_prelaunch_failed "$?"
fi
