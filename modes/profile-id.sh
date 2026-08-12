#!/usr/bin/env bash
# Source this file; call homevpn_profile_id to validate HOMEVPN_PROFILE_ID.
homevpn_profile_id() {
  local raw=${HOMEVPN_PROFILE_ID:-router}
  [[ -n $raw && ${#raw} -le 64 ]] || { echo 'invalid Router VPN profile id' >&2; return 2; }
  case "$raw" in
    .|..|*..*|*/*|*\\*) echo 'invalid Router VPN profile id' >&2; return 2 ;;
  esac
  [[ $raw =~ ^[A-Za-z0-9_.-]+$ ]] || { echo 'invalid Router VPN profile id' >&2; return 2; }
  printf '%s\n' "$raw"
}
