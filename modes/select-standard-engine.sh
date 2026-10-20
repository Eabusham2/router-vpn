#!/usr/bin/env bash
# This file is sourced by the owned native connection wrappers.
router_vpn_standard_engine() {
  case "${HOMEVPN_STANDARD_ENGINE:-stock}" in
    stock) command -v sing-box ;;
    native)
      local controller=${HOMEVPN_NATIVE_CONTROLLER:-} package=${HOMEVPN_NATIVE_PACKAGE:-} binary
      [[ -n "$controller" && -f "$controller" && ! -L "$controller" && -x "$controller" && -n "$package" ]] || {
        echo 'Captured native controller/package is missing or unsafe' >&2; return 1;
      }
      binary=$("$controller" --verify-native-runtime "$package") || return 1
      [[ -n "$binary" && "$binary" != *$'\n'* && -f "$binary" && ! -L "$binary" && -x "$binary" ]] || {
        echo 'Verified native engine is missing or unsafe' >&2; return 1;
      }
      printf '%s\n' "$binary"
      ;;
    amnezia)
      local controller=${HOMEVPN_AMNEZIA_CONTROLLER:-} package=${HOMEVPN_AMNEZIA_PACKAGE:-} binary
      [[ -n "$controller" && -f "$controller" && ! -L "$controller" && -x "$controller" && -n "$package" ]] || {
        echo 'Captured AmneziaWG controller/package is missing or unsafe' >&2; return 1;
      }
      binary=$("$controller" --verify-amnezia-runtime "$package") || return 1
      [[ -n "$binary" && "$binary" != *$'\n'* && -f "$binary" && ! -L "$binary" && -x "$binary" ]] || {
        echo 'Verified AmneziaWG engine is missing or unsafe' >&2; return 1;
      }
      printf '%s\n' "$binary"
      ;;
    *) echo 'Unknown captured standard-node engine' >&2; return 1 ;;
  esac
}
