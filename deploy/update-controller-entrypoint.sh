#!/bin/sh
set -eu

controller=''
auto=''

terminate() {
  [ -n "$auto" ] && kill -TERM "$auto" 2>/dev/null || true
  [ -n "$controller" ] && kill -TERM "$controller" 2>/dev/null || true
}
trap terminate INT TERM HUP

/usr/local/bin/router-vpn-update-controller &
controller=$!

case "${ROUTER_VPN_AUTO_UPDATE:-1}" in
  0|false|FALSE|no|NO|off|OFF|disabled|DISABLED)
    ;;
  *)
    /usr/local/bin/router-vpn-update-auto &
    auto=$!
    ;;
esac

set +e
wait "$controller"
rc=$?
set -e

[ -n "$auto" ] && kill -TERM "$auto" 2>/dev/null || true
[ -n "$auto" ] && wait "$auto" 2>/dev/null || true
exit "$rc"
