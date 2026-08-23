#!/bin/sh
set -eu

# Router VPN's ASUS integration is intentionally narrow and fail-open for
# ordinary household traffic.  It never changes built-in policies, never
# flushes built-in chains, never installs DROP/REJECT rules, and never touches
# IPv6.  Every IPv4 rule it owns is attached directly to the parent chain with
# WAN interface + protocol + exact destination-port scope.

JFFS_DIR=${ROUTER_VPN_JFFS_DIR:-/jffs/scripts}
RUNTIME="$JFFS_DIR/router-vpn-forward.sh"
CONFIG="$JFFS_DIR/router-vpn-forward.conf"
NAT_START="$JFFS_DIR/nat-start"
FIREWALL_START="$JFFS_DIR/firewall-start"
TAG=ROUTER_VPN
SELF=$0

[ ! -f "$CONFIG" ] || . "$CONFIG"

DST=${ROUTER_VPN_HOST:-192.168.50.133}
WG_PORT=${WG_PORT:-51820}
AWG_PORT=${AWG_PORT:-585}
ROSENPASS_PORT=${ROSENPASS_PORT:-51822}
REALITY_PORT=${REALITY_PORT:-443}
HY2_PORT=${HY2_PORT:-8443}
SS_PORT=${SS_PORT:-8388}
XRAY_PQ_PORT=${XRAY_PQ_PORT:-10443}
XHTTP_PORT=${XHTTP_PORT:-11443}
SS_V2RAY_PORT=${SS_V2RAY_PORT:-12443}
NAIVE_PORT=${NAIVE_PORT:-13443}
OVERTLS_PORT=${OVERTLS_PORT:-14443}
SSR_PORT=${SSR_PORT:-15443}
ACME_EXTERNAL_PORT=${ACME_EXTERNAL_PORT:-80}
ACME_INTERNAL_PORT=${ACME_INTERNAL_PORT:-18080}
ROUTER_VPN_WAN_INTERFACE=${ROUTER_VPN_WAN_INTERFACE:-}
ROUTER_VPN_HEALTH_PORT=${ROUTER_VPN_HEALTH_PORT:-8786}
ROUTER_VPN_HEALTH_PATH=${ROUTER_VPN_HEALTH_PATH:-/healthz}

IPTABLES=${ROUTER_VPN_IPTABLES:-}

say(){ printf '%s\n' "$*"; }
warn(){ printf 'WARNING: %s\n' "$*" >&2; }
fail(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
invalid(){ printf 'ERROR: %s\n' "$*" >&2; return 1; }

validate_port(){
  NAME=$1; VALUE=$2
  case "$VALUE" in
    ''|*[!0-9]*) invalid "$NAME must be a numeric TCP/UDP port."; return 1 ;;
  esac
  [ "$VALUE" -ge 1 ] && [ "$VALUE" -le 65535 ] || { invalid "$NAME must be between 1 and 65535."; return 1; }
}

validate_settings(){
  case "$DST" in
    ''|*[!0-9.]*) invalid 'ROUTER_VPN_HOST must be a literal IPv4 address.'; return 1 ;;
  esac
  if [ -n "$ROUTER_VPN_WAN_INTERFACE" ]; then
    case "$ROUTER_VPN_WAN_INTERFACE" in
      *[!A-Za-z0-9._:-]*) invalid 'ROUTER_VPN_WAN_INTERFACE contains unsupported characters.'; return 1 ;;
    esac
  fi
  case "$ROUTER_VPN_HEALTH_PATH" in
    /*) : ;;
    *) invalid 'ROUTER_VPN_HEALTH_PATH must begin with /.'; return 1 ;;
  esac
  case "$ROUTER_VPN_HEALTH_PATH" in
    *[!A-Za-z0-9._~/?=%:-]*) invalid 'ROUTER_VPN_HEALTH_PATH contains unsupported characters.'; return 1 ;;
  esac
  validate_port WG_PORT "$WG_PORT" || return 1
  validate_port AWG_PORT "$AWG_PORT" || return 1
  validate_port ROSENPASS_PORT "$ROSENPASS_PORT" || return 1
  validate_port REALITY_PORT "$REALITY_PORT" || return 1
  validate_port HY2_PORT "$HY2_PORT" || return 1
  validate_port SS_PORT "$SS_PORT" || return 1
  validate_port XRAY_PQ_PORT "$XRAY_PQ_PORT" || return 1
  validate_port XHTTP_PORT "$XHTTP_PORT" || return 1
  validate_port SS_V2RAY_PORT "$SS_V2RAY_PORT" || return 1
  validate_port NAIVE_PORT "$NAIVE_PORT" || return 1
  validate_port OVERTLS_PORT "$OVERTLS_PORT" || return 1
  validate_port SSR_PORT "$SSR_PORT" || return 1
  validate_port ACME_EXTERNAL_PORT "$ACME_EXTERNAL_PORT" || return 1
  validate_port ACME_INTERNAL_PORT "$ACME_INTERNAL_PORT" || return 1
  validate_port ROUTER_VPN_HEALTH_PORT "$ROUTER_VPN_HEALTH_PORT" || return 1
}

resolve_iptables(){
  [ -n "$IPTABLES" ] || {
    if [ -x /usr/sbin/iptables ]; then IPTABLES=/usr/sbin/iptables
    else IPTABLES=$(command -v iptables 2>/dev/null || true)
    fi
  }
  [ -n "$IPTABLES" ] && [ -x "$IPTABLES" ] || fail 'iptables is unavailable on this router.'
}

need_router(){
  if [ "$JFFS_DIR" = /jffs/scripts ]; then
    [ -d /jffs ] || fail 'This installer must run on the ASUS Asuswrt-Merlin router.'
  else
    [ -d "$JFFS_DIR" ] || mkdir -p "$JFFS_DIR"
  fi
  resolve_iptables
  "$IPTABLES" -m comment -h >/dev/null 2>&1 || fail 'iptables comment match is required so Router VPN can own/remove only its own rules.'
  "$IPTABLES" -m state -h >/dev/null 2>&1 || fail 'iptables state match is required for narrow NEW-only Router VPN forwarding.'
}

wan_if(){
  if [ -n "$ROUTER_VPN_WAN_INTERFACE" ]; then
    printf '%s\n' "$ROUTER_VPN_WAN_INTERFACE"
    return
  fi
  IF=$(ip route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
  [ -n "$IF" ] || IF=$(nvram get wan0_gw_ifname 2>/dev/null || true)
  [ -n "$IF" ] || IF=$(nvram get wan0_ifname 2>/dev/null || true)
  [ -n "$IF" ] || fail 'Could not determine the WAN interface. Set ROUTER_VPN_WAN_INTERFACE and rerun.'
  printf '%s\n' "$IF"
}

health_ok(){
  URL="http://$DST:$ROUTER_VPN_HEALTH_PORT$ROUTER_VPN_HEALTH_PATH"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --connect-timeout 1 --max-time 1 "$URL" >/dev/null 2>&1
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -T 1 -O /dev/null "$URL" >/dev/null 2>&1
    return $?
  fi
  return 1
}

require_health(){
  if health_ok; then return 0; fi
  warn "Router VPN health check failed at http://$DST:$ROUTER_VPN_HEALTH_PORT$ROUTER_VPN_HEALTH_PATH; no new WAN exposure was installed."
  return 1
}

preflight_port_conflicts(){
  WAN=$1
  RULES=$("$IPTABLES" -t nat -S PREROUTING 2>/dev/null || true)
  for SPEC in \
    "tcp:$ACME_EXTERNAL_PORT" "tcp:$REALITY_PORT" "udp:$AWG_PORT" \
    "tcp:$SS_PORT" "udp:$SS_PORT" "udp:$HY2_PORT" \
    "tcp:$XRAY_PQ_PORT" "tcp:$XHTTP_PORT" "tcp:$SS_V2RAY_PORT" \
    "tcp:$NAIVE_PORT" "udp:$NAIVE_PORT" "tcp:$OVERTLS_PORT" \
    "tcp:$SSR_PORT" "udp:$SSR_PORT" "udp:$WG_PORT" "udp:$ROSENPASS_PORT"
  do
    PROTO=${SPEC%%:*}; PORT=${SPEC#*:}
    if printf '%s\n' "$RULES" | grep -F -- "-i $WAN" | grep -F -- "-p $PROTO" | grep -F -- "--dport $PORT" | grep -F -- '-j DNAT' | grep -v -F -- "--comment $TAG" >/dev/null 2>&1; then
      warn "Existing non-Router-VPN DNAT owns $PROTO/$PORT; refusing to compete with or reorder that ASUS/add-on forward."
      return 1
    fi
  done
  return 0
}

ensure_nat(){
  WAN=$1 PROTO=$2 EXT=$3 INT=$4
  if ! "$IPTABLES" -t nat -C PREROUTING -i "$WAN" -p "$PROTO" --dport "$EXT" -m comment --comment "$TAG" -j DNAT --to-destination "$DST:$INT" >/dev/null 2>&1; then
    "$IPTABLES" -t nat -A PREROUTING -i "$WAN" -p "$PROTO" --dport "$EXT" -m comment --comment "$TAG" -j DNAT --to-destination "$DST:$INT"
  fi
}

ensure_fwd(){
  WAN=$1 PROTO=$2 PORT=$3
  if ! "$IPTABLES" -C FORWARD -i "$WAN" -d "$DST" -p "$PROTO" --dport "$PORT" -m state --state NEW -m comment --comment "$TAG" -j ACCEPT >/dev/null 2>&1; then
    "$IPTABLES" -A FORWARD -i "$WAN" -d "$DST" -p "$PROTO" --dport "$PORT" -m state --state NEW -m comment --comment "$TAG" -j ACCEPT
  fi
}

remove_owned_from_chain(){
  TABLE=$1 CHAIN=$2
  "$IPTABLES" -t "$TABLE" -S "$CHAIN" 2>/dev/null | grep -F -- "--comment $TAG" | while IFS= read -r RULE; do
    [ -n "$RULE" ] || continue
    case "$RULE" in
      "-A $CHAIN "*) SPEC=$(printf '%s\n' "$RULE" | sed "s/^-A $CHAIN //") ;;
      *) continue ;;
    esac
    "$IPTABLES" -t "$TABLE" -D "$CHAIN" $SPEC >/dev/null 2>&1 || true
  done
}

remove_legacy_chains(){
  "$IPTABLES" -t nat -S PREROUTING 2>/dev/null | grep -F -- '-j ROUTER_VPN_DNAT' | while IFS= read -r RULE; do
    SPEC=${RULE#-A PREROUTING }
    "$IPTABLES" -t nat -D PREROUTING $SPEC >/dev/null 2>&1 || true
  done
  "$IPTABLES" -S FORWARD 2>/dev/null | grep -F -- '-j ROUTER_VPN_FWD' | while IFS= read -r RULE; do
    SPEC=${RULE#-A FORWARD }
    "$IPTABLES" -D FORWARD $SPEC >/dev/null 2>&1 || true
  done
  "$IPTABLES" -t nat -F ROUTER_VPN_DNAT >/dev/null 2>&1 || true
  "$IPTABLES" -t nat -X ROUTER_VPN_DNAT >/dev/null 2>&1 || true
  "$IPTABLES" -F ROUTER_VPN_FWD >/dev/null 2>&1 || true
  "$IPTABLES" -X ROUTER_VPN_FWD >/dev/null 2>&1 || true
}

remove_rules(){
  need_router
  remove_owned_from_chain nat PREROUTING
  remove_owned_from_chain filter FORWARD
  remove_legacy_chains
}

apply_nat(){
  need_router
  if ! validate_settings; then
    remove_owned_from_chain nat PREROUTING
    warn 'Invalid Router VPN forwarding configuration; Router VPN NAT exposure was removed while ordinary Internet rules were left untouched.'
    return 1
  fi
  WAN=$(wan_if)
  if [ "${ROUTER_VPN_PREFLIGHT_DONE:-0}" != 1; then
    if ! require_health || ! preflight_port_conflicts "$WAN"; then
      remove_owned_from_chain nat PREROUTING
      return 1
    fi
  fi
  if ! {
    ensure_nat "$WAN" tcp "$ACME_EXTERNAL_PORT" "$ACME_INTERNAL_PORT" &&
    ensure_nat "$WAN" tcp "$REALITY_PORT" "$REALITY_PORT" &&
    ensure_nat "$WAN" udp "$AWG_PORT" "$AWG_PORT" &&
    ensure_nat "$WAN" tcp "$SS_PORT" "$SS_PORT" &&
    ensure_nat "$WAN" udp "$SS_PORT" "$SS_PORT" &&
    ensure_nat "$WAN" udp "$HY2_PORT" "$HY2_PORT" &&
    ensure_nat "$WAN" tcp "$XRAY_PQ_PORT" "$XRAY_PQ_PORT" &&
    ensure_nat "$WAN" tcp "$XHTTP_PORT" "$XHTTP_PORT" &&
    ensure_nat "$WAN" tcp "$SS_V2RAY_PORT" "$SS_V2RAY_PORT" &&
    ensure_nat "$WAN" tcp "$NAIVE_PORT" "$NAIVE_PORT" &&
    ensure_nat "$WAN" udp "$NAIVE_PORT" "$NAIVE_PORT" &&
    ensure_nat "$WAN" tcp "$OVERTLS_PORT" "$OVERTLS_PORT" &&
    ensure_nat "$WAN" tcp "$SSR_PORT" "$SSR_PORT" &&
    ensure_nat "$WAN" udp "$SSR_PORT" "$SSR_PORT" &&
    ensure_nat "$WAN" udp "$WG_PORT" "$WG_PORT" &&
    ensure_nat "$WAN" udp "$ROSENPASS_PORT" "$ROSENPASS_PORT";
  }; then
    remove_owned_from_chain nat PREROUTING
    warn 'A Router VPN NAT rule could not be installed; all Router VPN NAT exposure was removed. Ordinary LAN/WAN forwarding was untouched.'
    return 1
  fi
  say "Router VPN narrow NAT forwards active on $WAN -> $DST"
}

apply_filter(){
  need_router
  if ! validate_settings; then
    remove_owned_from_chain filter FORWARD
    warn 'Invalid Router VPN forwarding configuration; Router VPN FORWARD exposure was removed while ordinary Internet rules were left untouched.'
    return 1
  fi
  WAN=$(wan_if)
  if [ "${ROUTER_VPN_PREFLIGHT_DONE:-0}" != 1; then
    if ! require_health || ! preflight_port_conflicts "$WAN"; then
      remove_owned_from_chain filter FORWARD
      return 1
    fi
  fi
  if ! {
    ensure_fwd "$WAN" tcp "$ACME_INTERNAL_PORT" &&
    ensure_fwd "$WAN" tcp "$REALITY_PORT" &&
    ensure_fwd "$WAN" udp "$AWG_PORT" &&
    ensure_fwd "$WAN" tcp "$SS_PORT" &&
    ensure_fwd "$WAN" udp "$SS_PORT" &&
    ensure_fwd "$WAN" udp "$HY2_PORT" &&
    ensure_fwd "$WAN" tcp "$XRAY_PQ_PORT" &&
    ensure_fwd "$WAN" tcp "$XHTTP_PORT" &&
    ensure_fwd "$WAN" tcp "$SS_V2RAY_PORT" &&
    ensure_fwd "$WAN" tcp "$NAIVE_PORT" &&
    ensure_fwd "$WAN" udp "$NAIVE_PORT" &&
    ensure_fwd "$WAN" tcp "$OVERTLS_PORT" &&
    ensure_fwd "$WAN" tcp "$SSR_PORT" &&
    ensure_fwd "$WAN" udp "$SSR_PORT" &&
    ensure_fwd "$WAN" udp "$WG_PORT" &&
    ensure_fwd "$WAN" udp "$ROSENPASS_PORT";
  }; then
    remove_owned_from_chain filter FORWARD
    warn 'A Router VPN FORWARD rule could not be installed; all Router VPN FORWARD exposure was removed. Ordinary LAN/WAN forwarding was untouched.'
    return 1
  fi
  say "Router VPN narrow NEW-only FORWARD rules active on $WAN -> $DST"
}

apply_all(){
  need_router
  if ! validate_settings; then
    remove_owned_from_chain nat PREROUTING
    remove_owned_from_chain filter FORWARD
    warn 'Invalid Router VPN forwarding configuration; all Router VPN WAN exposure was removed. Ordinary Internet rules were untouched.'
    return 1
  fi
  WAN=$(wan_if)
  if ! require_health || ! preflight_port_conflicts "$WAN"; then
    remove_owned_from_chain nat PREROUTING
    remove_owned_from_chain filter FORWARD
    return 1
  fi
  remove_legacy_chains
  ROUTER_VPN_PREFLIGHT_DONE=1
  export ROUTER_VPN_PREFLIGHT_DONE
  if ! apply_nat || ! apply_filter; then
    remove_owned_from_chain nat PREROUTING
    remove_owned_from_chain filter FORWARD
    warn 'Router VPN apply failed closed for its own inbound services; ordinary household Internet rules were untouched.'
    return 1
  fi
  verify
}

write_hook(){
  FILE=$1 LINE=$2
  LINE="$LINE || true"
  [ -f "$FILE" ] || printf '#!/bin/sh\n' > "$FILE"
  grep -Fqx "$LINE" "$FILE" 2>/dev/null || printf '%s\n' "$LINE" >> "$FILE"
  chmod 755 "$FILE"
}

remove_hook_lines(){
  FILE=$1
  [ -f "$FILE" ] || return 0
  for LINE in \
    "$RUNTIME apply-nat" \
    "$RUNTIME apply-filter" \
    "$RUNTIME apply" \
    '/jffs/scripts/router-vpn-forward.sh apply-nat' \
    '/jffs/scripts/router-vpn-forward.sh apply-filter' \
    '/jffs/scripts/router-vpn-forward.sh apply' \
    '/jffs/scripts/router-vpn-forward.sh nat' \
    '/jffs/scripts/router-vpn-forward.sh filter "$1"'
  do
    TMP="$FILE.router-vpn.$$"
    grep -Fvx -- "$LINE" "$FILE" > "$TMP" || true
    cat "$TMP" > "$FILE"
    rm -f "$TMP"
    GUARDED_LINE="$LINE || true"
    TMP="$FILE.router-vpn.$$"
    grep -Fvx -- "$GUARDED_LINE" "$FILE" > "$TMP" || true
    cat "$TMP" > "$FILE"
    rm -f "$TMP"
  done
  chmod 755 "$FILE"
}

write_saved(){
  NAME=$1 VALUE=$2
  printf ': "${%s:=%s}"\n' "$NAME" "$VALUE" >> "$CONFIG"
}

write_config(){
  validate_settings || return 1
  : > "$CONFIG"
  printf '%s\n' '# Generated by router-vpn. Public forwarding settings only; no VPN keys/tokens.' >> "$CONFIG"
  write_saved ROUTER_VPN_HOST "$DST"
  write_saved ROUTER_VPN_WAN_INTERFACE "$ROUTER_VPN_WAN_INTERFACE"
  write_saved ROUTER_VPN_HEALTH_PORT "$ROUTER_VPN_HEALTH_PORT"
  write_saved ROUTER_VPN_HEALTH_PATH "$ROUTER_VPN_HEALTH_PATH"
  write_saved WG_PORT "$WG_PORT"
  write_saved AWG_PORT "$AWG_PORT"
  write_saved ROSENPASS_PORT "$ROSENPASS_PORT"
  write_saved REALITY_PORT "$REALITY_PORT"
  write_saved HY2_PORT "$HY2_PORT"
  write_saved SS_PORT "$SS_PORT"
  write_saved XRAY_PQ_PORT "$XRAY_PQ_PORT"
  write_saved XHTTP_PORT "$XHTTP_PORT"
  write_saved SS_V2RAY_PORT "$SS_V2RAY_PORT"
  write_saved NAIVE_PORT "$NAIVE_PORT"
  write_saved OVERTLS_PORT "$OVERTLS_PORT"
  write_saved SSR_PORT "$SSR_PORT"
  write_saved ACME_EXTERNAL_PORT "$ACME_EXTERNAL_PORT"
  write_saved ACME_INTERNAL_PORT "$ACME_INTERNAL_PORT"
  chmod 600 "$CONFIG"
}

install(){
  need_router
  validate_settings || { remove_owned_from_chain nat PREROUTING; remove_owned_from_chain filter FORWARD; return 1; }
  mkdir -p "$JFFS_DIR"
  remove_rules
  if [ "$SELF" != "$RUNTIME" ]; then cp "$SELF" "$RUNTIME"; fi
  chmod 755 "$RUNTIME"
  write_config
  remove_hook_lines "$NAT_START"
  remove_hook_lines "$FIREWALL_START"
  write_hook "$NAT_START" "$RUNTIME apply"
  write_hook "$FIREWALL_START" "$RUNTIME apply"
  if [ "${ROUTER_VPN_SKIP_NVRAM:-0}" != 1 ]; then
    nvram set jffs2_scripts=1
    nvram commit
  fi
  if "$RUNTIME" apply; then
    say 'Persistent narrow Merlin hooks installed. Existing nat-start/firewall-start content was preserved.'
    say "Saved forwarding overrides: $CONFIG"
  else
    warn 'Helper/hooks were installed, but Router VPN WAN exposure remains unavailable until the private health check succeeds.'
    return 1
  fi
}

remove(){
  remove_rules
  remove_hook_lines "$NAT_START"
  remove_hook_lines "$FIREWALL_START"
  say 'Router VPN-owned forwarding rules/hooks removed. Helper/config were preserved for manual apply/reinstall; every unrelated JFFS line and ASUS firewall rule was preserved.'
}

uninstall(){
  remove
  rm -f "$RUNTIME" "$CONFIG"
  say 'Router VPN forwarding helper/config uninstalled.'
}

status(){
  need_router
  validate_settings || return 1
  WAN=$(wan_if)
  say "WAN interface: $WAN"
  say "Destination:   $DST"
  if health_ok; then say 'Private health: OK'; else say 'Private health: UNAVAILABLE (normal household Internet is unaffected)'; fi
  say 'Expected external -> internal mapping:'
  printf 'TCP      %-7s -> %s\n' "$ACME_EXTERNAL_PORT" "$ACME_INTERNAL_PORT"
  printf 'TCP      %-7s -> %s\n' "$REALITY_PORT" "$REALITY_PORT"
  printf 'UDP      %-7s -> %s\n' "$AWG_PORT" "$AWG_PORT"
  printf 'TCP+UDP  %-7s -> %s\n' "$SS_PORT" "$SS_PORT"
  printf 'UDP      %-7s -> %s\n' "$HY2_PORT" "$HY2_PORT"
  printf 'TCP      %-7s -> %s\n' "$XRAY_PQ_PORT" "$XRAY_PQ_PORT"
  printf 'TCP      %-7s -> %s\n' "$XHTTP_PORT" "$XHTTP_PORT"
  printf 'TCP      %-7s -> %s\n' "$SS_V2RAY_PORT" "$SS_V2RAY_PORT"
  printf 'TCP+UDP  %-7s -> %s\n' "$NAIVE_PORT" "$NAIVE_PORT"
  printf 'TCP      %-7s -> %s\n' "$OVERTLS_PORT" "$OVERTLS_PORT"
  printf 'TCP+UDP  %-7s -> %s\n' "$SSR_PORT" "$SSR_PORT"
  printf 'UDP      %-7s -> %s\n' "$WG_PORT" "$WG_PORT"
  printf 'UDP      %-7s -> %s\n' "$ROSENPASS_PORT" "$ROSENPASS_PORT"
  say 'OverTLS loopback backend 14444 is never WAN-forwarded.'
  say 'Never exposed by this script: 22/53, 1080, 3000, 8786-8793, 9443, 14444, 45999, SSH, Portainer, AdGuard admin.'
  [ ! -f "$CONFIG" ] || say "Persistent settings: $CONFIG"
  say '--- Router-VPN-owned NAT rules ---'
  "$IPTABLES" -t nat -S PREROUTING 2>/dev/null | grep -F -- "--comment $TAG" || say 'No Router VPN NAT rules installed.'
  say '--- Router-VPN-owned FORWARD rules ---'
  "$IPTABLES" -S FORWARD 2>/dev/null | grep -F -- "--comment $TAG" || say 'No Router VPN FORWARD rules installed.'
}

verify(){
  need_router
  validate_settings || return 1
  WAN=$(wan_if)
  ERR=0
  NAT_RULES=$($IPTABLES -t nat -S PREROUTING 2>/dev/null || true)
  FWD_RULES=$($IPTABLES -S FORWARD 2>/dev/null || true)
  if printf '%s\n' "$NAT_RULES" | grep -F -- '-j ROUTER_VPN_DNAT' >/dev/null 2>&1; then warn 'broad legacy PREROUTING -> ROUTER_VPN_DNAT catch-all still exists'; ERR=1; fi
  if printf '%s\n' "$FWD_RULES" | grep -F -- '-j ROUTER_VPN_FWD' >/dev/null 2>&1; then warn 'broad legacy FORWARD -> ROUTER_VPN_FWD catch-all still exists'; ERR=1; fi
  NAT_OWNED=$(printf '%s\n' "$NAT_RULES" | grep -F -- "--comment $TAG" || true)
  FWD_OWNED=$(printf '%s\n' "$FWD_RULES" | grep -F -- "--comment $TAG" || true)
  if printf '%s\n%s\n' "$NAT_OWNED" "$FWD_OWNED" | grep -E -- ' -j (DROP|REJECT)( |$)|(^| )-P( |$)| -s 192\.168\.50\.| -o ' >/dev/null 2>&1; then warn 'Router VPN-owned rule escaped narrow inbound-only scope'; ERR=1; fi
  if printf '%s\n' "$NAT_OWNED" | grep -v '^$' | grep -v -F -- "-i $WAN" >/dev/null 2>&1; then warn 'Router VPN NAT rule lost WAN-interface scope'; ERR=1; fi
  if printf '%s\n' "$FWD_OWNED" | grep -v '^$' | grep -v -F -- "-i $WAN -d $DST" >/dev/null 2>&1; then warn 'Router VPN FORWARD rule lost WAN/destination scope'; ERR=1; fi
  if printf '%s\n' "$FWD_OWNED" | grep -v '^$' | grep -v -F -- '--state NEW' >/dev/null 2>&1; then warn 'Router VPN FORWARD rule is not NEW-only'; ERR=1; fi
  for PORT in 22 53 1080 3000 8786 8787 8788 8789 8790 8791 8792 8793 9443 14444 18080 45999; do
    if printf '%s\n' "$NAT_OWNED" | grep -E -- "--dport $PORT( |$)" >/dev/null 2>&1; then warn "forbidden/private WAN destination port $PORT is exposed"; ERR=1; fi
  done
  APPROVED=" $ACME_EXTERNAL_PORT $REALITY_PORT $AWG_PORT $SS_PORT $HY2_PORT $XRAY_PQ_PORT $XHTTP_PORT $SS_V2RAY_PORT $NAIVE_PORT $OVERTLS_PORT $SSR_PORT $WG_PORT $ROSENPASS_PORT "
  printf '%s\n' "$NAT_OWNED" | while IFS= read -r RULE; do
    [ -n "$RULE" ] || continue
    PORT=$(printf '%s\n' "$RULE" | sed -n 's/.*--dport \([0-9][0-9]*\).*/\1/p')
    case "$APPROVED" in *" $PORT "*) : ;; *) exit 23 ;; esac
  done || { warn 'Router VPN NAT contains a public port outside the approved allowlist'; ERR=1; }
  if [ -n "$NAT_OWNED" ] && [ "$(printf '%s\n' "$NAT_OWNED" | sort | uniq -d | wc -l | tr -d ' ')" != 0 ]; then warn 'duplicate Router VPN NAT rules detected'; ERR=1; fi
  if [ -n "$FWD_OWNED" ] && [ "$(printf '%s\n' "$FWD_OWNED" | sort | uniq -d | wc -l | tr -d ' ')" != 0 ]; then warn 'duplicate Router VPN FORWARD rules detected'; ERR=1; fi
  if command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save 2>/dev/null | grep -F "$TAG" >/dev/null 2>&1; then warn 'Router VPN IPv6 iptables rules exist even though IPv6 WAN forwarding is not implemented/tested'; ERR=1; fi
  [ "$ERR" -eq 0 ] || return 1
  say 'VERIFY OK: only narrow Router-VPN-owned IPv4 WAN rules are present; no legacy catch-all, forbidden port, duplicate, LAN->WAN mutation, or Router-VPN IPv6 rule was found.'
}

case "${1:-install}" in
  install) install ;;
  apply) apply_all ;;
  apply-nat) apply_nat ;;
  apply-filter) apply_filter ;;
  status) status ;;
  verify) verify ;;
  remove) remove ;;
  uninstall) uninstall ;;
  *) fail "usage: $0 [install|apply|apply-nat|apply-filter|status|verify|remove|uninstall]" ;;
esac
