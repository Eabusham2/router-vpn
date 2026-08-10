#!/bin/sh
set -eu

DST=${ROUTER_VPN_HOST:-192.168.50.133}
SELF=${0}
JFFS_DIR=/jffs/scripts
RUNTIME="$JFFS_DIR/router-vpn-forward.sh"
NAT_START="$JFFS_DIR/nat-start"
FIREWALL_START="$JFFS_DIR/firewall-start"
NAT_CHAIN=ROUTER_VPN_DNAT
FWD_CHAIN=ROUTER_VPN_FWD

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
ACME_EXTERNAL_PORT=${ACME_EXTERNAL_PORT:-80}
ACME_INTERNAL_PORT=${ACME_INTERNAL_PORT:-18080}

say(){ printf '%s\n' "$*"; }
fail(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_router(){
  [ -d /jffs ] || fail 'This installer must run on the ASUS Asuswrt-Merlin router.'
  command -v iptables >/dev/null 2>&1 || fail 'iptables is unavailable on this router.'
}

wan_if(){
  if [ -n "${ROUTER_VPN_WAN_INTERFACE:-}" ]; then
    printf '%s\n' "$ROUTER_VPN_WAN_INTERFACE"
    return
  fi
  IF=$(ip route show default 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
  [ -n "$IF" ] || IF=$(nvram get wan0_gw_ifname 2>/dev/null || true)
  [ -n "$IF" ] || IF=$(nvram get wan0_ifname 2>/dev/null || true)
  [ -n "$IF" ] || fail 'Could not determine the WAN interface. Set ROUTER_VPN_WAN_INTERFACE and rerun.'
  printf '%s\n' "$IF"
}

ensure_jump(){
  TABLE=$1; CHAIN=$2; shift 2
  if ! iptables -t "$TABLE" -C "$CHAIN" "$@" >/dev/null 2>&1; then
    iptables -t "$TABLE" -I "$CHAIN" 1 "$@"
  fi
}

clear_jump(){
  TABLE=$1; CHAIN=$2; shift 2
  while iptables -t "$TABLE" -C "$CHAIN" "$@" >/dev/null 2>&1; do
    iptables -t "$TABLE" -D "$CHAIN" "$@"
  done
}

make_chain(){
  TABLE=$1; CHAIN=$2
  iptables -t "$TABLE" -N "$CHAIN" >/dev/null 2>&1 || true
  iptables -t "$TABLE" -F "$CHAIN"
}

add_dnat(){
  PROTO=$1; EXT=$2; INT=$3
  iptables -t nat -A "$NAT_CHAIN" -p "$PROTO" --dport "$EXT" -j DNAT --to-destination "$DST:$INT"
}

add_fwd(){
  PROTO=$1; PORT=$2
  iptables -A "$FWD_CHAIN" -p "$PROTO" --dport "$PORT" -j ACCEPT
}

apply_nat(){
  need_router
  WAN=$(wan_if)
  make_chain nat "$NAT_CHAIN"

  add_dnat tcp "$ACME_EXTERNAL_PORT" "$ACME_INTERNAL_PORT"
  add_dnat tcp "$REALITY_PORT" "$REALITY_PORT"
  add_dnat udp "$AWG_PORT" "$AWG_PORT"
  add_dnat tcp "$SS_PORT" "$SS_PORT"
  add_dnat udp "$SS_PORT" "$SS_PORT"
  add_dnat udp "$HY2_PORT" "$HY2_PORT"
  add_dnat tcp "$XRAY_PQ_PORT" "$XRAY_PQ_PORT"
  add_dnat tcp "$XHTTP_PORT" "$XHTTP_PORT"
  add_dnat tcp "$SS_V2RAY_PORT" "$SS_V2RAY_PORT"
  add_dnat tcp "$NAIVE_PORT" "$NAIVE_PORT"
  add_dnat udp "$NAIVE_PORT" "$NAIVE_PORT"
  add_dnat udp "$WG_PORT" "$WG_PORT"
  add_dnat udp "$ROSENPASS_PORT" "$ROSENPASS_PORT"

  ensure_jump nat PREROUTING -i "$WAN" -j "$NAT_CHAIN"
  say "Router VPN NAT forwards active on $WAN -> $DST"
}

apply_filter(){
  need_router
  WAN=$(wan_if)
  make_chain filter "$FWD_CHAIN"

  add_fwd tcp "$ACME_INTERNAL_PORT"
  add_fwd tcp "$REALITY_PORT"
  add_fwd udp "$AWG_PORT"
  add_fwd tcp "$SS_PORT"
  add_fwd udp "$SS_PORT"
  add_fwd udp "$HY2_PORT"
  add_fwd tcp "$XRAY_PQ_PORT"
  add_fwd tcp "$XHTTP_PORT"
  add_fwd tcp "$SS_V2RAY_PORT"
  add_fwd tcp "$NAIVE_PORT"
  add_fwd udp "$NAIVE_PORT"
  add_fwd udp "$WG_PORT"
  add_fwd udp "$ROSENPASS_PORT"

  ensure_jump filter FORWARD -i "$WAN" -d "$DST" -j "$FWD_CHAIN"
  say "Router VPN FORWARD rules active on $WAN -> $DST"
}

write_hook(){
  FILE=$1; LINE=$2
  [ -f "$FILE" ] || printf '#!/bin/sh\n' > "$FILE"
  grep -Fqx "$LINE" "$FILE" 2>/dev/null || printf '%s\n' "$LINE" >> "$FILE"
  chmod 755 "$FILE"
}

install(){
  need_router
  mkdir -p "$JFFS_DIR"
  if [ "$SELF" != "$RUNTIME" ]; then
    cp "$SELF" "$RUNTIME"
  fi
  chmod 755 "$RUNTIME"
  write_hook "$NAT_START" "$RUNTIME apply-nat"
  write_hook "$FIREWALL_START" "$RUNTIME apply-filter"
  nvram set jffs2_scripts=1
  nvram commit
  "$RUNTIME" apply-nat
  "$RUNTIME" apply-filter
  status
  say 'Persistent Merlin hooks installed. Existing nat-start/firewall-start content was preserved.'
}

remove(){
  need_router
  WAN=$(wan_if)
  clear_jump nat PREROUTING -i "$WAN" -j "$NAT_CHAIN"
  clear_jump filter FORWARD -i "$WAN" -d "$DST" -j "$FWD_CHAIN"
  iptables -t nat -F "$NAT_CHAIN" >/dev/null 2>&1 || true
  iptables -t nat -X "$NAT_CHAIN" >/dev/null 2>&1 || true
  iptables -F "$FWD_CHAIN" >/dev/null 2>&1 || true
  iptables -X "$FWD_CHAIN" >/dev/null 2>&1 || true
  [ ! -f "$NAT_START" ] || sed -i '\|/jffs/scripts/router-vpn-forward.sh apply-nat|d' "$NAT_START"
  [ ! -f "$FIREWALL_START" ] || sed -i '\|/jffs/scripts/router-vpn-forward.sh apply-filter|d' "$FIREWALL_START"
  rm -f "$RUNTIME"
  say 'Router VPN forward hooks removed. Other JFFS script content was preserved.'
}

status(){
  need_router
  WAN=$(wan_if)
  say "WAN interface: $WAN"
  say "Destination:   $DST"
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
  printf 'UDP      %-7s -> %s\n' "$WG_PORT" "$WG_PORT"
  printf 'UDP      %-7s -> %s\n' "$ROSENPASS_PORT" "$ROSENPASS_PORT"
  say 'Never exposed by this script: 1080, 8786, 8787, 9443, SSH, Portainer, AdGuard admin.'
  say '--- NAT ---'
  iptables -t nat -S "$NAT_CHAIN" 2>/dev/null || say 'NAT chain not installed.'
  say '--- FORWARD ---'
  iptables -S "$FWD_CHAIN" 2>/dev/null || say 'FORWARD chain not installed.'
}

case "${1:-install}" in
  install) install ;;
  apply-nat) apply_nat ;;
  apply-filter) apply_filter ;;
  status) status ;;
  remove|uninstall) remove ;;
  *) fail "usage: $0 [install|apply-nat|apply-filter|status|remove]" ;;
esac
