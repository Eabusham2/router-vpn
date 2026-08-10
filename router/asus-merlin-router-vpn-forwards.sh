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

apply_nat(){
  need_router
  WAN=$(wan_if)
  make_chain nat "$NAT_CHAIN"

  iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 80 -j DNAT --to-destination "$DST:18080"
  iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 443 -j DNAT --to-destination "$DST:443"
  iptables -t nat -A "$NAT_CHAIN" -p udp --dport 585 -j DNAT --to-destination "$DST:585"
  iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 8388 -j DNAT --to-destination "$DST:8388"
  iptables -t nat -A "$NAT_CHAIN" -p udp --dport 8388 -j DNAT --to-destination "$DST:8388"
  iptables -t nat -A "$NAT_CHAIN" -p udp --dport 8443 -j DNAT --to-destination "$DST:8443"
  iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 10443 -j DNAT --to-destination "$DST:10443"
  iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 11443 -j DNAT --to-destination "$DST:11443"
  iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 12443 -j DNAT --to-destination "$DST:12443"
  iptables -t nat -A "$NAT_CHAIN" -p tcp --dport 13443 -j DNAT --to-destination "$DST:13443"
  iptables -t nat -A "$NAT_CHAIN" -p udp --dport 13443 -j DNAT --to-destination "$DST:13443"
  iptables -t nat -A "$NAT_CHAIN" -p udp --dport 51820 -j DNAT --to-destination "$DST:51820"
  iptables -t nat -A "$NAT_CHAIN" -p udp --dport 51822 -j DNAT --to-destination "$DST:51822"

  ensure_jump nat PREROUTING -i "$WAN" -j "$NAT_CHAIN"
  say "Router VPN NAT forwards active on $WAN -> $DST"
}

apply_filter(){
  need_router
  WAN=$(wan_if)
  make_chain filter "$FWD_CHAIN"

  iptables -A "$FWD_CHAIN" -p tcp --dport 18080 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p tcp --dport 443 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p udp --dport 585 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p tcp --dport 8388 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p udp --dport 8388 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p udp --dport 8443 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p tcp --dport 10443 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p tcp --dport 11443 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p tcp --dport 12443 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p tcp --dport 13443 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p udp --dport 13443 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p udp --dport 51820 -j ACCEPT
  iptables -A "$FWD_CHAIN" -p udp --dport 51822 -j ACCEPT

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
  cp "$SELF" "$RUNTIME"
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
  cat <<'MAP'
TCP      80      -> 18080
TCP      443     -> 443
UDP      585     -> 585
TCP+UDP  8388    -> 8388
UDP      8443    -> 8443
TCP      10443   -> 10443
TCP      11443   -> 11443
TCP      12443   -> 12443
TCP+UDP  13443   -> 13443
UDP      51820   -> 51820
UDP      51822   -> 51822
MAP
  say 'Never exposed by this script: 1080, 8786, 8787, 9443, SSH, AdGuard admin.'
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
