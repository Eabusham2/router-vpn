#!/usr/bin/env bash
set -euo pipefail
CONF=${WG_CONFIG:-/data/wg0.conf}
WAN=${WAN_INTERFACE:?WAN_INTERFACE is required}
IFACE=$(basename "$CONF" .conf)
cleanup(){
  nft delete table inet "router_vpn_${IFACE}_nat" >/dev/null 2>&1 || true
  wg-quick down "$CONF" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
wg-quick up "$CONF"
nft -f - <<NFT
add table inet router_vpn_${IFACE}_nat
add chain inet router_vpn_${IFACE}_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule inet router_vpn_${IFACE}_nat postrouting oifname "$WAN" ip saddr 10.77.0.0/24 masquerade
add rule inet router_vpn_${IFACE}_nat postrouting oifname "$WAN" ip6 saddr fd77:77::/64 masquerade
NFT
while sleep 3600; do :; done
