#!/usr/bin/env bash
set -euo pipefail
CONF=${AWG_CONFIG:-/data/awg0.conf}
WAN=${WAN_INTERFACE:?WAN_INTERFACE is required}
cleanup(){
  nft delete table inet router_vpn_awg_nat >/dev/null 2>&1 || true
  awg-quick down "$CONF" >/dev/null 2>&1 || true
  ip link del awg0 >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
awg-quick up "$CONF"
nft -f - <<NFT
add table inet router_vpn_awg_nat
add chain inet router_vpn_awg_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule inet router_vpn_awg_nat postrouting oifname "$WAN" ip saddr 10.78.0.0/24 masquerade
add rule inet router_vpn_awg_nat postrouting oifname "$WAN" ip6 saddr fd78:78::/64 masquerade
NFT
while sleep 3600; do :; done
