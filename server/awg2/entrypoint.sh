#!/usr/bin/env bash
set -euo pipefail
CONF=${AWG_CONFIG:-/data/awg0.conf}
WAN=${WAN_INTERFACE:?WAN_INTERFACE is required}
BACKEND=${ROUTER_VPN_FIREWALL_BACKEND:-auto}

pick_ipt(){
  local family=$1
  if [[ $family == 4 ]]; then
    if command -v iptables-legacy >/dev/null 2>&1; then echo iptables-legacy; else echo iptables; fi
  else
    if command -v ip6tables-legacy >/dev/null 2>&1; then echo ip6tables-legacy; else echo ip6tables; fi
  fi
}

cleanup_nat(){
  local ipt4 ipt6
  nft delete table inet router_vpn_awg_nat >/dev/null 2>&1 || true
  ipt4=$(pick_ipt 4); ipt6=$(pick_ipt 6)
  while "$ipt4" -t nat -D POSTROUTING -o "$WAN" -s 10.78.0.0/24 -j MASQUERADE >/dev/null 2>&1; do :; done
  while "$ipt6" -t nat -D POSTROUTING -o "$WAN" -s fd78:78::/64 -j MASQUERADE >/dev/null 2>&1; do :; done
}

cleanup(){
  cleanup_nat
  awg-quick down "$CONF" >/dev/null 2>&1 || true
  ip link del awg0 >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
awg-quick up "$CONF"
cleanup_nat

NFT_OK=0
if [[ $BACKEND != iptables ]]; then
  if nft -f - <<NFT
add table inet router_vpn_awg_nat
add chain inet router_vpn_awg_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule inet router_vpn_awg_nat postrouting oifname "$WAN" ip saddr 10.78.0.0/24 masquerade
add rule inet router_vpn_awg_nat postrouting oifname "$WAN" ip6 saddr fd78:78::/64 masquerade
NFT
  then
    NFT_OK=1
    echo 'AmneziaWG NAT: nftables active.'
  else
    echo 'Warning: AmneziaWG nftables NAT failed; using legacy iptables.' >&2
    nft delete table inet router_vpn_awg_nat >/dev/null 2>&1 || true
  fi
fi

if [[ $NFT_OK -eq 0 ]]; then
  IPT4=$(pick_ipt 4); IPT6=$(pick_ipt 6)
  "$IPT4" -t nat -A POSTROUTING -o "$WAN" -s 10.78.0.0/24 -j MASQUERADE
  "$IPT6" -t nat -A POSTROUTING -o "$WAN" -s fd78:78::/64 -j MASQUERADE
  echo 'AmneziaWG NAT: legacy iptables active.'
fi

while sleep 3600; do :; done
