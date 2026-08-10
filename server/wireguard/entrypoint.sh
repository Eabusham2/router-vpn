#!/usr/bin/env bash
set -euo pipefail
CONF=${WG_CONFIG:-/data/wg0.conf}
WAN=${WAN_INTERFACE:?WAN_INTERFACE is required}
BACKEND=${ROUTER_VPN_FIREWALL_BACKEND:-auto}

pick_nat(){
  local family=$1 candidate
  if [[ $family == 4 ]]; then
    for candidate in iptables-legacy iptables-nft iptables; do
      command -v "$candidate" >/dev/null 2>&1 || continue
      "$candidate" -t nat -L POSTROUTING >/dev/null 2>&1 && { echo "$candidate"; return 0; }
    done
  else
    for candidate in ip6tables-legacy ip6tables-nft ip6tables; do
      command -v "$candidate" >/dev/null 2>&1 || continue
      "$candidate" -t nat -L POSTROUTING >/dev/null 2>&1 && { echo "$candidate"; return 0; }
    done
  fi
  return 1
}

cleanup_nat(){
  local ipt4 ipt6
  nft delete table inet router_vpn_wg0_nat >/dev/null 2>&1 || true
  ipt4=$(pick_nat 4 || true); ipt6=$(pick_nat 6 || true)
  if [[ -n $ipt4 ]]; then
    while "$ipt4" -t nat -D POSTROUTING -o "$WAN" -s 10.77.0.0/24 -j MASQUERADE >/dev/null 2>&1; do :; done
  fi
  if [[ -n $ipt6 ]]; then
    while "$ipt6" -t nat -D POSTROUTING -o "$WAN" -s fd77:77::/64 -j MASQUERADE >/dev/null 2>&1; do :; done
  fi
}

cleanup(){
  cleanup_nat
  wg-quick down "$CONF" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wg-quick up "$CONF"
cleanup_nat

NFT_OK=0
if [[ $BACKEND != iptables ]]; then
  if nft -f - <<NFT
add table inet router_vpn_wg0_nat
add chain inet router_vpn_wg0_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule inet router_vpn_wg0_nat postrouting oifname "$WAN" ip saddr 10.77.0.0/24 masquerade
add rule inet router_vpn_wg0_nat postrouting oifname "$WAN" ip6 saddr fd77:77::/64 masquerade
NFT
  then
    NFT_OK=1
    echo 'WireGuard NAT: nftables active.'
  else
    echo 'Warning: WireGuard nftables NAT failed; trying iptables-compatible NAT.' >&2
    nft delete table inet router_vpn_wg0_nat >/dev/null 2>&1 || true
  fi
fi

if [[ $NFT_OK -eq 0 ]]; then
  IPT4=$(pick_nat 4) || { echo 'ERROR: no usable IPv4 NAT backend for WireGuard.' >&2; exit 1; }
  "$IPT4" -t nat -A POSTROUTING -o "$WAN" -s 10.77.0.0/24 -j MASQUERADE
  IPT6=$(pick_nat 6 || true)
  if [[ -n $IPT6 ]]; then
    "$IPT6" -t nat -A POSTROUTING -o "$WAN" -s fd77:77::/64 -j MASQUERADE
  else
    echo 'Warning: IPv6 NAT unavailable for WireGuard; IPv4 WireGuard remains active.' >&2
  fi
  echo 'WireGuard NAT: iptables-compatible fallback active.'
fi

while sleep 3600; do :; done
