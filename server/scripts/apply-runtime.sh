#!/usr/bin/env bash
set -euo pipefail
WAN=${1:?wan interface}
LAN=${2:-192.168.50.0/24}
LAN6=${LAN_CIDR6:-fd00::/8}
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
ACME_HTTP_PORT=${ACME_HTTP_PORT:-18080}
FIREWALL_BACKEND=${ROUTER_VPN_FIREWALL_BACKEND:-auto}

set_sysctl(){
  local key=$1 value=$2 current
  if sysctl -w "$key=$value" >/dev/null 2>&1; then return 0; fi
  current=$(sysctl -n "$key" 2>/dev/null || true)
  if [[ $current == "$value" ]]; then
    echo "Warning: could not write $key, but it is already $value." >&2
    return 0
  fi
  echo "ERROR: cannot enable required sysctl $key=$value (current=${current:-unknown})." >&2
  return 1
}

set_sysctl net.ipv4.ip_forward 1
set_sysctl net.ipv6.conf.all.forwarding 1
set_sysctl net.ipv6.conf.default.forwarding 1
sysctl -w net.ipv6.conf.all.accept_ra=2 >/dev/null 2>&1 || true

pick_filter(){
  local family=$1 candidate
  if [[ $family == 4 ]]; then
    for candidate in iptables-legacy iptables-nft iptables; do
      command -v "$candidate" >/dev/null 2>&1 || continue
      "$candidate" -t filter -L INPUT >/dev/null 2>&1 && { echo "$candidate"; return 0; }
    done
  else
    for candidate in ip6tables-legacy ip6tables-nft ip6tables; do
      command -v "$candidate" >/dev/null 2>&1 || continue
      "$candidate" -t filter -L INPUT >/dev/null 2>&1 && { echo "$candidate"; return 0; }
    done
  fi
  return 1
}

clear_guard(){
  local ipt=$1
  while "$ipt" -D INPUT -i "$WAN" -j ROUTER_VPN_GUARD >/dev/null 2>&1; do :; done
  "$ipt" -F ROUTER_VPN_GUARD >/dev/null 2>&1 || true
  "$ipt" -X ROUTER_VPN_GUARD >/dev/null 2>&1 || true
}

install_iptables_guard(){
  local ipt4 ipt6 port
  ipt4=$(pick_filter 4) || { echo 'ERROR: nftables failed and no usable IPv4 iptables filter backend exists.' >&2; return 1; }
  ipt6=$(pick_filter 6 || true)

  clear_guard "$ipt4"
  "$ipt4" -N ROUTER_VPN_GUARD
  "$ipt4" -A ROUTER_VPN_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    "$ipt4" -A ROUTER_VPN_GUARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  "$ipt4" -A ROUTER_VPN_GUARD -s "$LAN" -j ACCEPT
  for port in "$WG_PORT" "$AWG_PORT" "$ROSENPASS_PORT" "$HY2_PORT" "$SS_PORT" "$NAIVE_PORT" "$SSR_PORT"; do
    "$ipt4" -A ROUTER_VPN_GUARD -p udp --dport "$port" -j ACCEPT
  done
  for port in "$ACME_HTTP_PORT" "$REALITY_PORT" "$SS_PORT" "$XRAY_PQ_PORT" "$XHTTP_PORT" "$SS_V2RAY_PORT" "$NAIVE_PORT" "$OVERTLS_PORT" "$SSR_PORT"; do
    "$ipt4" -A ROUTER_VPN_GUARD -p tcp --dport "$port" -j ACCEPT
  done
  "$ipt4" -A ROUTER_VPN_GUARD -j DROP
  "$ipt4" -I INPUT 1 -i "$WAN" -j ROUTER_VPN_GUARD

  if [[ -n $ipt6 ]]; then
    clear_guard "$ipt6"
    "$ipt6" -N ROUTER_VPN_GUARD
    "$ipt6" -A ROUTER_VPN_GUARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
      "$ipt6" -A ROUTER_VPN_GUARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    "$ipt6" -A ROUTER_VPN_GUARD -s fe80::/10 -j ACCEPT
    "$ipt6" -A ROUTER_VPN_GUARD -s "$LAN6" -j ACCEPT
    "$ipt6" -A ROUTER_VPN_GUARD -p ipv6-icmp -j ACCEPT
    for port in "$WG_PORT" "$AWG_PORT" "$ROSENPASS_PORT" "$HY2_PORT" "$SS_PORT" "$NAIVE_PORT" "$SSR_PORT"; do
      "$ipt6" -A ROUTER_VPN_GUARD -p udp --dport "$port" -j ACCEPT
    done
    for port in "$ACME_HTTP_PORT" "$REALITY_PORT" "$SS_PORT" "$XRAY_PQ_PORT" "$XHTTP_PORT" "$SS_V2RAY_PORT" "$NAIVE_PORT" "$OVERTLS_PORT" "$SSR_PORT"; do
      "$ipt6" -A ROUTER_VPN_GUARD -p tcp --dport "$port" -j ACCEPT
    done
    "$ipt6" -A ROUTER_VPN_GUARD -j DROP
    "$ipt6" -I INPUT 1 -i "$WAN" -j ROUTER_VPN_GUARD
  else
    echo 'Warning: no usable IPv6 iptables filter backend; IPv6 fallback guard is unavailable.' >&2
  fi
  echo "Router VPN firewall: iptables-compatible fallback active on $WAN."
}

NFT_OK=0
if [[ $FIREWALL_BACKEND != iptables ]]; then
  nft delete table inet router_vpn_guard >/dev/null 2>&1 || true
  if nft -f - <<NFT
add table inet router_vpn_guard
add chain inet router_vpn_guard input { type filter hook input priority -100; policy accept; }
add rule inet router_vpn_guard input iifname "$WAN" ct state established,related accept
add rule inet router_vpn_guard input iifname "$WAN" ip saddr $LAN accept
add rule inet router_vpn_guard input iifname "$WAN" ip6 saddr fe80::/10 accept
add rule inet router_vpn_guard input iifname "$WAN" ip6 saddr $LAN6 accept
add rule inet router_vpn_guard input iifname "$WAN" meta l4proto 58 accept
add rule inet router_vpn_guard input iifname "$WAN" udp dport { $WG_PORT, $AWG_PORT, $ROSENPASS_PORT, $HY2_PORT, $SS_PORT, $NAIVE_PORT, $SSR_PORT } accept
add rule inet router_vpn_guard input iifname "$WAN" tcp dport { $ACME_HTTP_PORT, $REALITY_PORT, $SS_PORT, $XRAY_PQ_PORT, $XHTTP_PORT, $SS_V2RAY_PORT, $NAIVE_PORT, $OVERTLS_PORT, $SSR_PORT } accept
add rule inet router_vpn_guard input iifname "$WAN" drop
NFT
  then
    NFT_OK=1
    echo "Router VPN firewall: nftables active on $WAN."
  else
    echo 'Warning: nftables is unsupported on this host; trying iptables-compatible backends.' >&2
    nft delete table inet router_vpn_guard >/dev/null 2>&1 || true
  fi
fi

if [[ $NFT_OK -eq 0 ]]; then
  install_iptables_guard
fi

IPT4=$(pick_filter 4) || { echo 'ERROR: no usable IPv4 FORWARD backend.' >&2; exit 1; }
for subnet in 10.77.0.0/24 10.78.0.0/24; do
  "$IPT4" -C FORWARD -s "$subnet" -j ACCEPT >/dev/null 2>&1 || "$IPT4" -I FORWARD 1 -s "$subnet" -j ACCEPT
  "$IPT4" -C FORWARD -d "$subnet" -j ACCEPT >/dev/null 2>&1 || "$IPT4" -I FORWARD 1 -d "$subnet" -j ACCEPT
done

IPT6=$(pick_filter 6 || true)
if [[ -n $IPT6 ]]; then
  for subnet in fd77:77::/64 fd78:78::/64; do
    "$IPT6" -C FORWARD -s "$subnet" -j ACCEPT >/dev/null 2>&1 || "$IPT6" -I FORWARD 1 -s "$subnet" -j ACCEPT
    "$IPT6" -C FORWARD -d "$subnet" -j ACCEPT >/dev/null 2>&1 || "$IPT6" -I FORWARD 1 -d "$subnet" -j ACCEPT
  done
else
  echo 'Warning: IPv6 FORWARD table unavailable; IPv4 VPN forwarding remains enabled.' >&2
fi
