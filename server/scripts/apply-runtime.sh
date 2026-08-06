#!/usr/bin/env bash
set -euo pipefail
WAN=${1:?wan interface}
LAN=${2:-192.168.50.0/24}
LAN6=${LAN_CIDR6:-fd00::/8}
WG_PORT=${WG_PORT:-51820}
AWG_PORT=${AWG_PORT:-585}
REALITY_PORT=${REALITY_PORT:-443}
HY2_PORT=${HY2_PORT:-8443}
SS_PORT=${SS_PORT:-8388}
XRAY_PQ_PORT=${XRAY_PQ_PORT:-10443}
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null
sysctl -w net.ipv6.conf.all.accept_ra=2 >/dev/null || true
nft delete table inet router_vpn_guard >/dev/null 2>&1 || true
nft -f - <<NFT
add table inet router_vpn_guard
add chain inet router_vpn_guard input { type filter hook input priority -100; policy accept; }
add rule inet router_vpn_guard input iifname "$WAN" ct state established,related accept
add rule inet router_vpn_guard input iifname "$WAN" ip saddr $LAN accept
add rule inet router_vpn_guard input iifname "$WAN" ip6 saddr fe80::/10 accept
add rule inet router_vpn_guard input iifname "$WAN" ip6 saddr $LAN6 accept
add rule inet router_vpn_guard input iifname "$WAN" meta l4proto ipv6-icmp accept
add rule inet router_vpn_guard input iifname "$WAN" udp dport { $WG_PORT, $AWG_PORT, $HY2_PORT, $SS_PORT } accept
add rule inet router_vpn_guard input iifname "$WAN" tcp dport { $REALITY_PORT, $SS_PORT, $XRAY_PQ_PORT } accept
add rule inet router_vpn_guard input iifname "$WAN" drop
NFT

for IPT in iptables ip6tables; do
  command -v "$IPT" >/dev/null 2>&1 || continue
  "$IPT" -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || \
    "$IPT" -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  "$IPT" -C FORWARD -m conntrack --ctstate DNAT -j ACCEPT >/dev/null 2>&1 || \
    "$IPT" -I FORWARD 1 -m conntrack --ctstate DNAT -j ACCEPT
done
