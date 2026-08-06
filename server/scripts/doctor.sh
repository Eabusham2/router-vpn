#!/usr/bin/env bash
set -u
BASE=/opt/router-vpn
pass(){ printf '✓ %s\n' "$1"; }
fail(){ printf '✗ %s\n' "$1"; ERR=1; }
ERR=0
[[ $EUID -eq 0 ]] || fail 'run with sudo'
command -v docker >/dev/null && pass 'Docker' || fail 'Docker missing'
docker compose version >/dev/null 2>&1 && pass 'Docker Compose' || fail 'Docker Compose missing'
[[ -c /dev/net/tun ]] && pass '/dev/net/tun' || fail '/dev/net/tun missing'
[[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]] && pass 'IPv4 forwarding' || fail 'IPv4 forwarding disabled'
[[ $(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null) == 1 ]] && pass 'IPv6 forwarding' || fail 'IPv6 forwarding disabled'
for f in "$BASE/config/wireguard/wg0.conf" "$BASE/config/awg2/awg0.conf" "$BASE/config/socks5.json" "$BASE/config/router-agent.json"; do
  [[ -s $f ]] && pass "$f" || fail "$f missing"
done
for c in router-vpn-agent router-vpn-wireguard router-vpn-awg2 router-vpn-socks5 router-vpn-xray; do
  [[ $(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null) == true ]] && pass "$c running" || fail "$c not running"
done
ip link show wg0 >/dev/null 2>&1 && pass 'wg0 interface' || fail 'wg0 interface missing'
ip link show awg0 >/dev/null 2>&1 && pass 'awg0 interface' || fail 'awg0 interface missing'
ss -lun | grep -q ':51820 ' && pass 'WireGuard UDP listener' || printf '! WireGuard listener may use a custom port\n'
ss -lnt | grep -q ':1080 ' && pass 'SOCKS5 listener' || fail 'SOCKS5 listener missing'
nft list table inet router_vpn_guard >/dev/null 2>&1 && pass 'management firewall guard' || fail 'management firewall guard missing'
exit "$ERR"
