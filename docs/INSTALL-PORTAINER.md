# Install on the ASUS AI Board with Portainer

This is the easiest path and does not require router SSH.

## 1. Give the AI Board a fixed LAN address

In the ASUS router app/web page:

1. Open **LAN → DHCP Server**.
2. Reserve the AI Board address. Example: `192.168.50.133`.
3. Confirm AdGuard Home is reachable at that address.

## 2. Create a read-only GitHub token for this private repository

1. Open GitHub **Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Create a token named `router-vpn-portainer`.
3. Repository access: **Only select repositories → router-vpn**.
4. Repository permission: **Contents: Read-only**.
5. Copy the token.

## 3. Deploy the stack

1. Open the AI Board page, then open **Portainer**. A direct Portainer address is commonly `https://AI_BOARD_IP:9443`.
2. Select the local environment.
3. Open **Stacks → Add stack**.
4. Name: `router-vpn`.
5. Choose **Repository**.
6. Repository URL: `https://github.com/Eabusham2/router-vpn.git`
7. Enable repository authentication:
   - Username: `Eabusham2`
   - Password/token: the fine-grained token
8. Compose path: `server/portainer-compose.yaml`
9. Add these environment variables:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
ENDPOINT=YOUR_HOME_PUBLIC_IPV4
WG_PORT=51820
AWG_PORT=585
REALITY_PORT=443
HY2_PORT=8443
SS_PORT=8388
REALITY_TARGET=www.microsoft.com:443
```

10. Press **Deploy the stack**.
11. Open **Containers → router-vpn-init → Logs**.
12. Wait for `Initialization complete`.

If `eth0` is wrong, open the init container console and run `ip route`; use the interface shown after `default via`, then update the stack variable and redeploy.

## 4. Download the generated client bundle

While connected to home Wi-Fi, open:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

Keep this private. It contains keys, passwords, and the controller token.

## 5. Add ASUS port forwards

Open **WAN → Virtual Server / Port Forwarding** and send these to the AI Board:

```text
UDP 51820 → 192.168.50.133:51820   WireGuard
UDP 585   → 192.168.50.133:585     AmneziaWG 2
TCP 443   → 192.168.50.133:443     REALITY Vision
UDP 8443  → 192.168.50.133:8443    Hysteria2 QUIC
TCP 8388  → 192.168.50.133:8388    Shadowsocks
UDP 8388  → 192.168.50.133:8388    Shadowsocks UDP
```

Do not forward `22`, `53`, `1080`, `2053`, `8786`, `8787`, or `9443`.

## 6. Optional: allow remote port ranges or protected DMZ

For ordinary fixed public services, create normal ASUS forwards to the AI Board and use the client’s forwarding control.

For arbitrary ranges or **Protected DMZ**:

1. Confirm `router-vpn-init`, `router-vpn-agent`, `router-vpn-wireguard`, and `router-vpn-awg2` are healthy.
2. Confirm the stack firewall exists by opening a container console and running:

```bash
nft list table inet router_vpn_guard
```

3. Set **WAN → DMZ** to `192.168.50.133`.
4. Connect remotely through WireGuard or AmneziaWG.
5. In the client UI, add one port, a range, TCP/UDP/both, or Protected DMZ.

Never set DMZ before the firewall guard is active.

## 7. IPv6

1. Keep IPv6 enabled on the ASUS router.
2. In the ASUS IPv6 firewall, allow the same VPN listener ports to the AI Board’s global IPv6 address.
3. Do not open the management ports listed above.
4. The generated client routes both `0.0.0.0/0` and `::/0` and uses tunnel ULA IPv6 with NAT66 for home exit.

## 8. Diagnose

Portainer → `router-vpn-init` console, or a host shell:

```bash
sudo /opt/router-vpn/source/server/scripts/doctor.sh
```
