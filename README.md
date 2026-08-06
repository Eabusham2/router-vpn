# HomeVPN Suite — source prototype

A router-side agent plus a custom client mode picker. It manages upstream VPN engines; it does not reimplement their cryptography.

## Included UI controls

- AUTO or manual mode
- DAITA Off/On
- Jumbo TUN Off/On
- SOCKS5 Off/On
- IPv4 + IPv6
- Home AdGuard DNS
- Single port, range, TCP/UDP/both, or protected DMZ forwarding

## Modes

The UI reads `configs/client/modes.json`, including raw WireGuard, PQ WireGuard/Rosenpass, LWO, AmneziaWG 2, WireGuard-over-QUIC, WireGuard-over-Shadowsocks, VLESS PQ/REALITY Vision, Shadowsocks+V2Ray TLS, VLESS PQ/REALITY XHTTP+FinalMask, Naive HTTPS, MAX-TLS, and MAX-QUIC.

The latency/traffic figures are same-route engineering estimates, not guarantees.

## 1. Copy to the ASUS AI Board

On a Mac, unzip the folder. Open **Terminal**, then run:

```bash
scp -r homevpn-suite AI_BOARD_USER@AI_BOARD_IP:/tmp/
ssh AI_BOARD_USER@AI_BOARD_IP
```

Type `yes` once, then the AI Board Linux password. If direct AI Board SSH is unavailable, open Portainer → Containers → a Linux utility container → Console, or copy the folder to an attached share and run the installer from the AI Board shell.

## 2. Install the router stack

Inside the AI Board shell:

```bash
cd /tmp/homevpn-suite
sudo ./deploy/install-router.sh
```

Edit these two files:

```bash
sudo nano /opt/homevpn/config/router-agent.json
sudo nano /opt/homevpn/config/socks5.json
```

Set the real WAN-facing AI Board interface, SOCKS username/password, and tunnel ranges. Restart:

```bash
cd /tmp/homevpn-suite/deploy
sudo docker compose restart
```

Portainer normally lives at `https://AI-BOARD-HOST:9443` on the GT-BE19000AI.

## 3. ASUS routing

Router GUI:

1. Reserve the AI Board LAN address.
2. Set **WAN → DMZ** to the AI Board address only after the host firewall is active.
3. Do not expose Portainer, AdGuard admin, SSH, SOCKS5, or the router-agent API.
4. For IPv6, allow inbound to the AI Board; the AI Board nftables policy must remain the final filter.
5. Forward/listen only on the actual VPN transport ports configured by the engine server profiles.

## 4. Server engine profiles

Install/configure the upstream engines on the AI Board and place their server files under `/opt/homevpn/engines/`:

- WireGuard or Mullvad GotaTun/DAITA build
- Rosenpass
- AmneziaWG 2
- Xray-core: VLESS encryption + REALITY Vision and XHTTP/FinalMask
- Shadowsocks 2022 + v2ray-plugin TLS
- Hysteria2/QUIC
- sing-box with Naive outbound support

Bind the internal SOCKS5 service only to `10.77.0.1:1080` and use AdGuard at `192.168.50.133` plus its IPv6 address.

## 5. Build the custom client controller

```bash
cd homevpn-suite
./deploy/build-client.sh
```

Binaries appear in `dist/` for macOS, Windows, Linux, and ARM64 Linux. Copy `configs/client/client.json.example` to `client.json`, copy `configs/client/modes.json` and `modes/`, then update the router token and addresses.

Run as administrator/root:

```bash
sudo ./homevpn-client-darwin-arm64
```

Open:

```text
http://127.0.0.1:8788
```

Choose **AUTO** or a mode. The controller launches the upstream binaries through `modes/run-mode.sh`.

## 6. Away-from-home use

- At home: leave HomeVPN Off.
- Away: open the client UI, select AUTO, and connect.
- Full-tunnel routes must include `0.0.0.0/0` and `::/0`.
- DNS must be the home AdGuard addresses.
- Use the SOCKS5 address `10.77.0.1:1080` only after the VPN is connected.

## 7. Port forwarding

In the client UI, choose protocol, external range, and destination port. The router agent only accepts requests from authenticated tunnel peers and forwards to the requesting peer.

Protected DMZ forwards unused ports but excludes the reserved management/VPN ports listed in `router-agent.json`.

## 8. MTU/jumbo

- Default client TUN: 1500.
- Raw WireGuard: auto or 1380–1420.
- Obfuscated tunnels: 1320–1400.
- MAX modes: 1280–1320.
- Jumbo toggle is intended for Linux GSO-capable TUN paths; keep it off elsewhere.
- LAN MTU 9000 is accepted, then segmented into path-sized encrypted packets.
- Never block ICMPv6 Packet Too Big.

## Status

The controller and nftables API are implemented. The cryptographic/transport engines are intentionally upstream dependencies and must be built/configured for the target OS. Exact DAITA requires Mullvad's open-source Maybenot-enabled WireGuard implementation on both ends. Apple mobile builds require an Apple Developer account, Network Extension entitlement, signing, and a separate iOS integration.
