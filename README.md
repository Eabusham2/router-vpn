# Router VPN

Private home-exit VPN and SOCKS5 gateway for the ASUS AI Board/Portainer host.
The home router address is selected at runtime in the client; it is not compiled into the app.

## Included

- Raw WireGuard
- AmneziaWG 2 Fast and Strong
- Hybrid PQ VLESS encryption + REALITY/Vision
- VLESS + REALITY/Vision
- Hysteria2/QUIC
- Shadowsocks 2022
- Authenticated private SOCKS5
- AUTO or manual mode picker
- IPv4 and IPv6 full tunnel
- Home AdGuard DNS
- DAITA-like cover-traffic toggle
- Jumbo-payload/TUN option
- Single-port, range, TCP/UDP/both, and protected-DMZ forwarding
- Multiple editable home-router profiles
- Prebuilt macOS, Windows, Linux, and ARM64 Linux controller binaries
- iOS Xcode project and signed-IPA workflow template

See `docs/STATUS.md` for modes that are ready and experimental integrations that remain disabled.

## Install through Portainer

Follow `docs/INSTALL-PORTAINER.md`.

Portainer repository values:

```text
Repository: https://github.com/Eabusham2/router-vpn.git
Reference: refs/heads/main
Compose path: server/portainer-compose.yaml
```

The stack generates this LAN-only download:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

## Install through SSH

Follow `docs/INSTALL-SSH.md`, or run:

```bash
ssh YOUR_AI_BOARD_USERNAME@192.168.50.133
cd /tmp
rm -rf router-vpn
git clone https://github.com/Eabusham2/router-vpn.git
cd router-vpn
sudo ./server/install.sh
```

Leave the endpoint blank during installation. Set the home public IPv4, global IPv6, or hostname later in the client.

## Client

Follow `docs/CLIENT.md`.

On macOS, after extracting the router-generated client bundle:

```bash
cd /path/to/router-vpn-client-bundle
chmod +x client/*.sh modes/*.sh
./client/install-macos.sh .
```

Open:

```text
http://127.0.0.1:8788
```

Import `router-vpn-bundle.json`, enter the router endpoint, choose AUTO/manual mode, then connect.

For app-only use, enable **SOCKS5-only** and configure the app for `127.0.0.1:1080`.

## iPhone/iPad

See `docs/IOS.md`. A signed IPA cannot be distributed from this package without the user’s Apple signing certificate, provisioning profiles, Team ID, and Packet Tunnel entitlement. The Xcode project and signing workflow are included.
