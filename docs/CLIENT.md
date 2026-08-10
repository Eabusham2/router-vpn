# Install and use the client

The exact end-to-end sequence is in `docs/FULL-TUTORIAL.md`.

## Private Device Setup WebGUI

After the home-node finalizer completes, open this **only from your home LAN**:

```text
http://AI_BOARD_IP:8786/router-vpn-device-setup.html
```

It is also included inside `router-vpn-client-bundle.zip`, so you can open the HTML file locally after extracting the private bundle.

The page provides:

- device picker: iPhone/iPad, Android, macOS, Windows, Linux, other/manual
- method picker
- WireGuard and AmneziaWG configs + QR codes
- Shadowsocks 2022 import URL + QR
- Hysteria2 import URL + QR
- Shadowsocks + V2Ray-plugin URL + QR where supported
- plain SOCKS5 IP/port instructions for Potatso-compatible or other SOCKS5 apps
- copy buttons for URLs/configs
- native-system vs third-party-app instructions
- Router VPN custom-app installation guidance per device

The QR codes are generated locally on the home node with `qrencode`; the project does not send private configs/keys to an external QR website. Treat the page, ZIP, URLs and QR codes as private credentials.

## macOS

1. Extract the router-generated `router-vpn-client-bundle.zip`.
2. Open Terminal.
3. `cd` into the extracted bundle folder.
4. Run:

```bash
bash client/install-macos-final.sh "$PWD"
```

5. Start the controller using the command printed by the installer.
6. Open `http://127.0.0.1:8788`.
7. Import `router-vpn-bundle.json`.
8. Enter the home router's current public IPv4, global IPv6, or hostname if it was left blank during router setup.
9. Save/select the router.
10. Leave **SOCKS5-only** off for a full-device VPN.
11. Choose **AUTO** or a manual mode and connect.
12. Disconnect before switching router profiles.

For app-only SOCKS5 after the VPN reaches home, macOS can also use **System Settings → Network → service → Details → Proxies → SOCKS Proxy** with the home SOCKS host and port `1080`.

## Linux

```bash
cd /path/to/extracted/router-vpn-client-bundle
sudo bash client/install-linux.sh "$PWD"
```

Open `http://127.0.0.1:8788`, import the bundle JSON, enter/select the router endpoint, and connect.

## iPhone / iPad

- **WireGuard:** import the generated config or scan the WireGuard QR in the WireGuard app.
- **AmneziaWG:** import the generated AWG config in an Amnezia-compatible client.
- **Shadowsocks / SOCKS5 testing:** Potatso or another compatible proxy app can use the generated/importable settings when that format is supported.
- **Hysteria2:** use a Hysteria2/sing-box-compatible iOS client and import the generated URL/QR.
- **Router VPN IPA:** the current IPA is a controller/importer package until the native Packet Tunnel adapters are linked; it must not be presented as a finished all-mode VPN client yet.

## Android

- WireGuard: import the config file or scan its QR in WireGuard for Android.
- AmneziaWG: import the AWG config in an Amnezia-compatible client.
- Shadowsocks/Hysteria2: import the generated URL/QR in a compatible client.
- Router VPN APK: install the generated APK artifact if you want the current controller/importer app. The native all-mode `VpnService` adapters are not linked yet.

## Windows

Use either the normal Windows ZIP or the PortableApps-style ZIP from the GitHub build artifact. The controller is native Windows; the complete multi-engine shell launcher currently uses the Linux transport engines through WSL2. Raw WireGuard/AWG profiles remain importable in their native Windows clients.

## Add another router

1. Import the other router's `router-vpn-bundle.json`.
2. Enter its endpoint if needed.
3. Save/select it while disconnected.

Each imported router keeps separate private generated profile files.

## SOCKS5-only app mode

1. Enable **SOCKS5-only**.
2. Connect with Raw WireGuard or AmneziaWG.
3. Configure the selected application:

```text
SOCKS5 host: 127.0.0.1
Port: 1080
Authentication: none
Proxy DNS through SOCKS5: enabled
```

Only the configured application uses the home connection.

## Router SOCKS5 service

After a tunnel reaches the home network, the router SOCKS5 endpoint shown in the imported profile works like a normal SOCKS5 proxy using only its IP and port. Authentication is disabled because WAN access to TCP `1080` is blocked by the package firewall and must never be forwarded publicly.

## Port forwarding

1. Connect using Raw WireGuard or AmneziaWG.
2. Choose TCP, UDP, or both.
3. Enter one external port or a From/To range.
4. Enter the destination port; use `0` to preserve the same range.
5. Press **Apply**, or press **Protected DMZ** for all unused ports.
6. Press **Clear** when finished.

The ASUS router must forward the fixed VPN listeners to the AI Board. Protected DMZ requires a WireGuard/AmneziaWG peer path; proxy-only modes are outbound.

## Jumbo

- Keep normal WireGuard/AWG tunnel MTU on Auto/default.
- Enable **Jumbo TUN** only for a compatible proxy TUN mode.
- LAN jumbo payloads are segmented to the internet path MTU as required.
