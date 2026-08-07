# Install and use the client

The exact end-to-end sequence is in `docs/FULL-TUTORIAL.md`.

## macOS

1. Extract the router-generated `router-vpn-client-bundle.zip`.
2. Open Terminal.
3. `cd` into the extracted bundle folder.
4. Run:

```bash
chmod +x client/*.sh modes/*.sh
./client/install-macos.sh .
```

5. Start the controller using the command printed by the installer.
6. Open `http://127.0.0.1:8788`.
7. Import `router-vpn-bundle.json`.
8. Enter the home router's current public IPv4, global IPv6, or hostname if it was left blank during router setup.
9. Save/select the router.
10. Leave **SOCKS5-only** off for a full-device VPN.
11. Choose **AUTO** or a manual mode and connect.
12. Disconnect before switching router profiles.

## Linux

```bash
cd /path/to/extracted/router-vpn-client-bundle
sudo ./client/install-linux.sh .
```

Open `http://127.0.0.1:8788`, import the bundle JSON, enter/select the router endpoint, and connect.

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

The ASUS router must forward the fixed VPN listeners to the AI Board. Protected DMZ requires ASUS DMZ to the AI Board after the package firewall has passed diagnostics.

## Jumbo

- Keep normal WireGuard/AWG tunnel MTU on Auto/default.
- Enable **Jumbo TUN** only for a compatible proxy TUN mode.
- LAN jumbo payloads are segmented to the internet path MTU as required.

## Windows

Use either the normal Windows ZIP or the PortableApps-style ZIP from the GitHub build artifact. The controller is native Windows; the complete multi-engine shell launcher currently uses the Linux transport engines through WSL2. Raw WireGuard/AWG profiles remain importable in their native Windows clients.
