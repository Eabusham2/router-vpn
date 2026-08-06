# Install and use the client

The exact end-to-end sequence is in `INSTALL-EVERYTHING.md`.

## macOS

1. Double-click the router-generated `router-vpn-client-bundle.zip`.
2. Open **Terminal** with Command + Space → type `Terminal` → Return.
3. Type `cd `, drag the extracted bundle folder into Terminal, and press Return.
4. Run:

```bash
chmod +x client/*.sh modes/*.sh
./client/install-macos.sh .
```

5. Start the controller using the command printed by the installer.
6. Open `http://127.0.0.1:8788`.
7. In **Router backend**, import `router-vpn-bundle.json`.
8. Enter the home router's current public IPv4, global IPv6, or hostname.
9. Press **Save and use this router**.
10. Leave **SOCKS5-only** off for a full-device VPN.
11. Press **AUTO** or select a mode and press **Connect**.
12. Press **Off** when finished.

## Linux

```bash
cd /path/to/extracted/router-vpn-client-bundle
sudo ./client/install-linux.sh .
```

Open `http://127.0.0.1:8788`, import the bundle JSON, enter/select the router endpoint, and connect.

## Add another router

1. Press **Import router bundle**.
2. Choose the other router's `router-vpn-bundle.json`.
3. Enter its endpoint and press **Save and use this router**.
4. Switch routers from the drop-down while disconnected.

Each imported router keeps separate mode files and credentials.

## SOCKS5-only

1. Check **SOCKS5-only**.
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

After connecting to the VPN, the authenticated router proxy is listed in the app under **SOCKS5 proxy**. Do not expose router port `1080` publicly.

## Port forwarding

1. Connect using Raw WireGuard or AmneziaWG.
2. Choose TCP, UDP, or both.
3. Enter one external port or a From/To range.
4. Enter the destination port; use `0` to preserve the same range.
5. Press **Apply**, or press **Protected DMZ** for all unused ports.
6. Press **Clear** when finished.

The ASUS router must forward fixed VPN listeners to the AI Board. Protected DMZ requires ASUS DMZ to the AI Board after the package firewall has passed diagnostics.

## Jumbo

- Keep normal WireGuard/AWG tunnel MTU on Auto/default.
- Enable **Jumbo TUN** only for a compatible TUN proxy mode.
- LAN frames up to 9000 bytes are accepted as payload and segmented into internet-sized encrypted packets.

## Windows

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\client\install-windows.ps1 .
```

The controller is included. The complete multi-engine launcher currently uses the Linux scripts through WSL2; raw WireGuard/AWG profiles remain importable in their native apps.
