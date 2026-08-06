# Use the VPN and SOCKS5

## macOS

1. Double-click `router-vpn-client-bundle.zip`.
2. Open Terminal.
3. Type `cd ` with a trailing space.
4. Drag the extracted folder into Terminal and press Return.
5. Run:

```bash
chmod +x client/*.sh modes/*.sh
./client/install-macos.sh .
```

6. Start the controller with the command printed by the installer.
7. Open `http://127.0.0.1:8788`.
8. Leave **SOCKS5-only** off for full-device VPN.
9. Choose **AUTO Escalate** or select a mode and press **Connect**.
10. Press **Off** when back home.

## Linux

```bash
cd /path/to/extracted/router-vpn-client-bundle
sudo ./client/install-linux.sh .
```

Open `http://127.0.0.1:8788`.

## SOCKS5-only mode

1. Check **SOCKS5-only**.
2. Connect with AUTO or a ready mode.
3. Configure the selected app:

```text
SOCKS5 host: 127.0.0.1
Port: 1080
Authentication: none
Proxy DNS through SOCKS5: on
```

Only that app uses home; other device traffic stays direct.

## Port forwarding

Use Raw WireGuard or AmneziaWG mode, then enter:

- Protocol: TCP, UDP, or both
- From/To: one port or a range
- Target: destination port; use `0` to preserve a range
- Protected DMZ: forwards all unused public ports while excluding management/VPN ports

ASUS DMZ to the AI Board must be enabled for arbitrary ports. Press **Clear** when finished.

## Jumbo

- Leave Jumbo off for WireGuard/AWG.
- Enable Jumbo only for a ready TUN proxy mode on a system that supports it.
- LAN MTU 9000 is accepted as payload and segmented for the internet path.

## Windows

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\client\install-windows.ps1 .
```

The native controller binary is included. The complete multi-engine launcher currently requires WSL2; raw profiles remain importable into WireGuard/AmneziaWG apps.
