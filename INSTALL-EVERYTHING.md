# Exact setup

## A. Install on the ASUS AI Board through Portainer

### 1. Reserve the host address

1. Open the ASUS router page.
2. Open **LAN → DHCP Server**.
3. Reserve the AI Board/Portainer host as `192.168.50.133`.
4. Confirm AdGuard Home is reachable at `192.168.50.133`.

### 2. Make a read-only GitHub token

1. GitHub → **Settings → Developer settings → Personal access tokens → Fine-grained tokens**.
2. Create a token named `router-vpn-portainer`.
3. Repository access: **Only select repositories → router-vpn**.
4. Permission: **Contents → Read-only**.
5. Copy the token.

### 3. Deploy the stack

1. ASUS **AI Board → Portainer**.
2. **Stacks → Add stack → Repository**.
3. Name: `router-vpn`.
4. Repository URL: `https://github.com/Eabusham2/router-vpn.git`.
5. Reference: `refs/heads/main`.
6. Compose path: `server/portainer-compose.yaml`.
7. Enable repository authentication.
8. Username: `Eabusham2`.
9. Password/token: paste the read-only token.
10. Add these environment variables:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
LAN_CIDR6=fd00::/8
ADGUARD4=192.168.50.133
ENDPOINT=
WG_PORT=51820
AWG_PORT=585
REALITY_PORT=443
HY2_PORT=8443
SS_PORT=8388
XRAY_PQ_PORT=10443
REALITY_TARGET=www.microsoft.com:443
```

11. Press **Deploy the stack**.
12. Wait for `router-vpn-init` to finish with exit code `0`.
13. Confirm these containers are running:

```text
router-vpn-agent
router-vpn-wireguard
router-vpn-awg2
router-vpn-transports
router-vpn-xray
router-vpn-socks5
router-vpn-bundle-web
```

### 4. Confirm the firewall

1. Portainer → `router-vpn-agent` → **Console**.
2. Select `/bin/sh`.
3. Run:

```sh
nft list table inet router_vpn_guard
```

Do not continue to DMZ unless the table is shown.

### 5. ASUS inbound settings

Forward these to `192.168.50.133`:

```text
UDP 51820
UDP 585
TCP 443
UDP 8443
TCP + UDP 8388
TCP 10443
```

Do not forward:

```text
22
53
80
1080
2053
8786
8787
9443
45999
```

For app-controlled arbitrary port/range/protected-DMZ forwarding:

1. Confirm the firewall check passed.
2. ASUS → **WAN → DMZ**.
3. Set DMZ to `192.168.50.133`.

For IPv6:

1. ASUS → **Firewall → IPv6 Firewall**.
2. Allow only the VPN listener ports above to the AI Board global IPv6 address.
3. Keep ICMPv6 allowed.

### 6. Download the private client bundle

While connected to the home LAN, open:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

Do not expose port `8786` to the internet.

---

## B. Install through SSH instead

### 1. Open Terminal on Mac

Press **Command + Space**, type `Terminal`, press Return.

### 2. Copy the ZIP to the AI Board

After downloading `router-vpn.zip`:

```bash
cd ~/Downloads
unzip -o router-vpn.zip
scp -r router-vpn YOUR_AI_BOARD_USERNAME@192.168.50.133:/tmp/
```

Enter the AI Board Linux password.

### 3. Connect with SSH

```bash
ssh YOUR_AI_BOARD_USERNAME@192.168.50.133
```

Type `yes` once, then enter the password.

### 4. Install

```bash
cd /tmp/router-vpn
sudo ./server/install.sh
```

Use:

```text
AI Board interface: value shown by `ip route show default` after `dev`
Home LAN: 192.168.50.0/24
AdGuard: 192.168.50.133
Endpoint: leave blank
Raw WG: 51820
AWG2: 585
REALITY: 443
Hysteria2: 8443
Shadowsocks: 8388
PQ REALITY: 10443
REALITY target: www.microsoft.com:443
```

Then complete sections A.5 and A.6.

---

## C. Install the travel client on macOS

1. Extract `router-vpn-client-bundle.zip`.
2. Open Terminal.
3. Type `cd `, drag the extracted bundle folder into Terminal, and press Return.
4. Run:

```bash
chmod +x client/*.sh modes/*.sh
./client/install-macos.sh .
```

5. Start it using the command printed by the installer.
6. Open:

```text
http://127.0.0.1:8788
```

7. Import `router-vpn-bundle.json`.
8. Enter the home router's current public IPv4, global IPv6, or hostname.
9. Save the router profile.
10. Select **AUTO** or a manual mode.
11. Press **Connect**.
12. Press **Off** before switching router profiles.

The backend address is editable in the app and is not compiled into the binary.

---

## D. Linux travel client

```bash
cd /path/to/router-vpn-client-bundle
sudo ./client/install-linux.sh .
```

Open `http://127.0.0.1:8788`, import the JSON bundle, enter the router endpoint, and connect.

---

## E. Windows

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\client\install-windows.ps1 .
```

The controller and generated raw WG/AWG profiles are included. The unified script launcher requires WSL2 for the Linux transport tools.

---

## F. SOCKS5

### Full VPN plus router SOCKS5

1. Connect the VPN normally.
2. In the selected app, set:

```text
SOCKS5 host: 192.168.50.133
Port: 1080
Username/password: shown in CREDENTIALS.txt
Proxy DNS through SOCKS5: On
```

### App-only home proxy

1. In Router VPN, enable **SOCKS5-only**.
2. Select Raw WireGuard or AmneziaWG.
3. Connect.
4. In the selected app, set:

```text
SOCKS5 host: 127.0.0.1
Port: 1080
Authentication: none
Proxy DNS through SOCKS5: On
```

Do not expose router port `1080` publicly.

---

## G. Port forwarding

1. Connect using Raw WireGuard or AmneziaWG.
2. In the client UI select TCP, UDP, or both.
3. Enter one external port or a From/To range.
4. Destination port `0` preserves the same port/range.
5. Press **Apply**.
6. Use **Protected DMZ** only when ASUS DMZ points to the AI Board and the firewall test passed.
7. Press **Clear** when finished.

---

## H. DAITA-like and jumbo

- **DAITA-like Off/On**: use On only when extra cover traffic is acceptable.
- **Jumbo Off/On**: use On only with compatible proxy TUN modes.
- Keep normal WG/AWG tunnel MTU on Auto/default.
- LAN MTU 9000 can enter as payload; internet packets are segmented to path MTU.
- Keep ICMPv6 Packet Too Big allowed.

---

## I. iPhone/iPad

The ZIP includes the Xcode app and signing workflow, not a working pre-signed IPA.

For immediate use on iPhone:

1. Import `generated/wg/wg.conf` into WireGuard, or
2. Import `generated/awg2-fast/awg.conf` into an AmneziaWG-compatible iOS app.

For the custom app:

1. Follow `docs/IOS.md`.
2. Add your Apple Team and Packet Tunnel entitlement.
3. Link the AmneziaWG/WireGuardKit engine adapter.
4. Archive and export the IPA.
