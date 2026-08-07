# Router VPN — simple full setup

This installs the home VPN on the ASUS AI Board, creates the private client bundle, and shows how to use every build.

## 1. Reserve the AI Board address

In the ASUS router page:

1. Open **LAN → DHCP Server**.
2. Reserve the AI Board address. The examples below use `192.168.50.133`.
3. Confirm AdGuard Home is reachable at that address.

## 2. Install the router stack

Choose **Portainer** or **SSH**. Do not do both.

### Portainer — no terminal

1. Open **AI Board → Portainer → Stacks → Add stack**.
2. Choose **Repository**.
3. Name: `router-vpn`.
4. Repository: `https://github.com/Eabusham2/router-vpn.git`.
5. Reference: `refs/heads/main`.
6. Compose path: `server/portainer-compose.yaml`.
7. Because the repository is private, enable authentication and use your GitHub username plus a read-only fine-grained token for this repository.
8. Add these environment variables:

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
XHTTP_PORT=11443
REALITY_TARGET=www.microsoft.com:443
```

9. Press **Deploy the stack**.
10. In **Containers**, confirm `router-vpn-init` and `router-vpn-finalize` finish with exit code `0`.
11. Confirm the agent, WireGuard, AmneziaWG, transports, Xray, SOCKS5, and bundle-web containers are running.

### SSH — terminal

Copy or clone this repository onto the AI Board, then run:

```bash
cd router-vpn
chmod +x server/install.sh
sudo ./server/install.sh
```

Press Enter to accept the displayed defaults, or type different ports. The script waits for initialization and checks that the private bundle was created.

## 3. Add the ASUS WAN forwards

Forward these defaults to the AI Board address:

```text
UDP       51820   WireGuard
UDP       585     AmneziaWG 2
TCP       443     REALITY/Vision
UDP       8443    Hysteria2/QUIC
TCP+UDP   8388    Shadowsocks
TCP       10443   PQ REALITY
TCP       11443   XHTTP/FinalMask
```

Do **not** forward:

```text
TCP 1080   SOCKS5
TCP 8786   private bundle download
TCP 8787   router controller API
SSH, Portainer, AdGuard admin, or DNS admin ports
```

For IPv6, allow only the seven VPN listener ports above to the AI Board global IPv6 address. Keep ICMPv6 allowed.

## 4. Download the private client bundle

While connected to the home LAN, open:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

Extract it. Keep it private because it contains the router keys, token, and generated profiles.

The most important file is:

```text
router-vpn-bundle.json
```

## 5. Build or download the apps

Open the repository’s **Actions** page and run **Build all platforms**. Download the artifact for the platform you need, or download `RouterVPN-all-platforms` for everything.

The workflow produces:

- Windows x64 and ARM64 ZIPs
- Windows PortableApps-style x64 and ARM64 ZIPs
- macOS Intel and Apple Silicon archives
- Linux amd64, arm64, and armv7 archives
- FreeBSD, OpenBSD, NetBSD, DragonFly BSD, and illumos archives
- Android debug APK
- unsigned re-signable IPA
- signed IPA when all Apple signing secrets are configured
- SHA-256 checksums

Every archive, APK, and IPA is opened and checked before GitHub uploads it.

## 6. Use the desktop client

### macOS or Linux package

1. Extract the archive.
2. Open Terminal in the extracted folder.
3. Run:

```bash
chmod +x start-router-vpn.sh modes/*.sh
sudo ./start-router-vpn.sh
```

4. Open `http://127.0.0.1:8788`.
5. Import `router-vpn-bundle.json` from the private client bundle.
6. Enter the router’s current public IPv4, global IPv6, or hostname if the bundle left it blank.
7. Save the router.
8. Choose **AUTO** and connect.

### Windows package

1. Extract the Windows ZIP.
2. Run `Start-RouterVPN.ps1`.
3. Open `http://127.0.0.1:8788` if it does not open automatically.
4. Import `router-vpn-bundle.json`.

The native Windows build is the controller/importer. The included multi-engine shell launchers require WSL2 or matching native WireGuard, AmneziaWG, sing-box, and Xray engines. Raw generated WG/AWG profiles can also be imported into matching native clients.

### Windows PortableApps-style package

1. Extract the ZIP anywhere.
2. Run `RouterVPNPortable.exe`.
3. Import `router-vpn-bundle.json`.

Settings and private imported profiles stay inside the package’s `Data` folder.

## 7. Choose a mode

For normal use, choose **AUTO**. It tries the lightest available mode first and escalates only when the connection test fails.

The recommended manual mode is:

```text
VLESS + TCP + REALITY + Vision + Chrome uTLS
```

The strongest choices are at the bottom:

```text
MAX TLS — Standard WireGuard base
MAX TLS — AmneziaWG 2 base
MAX QUIC — Standard WireGuard base
MAX QUIC — AmneziaWG 2 base
ALL
```

`ALL` tries both validated MAX TLS bases first, then both validated MAX QUIC bases. It uses every compatible generated layer; incompatible transports are alternatives rather than being falsely nested together.

See `docs/MODES.md` for all 19 modes, added latency, traffic increase, and estimated speed loss.

## 8. DAITA-like and Jumbo switches

- **DAITA-like Off/On:** On adds randomized cover traffic and extra overhead. It is not claimed to be exact Mullvad DAITA/Maybenot.
- **Jumbo Off/On:** use On only for compatible proxy TUN modes. Leave it Off for normal WireGuard and AmneziaWG.

## 9. Use normal SOCKS5 without the Router VPN app

The router provides a standard no-auth SOCKS5 endpoint. A device or app only needs the IP and port after it already has tunnel or home-LAN reachability.

Use the exact address shown in `CREDENTIALS.txt` or the imported router profile. With the example address:

```text
SOCKS5 host: 192.168.50.133
SOCKS5 port: 1080
Username: blank
Password: blank
Proxy DNS through SOCKS5: On
```

No Router VPN app is required on the app using SOCKS5. Never expose TCP `1080` to the internet.

For Router VPN’s app-only proxy option, enable **SOCKS5-only**, connect a WG/AWG tunnel, and point the selected local app to:

```text
127.0.0.1:1080
```

## 10. Port forwarding

Port forwarding is available while connected through WireGuard or AmneziaWG.

In the client UI:

1. Select TCP, UDP, or both.
2. Enter one outside port or a From/To range.
3. Enter the target port. Use `0` to preserve the same port or range.
4. Press **Apply**.
5. Press **Clear** when finished.

**Protected DMZ** is optional. Use it only after the router firewall guard is active and ASUS DMZ points to the AI Board. Management, VPN listener, SOCKS5, controller, SSH, Portainer, and AdGuard admin ports remain excluded by the guard.

## 11. Android APK

Install `RouterVPN-android-debug.apk`, open it, and import `router-vpn-bundle.json`.

The current APK securely stores and displays the router profile, modes, and SOCKS5 address. It does **not** claim full-device VPN tunneling because the Android `VpnService` adapter for WireGuard, AmneziaWG, Xray, and sing-box is not linked yet.

## 12. iPhone and iPad IPA

The workflow always attempts to produce:

```text
RouterVPN-unsigned-resignable.ipa
```

That IPA must be signed before installation. When the Apple secrets in `docs/BUILDS.md` are configured, the workflow also produces:

```text
RouterVPN-signed.ipa
```

The app imports the router bundle and shows every mode. The current Packet Tunnel extension intentionally reports that its native WireGuard/AmneziaWG/Xray/sing-box adapter is not linked, so signing alone does not make the custom app a working VPN yet.

For immediate iPhone use, import the generated standard WireGuard profile into WireGuard or an AmneziaWG profile into a compatible client.

## 13. Check the router

Run:

```bash
sudo /opt/router-vpn/source/server/scripts/doctor.sh
```

Also check:

```bash
sudo nft list table inet router_vpn_guard
```

If an advanced profile fails Xray or sing-box validation, the installer removes it from the private bundle and leaves the working basic modes available.
