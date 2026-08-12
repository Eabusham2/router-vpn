# Install and use Router VPN clients

The complete server/router walkthrough is in `docs/CURRENT-GUIDE.md`. This file focuses on linking devices after the home node exists.

## Recommended link path

You normally **do not need `router-vpn-client-bundle.zip`**.

1. Stay on the home LAN.
2. Open `http://AI_BOARD_IP:8786/`.
3. Install the small client package for the device, or use the platform-native/simple protocol instructions.
4. Link Router VPN with the small private `router-vpn-bundle.json`:
   - use **Import from home LAN** when the native app exposes it, or
   - download/import `router-vpn-bundle.json` from Files.
5. Start with **Raw tunnel** using **Base: Auto**. Auto prefers the saved/default base and can fall back to the other compatible base.
6. Verify the public exit IP before moving to stronger methods.

The full private bundle remains available **on demand** for offline recovery/advanced installs; the AI Board does not retain the generated ZIP after delivery.

## Setup Center

The Setup Center is the server/router onboarding and compatibility surface. It is LAN-only by design and provides:

- persistent onboarding and full guide
- ASUS SSH/JFFS/forwarding checks and helper download
- current fixed WAN listener list and private ports that must never be exposed
- direct private bundle/profile downloads
- platform packages and checksums
- WireGuard and AmneziaWG configs / QR codes
- Shadowsocks 2022 URL/config/QR
- Hysteria2 URL/config/QR
- Shadowsocks + V2Ray-plugin material
- VLESS/REALITY, XHTTP/FinalMask and Naive configs
- SOCKS5 + TLS / OverTLS
- ShadowsocksR legacy compatibility
- plain internal SOCKS5 instructions
- custom/universal protocol files where a native OS import does not exist

Large packages are requested through the download broker. It prefers the matching short-lived GitHub Actions artifact, overlays this node's private profiles in temporary storage, streams the requested package, then deletes that temporary copy. If the GitHub artifact is unavailable, the AI Board compiles **only the requested client package** locally with the bounded runtime Go toolchain, applies the private node data in temporary storage, streams it, then deletes the temporary build/output.

QR images are generated on the home node. Treat the page, private JSON, QR codes and generated profiles as credentials.

## Logical modes and base selection

The app shows one row per **logical** method instead of duplicating WireGuard and AmneziaWG runtime variants. The server still retains the raw 20-mode catalog internally for AUTO and compatibility.

For compatible logical methods, choose:

- **Auto** — preferred base first, alternate compatible base as fallback
- **WireGuard**
- **AmneziaWG**

The current logical mapping lives in `configs/client/logical-modes.json`. Availability comes from the real generated-profile checkers; a logical row remains ready when at least one allowed base validates. If the preferred base is unavailable and fallback is valid, the UI should show that explicitly rather than greying the entire logical mode.

## macOS — Apple Silicon and Intel

The Setup Center provides architecture-specific packages on demand. The legacy/full bundle install path remains supported:

```bash
bash client/install-macos-final.sh "$PWD"
```

If macOS flags a locally-built component:

1. verify the package/binary checksum against the Setup Center `SHA256SUMS`;
2. use **System Settings → Privacy & Security → Open Anyway** for that verified Router VPN item;
3. if necessary, remove quarantine only from the verified extracted Router VPN folder:

```bash
xattr -dr com.apple.quarantine /path/to/router-vpn
```

Do not remove quarantine broadly from Downloads or unrelated files.

The desktop controller stores each imported node separately and can report the public VPN exit independently of the private SOCKS5 address.

## Windows — x64 and ARM64

GitHub Actions produces normal Windows packages and Router VPN's own no-install **Portable ZIPs** for both architectures. The home Setup Center provides the matching package on demand and does not retain a server-side ZIP after delivery.

PortableApps.com/PAF packages are not produced or supported. Use `RouterVPN-Portable-Windows-amd64.zip` or `RouterVPN-Portable-Windows-arm64.zip` for the no-install portable layout.

The existing complete multi-engine shell path can use the Linux transport runtime through WSL2. Native WireGuard/AmneziaWG profile import remains available in matching Windows clients. WSL execution alone is not claimed as a complete full-device Windows tunnel.

## Linux / Unix

Common direct packages are produced for Linux x64 and ARM64. GitHub Actions also builds Linux ARMv7 and the supported BSD/illumos targets listed in the root README.

Legacy Linux install path:

```bash
sudo bash client/install-linux.sh "$PWD"
```

## iPhone / iPad

The SwiftUI Router VPN app supports the native app UX, private bundle import from Files or directly from the home LAN, logical-mode/base selection, home-LAN access settings, forwarding controls and the permanent setup guide.

**Platform tunnel boundary:** the included Packet Tunnel target intentionally fails closed until the actual WireGuard/AmneziaWG and proxy engines are linked and validated. Its `completionHandler(error)` path is therefore an expected limitation, not an accidental build/runtime error. Until those adapters exist, use the generated Setup Center profiles in compatible native clients.

The Router VPN UI follows the real NetworkExtension status and does not mark itself connected merely because `startVPNTunnel()` was called.

## Android

The APK is currently the native Router VPN controller/importer shell. It must not claim full-device VPN operation until its `VpnService` engine integration is linked and validated.

Live protocol profiles remain importable into matching Android clients from the Setup Center. Android native engine work is tracked separately from server/runtime readiness so mobile UI status cannot make a server mode appear green by itself.

## Multiple routers / nodes

Each imported node stores separate generated profile material. The desktop/controller surface supports:

- remembered selected node and use count
- local coordinates/map
- sorting by median latency, 10% trimmed mean, usage, distance or name
- at least 50 TCP handshake samples per requested node test
- min / median / trimmed mean / average / p90 / max

Import another node's private JSON while disconnected, then select it.

## DNS

Default: **Home AdGuard**.

Other supported policy/configuration choices include:

- fastest measured public DNS from the home exit
- common primary/secondary IPv4 and IPv6 resolvers
- custom UDP or TCP DNS
- DoT
- DoH
- DoH3
- DNS Rescue fallback policy

The server benchmark performs actual DNS queries and reports query timing rather than treating ICMP ping as DNS latency.

## SOCKS5

The home SOCKS5 service is an internal LAN/tunnel service. It uses its IP + port and currently has no authentication. **Never WAN-forward TCP 1080.**

The app must display that private proxy address separately from the public VPN exit address.

## SOCKS5 + TLS / OverTLS

Generated compatibility path:

```text
Public TCP:       14443
Private backend:  127.0.0.1:14444
```

Never WAN-forward backend TCP 14444. OverTLS is a compatibility method outside the main AUTO runtime ladder.

## ShadowsocksR

Generated legacy compatibility listener:

```text
Public TCP+UDP: 15443
```

Prefer modern Shadowsocks 2022 or other current methods for new setups. SSR remains outside AUTO.

## Port forwarding / Protected DMZ

Inbound forwarding requires an authenticated tunnel peer path, normally WireGuard or AmneziaWG. Proxy-only methods are outbound.

The client supports TCP, UDP, both, a port/range, optional translated target port and Protected DMZ. Protected DMZ excludes reserved VPN, SSH, DNS, management, Portainer, Setup Center/API and internal SOCKS5 ports.

## Availability / grey-mode rule

Do not hide a broken mode and do not force it green. Generated configuration checks decide readiness. CI regenerates and validates the combined/MAX branches that previously produced relative-certificate and shell-variable errors before the branch is eligible for deployment.
