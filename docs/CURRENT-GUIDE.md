# Router VPN — Current Guide

This is the authoritative setup and product guide for the current `main` branch.

## 1. Architecture

Router VPN has two user-facing parts:

1. **Home Setup Center** on the home AI Board at private port `8786`.
2. **Router VPN client/controller** for day-to-day use.

The server keeps the 20 raw runtime profiles internally for validation/AUTO compatibility, while the app presents **16 logical modes** so WireGuard vs AmneziaWG is a base choice instead of duplicate rows.

Normal development/release flow:

```text
source change
→ GitHub Actions
→ ARM64/runtime/client validation
→ exact-SHA server images + short-lived client artifacts
→ production
```

The **Portainer server stack stays image-only** for reliability. The router-local build fallback applies to **client downloads**: when the matching GitHub client artifact is unavailable, the AI Board compiles only the requested client package, streams it, and deletes temporary build/output files.

## 2. Portainer deployment

Use:

```text
Repository: https://github.com/Eabusham2/router-vpn.git
Reference:  refs/heads/main
Compose:    server/portainer-current.yaml
```

The repository is public, so Git repository authentication is normally **off**.

Normal environment values:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` is optional. Leave it unset/blank for public-endpoint auto-detection.

Expected one-shot containers:

```text
router-vpn-init       Exited (0)
router-vpn-finalize   Exited (0)
```

Expected long-running services:

```text
router-vpn-agent
router-vpn-wireguard
router-vpn-awg2
router-vpn-rosenpass
router-vpn-transports
router-vpn-xray
router-vpn-naive
router-vpn-ss-v2ray
router-vpn-aux
router-vpn-bundle-web
router-vpn-socks5
```

`router-vpn-bundle-web` is now the **dynamic Setup Center/download broker**, not the retired BusyBox static ZIP server.

## 3. Setup Center

On the home LAN:

```text
http://192.168.50.133:8786/
```

Health:

```text
http://192.168.50.133:8786/healthz
```

Never WAN-forward `8786`.

The Setup Center provides onboarding, guide, private node data, platform downloads, normal Windows Portable ZIPs, WireGuard/SS/SSR imports, SOCKS/OverTLS details, ASUS helper and diagnostics.

### Client download policy

```text
matching GitHub Actions artifact
↓ if unavailable/unusable
router-local build of requested package only
↓
inject private node data in temporary storage
↓
stream
↓
delete temporary build/output
```

The AI Board does **not** permanently cache every platform package. PortableApps/PAF is retired; normal Router VPN Portable ZIP x64/ARM64 remains supported.

## 4. ASUS Merlin forwarding

Use:

```text
router/asus-merlin-router-vpn-forwards.sh
```

Default WAN → AI Board mapping:

```text
TCP      80      -> 18080
TCP      443     -> 443
UDP      585     -> 585
TCP+UDP  8388    -> 8388
UDP      8443    -> 8443
TCP      10443   -> 10443
TCP      11443   -> 11443
TCP      12443   -> 12443
TCP+UDP  13443   -> 13443
TCP      14443   -> 14443
TCP+UDP  15443   -> 15443
UDP      51820   -> 51820
UDP      51822   -> 51822
```

External TCP `80` maps to internal `18080` for ACME. Never change that to `80 -> 80`.

Never WAN-expose:

```text
1080   plain trusted-LAN/tunnel SOCKS5
8786   Setup Center/download broker
8787   internal router API
14444  internal OverTLS backend
9443   Portainer
SSH
AdGuard admin
```

The helper preserves unrelated JFFS hooks. Current Router VPN hook calls are:

```text
router-vpn-forward.sh apply-nat
router-vpn-forward.sh apply-filter
```

If ASUS SCP/SFTP is unavailable, use SSH stdin:

```bash
ssh ROUTER_USER@192.168.50.1 'cat > /tmp/router-vpn-forwards.sh && chmod 755 /tmp/router-vpn-forwards.sh' < router/asus-merlin-router-vpn-forwards.sh
ssh ROUTER_USER@192.168.50.1 'sh /tmp/router-vpn-forwards.sh install'
```

Status:

```bash
ssh ROUTER_USER@192.168.50.1 '/jffs/scripts/router-vpn-forward.sh status'
```

## 5. Logical modes

The app exposes 16 logical modes:

| Logical mode | Base choice |
|---|---|
| Raw tunnel | Auto / WireGuard / AmneziaWG |
| Base tunnel + Rosenpass PQ | Auto / WireGuard / AmneziaWG |
| AmneziaWG Strong | AmneziaWG only |
| Shadowsocks 2022 | native |
| VLESS + REALITY + Vision | native |
| Hysteria2 + QUIC + Salamander | native |
| PQ VLESS + REALITY + Vision | native |
| Shadowsocks + V2Ray TLS | native |
| Naive HTTPS HTTP/2 | native |
| Naive HTTPS HTTP/3 + QUIC | native |
| Dual Transport | native |
| PQ REALITY + XHTTP + FinalMask | native |
| PQ Dual Transport | native |
| MAX QUIC | Auto / WireGuard / AmneziaWG |
| MAX TLS | Auto / WireGuard / AmneziaWG |
| ALL | Auto / WireGuard / AmneziaWG |

If a preferred base fails and the alternate succeeds, the app must report the real fallback. It must not silently claim the original base remained active.

### AUTO
Tries eligible modes from lightest/fastest upward and keeps the first healthy path.

### SMART AUTO
Connects first, remembers the last-good stack, tests safe simplifications, and restores the last-good stack if a reduction fails.

### CUSTOM
Selects the lightest validated stack satisfying all requested properties without redundant layers.

### MAX / ALL
MAX uses validated strong layered branches. ALL health-tests strongest MAX TLS branches first and then MAX QUIC fallback branches. Incompatible outer transports are alternatives, not fake nested layers.

## 6. DNS

Choices include:

- Fastest measured public DNS
- Home AdGuard
- Custom UDP/TCP
- DoT
- DoH
- DoH3
- DNS Rescue

Fastest uses **real DNS query RTT**, not ICMP ping. The app should show active selection clearly, include primary/secondary addresses where relevant, and support retesting.

## 7. SOCKS / compatibility services

Plain SOCKS5:

```text
192.168.50.133:1080
```

Trusted LAN/tunnel only, no authentication. Never WAN-forward `1080`.

OverTLS:

```text
Public:   14443/TCP
Backend:  127.0.0.1:14444
```

Never expose `14444`.

ShadowsocksR legacy compatibility:

```text
15443/TCP+UDP
```

Prefer modern Shadowsocks 2022 for new setups.

## 8. Platforms and honest boundaries

Main targets:

```text
iOS / iPadOS
Android
macOS ARM64 / x64
Windows x64 / ARM64
Linux x64 / ARM64
```

CI also compiles supported ARMv7/BSD/illumos targets.

- **macOS/Linux:** most complete current multi-engine client path.
- **Windows:** normal ZIP + Portable x64/ARM64 build and execute in CI. WSL transport execution is not proof of full-device Windows VPN; native TUN/Wintun + DNS routing remains required for that claim.
- **Android:** APK is a controller/importer shell until real `VpnService` adapters are linked.
- **iOS/iPadOS:** SwiftUI + Packet Tunnel target build, but Packet Tunnel intentionally fails closed until native tunnel engines are linked.
- **Multihop / strict kill switch:** remain unavailable until real networking implementations are validated.

## 9. Multiple nodes and latency

The client supports multiple saved Router VPN nodes, selected-node persistence, local map coordinates where actually known, and latency testing with at least about 50 TCP handshake samples where practical.

Useful metrics include:

```text
best
median
trimmed mean
average
p90
max
```

Do not fabricate map coordinates.

## 10. LAN access / public IP / MTU

LAN access should be explicit. Connected state should show the real public exit IP separately from a private proxy address.

DAITA-like traffic padding is bounded cover traffic. It is **not exact Mullvad DAITA/Maybenot**.

Jumbo TUN/MTU 9000 is advanced LAN/TUN behavior only; public Internet paths normally cannot carry Ethernet MTU 9000 end-to-end.

## 11. Validation

Browser-safe checks:

- Setup Center loads
- broker `/healthz`
- config syntax
- package generation
- endpoint info

Real VPN checks require actual handshake/TUN, route change, tunneled DNS, public IP change, IPv6 behavior, off-LAN reachability, and forwarding where applicable.

A green HTML page is not a green VPN mode.

## 12. Update

For Portainer:

```text
Stacks
→ router-vpn
→ Pull and redeploy
```

Keep the existing environment unless a release explicitly adds a required variable. The production Portainer compose remains **exact-SHA image-only**.

After update verify:

```text
router-vpn-init       Exited (0)
router-vpn-finalize   Exited (0)
all long-running services Running
http://192.168.50.133:8786/healthz = 200
```

Do not reinstall the ASUS helper unless ports/helper logic changed or the router lost its hooks.

## 13. Diagnostics

AI Board/Docker host:

```bash
sudo bash server/scripts/doctor-current.sh
```

ASUS router:

```bash
/jffs/scripts/router-vpn-forward.sh status
```

If a mode is unavailable, inspect the real checker/runtime reason. Never force it green in UI only.
