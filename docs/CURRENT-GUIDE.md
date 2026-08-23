# Router VPN — Current Guide

This is the authoritative setup and product guide for the current `main` branch. Source/build success is not a substitute for the separate physical-device, off-LAN, leak-negative, signing, visual-QA and production-deploy release gates.

## 1. Architecture

Router VPN has two user-facing parts:

1. **Home Setup Center** on the home AI Board at private port `8786`.
2. **Router VPN app** for day-to-day VPN use.

The server keeps the established 20 raw runtime profiles internally for validation/AUTO compatibility, while the app presents **16 logical modes** so WireGuard vs AmneziaWG is a base choice instead of duplicate rows.

Normal development/release flow:

```text
source change
→ GitHub Actions
→ ARM64/runtime/client validation
→ exact-SHA server images + short-lived client artifacts
→ exact-SHA production compose materialization
→ physical/off-LAN/manual release gates
→ production
```

The **production Portainer stack stays exact-SHA image-only**. Router-local client fallback is **Windows/Portable only**: it can build only a requested Windows x64/ARM64 installed or Portable generic package when the matching same-SHA GitHub artifact is unavailable. macOS/Linux require matching same-SHA artifacts or source built in their proper native build environments, and Android/iOS/iPadOS never use router-local builds. This fallback never turns production into a moving source build.

## 2. Portainer deployment

The tracked file:

```text
server/portainer-current.yaml
```

is the image-only production **template/baseline**, not proof that its embedded SHA equals the newest `main`. Do not directly redeploy that tracked baseline as a newer release merely because the filename says `current`.

For an actual release, use the artifact from the GitHub Actions workflow:

```text
Exact-SHA production compose
→ RouterVPN-production-compose-<40-character-release-SHA>
→ RouterVPN-Portainer-<40-character-release-SHA>.yaml
```

The generated YAML must be for the exact verified `main` SHA, its checksum must pass, `Publish ARM64 Portainer images` must have succeeded for that same SHA, and every Router VPN custom image tag plus `ROUTER_VPN_GITHUB_SHA` in the generated file must equal that SHA. See `docs/PRODUCTION-RELEASE.md` for the release contract.

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

`router-vpn-bundle-web` is the dynamic authenticated Setup Center/download broker, not the retired BusyBox static ZIP server.

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

The Setup Center provides onboarding, Full Guide, private node linking/pairing data, platform downloads, Simple Methods, ASUS helper/status guidance, Connected Clients, forwarding controls, recovery/diagnostics and server-side AI Help.

### Client download policy

```text
matching same-SHA GitHub artifact
↓ only for Windows x64/ARM64 installed/Portable when unavailable
bounded router-local build of that requested generic Windows package only
↓
validate/package the generic secret-free Windows application
↓
stream
↓
cleanup temporary build/output
```

macOS and Linux never use the AI Board as a substitute native build environment; they require matching same-SHA artifacts or source built in the correct native environment. Android and iOS/iPadOS never use router-local builds. Private node data is linked/imported separately after installation and is never baked into a public generic installer or Portable package. One installed app can link multiple nodes without reinstalling. PortableApps/PAF is retired; normal Router VPN Portable ZIP x64/ARM64 remains supported.

## 4. ASUS Merlin forwarding

Use:

```text
router/asus-merlin-router-vpn-forwards.sh
```

The helper is deliberately **fail-open for normal household Internet**. Router VPN never changes INPUT/FORWARD/OUTPUT policies, never flushes built-in chains, never adds DROP/REJECT rules, never touches IPv6, and never disables Runner/FlowCache/hardware acceleration. It adds only direct IPv4 parent-chain rules that already match the WAN interface + protocol + one exact Router VPN destination port. Unrelated WAN packets never enter a Router VPN catch-all chain.

A private `http://192.168.50.133:8786/healthz` check must succeed before new Router VPN exposure is installed. If the AI Board is down, malformed, or an iptables add fails, Router VPN removes only its own tagged exposure; ordinary LAN -> WAN, DNS/DHCP, ASUS-generated firewall state, AT&T/BGW rules and unrelated port forwards are left alone.

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

`14443/TCP` (OverTLS) and `15443/TCP+UDP` (legacy SSR) remain because current source still publishes those services. External TCP `80` maps to internal `18080` for ACME; never change it to `80 -> 80`.

Never WAN-expose:

```text
22/53   SSH / DNS management
1080    plain trusted-LAN/tunnel SOCKS5
3000    AdGuard UI
8786    Setup Center/download broker
8787    internal router API
8788-8793 internal client/control/update/health surfaces
9443    Portainer
14444   internal OverTLS backend
```

Every owned IPv4 rule carries `-m comment --comment ROUTER_VPN`. FORWARD rules are destination-scoped to `192.168.50.133`, exact-port scoped, and `NEW` only; normal ASUS ESTABLISHED/RELATED handling remains in charge.

Current persistent Merlin hook calls remain component-specific and idempotent:

```text
router-vpn-forward.sh apply-nat
router-vpn-forward.sh apply-filter
```

The helper also provides:

```text
router-vpn-forward.sh apply
router-vpn-forward.sh status
router-vpn-forward.sh verify
router-vpn-forward.sh remove
```

`verify` rejects the retired broad `PREROUTING -> ROUTER_VPN_DNAT` / `FORWARD -> ROUTER_VPN_FWD` layout, forbidden ports, duplicates, LAN->WAN mutations, and Router VPN IPv6 rules. `remove` deletes only Router-VPN-tagged/direct/legacy-owned rules and exact Router VPN hook lines; every unrelated line in `nat-start` / `firewall-start` is preserved.

No-reboot migration/update from Mac/Linux (SSH stdin also works when ASUS SFTP/scp is unavailable):

```bash
curl -fsS http://192.168.50.133:8786/asus-merlin-router-vpn-forwards.sh | ssh ROUTER_USER@192.168.50.1 'cat >/tmp/router-vpn-forwards.sh && chmod 755 /tmp/router-vpn-forwards.sh && sh /tmp/router-vpn-forwards.sh install && /jffs/scripts/router-vpn-forward.sh verify'
```

Status/verification:

```bash
ssh ROUTER_USER@192.168.50.1 '/jffs/scripts/router-vpn-forward.sh status && /jffs/scripts/router-vpn-forward.sh verify'
```

Inspect current router state before reinstalling/updating hooks. Preserve unrelated JFFS scripts and ASUS/AT&T firewall behavior.

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

If a preferred base fails and the alternate succeeds, the app reports the real fallback rather than claiming the original base stayed active.

### AUTO
Tries eligible modes from lightest/fastest upward and keeps the first proven healthy path.

### SMART AUTO
Connects first, remembers the last-good stack, tests safe simplifications, and restores the last-good stack if reduction fails.

### CUSTOM
Selects the lightest validated stack satisfying requested properties without redundant layers.

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

Fastest uses real DNS query RTT, not ICMP ping. Active selection and primary/secondary addresses are shown where relevant and can be retested. DNS policy is not itself proof that DNS actually traversed the selected VPN path; live leak-negative validation remains required.

## 7. Simple Methods and compatibility services

Setup Center **Simple Methods** are interoperable external/native-compatible configurations. Complex Router VPN logical stacks stay in the Router VPN app.

Current Simple Methods:

- WireGuard Raw
- AmneziaWG 2
- Shadowsocks 2022
- Hysteria2 + QUIC
- SOCKS5 + TLS / OverTLS compatibility
- ShadowsocksR legacy compatibility
- private in-tunnel SOCKS5

Public import URLs/QRs are emitted only when the required public endpoint/config is actually known. Private SOCKS5 remains:

```text
192.168.50.133:1080
```

It is trusted LAN/tunnel only, no authentication, and must never be WAN-forwarded.

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

External-app compatibility remains a **live off-LAN gate**: import → connect → tunneled DNS → HTTP → exact public-exit proof must succeed in a genuinely compatible external client.

## 8. Platforms and honest boundaries

Main first-class targets:

```text
iOS / iPadOS
Android
macOS ARM64 / x64
Windows x64 / ARM64
Linux x64 / ARM64
```

CI also compiles supported ARMv7/BSD/illumos controller targets where documented. CI/source success does not replace physical full-device validation.

### Windows

The daily-use app is native WPF. Raw/native WireGuard, native full-device layered TUN paths, Router VPN DNS policy, Windows firewall kill-switch handling and real multihop source paths are implemented. WSL is not counted as the native Windows VPN implementation. Validated custom exits support WireGuard, SOCKS5, Shadowsocks and Hysteria2. OpenVPN 2.7 profile import and native helper/adapter source remain implemented because Windows OpenVPN is still a project target, but current product capability reports it unavailable until strict Windows lifecycle cleanup passes native leak tests. Expected public exit must be proven before Connected for every supported exit.

**Release gate:** physical Windows full-device routing, DNS/IPv4/IPv6, leak-negative behavior, reconnect/network change, custom exits and installed/Portable package variants. Windows OpenVPN remains unavailable until its native strict lifecycle/leak gate passes.

### macOS

The daily-use app is native AppKit/MapKit. Native routing, PF kill switch, real multihop and validated custom exits are source-implemented. WireGuard/SOCKS5/Shadowsocks/Hysteria2 are supported custom exits; OpenVPN 2.7 is supported for direct and the safe TCP-over-entry case, with unsupported DNS/hop combinations failing closed.

**Release gate:** physical macOS networking/custom-exit/visual validation plus signing/notarization.

### Linux

The daily-use app is native GTK. Linux has broad native runtime coverage, nftables kill switch, real multihop, validated external-node import/direct/hopped paths, measured node sorting and native OpenVPN 2.7 direct/safe TCP-over-entry support with expected-public-exit proof.

**Release gate:** live distro/runtime/desktop integration and leak-negative/custom-exit validation.

### Android

Android is a native `VpnService` application. It has real WireGuard and AmneziaWG paths plus the pinned combined libbox/Xray path for supported layered modes, AUTO/SMART/CUSTOM orchestration, strict-policy handling, exact selected-node proof and a deliberately narrow real multihop subset. External WireGuard, SOCKS5, Shadowsocks and Hysteria2 exits use one full-device path and exact expected-public-exit proof. OpenVPN and unsupported mixed-engine/AWG-entry multihop stay unavailable rather than simulated.

**Release gate:** physical Android VPN permission, lockdown, reconnect/network-change, DNS/IPv4/IPv6, custom-exit traffic and leak-negative tests.

### iOS / iPadOS

The SwiftUI app uses a real pinned WireGuardKit PacketTunnel for raw WireGuard and a pinned Libbox Apple bridge for supported Router VPN layered profiles. Strict mode uses NetworkExtension route-lockdown controls and fails closed if those controls are not active. External WireGuard, SOCKS5, Shadowsocks and Hysteria2 use the Libbox PacketTunnel path and exact expected-public-IP proof. External OpenVPN, AmneziaWG-only paths and full desktop-equivalent multihop remain unavailable unless a real pinned Apple dataplane exists; MAX/ALL names do not grant readiness.

**Release gate:** physical iPhone/iPad permission, route lockdown, reconnect/network change, DNS/IPv4/IPv6, Libbox/external-exit traffic, leak-negative behavior and signing validation.

## 9. Nodes, maps, latency and custom exits

The app supports multiple linked/saved Router VPN nodes without reinstalling. Native node managers support current/recent, last-used, measured-latency and name ordering. Automatic lowest-latency selection is withheld until at least two usable nodes have real measurements. Node latency testing uses at least about 50 TCP handshake samples where practical, with real statistics rather than one-shot guesses.

Coordinates are displayed only when actually known. Coordinate-less nodes remain usable in lists and are never assigned invented locations.

Custom standard-protocol exits are separate from Router VPN `CUSTOM` transport selection and from Setup Center Methods. Current product capability:

- WireGuard — Windows/macOS/Linux/Android/iOS
- SOCKS5 — Windows/macOS/Linux/Android/iOS
- Shadowsocks — Windows/macOS/Linux/Android/iOS
- Hysteria2 — Windows/macOS/Linux/Android/iOS
- OpenVPN — Linux/macOS where the native OpenVPN 2.7 runtime and requested direct/hop policy are supported; Windows import/helper/adapter source remains a target but is unavailable until native strict lifecycle/leak validation passes

Private external-profile credentials stay private; public list/status APIs expose redacted summaries. Connected requires exact expected-public-exit proof.

## 10. LAN access / forwarding / public IP / MTU

LAN access is explicit. When LAN access is OFF, tunnel peers are blocked from ordinary access to both the AI Board's home-LAN address space and forwarded home-LAN destinations, while the private tunnel control path remains available for the minimum recovery/control plane.

Explicit inbound forwarding requested by a daily client is authenticated and peer-owned; clearing it removes only that peer's tagged rules. Broad **Protected DMZ** is an authenticated Setup Center/server-admin action, not a tunnel-peer shortcut. Its allowed ranges exclude reserved infrastructure ports and enabled explicit forwarding ranges.

Connected state shows the real public exit separately from private proxy addresses.

DAITA-like traffic padding is bounded cover traffic; it is not exact Mullvad DAITA/Maybenot.

MTU support includes catalog/default, manual, PMTU-safe auto selection, effective-MTU proof metadata, per-path memory and an explicit Jumbo `9000` policy where requested. The throughput-aware optimizer tests safe candidate MTUs only after the selected private path is proven and restores the original MTU on failure. Jumbo 9000 is not claimed to work Internet-wide.

## 11. AI Help

Setup Center AI Help is server-side. Supported adapters are OpenAI, Gemini, Anthropic/Claude, DeepSeek, xAI/Grok, Moonshot/Kimi and a restricted private/local OpenAI-compatible endpoint. Provider credentials stay server-side in private files; repository/runtime/page context is bounded and redacted. Web capability is optional and never grants arbitrary SSRF access.

Use `server/scripts/configure-ai-help.sh` locally on the Router VPN host to configure/disable it. Real-provider/local-endpoint operation remains a live release gate.

## 12. Validation and update

Browser/source-safe checks include Setup Center load, `/healthz`, syntax/contracts, package generation/checksums, exact-SHA builds and endpoint metadata. Real VPN checks require actual VPN permission/handshake/TUN, route change, tunneled DNS, public-IP proof, IPv6 behavior, fail-closed/leak-negative transitions, off-LAN reachability and forwarding where applicable. A green page or CI job is not a green live VPN path.

For a Portainer production update, first choose one verified exact `main` SHA and require the exact-head build/release gates, including **Publish ARM64 Portainer images** and **Exact-SHA production compose**, to succeed for that same SHA. Download the `RouterVPN-production-compose-<sha>` artifact, verify its `.sha256`, verify all Router VPN custom image tags and `ROUTER_VPN_GITHUB_SHA` equal the selected SHA, then deliberately update the `router-vpn` stack using that generated YAML. Full procedure: `docs/PRODUCTION-RELEASE.md`.

Keep the existing environment unless a release explicitly adds a required variable. Production remains exact-SHA image-only. Do not deploy the tracked baseline, an older generated compose, or an old RC merely because it once passed.

After update verify:

```text
router-vpn-init       Exited (0)
router-vpn-finalize   Exited (0)
all long-running services Running
http://192.168.50.133:8786/healthz = 200
running Router VPN custom images/provenance = selected release SHA
```

Do not reinstall the ASUS helper unless its Router VPN port/helper logic changed or the router lost its hooks; inspect current state first.

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

Use `docs/CURRENT-STATUS.md` for the current source-vs-live release boundary, `docs/NATIVE-APPS.md` for native application specifics, `docs/CLIENT.md` for linking/client notes, and `docs/PRODUCTION-RELEASE.md` for exact-SHA production materialization/deployment.
