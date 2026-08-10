# Router VPN — Current Guide

This is the authoritative current setup guide. Use `server/portainer-current.yaml` for Portainer deployments and the in-client **Run full onboarding again** flow for the same steps interactively.

## Small summary

Router VPN is one home node with 20 ordered manual modes plus fast **AUTO**, slower **SMART AUTO**, constrained **CUSTOM**, Standard WireGuard/AmneziaWG 2 bases, live Rosenpass post-quantum PSK rotation, Xray VLESS/REALITY/Vision, Shadowsocks, V2Ray-plugin TLS, Hysteria2/QUIC, Naive HTTPS H2/H3, XHTTP/FinalMask, PQ MAX TLS/QUIC branches, and **ALL** with health-tested TLS-to-QUIC fallback.

It also includes IPv4 + IPv6, Home AdGuard/custom/public DNS and encrypted DNS policies, DNS Rescue, DAITA-like bidirectional cover traffic, Jumbo TUN on compatible proxy/TUN modes, tunnel-only no-auth SOCKS5, and configurable port/range/TCP/UDP/both/Protected-DMZ forwarding.

**Boundaries:** DAITA-like is not exact Mullvad Maybenot/DAITA. Jumbo payloads may enter a tunnel-facing interface but public-Internet packets still have to be segmented to the real path MTU. Android/iOS controller builds do not claim full native all-mode tunneling until their platform tunnel adapters are linked.

## Mode chart — lightest to strongest

| # | Mode | Main stack | Added ping | Traffic increase | Speed loss |
|---:|---|---|---:|---:|---:|
| 1 | WireGuard Raw | WireGuard | 0.1–0.8 ms | +3–5% | 0.5–2% |
| 2 | AmneziaWG 2 Fast | AmneziaWG 2 + light obfuscation | 0.2–1.5 ms | +4–7% | 0.7–3% |
| 3 | WireGuard + Rosenpass PQ | WireGuard + live Rosenpass PQ PSK rotation | 0.2–1.2 ms | +3–6% | 0.7–3% |
| 4 | Shadowsocks 2022 | Shadowsocks 2022 | 0.8–3.5 ms | +4–9% | 2–8% |
| 5 | AmneziaWG 2 Strong | AmneziaWG 2 + stronger randomized obfuscation | 0.3–2.5 ms | +6–12% | 1.5–6% |
| 6 | AmneziaWG 2 + Rosenpass PQ | AmneziaWG 2 + strong obfuscation + Rosenpass PQ | 0.4–3 ms | +6–13% | 2–7% |
| 7 | VLESS + REALITY + Vision + Chrome uTLS — RECOMMENDED | Xray VLESS + TCP 443 + REALITY + XTLS Vision + Chrome fingerprint; sing-box TUN | 0.7–3 ms | +4–8% | 2–6% |
| 8 | Hysteria2 + QUIC + Salamander | Hysteria2 + QUIC + Salamander | 0.8–4 ms | +6–12% | 3–10% |
| 9 | PQ VLESS + REALITY + Vision | Hybrid-PQ VLESS + REALITY + Vision | 0.9–3.5 ms | +5–10% | 2.5–7% |
| 10 | Shadowsocks + V2Ray-plugin TLS | Shadowsocks 2022 + V2Ray SIP003 + WebSocket/TLS; Hysteria2/QUIC for UDP | 1.5–6 ms | +7–14% | 4–12% |
| 11 | Naive HTTPS HTTP/2 | Naive HTTPS + HTTP/2 + UDP-over-TCP v2 | 2–8 ms | +8–18% | 6–16% |
| 12 | Naive HTTPS HTTP/3 + QUIC | Naive HTTPS + HTTP/3/QUIC | 1.5–7 ms | +8–18% | 5–15% |
| 13 | Dual Transport | REALITY/Vision/uTLS for TCP + Hysteria2/QUIC for UDP | 1–5 ms | +6–14% | 3–12% |
| 14 | PQ VLESS + REALITY + XHTTP + FinalMask | PQ VLESS + REALITY + XHTTP + FinalMask + Chrome fingerprint | 1.5–7 ms | +7–15% | 5–14% |
| 15 | PQ Dual Transport | PQ REALITY/Vision for TCP + Hysteria2/QUIC for UDP | 2–9 ms | +10–22% | 7–18% |
| 16 | MAX QUIC — PQ WireGuard base | WireGuard + Rosenpass PQ → Shadowsocks 2022 → Hysteria2/QUIC | 4–16 ms | +20–70% | 15–40% |
| 17 | MAX QUIC — PQ AmneziaWG 2 base | AmneziaWG 2 + Rosenpass PQ → Shadowsocks 2022 → Hysteria2/QUIC | 4.5–18 ms | +23–75% | 17–43% |
| 18 | MAX TLS — PQ WireGuard base | WireGuard + Rosenpass PQ → Shadowsocks 2022 → PQ VLESS/REALITY/XHTTP/FinalMask | 5–20 ms | +25–80% | 18–45% |
| 19 | MAX TLS — PQ AmneziaWG 2 base | AmneziaWG 2 + Rosenpass PQ → Shadowsocks 2022 → PQ VLESS/REALITY/XHTTP/FinalMask | 5.5–22 ms | +28–85% | 20–48% |
| 20 | ALL | Health-tests complete PQ MAX TLS branches, then PQ MAX QUIC fallback branches | 5–25 ms | +25–100% | 18–60% |

**AUTO** tries modes 1→19 and immediately keeps the first one that passes a real connectivity check. **SMART AUTO** gets connected first, then tests declared layer removals/replacements and restores the last-good stack whenever simplification fails. **CUSTOM** takes the layers you select and chooses the lightest already-validated compatible profile containing all of them. **ALL** keeps mutually exclusive outer transports in separate strongest branches instead of fake-nesting them.

## Complete first-run tutorial

### 1. Deploy the home node on the ASUS AI Board

Open **Portainer → Stacks → Add stack → Repository**.

Use:

```text
Name: router-vpn
Repository reference: refs/heads/main
Compose path: server/portainer-current.yaml
```

If the repository is private, enable Git authentication. If it is public, authentication can stay off.

Normal environment values:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
```

`ENDPOINT` is optional. Leave it unset/blank for automatic public-IP detection, or set your public IPv4/IPv6/hostname manually. The listener ports already have defaults.

Deploy the stack.

### 2. Verify the stack before exposing WAN ports

Expected one-shot containers:

```text
router-vpn-init      exited 0
router-vpn-finalize  exited 0
```

That is normal. Do not restart them just because they are exited.

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
router-vpn-bundle-web
router-vpn-socks5
```

Optional host check:

```bash
sudo bash server/scripts/doctor-current.sh
```

Fix core failures before adding WAN forwarding.

### 3. Download the private client bundle

While on your home LAN open:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

Extract it and keep it private. It contains router-specific profiles/keys plus the persistent ASUS forwarding helper:

```text
router/asus-merlin-router-vpn-forwards.sh
```

### 4. Install the ASUS Merlin WAN forwards

From a computer on your LAN, copy the helper to the ASUS router and run it through SSH:

```bash
scp router/asus-merlin-router-vpn-forwards.sh ROUTER_USER@192.168.50.1:/tmp/router-vpn-forwards.sh
ssh ROUTER_USER@192.168.50.1 'sh /tmp/router-vpn-forwards.sh install'
```

The helper auto-detects the active WAN interface, creates dedicated Router VPN iptables chains, and appends persistent calls to `/jffs/scripts/nat-start` and `/jffs/scripts/firewall-start` without replacing existing script content.

Default WAN mappings:

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
UDP      51820   -> 51820
UDP      51822   -> 51822
```

The destination is the AI Board/Docker host, normally `192.168.50.133`.

**Important:** external TCP 80 goes to **internal TCP 18080**, not the AI Board's port 80. Port 80 on the AI Board can remain the AdGuard block page. ASUS TCP 8443 management does not conflict with Router VPN's **UDP** 8443.

Never WAN-expose:

```text
1080   SOCKS5
8786   private bundle server
8787   internal router-agent API
9443   Portainer
SSH
AdGuard admin
```

To inspect the persistent rules later:

```bash
/jffs/scripts/router-vpn-forward.sh status
```

If you intentionally changed VPN listener ports in Portainer, run the helper with matching environment overrides for `WG_PORT`, `AWG_PORT`, `ROSENPASS_PORT`, `REALITY_PORT`, `HY2_PORT`, `SS_PORT`, `XRAY_PQ_PORT`, `XHTTP_PORT`, `SS_V2RAY_PORT`, or `NAIVE_PORT`.

### 5. Install the desktop client

macOS, from the extracted bundle as your normal user:

```bash
bash client/install-macos-final.sh "$PWD"
```

Linux:

```bash
sudo bash client/install-linux.sh "$PWD"
```

Open:

```text
http://127.0.0.1:8788
```

The first launch opens the full onboarding automatically. Its current step is saved if you close it. **Finish** marks setup complete and keeps it dismissed later. **Help & setup → Run full onboarding again** reopens it without deleting your saved router profile.

### 6. Import/select the home-router profile

Use **Import router bundle** and choose `router-vpn-bundle.json` from the extracted bundle. This carries the endpoint, internal API/token, generated profiles, AdGuard/SOCKS settings, DNS benchmark result and mode catalog.

You may keep multiple router profiles and choose them at runtime. The normal base selector is Standard WireGuard or AmneziaWG 2.

### 7. Choose DNS

Default:

```text
Fastest measured at home
```

The server benchmarks real A/AAAA DNS query RTT from the home exit, including IPv4/IPv6 candidates. Alternatives:

```text
Home AdGuard
Custom UDP/TCP DNS
DNS over TLS
DNS over HTTPS
DNS over HTTPS/3
DNS Rescue
```

DNS Rescue helps with name-resolution interference/captive or filtered networks; it is not presented as a magical bypass for a direct-IP VPN handshake.

### 8. Choose connection behavior

For the fastest automatic connection, press **AUTO**.

For slower optimization, press **SMART AUTO**.

For manual control, choose any numbered mode and press **Connect selected**.

For a required-layer combination, open **CUSTOM layer picker**, select the layers, save the router profile, then press **CUSTOM**.

Options:

```text
DAITA-like Off = normal traffic
DAITA-like On  = bounded bidirectional cover traffic
Jumbo TUN      = optional on compatible TUN/proxy modes
SOCKS5-only    = app/proxy path instead of normal full VPN
```

### 9. Plain SOCKS5

After a VPN path to home exists, normal SOCKS5-capable applications can use the profile's SOCKS address, normally:

```text
192.168.50.133:1080
```

There is no username/password. You do not need the custom Router VPN app for the program consuming SOCKS5. TCP 1080 remains unavailable from public WAN.

### 10. Incoming port forwarding / Protected DMZ

The client Port forwarding card supports:

```text
TCP
UDP
both
single port
port range
same or custom target port
Protected DMZ
```

Protected DMZ forwards unused ports while reserving Router VPN listeners plus management, DNS, Portainer, SSH, bundle/API and SOCKS5 ports.

Incoming connections to the remote device require a WireGuard/AmneziaWG peer path: raw WG/AWG, their Rosenpass variants, MAX, or ALL. Proxy-only outer modes are outbound-only for arbitrary inbound forwarding.

### 11. Optional checks/tests

Safe local client check: **Help & setup → Run safe client checks**.

AI Board/Docker host:

```bash
sudo bash server/scripts/doctor-current.sh
```

ASUS router:

```bash
/jffs/scripts/router-vpn-forward.sh status
```

A live VPN protocol test only counts after an actual connection and mode health/handshake check. Test WAN reachability from cellular/off-LAN. Generic UDP port checkers do not prove WireGuard/AWG/Hysteria handshakes.

### 12. Update later

For Portainer Git stacks, pull/redeploy the same:

```text
server/portainer-current.yaml
```

Current-version profile credentials are preserved. If an older profile-engine layout requires a one-time migration, download/import the private client bundle once afterward.

Terminal-managed installs can use:

```bash
sudo bash server/manage.sh
```

## Build artifacts

The single GitHub Actions workflow builds the all-in-one project ZIP, Windows x64/ARM64 and PortableApps packages, macOS Intel/Apple Silicon, Linux, Unix/BSD/illumos packages, Android APK, unsigned re-signable IPA, optional signed IPA when signing secrets exist, checksums, and aggregate all-platform archives.

The macOS/Linux path has the full engine installers today. Android/iOS controller/importer artifacts and other platform packages must not be described as having identical native all-mode tunnel-engine parity until those platform-specific adapters are actually linked and tested.
