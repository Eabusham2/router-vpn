# Router VPN — Current Guide

This is the authoritative guide for the current stack. Use `server/portainer-current.yaml` for Portainer deployments.

## Small summary

Router VPN now provides one home node with a least-to-strongest manual picker, fast **AUTO**, slower **SMART AUTO**, constrained **CUSTOM** stacks, Standard WireGuard or AmneziaWG 2 bases, live Rosenpass post-quantum PSK rotation, Xray VLESS/REALITY/Vision, Shadowsocks, V2Ray-plugin TLS, Hysteria2/QUIC, Naive HTTPS H2/H3, XHTTP/FinalMask, PQ MAX TLS/QUIC branches, and **ALL** with health-tested TLS-to-QUIC fallback.

It also includes IPv4 + IPv6, Home AdGuard/custom/public DNS and encrypted DNS policies, DNS Rescue, DAITA-like bidirectional cover traffic, Jumbo TUN on compatible proxy/TUN modes, tunnel-only no-auth SOCKS5, and configurable port/range/TCP/UDP/both/protected-DMZ forwarding. Generated modes fail closed when their required engine/config is unavailable instead of silently dropping a claimed layer.

**Important:** the traffic-shaping toggle is DAITA-like, not Mullvad's exact Maybenot/DAITA implementation. The estimates below are same-route estimates, not measured guarantees, and exclude the physical latency of traveling back to the home node.

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

**AUTO** is not another tunnel: it tries modes 1→19 and immediately keeps the first one that passes a real connectivity check. **SMART AUTO** intentionally takes longer: it gets connected first, then tests declared layer removals/replacements and restores the last working stack whenever a reduction fails. **CUSTOM** takes the layers you select and chooses the lightest already-validated compatible profile containing all of them; impossible combinations are rejected instead of being fabricated.

DAITA-like cover traffic is an independent On/Off toggle and can add traffic beyond the table. The **Base tunnel** selector chooses Standard WireGuard or AmneziaWG 2 when a MAX/ALL/CUSTOM branch has both compatible bases.

## Simple tutorial

### A. Install the home node with Portainer

1. Open the ASUS AI Board / Portainer page.
2. In Portainer open **Stacks → Add stack → Repository**.
3. Enter this private repository and your GitHub credentials/token.
4. Set the Compose path to:

```text
server/portainer-current.yaml
```

5. Add these environment variables:

```text
WAN_INTERFACE=eth0
LAN_CIDR=192.168.50.0/24
ADGUARD4=192.168.50.133
ENDPOINT=
```

Leave `ENDPOINT` blank to let the finalizer detect the public IPv4, or enter the home public IP yourself. Leave all other variables at their defaults unless you want custom ports.

6. Press **Deploy the stack**.
7. Wait until `router-vpn-init` and `router-vpn-finalize` finish successfully and the long-running Router VPN containers show as running.

### B. Add the ASUS WAN forwards

Forward these to the AI Board / Docker host (`192.168.50.133` in this example):

```text
TCP      80      -> 80
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

Do **not** forward `1080`, `8786`, `8787`, Portainer, SSH, or the AdGuard admin page.

If you changed any listener port in Portainer, forward that custom port instead. Protected DMZ automatically reserves the generated listener ports.

### C. Download the private client bundle

While connected to your home LAN, open:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

Extract it. Keep this ZIP private because it contains the router-specific client profiles/keys.

### D. Install the client

#### macOS

Open Terminal in the extracted folder and run as your normal user:

```bash
bash client/install-macos-complete.sh "$PWD"
```

Enter the Mac password when `sudo` asks. Then open:

```text
http://127.0.0.1:8788
```

#### Linux

Open a terminal in the extracted folder:

```bash
sudo bash client/install-linux.sh "$PWD"
```

Then open:

```text
http://127.0.0.1:8788
```

If the router address is blank in the UI, use **Import router bundle** and select `router-vpn-bundle.json` from the extracted folder.

### E. Choose the normal settings

In the client:

1. **Base tunnel:** choose Standard WireGuard or AmneziaWG 2.
2. **DNS:** choose Fastest measured at home, Home AdGuard, Custom, DoH, DoT, or DNS Rescue. Public DNS timing is measured by real DNS queries at the home exit; IPv4 and IPv6 candidates are tested.
3. Leave **DAITA-like** Off for normal speed, or turn it On when you want bidirectional cover traffic.
4. Leave **Jumbo TUN** Off unless you specifically need it on a compatible proxy/TUN mode.
5. Leave **SOCKS5-only** Off for a normal full VPN.
6. Press **AUTO** for the quickest automatic connection, **SMART AUTO** for slower optimization, or select a mode manually.

### F. Use plain SOCKS5

After the VPN reaches home, point any SOCKS5-capable app at:

```text
192.168.50.133:1080
```

There is no SOCKS username or password. Port `1080` stays blocked from the public WAN.

### G. Port forwarding / Protected DMZ

In the client **Port forwarding** card choose TCP, UDP, or both; enter a single port or range; then press **Apply**. Use **Protected DMZ** to forward all unused ports while keeping Router VPN, management, DNS, Portainer, SSH, and SOCKS5 ports reserved.

For incoming connections to the remote device, use a mode that has a WireGuard/AmneziaWG peer path: raw WG/AWG, their Rosenpass variants, MAX, or ALL. Proxy-only modes are outbound tunnels and do not create an inbound peer address.

### H. Check the router

If you have a host terminal, from the repository run:

```bash
sudo bash server/scripts/doctor-current.sh
```

A fresh current install should have no core failures. Optional modes that cannot be supported by an installed client engine are reported as warnings/disabled rather than silently downgraded.

### I. Update later

For Portainer Git stacks, pull/redeploy the same `server/portainer-current.yaml`. The current finalizer preserves current-version profile credentials. An older profile-engine layout may migrate once; after such a migration, download/import the new private client bundle once.

If you use a host terminal instead, run from the updated repository:

```bash
sudo bash server/manage.sh
```

### Build artifacts

The single GitHub Actions workflow builds the all-in-one project ZIP, Windows and PortableApps packages, macOS, Linux, Unix/BSD/illumos packages, Android APK, an unsigned re-signable IPA, an optional signed IPA when Apple signing secrets are configured, checksums, and an aggregate all-platform archive.

The current Android and iOS projects build controller/importer applications, but the native mobile packet-tunnel engines for the full desktop mode set are not yet linked. Do not treat those mobile artifacts as full all-mode VPN clients until that adapter work is completed.
