# Modes

Modes are listed from the lightest/least intensive to the strongest/heaviest. Added ping and traffic are same-route engineering estimates; the travel distance back home is separate.

| Order | Mode | Layer stack | Added ping | Traffic increase | Speed loss | State |
|---:|---|---|---:|---:|---:|---|
| AUTO | First working eligible profile | Tries the eligible modes below in order and stops at the first successful health check | varies | varies | varies | ready |
| 1 | WireGuard Raw | Standard WireGuard encryption | 0.1–0.8 ms | 3–5% | 0.5–2% | ready |
| 2 | AmneziaWG 2 Fast | Modded WireGuard + light packet obfuscation | 0.2–1.5 ms | 4–7% | 0.7–3% | ready |
| 3 | WireGuard + Rosenpass PQ | Standard WireGuard + hybrid post-quantum key exchange | 0.2–1.2 ms | 3–6% | 0.7–3% | integration |
| 4 | AmneziaWG 2 Strong | Modded WireGuard + stronger padding/signature obfuscation | 0.3–2.5 ms | 6–12% | 1.5–6% | ready |
| 5 | AmneziaWG 2 + Rosenpass PQ | Modded WireGuard + stronger obfuscation + hybrid-PQ key exchange | 0.4–3 ms | 6–13% | 2–7% | integration |
| 6 | **VLESS + TCP + REALITY + Vision + Chrome uTLS — RECOMMENDED** | VLESS + TCP + REALITY + XTLS Vision + Chrome-style TLS fingerprint on TCP 443 | 0.7–3 ms | 4–8% | 2–6% | ready |
| 7 | PQ VLESS + REALITY + Vision | Hybrid-PQ VLESS encryption + REALITY + Vision | 0.9–3.5 ms | 5–10% | 2.5–7% | ready |
| 8 | Hysteria2 QUIC | Encrypted Hysteria2 + QUIC camouflage/loss resistance | 0.8–4 ms | 6–12% | 3–10% | ready |
| 9 | Shadowsocks 2022 | Shadowsocks encryption/obfuscation | 0.8–3.5 ms | 4–9% | 2–8% | ready |
| 10 | Shadowsocks + V2Ray TLS | Shadowsocks + V2Ray-plugin TLS/WebSocket camouflage | 1.5–6 ms | 7–14% | 4–12% | integration |
| 11 | VLESS PQ + REALITY + XHTTP + FinalMask | Hybrid-PQ VLESS + REALITY + XHTTP + FinalMask | 1.5–7 ms | 7–15% | 5–14% | integration |
| 12 | Naive HTTPS HTTP/2 | Chromium-style HTTPS proxy camouflage | 2–8 ms | 8–18% | 6–16% | integration |
| 13 | MAX TLS — Standard WireGuard base | WG/PQ option + DAITA-like shaping + Shadowsocks/V2Ray TLS + VLESS PQ/REALITY/XHTTP/FinalMask | 5–20 ms | 25–80% | 18–45% | lab |
| 14 | MAX TLS — AmneziaWG 2 base | AWG2/PQ option + DAITA-like shaping + Shadowsocks/V2Ray TLS + VLESS PQ/REALITY/XHTTP/FinalMask | 5.5–22 ms | 28–85% | 20–48% | lab |
| 15 | MAX QUIC — Standard WireGuard base | WG/PQ option + DAITA-like shaping + Shadowsocks + Hysteria2/QUIC | 4–16 ms | 20–70% | 15–40% | lab |
| 16 | MAX QUIC — AmneziaWG 2 base | AWG2/PQ option + DAITA-like shaping + Shadowsocks + Hysteria2/QUIC | 4.5–18 ms | 23–75% | 17–43% | lab |
| 17 | **ALL** | Tries both MAX TLS bases first, then both MAX QUIC bases; uses every compatible generated layer | 5–25 ms | 25–100% | 18–60% | lab |

## AUTO order

AUTO does **not** default to MAX. It tries the least intensive eligible mode first and escalates only when the current mode cannot pass the health check:

WireGuard Raw → AmneziaWG 2 Fast → AmneziaWG 2 Strong → recommended REALITY/Vision/uTLS → PQ REALITY/Vision → Hysteria2 → Shadowsocks 2022.

Rosenpass and the laboratory chains are excluded from AUTO until their required local binaries and generated profiles pass validation. They remain available manually.

## Base tunnel choice

The strongest profiles expose both bases in the picker:

- **Standard WireGuard base** — lower overhead and widest compatibility.
- **AmneziaWG 2 base** — modded WireGuard with additional packet obfuscation.

**ALL** automatically tries both bases. This avoids silently forcing one engine and provides a fallback when a network blocks or breaks the other.

## Toggles

- **DAITA Off/On:** On enables the shipped randomized cover-traffic control. It is DAITA-like unless both ends use a compatible Maybenot-enabled implementation.
- **Jumbo Off/On:** On exposes a 9000-byte client TUN only for compatible proxy modes. Internet packets are still segmented to the path MTU.
- **SOCKS5:** The router proxy works as a normal SOCKS5 endpoint after a tunnel connects. Use the tunnel IP and port shown in the generated credentials; no Router VPN app is required on the device using the proxy.

## Censorship-resistance note

The heavier modes provide additional camouflage and multiple fallback transports, but no VPN or proxy can honestly guarantee bypassing every country or every future filtering system.
