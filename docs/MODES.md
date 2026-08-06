# Modes

Same-route estimates; travel distance back home is separate. Modes that were strictly weaker while costing the same or more were removed.

| Order | Mode | Protection | Added ping | Traffic increase | Speed loss | State |
|---:|---|---|---:|---:|---:|---|
| AUTO | Fastest working eligible profile | varies | varies | varies | ready |
| 1 | WireGuard Raw | Encryption only | 0.1–0.8 ms | 3–5% | 0.5–2% | ready |
| 2 | AmneziaWG 2 Fast | Encryption + lightweight obfuscation | 0.2–1.5 ms | 4–7% | 0.7–3% | ready |
| 3 | WireGuard PQ | WireGuard + Rosenpass hybrid-PQ keying | 0.2–1.2 ms | 3–6% | 0.7–3% | integration |
| 4 | AmneziaWG 2 + PQ | Hybrid-PQ encryption + AWG2 obfuscation | 0.3–2 ms | 4–8% | 1–5% | integration |
| 5 | **VLESS + REALITY + Vision + uTLS — RECOMMENDED** | Encryption + HTTPS camouflage | 0.7–3 ms | 4–8% | 2–6% | ready |
| 6 | PQ VLESS + REALITY + Vision | Hybrid-PQ payload encryption + HTTPS camouflage | 0.9–3.5 ms | 5–10% | 2.5–7% | ready |
| 7 | Hysteria2 QUIC | Encryption + QUIC camouflage | 0.8–4 ms | 6–12% | 3–10% | ready |
| 8 | Shadowsocks + V2Ray TLS | Encryption + TLS/WebSocket camouflage | 1.5–6 ms | 7–14% | 4–12% | integration |
| 9 | VLESS PQ + REALITY XHTTP + FinalMask | Hybrid-PQ encryption + stronger HTTP camouflage | 1.5–7 ms | 7–15% | 5–14% | integration |
| 10 | Naive HTTPS HTTP/2 | Encryption + Chromium-style HTTPS | 2–8 ms | 8–18% | 6–16% | integration |
| 11 | MAX TLS | PQ-WG + DAITA toggle + Shadowsocks/V2Ray TLS + VLESS PQ/REALITY/XHTTP/FinalMask | 5–20 ms | 25–80% | 18–45% | lab |
| 12 | MAX QUIC | PQ-WG + DAITA toggle + Shadowsocks + Hysteria2/QUIC masking | 4–16 ms | 20–70% | 15–40% | lab |
| 13 | **ALL** | Every compatible serial layer, with MAX-TLS first and MAX-QUIC fallback | 5–25 ms | 25–100% | 18–60% | lab |

## Toggles

- **DAITA Off/On:** On enables the shipped cover-traffic control. It is DAITA-like unless both ends are replaced with a compatible Maybenot-enabled WireGuard build.
- **Jumbo Off/On:** On exposes a 9000-byte client TUN only for compatible proxy modes. Internet packets are still segmented to path MTU.
- **SOCKS5 Off/On:** Off is full-device VPN. On creates the local authenticated SOCKS route for selected applications.

## AUTO order

WireGuard Raw → AmneziaWG 2 Fast → recommended REALITY/Vision → PQ REALITY/Vision → Hysteria2 → Shadowsocks/V2Ray TLS.
