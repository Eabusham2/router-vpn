# Modes

Same-route engineering estimates; distance back home is separate. AUTO tries ready profiles from fastest upward until one passes the health test.

| Order | Mode | Protection | Added ping | Traffic increase | Speed loss | State |
|---:|---|---|---:|---:|---:|---|
| 1 | WireGuard Raw | Encryption | 0.1–0.8 ms | 3–5% | 0.5–2% | ready |
| 2 | AmneziaWG 2 Fast | Encryption + lightweight obfuscation | 0.2–1.5 ms | 4–7% | 0.7–3% | ready |
| 3 | WireGuard PQ | Encryption + Rosenpass hybrid PQ keying | 0.2–1.2 ms | 3–6% | 0.7–3% | integration |
| 4 | AmneziaWG 2 + PQ | Hybrid PQ encryption + AWG obfuscation | 0.3–2 ms | 4–8% | 1–5% | integration |
| 5 | AmneziaWG 2 Strong | Encryption + stronger padding/signature obfuscation | 0.4–2.5 ms | 6–12% | 1.5–6% | ready |
| 6 | PQ VLESS + REALITY Vision | Hybrid post-quantum VLESS encryption + HTTPS camouflage | 0.9–3.5 ms | 5–10% | 2.5–7% | ready |
| 7 | VLESS + REALITY Vision | Encryption + HTTPS camouflage; hybrid PQ TLS when negotiated | 0.7–3 ms | 4–8% | 2–6% | ready |
| 8 | Hysteria2 QUIC | Encryption + QUIC transport camouflage | 0.8–4 ms | 6–12% | 3–10% | ready |
| 9 | WireGuard over QUIC | WireGuard encryption + QUIC obfuscation | 1–4.5 ms | 8–15% | 4–12% | adapter |
| 10 | Shadowsocks 2022 | Encryption + basic obfuscation | 0.8–3.5 ms | 4–9% | 2–8% | ready |
| 11 | Shadowsocks + V2Ray TLS | Encryption + TLS/WebSocket camouflage | 1.5–6 ms | 7–14% | 4–12% | integration |
| 12 | VLESS PQ + REALITY XHTTP | Hybrid PQ payload encryption + HTTP camouflage + FinalMask | 1.5–7 ms | 7–15% | 5–14% | integration |
| 13 | Naive HTTPS HTTP/2 | Encryption + Chromium-style HTTPS | 2–8 ms | 8–18% | 6–16% | integration |
| 14 | Naive HTTPS HTTP/3 | Encryption + browser-like QUIC/HTTPS | 1.5–7 ms | 9–19% | 5–15% | integration |
| 15 | WireGuard over Shadowsocks/V2Ray TLS | Inner WireGuard encryption + Shadowsocks + TLS camouflage | 2–8 ms | 11–22% | 7–20% | chain |
| 16 | MAX TLS — All Compatible TLS Layers | DAITA/PQ-WG → Shadowsocks/V2Ray TLS → VLESS PQ/REALITY/XHTTP/FinalMask | 5–20 ms | 25–80% | 18–45% | lab |
| 17 | MAX QUIC — All Compatible QUIC Layers | DAITA/PQ-WG → Shadowsocks → Hysteria2/QUIC masking | 4–16 ms | 20–70% | 15–40% | lab |

## Toggles

- **DAITA-like Off/On:** On sends configurable router-bound cover traffic. It is not labeled as exact Mullvad DAITA.
- **Jumbo Off/On:** On exposes MTU 9000 only for compatible TUN proxy modes; public internet packets remain path-sized.
- **SOCKS5-only Off/On:** Off is a full-device VPN; On creates `127.0.0.1:1080` for selected apps.

## Recommended daily order

1. WireGuard Raw
2. AmneziaWG 2 Fast
3. AmneziaWG 2 Strong
4. PQ VLESS + REALITY Vision
5. VLESS + REALITY Vision
6. Hysteria2 QUIC
7. Shadowsocks 2022
