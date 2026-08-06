# Modes

Estimates are protocol overhead on the same route and hardware. Travel distance back home is separate.

| Order | Mode | Protection | Added ping | Traffic increase | Speed loss | Included state |
|---:|---|---|---:|---:|---:|---|
| AUTO | Tests available modes and keeps the fastest working one | Varies | Varies | Varies | Varies | Ready on desktop |
| 1 | WireGuard Raw | Encryption | 0.1–0.8 ms | 3–5% | 0.5–2% | Ready |
| 2 | AmneziaWG 2 Fast | Encryption + light obfuscation | 0.2–1.5 ms | 4–7% | 0.7–3% | Ready |
| 3 | WireGuard + Rosenpass PQ | Hybrid PQ keying + encryption | 0.2–1.2 ms | 3–6% | 0.7–3% | Adapter |
| 4 | AmneziaWG 2 + Rosenpass PQ | PQ keying + AWG obfuscation | 0.3–2 ms | 4–8% | 1–5% | Adapter |
| 5 | AmneziaWG 2 Strong | Encryption + stronger padding/signatures | 0.4–2.5 ms | 6–12% | 1.5–6% | Ready |
| 6 | VLESS + REALITY Vision | Encryption + HTTPS camouflage | 0.7–3 ms | 4–8% | 2–6% | Ready |
| 7 | Hysteria2 QUIC | Encryption + QUIC camouflage | 0.8–4 ms | 6–12% | 3–10% | Ready |
| 8 | WireGuard over QUIC | WG encryption + QUIC outer transport | 1–4.5 ms | 8–15% | 4–12% | Adapter |
| 9 | Shadowsocks 2022 | Encryption + basic obfuscation | 0.8–3.5 ms | 4–9% | 2–8% | Ready |
| 10 | Shadowsocks + V2Ray TLS | Encryption + TLS/WebSocket camouflage | 1.5–6 ms | 7–14% | 4–12% | Needs domain/certificate |
| 11 | VLESS PQ + REALITY XHTTP/FinalMask | PQ payload layer + HTTP camouflage | 1.5–7 ms | 7–15% | 5–14% | Xray adapter |
| 12 | Naive HTTPS HTTP/2 | Encryption + Chromium-style HTTPS | 2–8 ms | 8–18% | 6–16% | Adapter |
| 13 | Naive HTTPS HTTP/3 | Encryption + browser-like QUIC/HTTPS | 1.5–7 ms | 9–19% | 5–15% | Adapter |
| 14 | WG over Shadowsocks/V2Ray | Inner WG + SS + TLS camouflage | 2–8 ms | 11–22% | 7–20% | Chain adapter |
| 15 | MAX TLS | DAITA/PQ-WG → SS/V2Ray → VLESS/REALITY/XHTTP/FinalMask | 5–20 ms | 25–80% | 18–45% | Lab adapter |
| 16 | MAX QUIC | DAITA/PQ-WG → Shadowsocks → Hysteria2/QUIC | 4–16 ms | 20–70% | 15–40% | Lab adapter |

AUTO considers only modes whose engine and generated profile are actually present. Disabled modes remain visible so they can be completed later without changing the client interface.

## DAITA toggle

- **Off:** normal mode.
- **On:** accepted only by a mode with a linked Maybenot/GotaTun-compatible engine. The supplied build does not label ordinary padding as exact DAITA.

## Jumbo toggle

- Raw WireGuard/AWG keep their safe tunnel MTUs.
- TUN proxy modes can expose MTU 9000 to applications and segment payload into ordinary path-sized outer packets.
- A 9000-byte Ethernet frame does not remain one intact frame across the public internet.
