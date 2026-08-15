# Router VPN modes

The server keeps **20 raw runtime profiles** ordered from lightest/fastest to strongest/heaviest. The app normally presents **16 logical modes** from `configs/client/logical-modes.json`, combining WireGuard/AmneziaWG variants behind a base selector where they are compatible.

Availability is dynamic. A profile is Ready only when its generated configuration/dependencies validate on the current node/client; this document does not override the real checker result. The native app mode surface must show the same semantic contract on every platform where that mode exists:

```text
logical mode
layers / stack
engineering added-latency estimate
engineering traffic-overhead estimate
engineering speed-loss estimate
runtime readiness
exact readiness / unavailability reason
actual runtime/base/fallback after connection
```

The estimate ranges are catalog guidance, not measured promises. **Readiness and exact reason are live runtime facts.** Setup Center separately labels server/source generation readiness so it never pretends a generated home-node profile proves that Windows, macOS, Linux, Android, or iOS has a compatible local dataplane. Unsupported platform graphs stay unavailable.

## Raw runtime catalog

| # | Runtime profile | Main stack | Added ping | Traffic increase | Speed loss |
|---:|---|---|---:|---:|---:|
| 1 | WireGuard Raw | WireGuard | 0.1–0.8 ms | +3–5% | 0.5–2% |
| 2 | AmneziaWG 2 Fast | AmneziaWG + light obfuscation | 0.2–1.5 ms | +4–7% | 0.7–3% |
| 3 | WireGuard + Rosenpass PQ | WireGuard + live Rosenpass hybrid-PQ PSK rotation | 0.2–1.2 ms | +3–6% | 0.7–3% |
| 4 | Shadowsocks 2022 | Shadowsocks 2022 | 0.8–3.5 ms | +4–9% | 2–8% |
| 5 | AmneziaWG 2 Strong | AmneziaWG + stronger randomized obfuscation | 0.3–2.5 ms | +6–12% | 1.5–6% |
| 6 | AmneziaWG 2 + Rosenpass PQ | AmneziaWG + Rosenpass hybrid-PQ PSK rotation | 0.4–3 ms | +6–13% | 2–7% |
| 7 | VLESS + REALITY + Vision | VLESS + TCP + REALITY + Vision + Chrome-style fingerprint | 0.7–3 ms | +4–8% | 2–6% |
| 8 | Hysteria2 + QUIC + Salamander | Hysteria2 + QUIC + Salamander | 0.8–4 ms | +6–12% | 3–10% |
| 9 | PQ VLESS + REALITY + Vision | hybrid-PQ VLESS + REALITY + Vision | 0.9–3.5 ms | +5–10% | 2.5–7% |
| 10 | Shadowsocks + V2Ray TLS | Shadowsocks 2022 + V2Ray SIP003 WebSocket/TLS; UDP fallback path | 1.5–6 ms | +7–14% | 4–12% |
| 11 | Naive HTTPS HTTP/2 | Naive HTTPS + H2 + UDP-over-TCP | 2–8 ms | +8–18% | 6–16% |
| 12 | Naive HTTPS HTTP/3 + QUIC | Naive HTTPS + H3/QUIC | 1.5–7 ms | +8–18% | 5–15% |
| 13 | Dual Transport | REALITY/Vision for TCP + Hysteria2/QUIC for UDP | 1–5 ms | +6–14% | 3–12% |
| 14 | PQ REALITY + XHTTP + FinalMask | PQ VLESS + REALITY + XHTTP + FinalMask | 1.5–7 ms | +7–15% | 5–14% |
| 15 | PQ Dual Transport | PQ REALITY/Vision for TCP + Hysteria2/QUIC for UDP | 2–9 ms | +10–22% | 7–18% |
| 16 | MAX QUIC — PQ WireGuard base | WG + Rosenpass PQ → Shadowsocks 2022 → Hysteria2/QUIC | 4–16 ms | +20–70% | 15–40% |
| 17 | MAX QUIC — PQ AmneziaWG base | AWG + Rosenpass PQ → Shadowsocks 2022 → Hysteria2/QUIC | 4.5–18 ms | +23–75% | 17–43% |
| 18 | MAX TLS — PQ WireGuard base | WG + Rosenpass PQ → Shadowsocks 2022 → PQ REALITY/XHTTP/FinalMask | 5–20 ms | +25–80% | 18–45% |
| 19 | MAX TLS — PQ AmneziaWG base | AWG + Rosenpass PQ → Shadowsocks 2022 → PQ REALITY/XHTTP/FinalMask | 5.5–22 ms | +28–85% | 20–48% |
| 20 | ALL | health-tested MAX TLS branches, then MAX QUIC fallback branches | 5–25 ms | +25–100% | 18–60% |

These latency/traffic/speed values are engineering estimate ranges, not guarantees. Travel distance back to the home node is separate.

## Logical app model

The app does **not** need duplicate rows such as `MAX TLS WG` and `MAX TLS AWG`. Compatible logical modes expose:

```text
Base: Auto
Base: WireGuard
Base: AmneziaWG
```

If the preferred base is unavailable and the alternate succeeds, Router VPN must report the actual fallback instead of silently claiming the preferred base stayed active.

The 16 logical choices are:

1. Raw tunnel
2. Base tunnel + Rosenpass PQ
3. AmneziaWG Strong
4. Shadowsocks 2022
5. VLESS + REALITY + Vision
6. Hysteria2 + QUIC + Salamander
7. PQ VLESS + REALITY + Vision
8. Shadowsocks + V2Ray TLS
9. Naive HTTPS HTTP/2
10. Naive HTTPS HTTP/3 + QUIC
11. Dual Transport
12. PQ REALITY + XHTTP + FinalMask
13. PQ Dual Transport
14. MAX QUIC
15. MAX TLS
16. ALL

## AUTO / SMART AUTO / CUSTOM

**AUTO** tries eligible runtime profiles from lightest upward and stops at the first path that actually starts and passes health checks.

**SMART AUTO** gets connected first, remembers the last-good stack, tests declared simplifications/replacements, and restores the last-good path when a reduction fails.

**CUSTOM** selects the lightest already-validated compatible stack containing every requested layer/property without unnecessary layers.

## MAX / ALL

MAX modes use validated multi-engine chains and fail closed when their requested branch is not valid. `ALL` keeps mutually exclusive outer transports as separate branches: strongest validated MAX TLS first, then MAX QUIC fallback. It reports any fallback instead of pretending incompatible transports are simultaneously nested.

## DNS presentation paired with mode truth

The native product surfaces also expose the selected Router VPN DNS policy rather than reducing DNS to a read-only label:

- Home AdGuard
- Fastest measured resolver
- Custom UDP/TCP
- DNS-over-TLS
- DNS-over-HTTPS
- DNS-over-HTTP/3
- DNS Rescue
- common IPv4 and IPv6 resolver presets

Resolver benchmark values are real **A/AAAA DNS query RTTs measured from the selected home node**, not ICMP ping. Saving a DNS policy is not active-runtime proof; reconnect/session proof remains authoritative.

## DAITA-like / Jumbo / SOCKS5

- **DAITA-like traffic padding:** bounded Router VPN cover traffic; not exact Mullvad DAITA/Maybenot.
- **Jumbo TUN:** advanced option for compatible TUN/proxy paths; Internet traffic still follows real path MTU constraints.
- **SOCKS5:** private LAN/tunnel proxy on port `1080`; never WAN-forward it.

See `docs/CURRENT-GUIDE.md` for the current logical-mode UX, platform limits, DNS and setup flow.
