
# Unified Map Control Center v2

The daily Router VPN surface is map-first on every native platform. The map or custom vector globe remains visible above a swipe-up/bottom control sheet. The fixed order is Connection, Multihop, Settings, Mode, DNS.

## Interaction contract

Node selection never starts a connection. The primary button alone changes between Connect and Disconnect. Its left menu measures/selects the fastest node; compact kill-switch and master-forwarding controls sit beside it, capability-gated. Live end-to-end RTT is visible beside Disconnect.

The default profile contains one node, uses SMART AUTO, IPv6 On and Auto MTU. AUTO requirements for encrypted and obfuscated candidates remain off until explicitly selected. Profiles support create, load, update, delete and router-bundle import. Custom mode presets support create, load, update and delete through a separate visual builder page.

Multihop uses color-coded device, bridge, entry, middle, custom and exit roles, animated packet lines, per-node/pairwise/total RTT, per-hop throughput and end-to-end throughput. Measurements are real and remain unavailable with an explanation when the active dataplane cannot prove them.

## Bridges and encryption

Supported profile forms include Router VPN, WireGuard, AmneziaWG, OpenVPN, Shadowsocks 2022, SOCKS5, HTTP CONNECT, HTTPS CONNECT and Tor bridge. Plain proxy/bridge types cannot be the final transport; they require an authenticated encrypted inner tunnel.

Authenticated transport is mandatory. Router VPN uses standard, reviewed constructions such as WireGuard/AmneziaWG Noise_IK with ChaCha20-Poly1305, TLS 1.3 AEAD, Shadowsocks 2022 BLAKE3/AEAD and Tor ntor-v3. It never invents XOR-based or custom packet encryption.

Jumbo TUN, DAITA-like padding, arbitrary forwarding and Tor are shown as enabled only when the current platform and selected path report real runtime support.
