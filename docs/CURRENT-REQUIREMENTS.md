# Router VPN Current Requirements

This file indexes the surviving requirements. The latest explicit user
correction refines earlier requests; shorter assistant handoffs cannot remove
uncancelled scope. Current source and exact-SHA results establish implementation
and delivery evidence, not a different requirement set.

## Binding product

- Native map-first daily app on Windows, macOS, Linux, Android, iPhone and iPad.
- Separate private Setup Center for deployment, downloads, administration, update and recovery.
- One selected node by default; SMART AUTO default; Connect/Disconnect, Multihop, Settings, Mode and DNS in the expandable control surface.
- Real-coordinate VPN map/globe, truthful role colors, route lines, packet animation, node/path RTT and real speed tests.
- Whole-connection profile Add/Load/Update/Delete without duplicating secrets.
- Home AdGuard by default, with explicit alternative resolvers and no silent public-DNS substitution.
- Auto/Fixed/Retest MTU; IPv6 On; AUTO encryption/obfuscation requirements Off by default; capability-gated kill switch, forwarding, Jumbo and DAITA-like padding.
- External nodes and bridges need a real native dataplane. Start Layer choices remain Off, AES-256-GCM, and AES-256-GCM + XOR whitening. XOR is obfuscation alongside authenticated encryption, never a replacement cipher.

## Package delivery

Exact-SHA GitHub Release first, then exact-SHA Actions artifact, then one bounded locally supported desktop/Portable build. Mobile is artifact-only. The completed package and its owned build workspace are retained for exactly 30 minutes from READY for retry/re-download; delivery does not extend the deadline; cancel/delete/shutdown removes them immediately.

## Canceled/superseded

No branches/PRs for routine work, no browser/PWA daily client, no WSL-as-native, no PortableApps/PAF, no moving-latest artifact fallback, no fake readiness/proof/location/speed/forwarding, no homemade cryptography, and no broad ASUS rules that can own ordinary household traffic.
