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

## Original UI details recovered on November 19, 2026

The August 10–13 and August 19 user messages remain the authority for these
details. The earlier concise lists did not cancel them.

- Fastest appears beside Connect only when multiple eligible nodes can actually be compared. Router TCP and external HTTPS measurements retain their separate meanings.
- Kill switch and the available forwarding master flank Connect. The expanded sheet keeps Connect, Multihop, Settings, Mode and DNS in that order.
- The custom globe shows every chosen hop with role colors, route segments and packet animation. Unknown coordinates leave a gap; device location comes from an explicitly requested OS fix.
- Choosing the first hop measures the next candidates through that hop. Choosing another repeats the measurement through the selected prefix. Draft measurement must not implicitly save or replace the user's connection profile.
- The multihop surface shows a fresh measured total response through the actual connection, in addition to the main control's live response. It must not sum unrelated hop measurements or show an old connection's result.
- Controls must remain reachable at supported screen sizes, orientations and accessibility text sizes. Source audits are separate from rendered native acceptance.
- The MTU wording was "in settings u set it fixed for all" while Retest tests "that config". The device-wide preference is separate from per-profile Auto/Fixed/Retest and must be applied and read back by the actual client-tunnel owner. The November 19 implementation record identifies the new runtime/UI integration and its verification boundaries; a saved setting alone does not satisfy this requirement.
- No original acceptance of eight as the final maximum hop count was recovered. The implementation's current protocol, source and ownership bounds describe capability, not a cancellation of the wider ordered-hop request. The [extended original execution record](AI-DEVELOPMENT-HISTORY.md#note-implementation-2026-11-22-extended-execution) documents the qualified longer Local/Server/Compare family and its verification; it does not establish support for every protocol combination.
- macOS Developer ID signing/notarization is optional distribution polish when practical. Legitimate iOS provisioning and truthful package identity remain required.

The implementation and validation records for this continuation are
[November 19 implementation status](AI-DEVELOPMENT-HISTORY.md#note-implementation-2026-11-19) and
[November 21 repairs and independent imported paths](AI-DEVELOPMENT-HISTORY.md#note-implementation-2026-11-21).

## Package delivery

Exact-SHA GitHub Release first, then exact-SHA Actions artifact, then one bounded locally supported desktop/Portable build. Mobile is artifact-only. The completed package and its owned build workspace are retained for exactly 30 minutes from READY for retry/re-download; delivery does not extend the deadline; cancel/delete/shutdown removes them immediately.

## Canceled/superseded

No branches/PRs for routine work, no browser/PWA daily client, no WSL-as-native, no PortableApps/PAF, no moving-latest artifact fallback, no fake readiness/proof/location/speed/forwarding, no homemade cryptography, and no broad ASUS rules that can own ordinary household traffic.
