# Router VPN reconciled product and release contract

This file records the newest surviving requirement set after reconciling the Router VPN handoffs, `mm.md`, recovered requirements 1–356, corrections C1–C7, the later UI/product prompt, transaction and durability corrections, and subsequent user overrides.

## Authority and superseded directions

Later verified source and later explicit user direction win over stale handoff status text.

The following older directions are superseded or canceled:

- Development changes land directly on `main`; do not create feature branches or pull requests for routine continuation work.
- The old tab-heavy/debug-console daily UI is retired. The native map-first product is authoritative.
- Temporary package output is **not** deleted immediately after a successful or interrupted browser delivery. It is retained for 30 minutes from READY for repeat download/retry; delivery does not extend that deadline. Explicit cancellation, Delete now, or service shutdown cleans it immediately.
- Do not invent XOR, homemade packet encryption, or a cosmetic “extra encryption” cipher. Use established authenticated encryption and require an encrypted inner tunnel when a bridge/proxy is not itself an authenticated full VPN.
- Unsupported platform functionality remains disabled/unavailable with a precise reason. Parity never permits fake controls, fake Connected state, fake public exit, fake location, fake Mbps, or fake multihop.
- No moving `latest`, `main`, `/releases/latest`, or newest-artifact fallback may certify or feed an exact-SHA release.
- Android/iOS packages remain exact-SHA artifact-only; the Linux AI Board does not pretend to build or sign native mobile applications.
- The AI Board is the production/private Setup Center host and a bounded requested desktop-package fallback, not the routine cross-platform compile farm.

## Canonical requirement basis

The binding implementation basis is:

```text
356 explicit requirements
+ C1–C7 corrections
+ latest product/breakage items
+ the later map-first UI prompt
+ still-agreed mm.md and named-chat requirements
+ external node/hop/exit requirements
+ all later security, session-transaction, durable-state, shipping and release corrections
```

## Native daily product

All five native products—Windows, macOS, Linux, Android, and iOS/iPadOS—share the same product meaning while using native platform controls.

- Open on a custom VPN map/vector-globe surface, not a browser/PWA or generic maps product.
- Startup/onboarding overlays are hidden or dismissible and may not cover the primary controls.
- Exactly one ordinary node is selected by default when eligible nodes exist.
- Router VPN and custom/external nodes share the catalog, map and path model; users can add, import, select, remove and relink nodes without reinstalling.
- Real stored node coordinates only. Device location appears only from a permission-approved OS location fix. No IP-derived synthetic location.
- Role-colored Router, selected, bridge, entry, intermediate, custom/external, exit and device markers; colored hop lines; animated packet; node/path RTT labels.
- Desktop uses a bottom dock/card; touch devices use a draggable/swipe-up sheet ordered:

```text
Connect / Disconnect
Multihop (when enabled)
Settings
Mode
DNS
```

- One primary button changes between Connect and Disconnect.
- Fastest is a separate selector: measure and select, then wait for Connect; node selection never silently starts a tunnel.
- Compact kill-switch control and capability-gated forwarding-master control flank the primary connection action where supported.
- Connected requires the actual tunnel/engine, frozen selected graph, route, DNS and public-exit proof—not process start.

### Modes and profiles

- SMART AUTO is the normalized default; AUTO is first-class.
- All logical modes remain visible with readiness, reason, layers, overhead, actual runtime/base and fallback truth.
- Saved CUSTOM presets appear in Mode. New CUSTOM opens a visual builder with save, edit, delete and Save & Connect. Impossible graphs fail closed.
- Whole-connection profiles support Add, Load, Update and Delete for node, mode/CUSTOM, DNS, LAN, kill switch, IPv6, MTU, AUTO requirements, base/fallback and multihop choices.
- Profiles reference private node/exit credentials; they never duplicate keys, passwords or administrator tokens.
- Profile mutation/load is idle-only, validated and transactional with complete rollback on failure.

### Settings, DNS, MTU and telemetry

- IPv6 On by default.
- MTU Auto by default, plus Fixed and Retest. Auto/Retest is tied to the current node/profile/mode/runtime/base/path identity; stale measurements cannot be adopted.
- Require encrypted AUTO candidates and Require obfuscation for AUTO candidates are both Off by default.
- Expose kill switch, LAN policy, base/fallback, startup/autoconnect, bounded DAITA-like padding, Jumbo where real, forwarding/Protected DMZ entry, diagnostics and updates.
- DNS offers Home AdGuard, Fastest measured, Custom UDP/TCP, DoT, DoH, DoH3 where enforceable, and Rescue. Benchmark means DNS-query RTT and may not overwrite a newer saved policy.
- Keep live RTT, durable 50-sample node statistics, current-path Mbps, routed-hop Mbps and MTU-optimizer throughput separate.
- Multihop candidate X→Y/X→Z measurements must actually traverse X; no direct-cache substitution and no RTT-to-Mbps conversion.

### External paths and bridges

Supported imports are capability-gated per platform and may include WireGuard, AmneziaWG, SOCKS5, HTTP CONNECT, HTTPS CONNECT with TLS/SNI verification, Shadowsocks 2022, Hysteria2, Tor bridge, and OpenVPN only where a real native dataplane/lifecycle/leak contract exists.

A bridge or plaintext proxy cannot be advertised as encrypted transport by itself. It must sit outside an authenticated encrypted inner path when confidentiality is required.

## Setup Center and package delivery

Setup Center remains a separate private deployment/admin/recovery product. It is never intentionally WAN exposed and does not replace the native daily app.

Package resolution order is:

```text
immutable exact-SHA GitHub Release asset
→ matching exact-SHA GitHub Actions artifact
→ bounded requested local desktop/Portable fallback where technically real
```

All packages are generic and secret-free; private node linking is separate.

A completed package and its owned build workspace are retained for 30 minutes from READY. Repeat download and interrupted-delivery retry use the same retained job and do not extend the deadline. A reaper deletes package and workspace at expiry. Explicit Cancel/Delete now and service shutdown clean immediately. Cleanup failure is reported as cleanup-pending and retried; it is never silently called complete.

## Exact-SHA release and production

One source generation must prove source/security, recovered requirements, native session/UI/durability contracts, Windows installed and Portable x64/ARM64, macOS Intel/Apple Silicon, Linux x64/ARM64, Android APK, real iOS build/IPA, ARM64 images, Portainer preflight, exact production-compose materialization, archive parity, provenance and checksums.

`server/portainer-current.yaml` is a reviewed tracked baseline/template. Release workflows create a separate generated exact-SHA compose; they do not overwrite the tracked template merely because `main` moved.

GitHub completion and whole-project release are distinct. After exact-head repository/artifact proof, continue through physical devices, selected-path/leak/network transitions, off-LAN paths, visual/DPI QA, private server features, live AI providers, Apple signing/notarization/distribution, one deliberate exact-SHA production deployment, ASUS fail-open revalidation and final regression.

## ASUS household safety

Router VPN exposure uses exact tagged per-port IPv4 DNAT/FORWARD rules only. It never owns normal household LAN→WAN traffic, DNS, DHCP, ordinary IPv6, built-in-chain policy, Runner/FlowCache/hardware acceleration, or unrelated JFFS hooks. Failure of Router VPN or the AI Board withdraws only Router VPN exposure and remains fail-open for ordinary household Internet. Foreign same-port DNAT wins. Private/admin ports remain private.
