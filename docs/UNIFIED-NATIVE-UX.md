# Router VPN unified native app UX

This is the shipping interaction contract for iOS/iPadOS, Android, macOS, Windows and Linux. Platform controls may look native, but the information architecture and truth rules stay the same.

## Primary surface

- The map is the app's primary surface. It opens first and consumes the upper/main region.
- Plot only coordinates explicitly stored with linked Router VPN or external/custom nodes. Never infer, geolocate, or fabricate a map pin from an IP address.
- A selected path is visually distinct. Multihop entry, intermediate and exit nodes use stable, distinct hop colors and a path overlay; custom/external hops use the same path model.
- Exactly one normal node is selected by default. The node control distinguishes `Router node` from `Custom / external`, with Add/Manage as a drill-in action rather than cluttering the primary surface.
- Desktop uses a bottom dock/control card. Touch platforms use the equivalent draggable/swipe-up bottom sheet. The sheet must never cover its own controls with a floating banner or top popup.

## Bottom control order

1. **Connect / Disconnect** — one primary button. It becomes Disconnect only for an active/proving session. A compact quick kill-switch control sits beside it.
2. **Multihop** — visible immediately below Connect when enabled and one tap away when disabled. The editor chooses each entry/exit/hop from the unified node catalog. Unsupported runtime graphs remain visibly unavailable with the exact reason; they are never simulated.
3. **Settings** — opens the detailed settings page/sheet.
4. **Mode** — compact selector plus a detailed picker. `SMART AUTO` is the default selection, `AUTO` is a first-class mode, all logical presets remain discoverable, unavailable presets remain visible with their reason, and CUSTOM opens the visual preset system.
5. **DNS** — compact selector in the sheet. Detailed DNS setup/retest is a drill-in page, not a permanent top-level tab.

Connection progress remains truthful and visible: preparing, engine, interface/TUN, handshake, route, DNS, selected-node path proof, public-exit proof, failure/fallback/rollback and winner. Connected is not asserted merely because a process started.

## Modes and CUSTOM

- `SMART AUTO` is the initial/default UI mode for a new Router VPN profile. It first obtains a proven path, remembers the last good runtime, tries simplification, validates each change and restores the last good runtime if a simplification fails.
- `AUTO` is a mode, not a separate magic action button. It chooses the first eligible path that actually passes required connection/path proof.
- Normal logical presets are shown together with readiness and exact unavailable reason.
- `CUSTOM` is a preset system, not a comma-separated text prompt. The picker shows saved custom presets and `New custom preset…`.
- The custom builder is a dedicated page/sheet with selectable layers/features, compatibility/readiness feedback, name/save/connect actions and delete for user presets. The runtime still chooses only a validated compatible stack containing every requested layer and fails closed if no such stack exists.
- Saved presets contain product choices only; private node credentials remain in the private node store.

## Settings

The detailed settings surface exposes, where supported by the selected node/runtime:

- Kill switch policy. A compact quick toggle is also beside Connect.
- IPv6, **On by default for newly normalized Router VPN profiles**.
- Full home-LAN access policy.
- WireGuard / AmneziaWG base preference and compatible fallback.
- MTU policy: Auto measured by default, Fixed/manual override, current effective MTU and Retest. Retest is path/config specific; a fixed profile MTU applies until changed. On connection, Auto uses the best valid measurement available for that path/config and remains truthful about the source.
- DAITA-like traffic padding. It stays bounded/non-amplifying and is never described as Mullvad DAITA itself.
- Jumbo TUN / jumbo packet option when supported.
- Port forwarding / Protected-DMZ entry point only for routable tunnel modes with authenticated home-node ownership; proxy-only paths never claim arbitrary DNAT.
- AUTO filters: `Require encrypted` and `Require obfuscation`. Both are Off by default. When enabled, AUTO/SMART candidate selection rejects non-matching candidates before attempting them and reports the filtering reason.

## DNS

The primary sheet can change the selected DNS policy without navigating away from the map. Detailed DNS supports Home AdGuard, Fastest measured, Custom, DoT, DoH, DoH3 and Rescue; common IPv4/IPv6 resolver choices remain available. Measurements are real DNS-query RTT, not ICMP, and the selected session's DNS proof is authoritative.

## Cross-platform consistency

- No eight-tab top navigation in the daily app.
- No PWA/browser shell as the final daily app.
- Native detail pages may use platform-standard navigation, sheets, dialogs and keyboard shortcuts.
- iPad/desktop can expose more map and side detail at once; phones collapse the same controls into the bottom sheet.
- Buttons, mode/node cards, DNS controls, progress, maps and settings must remain usable at small windows, high DPI/scaling, phone portrait/landscape and tablet/desktop sizes.
- Setup Center remains the separate authenticated deployment/admin surface.

## Truth / safety invariants

- Real coordinates only.
- Lowest-latency selection only from actually measured nodes (robust multi-sample metrics remain authoritative).
- AUTO/SMART/CUSTOM/ALL never fake runtime compatibility.
- Multihop means a real entry → exit → Internet path with distinct nodes and real exit proof.
- Actual public exit is displayed/proved separately from a local/proxy address.
- DNS choice changes the real tunnel resolver path and is session-proved.
- Kill switch, MTU, IPv6, forwarding, DAITA-like padding and jumbo controls reflect actual platform/runtime support; unsupported controls explain why.
