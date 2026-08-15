# Implementation status

This compatibility page intentionally points to the maintained source-vs-live status document:

```text
docs/CURRENT-STATUS.md
```

Use `docs/CURRENT-GUIDE.md` for setup/product operation and `docs/NATIVE-APPS.md` for native application boundaries.

Do not infer current readiness from older copied checklists. Current source includes native Android `VpnService`, pinned iOS WireGuardKit + supported Libbox PacketTunnel paths, Windows native full-device TUN/DNS paths, desktop multihop/kill-switch implementations and the narrower platform-specific subsets described in `docs/CURRENT-STATUS.md`.

Those source implementations still have separate release gates. Physical-device VPN permission/routing/DNS/IPv4/IPv6, reconnect/network-change behavior, leak-negative behavior, off-LAN interoperability, Apple signing/notarization and the live production deployment must be proven before final release claims. Unsupported platform graphs remain unavailable rather than simulated.
