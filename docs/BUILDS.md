# Router VPN builds

GitHub Actions is the normal builder. The AI Board is not used as the routine cross-platform compile farm.

## Workflows

Primary release validation:

```text
.github/workflows/build-all.yml
```

Additional gates cover:

- native ARM64 production preflight
- real OverTLS/SSR ARM64 startup
- client apps / Windows Portable execution
- exact-SHA ARM64 image publishing

## Desktop / Unix artifacts

The desktop build produces checked packages for:

- Windows x64
- Windows ARM64
- Router VPN Portable ZIP x64
- Router VPN Portable ZIP ARM64
- macOS Intel
- macOS Apple Silicon
- Linux x64
- Linux ARM64
- Linux ARMv7
- supported FreeBSD/OpenBSD/NetBSD/DragonFly BSD/illumos targets

**PortableApps.com / PAF is not produced.** Use the normal Router VPN Portable ZIP.

## Android

The APK builds as the Router VPN controller/importer. It does not claim full-device VPN until native `VpnService` engine adapters are implemented.

## iOS / iPadOS

CI builds an unsigned re-signable IPA and Packet Tunnel target. Optional signing assets can produce a signed IPA, but signing does not make the placeholder Packet Tunnel engine complete. The extension remains fail-closed until real tunnel engines are linked.

## Home Setup Center download policy

Large platform packages are on-demand:

```text
matching GitHub Actions artifact
↓ if unavailable
router-local compile of requested package only
↓
inject home-node private data temporarily
↓
stream
↓
delete temporary build/output
```

The GitHub artifact retention target is short (normally 1 day). The AI Board does not keep every platform archive permanently.

## What CI proves

Release workflows validate source, package integrity, logical-mode contracts, Windows Portable execution/relocation, ARM64 server init/finalizer, userspace WireGuard, auxiliary proxies, generated mode validation, and production compose contracts.

CI cannot prove a specific ISP/firewall path. Final WAN validation still requires a real off-LAN client connection.
