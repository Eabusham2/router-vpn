# Router VPN builds

GitHub Actions is the normal compile/test environment. The AI Board is not the routine cross-platform build farm; its bounded local toolchain exists only as a fallback for one requested generic client package when the matching artifact is unavailable, and only where the finished product can be assembled truthfully from same-image components.

## Release workflows

The current release path uses multiple gates rather than treating one workflow as proof of everything. Important workflows include:

- cross-platform client/native app CI
- release-candidate packaging and one-SHA aggregation
- repository-state and weighted/source audits
- exact-SHA ARM64 server image publishing
- native ARM64 server/runtime preflight
- standard/custom-exit contracts
- AI Help/setup-center contracts

A release candidate is valid only for its exact source SHA. Do not deploy an older candidate merely because it passed previously.

## Desktop / Unix artifacts

The native desktop release package matrix contains:

- Windows x64
- Windows ARM64
- Router VPN Portable ZIP x64
- Router VPN Portable ZIP ARM64
- macOS Intel
- macOS Apple Silicon
- Linux x64
- Linux ARM64

`deploy/build-client.sh` also retains Linux ARMv7 and FreeBSD/OpenBSD/NetBSD/DragonFly BSD/illumos controller/helper targets where supported. Those targets are not evidence of an equivalent native daily-use application or of inclusion in the published ten-package native release. Their feasibility-qualified requirements remain accounted for separately.

**PortableApps.com / PAF is not produced.** Use the normal Router VPN Portable ZIP.

## Windows

Windows package CI builds the native WPF product and executes normal installed-package plus Portable amd64/arm64 self-test/relocation gates. The normal package includes `RouterVPN.exe`, Start Menu/icon integration and the WPF daily-use app. Windows source includes native full-device runtime paths; WSL is not counted as the native Windows VPN implementation.

The AI Board can assemble the complete requested Windows/Portable package from same-image prebuilt Go components plus the shipped WPF/runtime sources and deterministic Router VPN icons. If one supported Windows Go component is unexpectedly absent, only that requested component may be rebuilt with the bounded, patch-pinned Go 1.24.13 toolchain.

CI execution still does not replace physical Windows full-device routing, DNS/IPv4/IPv6, leak-negative, reconnect/network-change and custom-exit testing.

## Android

The APK is a real native `VpnService` application. Build/runtime-contract CI compiles WireGuard/AmneziaWG and the combined pinned Libbox/Xray runtime, including supported PQ, helper/composite and complete MAX graphs. It also packages native Tor/pluggable transports and the bounded userspace OpenVPN endpoint. Native constructor/configuration gates exercise supported captured graphs and missing-engine rejection; they do not prove all requested compositions or physical networking. See [NATIVE-APPS.md](NATIVE-APPS.md) and [MOBILE-OPENVPN.md](MOBILE-OPENVPN.md) for current boundaries.

Current Android workflows assemble debug APKs. Persistent production signing, signing-key continuity and real-device upgrade acceptance remain open. Physical VPN permission, lockdown, reconnect, DNS/IPv4/IPv6, custom-exit traffic and leak-negative tests also remain release gates; native-library/provenance verification does not close them.

## iOS / iPadOS

CI builds the SwiftUI app plus PacketTunnel with the pinned WireGuardKit/AmneziaWG and Libbox Apple bridge, including supported layered/multihop, Tor and bounded inline OpenVPN paths, then packages an unsigned re-signable IPA. Source and constructor gates remain separate from the actual Xcode app/extension build and package verification.

A green unsigned build does not provide Apple signing/provisioning or physical-device proof. Legitimate signing plus real iPhone/iPad VPN permission, route-lockdown, reconnect, DNS/IPv4/IPv6, supported Libbox/custom-exit traffic and leak-negative validation remain release gates.

## macOS / Linux native apps

Release CI builds the native AppKit/MapKit macOS application for amd64/arm64 and native GTK Linux packages for amd64/arm64. Their source includes native routing/kill-switch/multihop/custom-exit paths as documented in `docs/CURRENT-STATUS.md`.

The AI Board runtime image intentionally does **not** contain AppKit or GTK native build SDK environments. Therefore if the matching same-SHA macOS/Linux native artifact is unavailable, the download broker fails closed with an exact reason instead of returning a controller-only archive pretending to be the finished native app. This is the deliberate “requested package only / where possible” boundary, not a loss of platform support.

Physical macOS/Linux networking, custom-exit and leak-negative validation remain separate; macOS also requires release signing/notarization.

## Home Setup Center download policy

Generic platform packages are on demand:

```text
matching exact-SHA published GitHub Release asset
↓ if unavailable/unusable
matching same-SHA GitHub Actions native/package artifact
↓ if unavailable/unusable
Windows/Portable only: assemble the requested complete package from same-image components
↓ if needed: bounded Go build of a missing approved Windows component
↓ if a true native platform component cannot be produced on the AI Board: fail closed with exact reason
↓
validate/package the generic secret-free application
↓
READY: retain the package and owned workspace for 30 minutes
↓
download/retry without extending that deadline
↓
cleanup on expiry; Cancel/Delete now/shutdown clean immediately
```

Private node data is **not injected into the public generic package**. Link/import/pair private nodes separately after installation. Cleanup failure remains visible and is retried. The GitHub artifact retention window may be short; the AI Board does not keep every platform archive permanently and does not fabricate missing native AppKit/GTK products. Android and iOS are exact-SHA artifact-only and never use this local fallback.

## Server images

Production custom server services are built/published by GitHub Actions for ARM64 with both moving development convenience tags and exact commit-SHA tags. Production Portainer must use the release-approved **exact-SHA image set**, never a moving branch tag and never a local source-build fallback.

## What CI proves

Current workflows can prove source/security contracts, package integrity, logical/raw mode contracts, native compilation, Windows normal/Portable execution and relocation, ARM64 server preflight, userspace WireGuard fallback, auxiliary proxy/runtime startup, generated mode validation, exact-SHA image publication and production-compose invariants.

CI results apply only to the exact commit and jobs that actually passed. A successful build or published package does not complete an unsupported requested feature, and an older green release cannot certify later source changes.

CI cannot prove a specific physical device, ISP/firewall/WAN path, OS permission flow, DNS/IPv4/IPv6 leak-negative behavior, third-party client interoperability, Android production-signing/upgrade acceptance, Apple distribution credentials, rendered visual quality or the live production deployment. Those remain separate manual/live release gates.
