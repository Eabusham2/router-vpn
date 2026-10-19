# Current implementation status

Updated October 19, 2026. This file describes committed source and remaining
delivery work. The binding scope is [REQUIREMENTS-RECONCILED.md](REQUIREMENTS-RECONCILED.md).
Source tests, native configuration tests and older releases do not establish
completion of the current commit's packages, physical devices or deployment.

## Current continuation

The source has advanced beyond the old WireGuard-only mobile multihop and
mobile-Tor exclusions. Those historical restrictions no longer describe the
application source and must not trigger reimplementation of committed work.

The active implementation work is:

- Finish Android and Apple adoption of complete MAX profiles whose physical
  outer endpoint is a hostname. The committed shared compiler validates the
  complete capture, uses an explicitly owned cancellable resolver and preserves
  credentials, TLS identity, mode and source hashes. The app/provider handoff
  must retain that ownership through startup, cancellation and replacement.
- Apply saved DNS, IPv6, LAN and MTU policy consistently to ordinary external
  nodes in the graph compiler and native hosts. Explicit Home DNS now survives
  import and reload. It requires a captured, proven Router VPN entry; a direct
  external connection cannot silently replace it with Rescue. Absent legacy
  policy retains its documented persisted migration.
- Complete the new exact-SHA APK, Xcode/IPA, desktop packages, server images,
  generated compose and publication gates after source changes.

The Apple MAX source gate, LAN-policy fixture, canonical macOS native-test
paths and Android pinned-NDK setup order have been corrected on main. These
fixes preserve production validation and native failure propagation. The final
release pipeline is not declared complete by those individual corrections.

## Product split

- **Router VPN app:** the native daily VPN client with map and shared node
  catalog, Connect/Disconnect, modes, saved connection profiles, DNS, multihop,
  Speed Lab, MTU, kill switch, LAN policy, forwarding and settings.
- **Setup Center:** private deployment, administration, recovery, downloads,
  pairing, simple third-party Methods, Full Guide and AI Help.

Generic packages contain no private node credentials. Install once and link
nodes separately. Node selection never silently connects. Fastest requires
usable measurements; missing coordinates are never replaced by IP-derived
fiction. Profile changes require an idle, validated transaction with rollback.

## Native application source

| Platform | Application and runtime |
| --- | --- |
| Windows x64/ARM64 | Native WPF application, normal installer and Portable ZIP, native tunnel engines, firewall ownership, custom exits and local/server multihop. |
| macOS Intel/Apple Silicon | Native AppKit/MapKit application, tunnel engines, PF policy and desktop multihop. The installed application is not a browser wrapper. |
| Linux x64/ARM64 | Native GTK application, tunnel engines, nftables policy and desktop multihop. |
| Android | Native VpnService with WG/AWG and the combined pinned Libbox/Xray runtime. Layered modes, Tor, complete MAX and multihop use one owned system VPN interface. |
| iOS/iPadOS | SwiftUI app and one PacketTunnel. Raw WG/AWG uses the pinned WireGuardKit owner where appropriate; layered, adaptive-MTU, Tor, complete MAX and multihop use the owned Libbox runtime. |

Strict Apple sessions require actual NetworkExtension route-lockdown settings
and LAN exclusion matching the selected graph. Both nodes participate in
multihop LAN policy. Native session ownership rejects stale Connect, proof,
measurement, cancellation and profile handoffs.

Compilation and executable boundary tests remain distinct from physical
permission, routing, leak, reconnect, sleep and network-transition tests.

## Modes, helpers and profiles

The source implements WG, AWG Fast/Strong, Rosenpass-protected WG/AWG,
Shadowsocks 2022, Hysteria2, REALITY/Vision, PQ REALITY, XHTTP, Naive H2/H3,
SIP003/TLS helpers, split transport, complete MAX TLS/QUIC and validated
Start Layer compositions. Raw Xray mode `max` is distinct from a complete MAX
chain containing its mandatory PQ base and middle/outer layers.

AUTO, SMART AUTO, logical fallback, CUSTOM and ALL use captured profiles under
the saved encryption, obfuscation, base and fallback policy. ALL requires
complete MAX branches. Labels or incomplete credentials do not grant readiness.
Apple trials run inside one provider session with checked native close, fresh
node/DNS proofs, final MTU activation and restoration semantics; see
[IOS-OWNED-STRATEGIES.md](IOS-OWNED-STRATEGIES.md).

Saved connection profiles retain node references, mode, DNS, policy and
multihop choices without duplicating private keys into another credential store.

## Multihop and comparison

Mobile graphs now include WG/AWG, proxy, native Xray, PQ, complete MAX and
helper/composite families, including captured entry and exit Start Layers.
They are no longer restricted to WG entry with WG/Shadowsocks/Hysteria2 exits.
Every accepted graph preserves node credentials, separate entry/exit proofs,
routing ownership, selected DNS and individual MTU bounds.

**Local** executes the nested exit on the device. **Server** executes an
isolated exit session on a paired entry server and therefore gives the entry
the exit-tunnel trust role. **Compare both** retains the eligible lower score:

```text
(last-node routed response time + external-server routed response time) / 2
```

Both candidates use the same randomly selected external endpoint. A timeout,
failed identity/probe, stale path or invalid measurement disqualifies the
candidate. The selected candidate must pass both probes again before adoption.
These are routed response times, not mislabeled ICMP pings.

Private registry pairing, separate protocol peer ownership where required,
authentication, expiry, acknowledged deletion and relay cleanup remain
mandatory. See [MULTIHOP-EXECUTION.md](MULTIHOP-EXECUTION.md).

## DNS, MTU and measurement

Router VPN node paths support Home AdGuard, measured Fastest, Custom UDP/TCP,
DoT, DoH, DoH3 and Rescue through captured policy. Resolver names, bootstrap
routes and destination retain the selected tunnel owner. Ordinary external-node
policy integration is tracked above; controls on Router VPN nodes do not
complete that separate host path.

Android and Apple implement Auto-MTU, Retest and Cancel using the owned native
interface, actual readback, authenticated through-tunnel probes, rollback,
path-specific history and measurement holds. History is not presented as a
fresh current-path result. Adaptive WG/AWG uses the Libbox endpoint owner
without discarding AWG parameters; fixed/manual/default may retain the raw
backend. See [../internal/mobilemtu/README.md](../internal/mobilemtu/README.md).

The private optimizer requires an authenticated probe peer. An external node
cannot claim that optimizer merely by accepting Auto or applying a default
MTU; it needs a supported probe and actual native interface owner.

Bounded padding, compatible Jumbo TUN policy and nested MTU checks are present
in mobile source. A configured 9000-byte TUN does not prove that a public path
carries 9000-byte packets.

Speed Lab and per-hop measurements use owned transfer lanes, actual bytes,
latency samples and stale-result rejection. Live RTT, 50-sample node statistics,
current-path Mbps, per-hop Mbps and optimizer throughput remain distinct.
Temporary trials preserve saved policy and restore the captured prior runtime.
See [SPEED-LAB.md](SPEED-LAB.md).

## Native Tor and external protocols

Android and Apple now contain native Tor and pluggable-transport source for
plain Tor, obfs4, meek_lite, Snowflake, WebTunnel and validated bridge sets.
The C package and PT/session implementation join the existing VPN runtime;
Tor is not simulated by an ordinary SOCKS profile. Selected DNS, Tor proof and
the captured predecessor are checked before Connected. Imported values cannot
inject torrc commands or executable plugin paths.

Real Java/Swift graph fixtures cover 348 Tor variants per mobile platform.
The pinned native registry accepts those graphs and rejects corresponding
missing-Tor-engine mutations. These constructor/configuration checks do not
start a public Tor circuit or replace APK/IPA and device networking tests.

Windows x64, macOS and Linux use pinned owned Tor/helper processes. Windows
ARM64 uses verified Windows 11 x64 userspace compatibility for Tor/Lyrebird;
the app, VPN engine and driver stay ARM64. Capability checks describe this
accurately and reject hosts without the required execution support.
See [WINDOWS-TOR-ARM64.md](WINDOWS-TOR-ARM64.md).

External imports include validated WG/AWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks,
Hysteria2 and OpenVPN paths exposed by native hosts. Ordinary external exits
prove the saved expected public IP. Tor uses its separate owned public-exit
proof. Plain proxies are not labeled authenticated encrypted VPNs.

Windows OpenVPN capability checks its installed native runtime/helper; it is
not unconditionally disabled. Mobile OpenVPN uses the pinned userspace TLS
client and documented inline-profile subset. Exact transport, authentication,
certificate and hop requirements still apply; see [MOBILE-OPENVPN.md](MOBILE-OPENVPN.md).

## Server and private production

Server source includes the protocol/helper families, private node proof and
authenticated MTU services, paired relay sessions, forwarding, Setup Center
administration and server-side multi-provider AI Help. Actual provider
credentials and availability require live validation.

Production Portainer compose is exact-SHA and image-only. Nine custom images
and their compose references must match the release source. A moving branch
or unrelated green workflow cannot certify it. The stack obtains no
Docker-socket mount.

Setup Center/admin ports **8786-8793**, private SOCKS5 and DAITA-like port
**45999** remain private. ASUS exposure owns only exact tagged Router VPN
DNAT/FORWARD rules. Foreign same-port rules win. Failure withdraws Router VPN
exposure while preserving household Internet, DNS, DHCP, IPv6 and unrelated
hooks.

## Build, downloads and acceptance

GitHub Actions is the normal native build environment. Downloads require the
exact requested revision, source provenance and checksums:

```text
matching exact-SHA GitHub Release asset or Actions artifact
→ Windows x64/ARM64 installed/Portable only: bounded requested-package fallback
→ verified generic secret-free package
→ download with owned progress, cancellation and retained retry
```

macOS and Linux never use the AI Board as a substitute native build environment.
Android and iOS/iPadOS never use router-local builds. The router-local fallback is bounded to the requested generic **Windows/Portable** package
and uses approved same-image components. PortableApps/PAF is retired; normal
Router VPN Portable ZIP x64/ARM64 remains supported.

READY output and its workspace remain available for 30 minutes. Repeat or
interrupted download does not extend the deadline. Cancel/Delete, expiry and
shutdown clean owned files; failure remains visible and retried.

The final source generation needs its authoritative native matrix, ARM64
server/preflight checks, exact compose and publication. Whole-project acceptance
then also requires physical devices, visual/DPI testing, leak/network
transitions, off-LAN interoperability, private server and AI-provider checks,
Apple signing/distribution, deliberate deployment and live ASUS validation.
Use [LIVE-RELEASE-EVIDENCE.md](LIVE-RELEASE-EVIDENCE.md) and
`deploy/live-release-evidence.py` to bind real evidence to the exact SHA.
This source-status document marks none of those live gates complete.
