# Router VPN native applications

Router VPN client packages are **generic application/runtime packages**. Installing an app and linking a home router are separate operations. The app is installed once; private router/node data can then be added, replaced, revoked or expanded without reinstalling.

A source/build claim is not a physical-device release claim. Real VPN permission, route/DNS/IPv4/IPv6 behavior, reconnect/network-change handling, leak-negative behavior and exact selected-node/exit proof remain live gates where applicable. The current source contract is below; use the exact commit's native/package results for build evidence and [LIVE-RELEASE-EVIDENCE.md](LIVE-RELEASE-EVIDENCE.md) for device and deployment evidence. An older green release does not certify newer source.

## Windows

The Windows daily-use application is native WPF (`PresentationFramework`) and talks to the private loopback Router VPN controller at `127.0.0.1:8788`. Installed and Portable packages launch the WPF application, not Edge/Chrome app mode or a WebView wrapper. The normal installed package has a Router VPN Start Menu/icon entry. While the app is running, a native Windows system-tray companion provides **Open Router VPN**, **Emergency Stop** and **Exit Router VPN**; minimizing the WPF window moves it to that tray without changing VPN state. Portable self-tests must exit the native UI/controller cleanly and still pass after the folder is relocated.

Windows source includes native raw WireGuard, full-device layered TUN/DNS paths, a Windows firewall kill-switch helper and real multihop where supported. WSL is not counted as the native Windows VPN implementation.

The current native external-node path supports validated WireGuard, AmneziaWG, SOCKS5, HTTP CONNECT, HTTPS CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN profiles. OpenVPN readiness checks the packaged native engine; it is not unconditionally disabled on Windows. The older standard-exit/helper API has a separate, narrower contract. Every ordinary external connection requires selected DNS and expected-public-exit proof. See the graph boundaries below and [MOBILE-OPENVPN.md](MOBILE-OPENVPN.md) for the shared native OpenVPN profile contract.

Windows owns a pinned standalone Tor process and Router VPN's native Go pluggable transports for obfs4, meek/meek_lite, Snowflake, WebTunnel and validated Auto/Custom bridge sets. The active connection does not launch Lyrebird. Windows ARM64 uses the verified x64 Tor process under Windows 11 userspace compatibility; the app, Go transports, packet engine and driver remain ARM64. Hosts without the required execution support remain unavailable. See [WINDOWS-TOR-ARM64.md](WINDOWS-TOR-ARM64.md).

## macOS

The macOS package contains a native AppKit/MapKit `RouterVPN.app` for amd64 and arm64 with its Router VPN application icon and native menu-bar status item. The menu-bar item provides **Open Router VPN**, **Emergency Stop** and **Quit Router VPN** while the app is running. The app owns a sibling Router VPN controller only when it starts that controller itself. Closing the app performs Router VPN emergency cleanup and stops only the owned process. The app contains no WebKit view.

Native routing, PF kill-switch handling and real multihop are source-implemented. Shared graph compilation and retained native-host admission are separate contracts. The retained macOS direct Local host admits WireGuard, AmneziaWG, authenticated SOCKS5, HTTP CONNECT, HTTPS CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN with captured On-connect or Always protection. Imported AWG Fast/Strong profiles retain all eleven original parameters. OpenVPN preserves captured TLS/authentication and ordered compatible TCP/UDP fallback. Provisioned Hysteria2 also retains AES-256-GCM and AES-256-GCM plus XOR Start Layers. The host preserves selected DNS, LAN/IPv6, MTU, credentials and the original PF/utun cleanup owner.

The retained Local ordinary WG/AWG-entry path supports Shadowsocks, HTTP CONNECT, HTTPS CONNECT and unlayered Hysteria2 exits while capturing both private sources and their independent proofs. Only the first root receives physical egress; the final profile owns published status, Stop, measurements and exact proved-Local restoration. CONNECT preserves separate proxy credentials, and HTTPS additionally preserves its captured TLS server name and trust. Hysteria2 keeps the final QUIC/TLS/password peer and selected UDP DNS inside the encrypted entry path. The installed native gate requires its complete 117-case positive/refusal inventory, actual encrypted entry and authenticated final peers, selected-policy proof and original native cleanup. Source/race/cross-build evidence does not establish actual macOS PF/utun execution. Other entry/final families, broader layers, predecessor and ordinary Server/Compare host admission remain separately accountable. See `cmd/client/desktop_external_host_darwin.go`, `internal/mobilemultihop/desktop_external_policy.go`, `deploy/test_macos_external_host.py` and [the current continuation evidence](CONTINUATION-EVIDENCE-2026-11-04.md).

macOS also ships the native Tor bridge builder with an owned standalone Tor process and native Go pluggable transports. The UI exposes obfs4, meek/meek_lite, Snowflake, WebTunnel and validated Auto/Custom bridge sets while keeping private bridge lines out of public profile/status output.

Unsigned/local builds use the targeted System Settings → Privacy & Security → Open Anyway flow only after verifying the artifact. Do not globally disable Gatekeeper. Original requirement #339 qualifies macOS signing/notarization as optional polish when practical; signed/notarized claims require actual evidence. Physical macOS visual/network validation remains required. This qualification does not waive iOS provisioning or truthful Apple distribution requirements; see [the recovered authority](RECONCILIATION-2026-10-30-SOURCES.md#qualifications-and-attribution-corrections).

## Linux

Linux packages contain a native GTK3 application for amd64 and arm64, built on matching native GitHub runners. It uses libcurl/json-glib for the loopback controller API and does not launch or embed a browser. The package remains generic and requires GTK3/libcurl/json-glib desktop runtime libraries.

Linux has native routing, nftables kill-switch handling and real multihop. Its current native external-node path supports WireGuard, AmneziaWG, SOCKS5, HTTP CONNECT, HTTPS CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN. Direct and composed paths retain the selected DNS, device policy and expected-public-exit proof inside one owned packet runtime; the legacy helper API remains a separate, narrower path.

The separate legacy direct stock path retains its original sealed engine/configuration, creation pidfd, native table creator, state-file capability and joined cleanup for Off, On-connect and Always. The installed persistent standard-owner service retains that authority across controller retirement and authenticates each bounded control request through its original native peer. Explicit Off releases the actual creator, proves absence and saves the exact preference; boot dispatch preserves standard versus legacy selection, and proved-idle upgrades join the original service before source replacement. Selected-DNS proof must traverse the original child listener without a cached answer before public proof and Connected; runtime/protection, profile and preparation-time network ownership remain captured. Actual pinned-core DNS and installed service/nft/TUN cases are mandatory in native validation. Protected cross-adapter transfers, active Always upgrades, same-boot service-crash recovery and monotonic network-event continuity remain unfinished. See [the service contract](LINUX-STANDARD-OWNER-SERVICE.md); neither a refusal nor a source test closes those requirements.

Linux also ships the native Tor censorship-bridge panel, owned standalone Tor process and native Go pluggable transports for obfs4, meek/meek_lite, Snowflake, WebTunnel and validated Auto/Custom bridge sets.

## Android

Android is a native `VpnService` application. It has real WireGuard and native AmneziaWG paths plus the pinned combined libbox/Xray runtime for supported layered modes. AUTO/SMART/CUSTOM require exact selected-node private path proof. Strict embedded sessions require the platform lockdown contract; unsupported strict paths fail closed.

Android multihop now composes supported WG/AWG, PQ, proxy, native Xray, helper/composite and complete MAX families inside one owned system VPN. Entry and exit retain separate identities, credentials, Start Layers and proofs. Local, Server and Compare both use the implemented graph and pairing contracts; family support does not establish every possible combination.

The app-private custom-node store and native controls support WireGuard, AmneziaWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN through the shared external-policy compiler. OpenVPN runs as a userspace endpoint in the existing Libbox VPN owner; it does not start a second system VPN. Selected DNS, expected public exit and any required entry proof precede Connected. Paired OpenVPN Server/Compare requires independently provisioned Local and Server credentials; see [MOBILE-OPENVPN.md](MOBILE-OPENVPN.md).

Plain Tor and supported Tor bridges use the packaged native Tor and Go pluggable transports inside the existing VPN lifecycle. Direct and supported captured-predecessor Local paths require circuit, selected-DNS and entry proofs as applicable. Tor Server and Compare have distinct owned paths: `AndroidTorProfile` captures the private Router entry and authenticated Server source, while `AndroidTorCompareRuntime` and `LayeredVpnService.TorCompareTrial` own concrete candidate trials inside the system VPN. An ordinary external execution receipt cannot authorize Tor. The source path does not establish unrestricted graph support or physical acceptance; see [the measurement contract](TOR-LAST-RELAY-PROBE.md).

Physical VPN permission, lockdown, reconnect/network change, DNS/IPv4/IPv6, custom-exit traffic and leak-negative validation remain release gates. The authoritative delivery supports a configured persistent production key and verifies the final APK's signer, version and source; a missing optional configuration remains explicitly debug-signed and the dedicated CI fallback is debug-only. See [Android signing and upgrade delivery](../android/PRODUCTION-SIGNING.md). The owner's signing configuration, production-signed full release and real-device upgrade acceptance remain separate evidence requirements.

## iOS / iPadOS

The SwiftUI app uses the pinned WireGuardKit/AmneziaWG owner for applicable raw WG/AWG paths and the pinned Libbox Apple bridge for layered, adaptive-MTU, multihop, Tor and external paths. One owned PacketTunnel retains the selected graph and verifies the exact node, DNS and required exit before reporting success.

Strict mode uses NetworkExtension route lockdown (`includeAllNetworks` + `enforceRoutes`), aligns local-network exclusion with imported LAN policy and enables on-demand reconnect; strict startup fails closed when those platform controls are not active.

Per-node private bundle storage and validated external-node selection are implemented. External WireGuard, AmneziaWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and bounded inline OpenVPN use the Libbox PacketTunnel path and require selected-DNS and expected-public-exit proof. The original OpenVPN profile, TLS material, ordered remotes and supported fallback transports remain captured; arbitrary provider profiles are not promised.

The native graph includes supported WG/AWG, PQ, proxy/Xray, helper/composite and complete MAX families, with separately captured entry and exit Start Layers. AUTO, SMART AUTO, CUSTOM and ALL preserve their owned trial, proof and restoration rules; ALL selects validated complete MAX branches. This source support does not establish unrestricted graph parity or physical acceptance.

Plain Tor and supported Tor bridges use the native Tor and pluggable-transport PacketTunnel implementation. Direct and supported captured-predecessor Local paths preserve their own circuit, selected-DNS and entry proofs. `RouterVPNExternalExit` compiles the distinct authenticated Server path; `RouterVPNTorCompare` and `PacketTunnelProvider` retain candidate engines, source/network ownership, cancellation and the proved winner. Server/Compare requires the captured private Router entry and its matching private Tor source. These source integrations do not replace native package and physical iPhone/iPad acceptance.

Physical iPhone/iPad permission, route-lockdown, reconnect/network change, DNS/IPv4/IPv6, Libbox/custom-exit traffic, leak-negative behavior and signing validation remain release gates.

## Graph boundaries

The packaged desktop Router VPN node-to-node API composes a WG/AWG entry with Shadowsocks, Hysteria2, REALITY Vision, PQ REALITY Vision, REALITY XHTTP, Naive H2, Naive H3, WireGuard, AWG Fast, AWG Strong, SS-V2Ray, Split or MAX composite exits. Windows, macOS and Linux selectors, complete connection profiles and Speed Lab preserve these exact transport IDs and Local/Server/Compare choices; invalid saved choices cannot silently become Shadowsocks. A legacy Linux installation without the verified native runtime retains its narrower Shadowsocks/Hysteria2 capability catalog. It captures both nodes, their Start Layers, policy and the proved Local/Server execution. The desktop external-node API separately supports the broader captured Router-entry mode set and ordinary imported entry/exit protocols. Mobile node-to-node graphs also have broader supported families. A graph accepted by one API is not evidence that another API or platform supports it. Broader Router entry modes and other requested node-to-node compositions remain unfinished.

The desktop WG/AWG exit is its exact native packet endpoint in Local execution; Fast and Strong retain all eleven captured AWG parameters and the keys belonging to each node. Server execution removes that local exit endpoint and uses an authenticated isolated relay with an independently paired WG/AWG client identity. The updated agent validates the captured public-key pin on acquisition and renewal; the client rechecks capabilities on renewal and retains the same pin when Speed Lab restores a proved Server choice. Both sides compare canonical X25519 public identities, so alternate encodings of the same private key cannot authorize independent peers. Entry/exit Start Layers, selected DNS and protection remain captured. Nested packet MTU includes IPv4/IPv6 framing, AWG S4 transport padding and the selected Start Layer envelope before alignment. Incompatible fixed values and an entry too small for the minimum nested packet fail rather than being replaced with defaults; see the explicit capacity example in the execution guide. See [MULTIHOP-EXECUTION.md](MULTIHOP-EXECUTION.md) for pairing and version boundaries. Native package and physical-device acceptance remain separate evidence.

The SS-V2Ray, Split and MAX additions are their captured TCP/UDP composite forms. Their dispatcher keeps separate authenticated TCP and HY2 children; both children traverse the captured entry, or the one captured exit AES/XOR Start Layer which traverses that entry. Server execution removes the entire local exit closure and retains the entry, selected DNS/bootstrap and proof lanes before using its authenticated private lease. Complete saved profiles and Speed Lab retain the exact composite mode and already-proved execution. This does not establish the distinct complete MAX packet/helper graph or broader Router-entry parity. See the execution guide for the exact native traffic and release boundaries.

Ordinary external Server/Compare paths require a paired Router entry with an authenticated isolated execution owner and the exit's required independent credentials and response probes. An unmanaged external provider import cannot authorize server administration. OpenVPN remotes, TLS/authentication options, transport nesting, MTU and Start Layer maps must satisfy the bounded native contract; unsupported directives and incompatible graphs are rejected without dropping policy. See [MULTIHOP-EXECUTION.md](MULTIHOP-EXECUTION.md) and [MOBILE-OPENVPN.md](MOBILE-OPENVPN.md).

Desktop Tor has direct Local, supported captured Router/ordinary-external predecessor Local, and authenticated Server implementations. Server/Compare requires the private Router entry; an ordinary external provider cannot authorize server administration. `desktop_tor_prepare.go`, `desktop_tor_predecessor.go` and `desktop_tor_comparison_driver.go` retain those separate captures. Public Compare uses last-relay and shared-external HTTP probes, rechecks the winner and preserves its proved execution during restoration. See [TOR-LAST-RELAY-PROBE.md](TOR-LAST-RELAY-PROBE.md) for the exact measurement and ownership contract.

Desktop Local and Server Tor cover have native ownership paths; outgoing cover is distinct from predecessor padding and virtual Jumbo capacity. Their selected policy, native counters, expiry and source identity must pass their own host gates. See [TOR-PADDING.md](TOR-PADDING.md). These existing implementations supersede blanket older claims that Tor Server/Compare, ordinary predecessors or all desktop Tor cover are absent. Applicable graph admission, current-SHA native/package verification and physical acceptance remain required for each path.

## Native Speed Lab

Windows, macOS, Linux, Android and iOS/iPadOS expose a native **Speed Lab** surface. It is separate from lightweight live telemetry and from Auto-MTU testing.

Speed Lab measures real Internet download/upload throughput, idle latency distribution, download-loaded latency and upload-loaded latency. Auto timing can stop after bounded throughput stabilization; custom minimum/maximum test-time controls are also available. Mbps is measured from real transfers and is never derived from RTT.

The default test follows the exact current path. Temporary tests are transactional: they may construct only a platform-real configuration, must not overwrite the saved profile, and restore the prior runtime/state after the test. Results are rejected if the measured session/graph changes before adoption.

Supported multihop measurements keep entry and exit identity separate even when the nodes reuse private addresses. Android and iPhone/iPad also expose an owned native routed-hop measurement action, and iPhone/iPad temporary tests can use the saved supported multihop graph. Results describe the cumulative device-to-entry and device-through-entry-to-exit paths; they do not invent segment bandwidth or extend the supported graph family. See `docs/SPEED-LAB.md`.

## Tor censorship-circumvention policy

The Tor bridge family uses vetted Tor circuit cryptography plus real pluggable transports: **obfs4, meek/meek_lite, Snowflake, WebTunnel and validated Auto/Custom bridge sets**. Imported profile data cannot inject executable paths or raw `ClientTransportPlugin` commands; the trusted runtime owns PT registration and Tor bootstrap.

Strict Direct dynamic Tor traffic on Linux uses the mandatory native socket owner. Other desktop targets require the eligible fixed-obfs4 or proved-predecessor contract enforced by `internal/mobiletor/desktop_bridge.go`; Linux admission does not grant Windows or macOS dynamic Direct support. Incompatible strict combinations fail closed and remain unfinished requirements. Mobile uses its own system VPN/route-lockdown contract. Tor remains the proved encrypted final path. Compatible Router entry Start Layers may use AES-256-GCM with optional XOR whitening; whitening is obfuscation alongside authenticated encryption, never a substitute cipher.

## Native application updates

Desktop launchers run a short-lived exact-SHA update helper. It requires a strict-descendant gated release, verifies the release manifest and package digest, stages one package atomically, persists private status and notifies the user. It does not replace a running installed or Portable application.

Android verifies the published APK metadata before opening a trusted GitHub asset; Android's package signature and confirmation remain authoritative. iOS/iPadOS verifies the published IPA metadata before opening the exact release page; Apple/TestFlight/App Store or explicit sideload signing remains authoritative. See `docs/AUTO-UPDATES.md`.

## Nodes, maps and latency

Native node managers support current/recent, last-used, measured-latency and name ordering. Automatic lowest-latency selection is withheld until at least two usable nodes have real measurements. Missing coordinates remain missing; a node can stay fully usable in the list without an invented map position.

## Router linking and node identity

A private router bundle import is data, not application installation. Generic packages contain no linked router secrets. The desktop importer stages decoded private files in a bounded `0700` temporary tree, uses `0600` files, validates names/counts/sizes and the WireGuard server-public-key-derived node identity, then atomically commits the generated profile. A failed import must not leave a partially visible node.

The stable public proof identity is derived from the server WireGuard public key. `Connected` requires the private Router VPN proof endpoint or the custom exit proof path to return/observe the exact expected identity/exit. Generic Internet reachability or `{"ok":true}` alone is not VPN path proof.

## Forwarding ownership

Daily client forwarding is explicit and owned by the authenticated requesting tunnel peer. A peer clear operation must remove only that peer's rules. Broad Protected DMZ is intentionally an authenticated Setup Center/server-admin action because it must reserve infrastructure ports and avoid collisions with enabled explicit forwarding ranges.

## Truth boundary

Unsupported platform capabilities remain unavailable with a real reason and remain unfinished requirements until implemented and verified. CI/source readiness does not replace physical full-device validation, and UI/CSS must never force a mode or platform feature Ready/Connected.
