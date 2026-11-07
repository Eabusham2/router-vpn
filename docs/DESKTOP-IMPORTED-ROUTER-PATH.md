# Desktop imported entry to paired Router final

Source admission added November 7, 2026. Installed Windows, macOS and Linux
acceptance remains distinct from the compiler, controller and parser evidence
below. The broader original requirement still covers imported nodes in either
hop role; this implementation does not close every imported graph or execution
mode. The shared compiler's wider scope is recorded in
[MOBILE-IMPORTED-ROUTER-PATH.md](MOBILE-IMPORTED-ROUTER-PATH.md).

## Daily connection

Select the independently paired Router VPN final as the main node. In the
multihop controls, choose the original imported entry, that same paired final,
Local execution and an admitted final transport. Entry mode can name the
original import protocol, or use the saved selection when it agrees with that
original profile. Windows, macOS and Linux include SOCKS5 and HTTP/HTTPS CONNECT
in their native entry selectors alongside the existing Shadowsocks and Hysteria2
choices.

The desktop host admits original SOCKS5, Shadowsocks 2022, Hysteria2, HTTP CONNECT
and HTTPS CONNECT entries. Its final transport catalog is Shadowsocks,
Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong and REALITY/Vision. A
catalog entry alone does not promise that every cross-product can be compiled.
The existing imported-entry compiler validates each original transport,
independent Start Layer, selected final resolver and physical socket graph.

| Captured entry | Baseline desktop graph admission |
|---|---|
| Shadowsocks 2022, Hysteria2 | All six listed paired final transports |
| SOCKS5 | REALITY/Vision; other compiler-supported graphs require an exactly bounded outer socket graph |
| HTTP CONNECT, HTTPS CONNECT | Shadowsocks or REALITY/Vision with the original carrier and selected-DNS capability |

An ordinary SOCKS5 UDP association negotiates a relay address. Desktop physical
ownership cannot grant that changing destination from the original control
socket, so such graphs fail before the current connection is stopped. An
independently provisioned Start Layer can make a graph's outer sockets static;
the same exact physical projection decides admission. No endpoint-wide or
all-port permission is substituted.

For CONNECT to Shadowsocks, the baseline carrier is TCP-only and requires a
compatible selected TCP, DoT or DoH policy. Home AdGuard UDP and other datagram
traffic require the independently paired final's original validated SS UoT-v2
service declaration. A raw imported option cannot grant that capability.
REALITY/Vision uses the paired final's own validated transport. Unsupported DNS
or transport combinations fail without changing the saved resolver. Home
AdGuard remains the default wherever the original graph can carry it.

## Source, proof and ownership

The imported profile and the paired final bundle stay separate. The final's
saved WireGuard identity must match its authenticated NodeProofID before its
selected transport can be captured. Entry protocol credentials, expected public
exit, TLS settings and Start Layer are taken only from the original external
profile. No private Router API token or synthetic Router address is invented for
that entry.

Each node retains its own Off, AES-256-GCM or AES-256-GCM + XOR choice. An entry
layer retains the original same-node public address, its separately provisioned
outer port and credentials, and its validated private inner service. The final
layer retains the final's own asset map. The complete original profiles,
credentials, policies and asset digests are sealed into the captured path.

The compiled graph uses one protected full-device TUN and two reserved loopback
proof lanes. The entry lane proves the original expected public address through
the imported transport. The final lane proves the paired node's private identity
through the complete chain. The selected final DNS configuration and resolver
query must then pass before public Connected state is published. A fresh private
mailbox nonce and monotonically increasing request generation bind that query
to the original session, complete configuration, network path, TUN reader, MTU
and caller deadline. Request and cancellation files become visible atomically
only after their private contents are complete and synced. The retained native Box uses
its selected DNS router with both caches disabled, preserving the original
upstream transport, TLS and bootstrap policy. Its matching result is admitted
only after the request is consumed and the same live TUN reader is observed.
An already cancelled request never enters DNS. Cancellation joins an entered
query and cannot adopt a late successful reply. A long query waits for a fresh
heartbeat from the same reader; a replacement reader or MTU transaction fails.
No OS resolver lookup can substitute for this proof, including when the live
launch disappears but its captured imported identity remains. The temporary
standalone transport seed never supplies DNS to the executable chain.

Preflight runs before draining the previous connection. The existing retained
native-node transaction stages the private graph, applies protection, owns the
child process and keeps its cleanup identity until Stop joins. The launch's
exact outer address, port and protocol tuples reach all three desktop hosts.
Unix helpers require the captured node session and configuration digest plus
the imported-path marker; a missing tuple list cannot fall back to broad
endpoint permissions. Persisted protection retains the same exact tuples.

A cancelled proof, changed original profile, changed paired source or replaced
runtime cannot admit the old result. Failed startup uses the existing owned
teardown. Temporary restoration captures the original graph, independent
profiles, settings and actual owned MTU readback before retiring the old owner;
the restored process receives a fresh runtime directory and session.

Saved connection profiles support Add, Load, Update and Delete for this direction.
Their independently captured imported hop policy must exist on Load. Deleting
the connection profile keeps the original nodes. An explicit Local request can
run a candidate when the saved final has Server or Compare selected, without
rewriting that saved choice; omission of the override is rejected. Server and
Compare requests for ordinary imported entries are rejected before acquiring
network authority.

## Evidence and required release checks

The new tests exercise original-source capture, exact physical permissions,
final-owned DNS, private final identity mismatch, credential replacement,
cancellation, complete saved profiles and explicit Local restoration semantics.
The shared physical projection test verifies immutable repeated capture and
rejects the controller after Close. The Unix adapter tests execute its actual
tuple parser and nft rule generator and reject missing, malformed, mixed-owner
or unbounded permissions.

`ROUTERVPN_IMPORTED_DESKTOP_FIXTURES` must identify an existing private output
directory. Failure to emit a requested file is fatal. The fixed inventory is
26 JSON files:

- 12 Shadowsocks/Hysteria2 entry graphs across the six admitted final modes.
- One SOCKS5 to REALITY/Vision graph. SOCKS5 to unwrapped Shadowsocks is a
  required negative verdict and emits no file.
- Four HTTP/HTTPS CONNECT graphs across Shadowsocks and REALITY/Vision.
- Nine independent entry/final layer pairs for Shadowsocks to REALITY/Vision.

The release-selected roots are
`TestDesktopImportedNativeCaptureExactGraphAndPhysicalSockets`,
`TestDesktopImportedExplicitLocalPreservesSavedExecutionAndLayers`, and
`TestDesktopImportedDailyConnectRestoreAndOwnedTeardown`. Their exact verdict
set on Linux contains three root passes, 18 graph leaves, 27 saved-execution/layer
leaves and three lifecycle leaves. Windows and macOS run the 47 graph/layer
verdicts; the retained-process fixture is currently Linux-specific. The lifecycle leaves are `success`, `public-proof`
and `source-replaced`. The saved executions are `local`, `server` and `auto`;
each has all nine independent layer pairs. Missing, skipped, duplicate or foreign
verdicts cannot count as release evidence.

The DNS parent group adds ten exact verdicts: the six
`TestDesktopImportedDNSReceiptAdmission` cases (`success`, `dns-failed`,
`reader`, `source`, `owner`, `old-receipt`) and its root, plus
`TestDesktopImportedDNSCancellationWaitsForNativeJoin` and
`TestDesktopImportedDNSCannotUseSuccessfulOSLookup`, and
`TestDesktopImportedDNSAtomicPublicationAndFreshHeartbeat`. The prepared native
`cmd/sing-box` group adds thirteen: `TestRouterVPNImportedDNSMailbox` and its
ten cases (`success`, `dns-failed`, `session`, `config`, `path`, `reader`,
`deadline`, `replay`, `source-replaced`, `owner-replaced`),
`TestRouterVPNImportedDNSCancellationJoins`, and
`TestRouterVPNImportedDNSNativeRouterIsUncached`. The last test executes the
real Box and DNS router against a real captured TCP resolver, alternating
success, NXDOMAIN and success and counting all three wire queries. Its TUN
readback is an explicit fixture; it does not claim an installed OS tunnel.

The production builder therefore requires exactly 61 host verdicts on Linux
and 57 on Windows/macOS. It checks all 26 emitted graphs with the completed
bundle's actual CLI, comparing the source-owned bundle receipt before and after
the checks. Fresh builds and reused bundles both execute that gate. A separate
matching-host native run executes all 13 DNS verdicts immediately after the
existing native command tests, with the full production tags and the original
verified PQ linker environment. Only Windows ARM64 uses the established
non-race exception. A missing, skipped, failed, duplicate, foreign, reordered or
timed-out verdict prevents successful completion; a root pass cannot replace
its leaf results. Runner regressions exercise these failures, source template
registration and failure propagation before build/reuse success.

`ROUTERVPN_REQUIRE_IMPORTED_DESKTOP_LIFECYCLE=1` makes unavailable physical
network inventory fatal. Without that release flag, the lifecycle test explicitly
skips on hosts that deny the required interface inventory. This test retains
the shipping compiler, staging, process/Stop join, private directory, graph
registry and restoration transaction; installed-image and remote-proof
boundaries use the existing retained-runtime fixture seams.

The November 7 development workspace passed the focused Go race suites, exact
26 graph checks with a freshly prepared pinned native CLI, and the Unix policy
regressions. That supplementary CLI omitted the optional PQ tag because the
workspace lacked the required Rust archive; none of these 26 graphs selects a
PQ mode. The full production native CLI parser remains mandatory in the release
gate. The lifecycle test could not run here because netlink interface inventory
was denied. The prepared native DNS mailbox and cancellation race cases passed;
the real Box uncached-query case failed during network-manager startup because
the workspace denied netlink sockets. That native query case remains mandatory
in the production gate. Native GUI compilation was also unavailable locally: Swift,
PowerShell and GTK development dependencies were absent. These are explicit
remaining validation obligations, not successful installed-desktop acceptance.

## Remaining product scope

The shared mobile compiler also supports imported WireGuard, AmneziaWG and
OpenVPN entry families; this desktop admission does not yet expose them.
Dynamic SOCKS UDP physical ownership remains unfinished. Additional paired final
families, Server/Compare for this direction, and complete graph parity remain
open requirements. Selected-path live proof, retained native lifecycle, package
verification and real installed-device acceptance are required independently
of source or configuration-parser success.
