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
original profile. Windows, macOS and Linux include original imported WireGuard,
AmneziaWG, bounded OpenVPN TCP/UDP, SOCKS5 and HTTP/HTTPS CONNECT in their native entry selectors alongside
the existing Shadowsocks and Hysteria2 choices. Imported packet selections use
the original `wireguard` or `amneziawg` protocol identity, independently of the
paired-node `wg`, `awg2-fast` and `awg2-strong` choices.

The main/profile catalog contains 25 explicit entry choices: the 19 paired
Router transports plus the distinct `wireguard`, `amneziawg`, `socks5`,
`http-connect`, `https-connect` and `openvpn` imports. Full-profile Add/Load/Update and
Connect serialization preserve those original IDs. Saving a choice does not
grant a new execution mode; imported connection admission still requires Local
and the original independent profiles.

Speed Lab's **temporary Router multihop** chooser and resolver currently admit
only the 19 paired Router entry transports. Selecting a new temporary imported
entry to a paired final remains unfinished work. The form preserves a main
profile's imported mode and rejects that unsupported temporary request instead
of replacing it with WG. This boundary does not narrow **Current path**
measurement of an already connected, captured imported graph. Native callback
tests consume the real daily and temporary controller catalogs separately;
catalog equality between those two workflows is not a capability contract.

The desktop host admits original WireGuard, AmneziaWG, SOCKS5, Shadowsocks 2022,
Hysteria2, HTTP CONNECT, HTTPS CONNECT and bounded OpenVPN entries. Its final transport catalog is Shadowsocks,
Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong and REALITY/Vision. A
catalog entry alone does not promise that every cross-product can be compiled.
The existing imported-entry compiler validates each original transport,
independent Start Layer, selected final resolver and physical socket graph.

| Captured entry | Baseline desktop graph admission |
|---|---|
| WireGuard, AmneziaWG | All six listed paired final transports, with independently captured entry/final layers and sufficient original packet capacity |
| OpenVPN TCP or UDP | The same six finals, with one original literal remote in a supported inline profile, fresh native connected-state observation, and sufficient actual packet capacity |
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

WireGuard and AmneziaWG remain userspace endpoints inside the same native Box.
The original private key, peer key, preshared key, addresses, AllowedIPs,
keepalive, endpoint MTU and AWG parameters remain attached to the imported
profile. Their physical permission is one original UDP peer tuple, or the
independently provisioned original entry layer's UDP tuple. Neither the final
peer, public proof destination nor DNS server gains a physical bypass.

The original entry's configured packet capacity must contain the complete
selected nested data and control envelopes, including AWG junk and both Start
Layers. A saved 1280-byte entry can therefore reject a nested packet final.
Admission never enlarges that original endpoint MTU. The restored TUN value is
validated with the shared `mobilemtu.NewPlan` contract against the captured
graph; it cannot expand the original packet envelope. This distinguishes the
virtual interface size from captured packet capacity without imposing a new
blanket Jumbo policy.

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

### Additional WireGuard and AmneziaWG gate

The packet extension preserves the 26 graph, 57/61 host and 13 native DNS
inventories above. `ROUTERVPN_IMPORTED_DESKTOP_PACKET_FIXTURES` names another
existing private directory for exactly 108 complete desktop graph files:
two original entry protocols, all six paired final transports, and all nine
independent entry/final layer pairs. Missing output or an unwritable requested
destination is fatal. Every graph retains one protected TUN, both original
proof lanes, final-owned Home AdGuard DNS and one bounded outer UDP tuple.

The additional exact host verdict inventory is:

| Test root | Required verdicts, including its root |
|---|---:|
| `TestDesktopImportedPacketGraphs` | 109 |
| `TestDesktopImportedPacketSourceOwnership` | 29 |
| `TestDesktopImportedPacketLimits` | 17 |
| `TestDesktopImportedPacketSelectedDNS` | 7 |
| `TestDesktopImportedPacketProfiles` | 3 |
| `TestDesktopImportedPacketProof` | 11 |
| `TestDesktopImportedPacketDailyConnectRestoreAndOwnedTeardown` (Linux) | 9 |

The source controls replace original keys, addresses, AllowedIPs, keepalive,
endpoint, packet MTU, AWG parameters, expected public exit, paired token, final
DNS and each independent layer. The limits reject cancellation, insufficient
entry capacity, an overflowing fixed MTU, missing layer provisioning,
Server/Compare, a paired entry-mode alias and an OpenVPN label substituted onto
a WireGuard/AWG profile without its original OpenVPN credentials. Home AdGuard, custom DoT
and custom DoH retain the final's original transport, port, TLS name and path.
The profile tests execute Add, Load, Update and Delete for both packet families.
Public entry proof rejects the wrong address, cancellation and owner replacement.

The production builder requires all 176 additional host verdicts on
Windows/macOS or 185 on Linux, with the same mandatory physical-inventory flag
for Linux lifecycle cases. It then executes the completed full-production
CLI against all 108 original graphs. The exact bundle receipt and graph bytes
must remain unchanged. Both new-build and reuse paths run this gate after the
existing 26-graph gate and before successful completion. Runner regressions
reject missing/duplicate/foreign/early verdicts, skips, failures, timeouts,
changed or linked graph files and replaced bundle receipts. Existing shared
native packet peer gates remain independently required; neither a parser pass
nor a fixture-based controller proof substitutes for installed-device traffic.

`ROUTERVPN_REQUIRE_IMPORTED_DESKTOP_LIFECYCLE=1` makes unavailable physical
network inventory fatal. Without that release flag, the lifecycle test explicitly
skips on hosts that deny the required interface inventory. This test retains
the shipping compiler, staging, process/Stop join, private directory, graph
registry and restoration transaction; installed-image and remote-proof
boundaries use the existing retained-runtime fixture seams.

### Additional bounded OpenVPN gate

OpenVPN uses the original inline profile inside the same retained native Box.
This admission requires exactly one literal TCP or UDP remote; scripts,
multiple remotes, hostname remotes, a system OpenVPN interface and incomplete
credentials are rejected. The original user/password bytes, certificate or
fingerprint policy, remote, transport, entry packet capacity, expected public
exit and independent Start Layer stay attached to that entry. No second VPN
service or invented connected receipt is used.

Before authentication, the native owner pins the exact Box endpoint pointer,
configuration digest and application TUN reader. Its first successful native
observation additionally pins the connected remote, native connection generation,
connection timestamp and actual packet capacity. The observation reads the
endpoint's existing authentication/ready state and live packet device; saved
MTU is only the required lower bound. Reconnection, a replaced endpoint or TUN
reader, changed remote/capacity, pending authentication after connection, or an
active/failed MTU transaction invalidates that owner. A later successful read
cannot replace the original tuple. A replacement child receives a fresh owner.

The host uses the existing atomic private mailbox with the explicit
`openvpn-observe` operation. It binds the response to the original process,
source, session, physical network generation, request generation, nonce,
caller deadline and TUN readback. Observation responses cannot substitute for
DNS responses. Cancellation joins an entered operation and does not adopt a
late success or retire a healthy connection solely because the caller stopped
measuring. Entry/final proof, selected DNS, response measurements, Current-path
Speed Lab, asynchronous measurement adoption and restore capture revalidate
the original connected observation. The native loop also checks it around
readiness, at heartbeat boundaries and around the actual selected-DNS query.
The observation cost is excluded from response sample timing.

Periodic native observation uses at most 250 ms and is capped by the last
successful original-tuple observation plus the existing two-second heartbeat
freshness bound. A brief timeout skips heartbeat, mailbox and MTU work and
retries; it does not close a still-fresh healthy child. Only a real successful
read advances freshness. Exceeding that bound or losing the original tuple
fails closed. A completed query must reobserve before another heartbeat can
publish. The portable actual-loop runner passes 15 race verdicts and rejects
five causal mutations, including the old terminal-timeout behavior and stale
publication. This extracted-loop evidence keeps its explicit native/OS fixture
boundaries; the 44 native and 13 DNS production verdicts remain independent.

`ROUTERVPN_IMPORTED_DESKTOP_OPENVPN_FIXTURES` is a separate required output
directory. Exactly 108 files cover TCP/UDP, all six paired final transports and
all nine independent entry/final Start Layer pairs. These graphs retain the
original physical TCP or UDP tuple, one protected application TUN, both proof
lanes and the paired final's selected DNS. The existing 26 proxy graphs and
108 WireGuard/AWG graphs are unchanged.

The separate host inventory has 192 verdicts on Windows/macOS and 196 on Linux:
108 graph children, full-profile round trips, public-proof negatives, exact
selected resolver tests, original-source replacement controls, bounded-admission
negatives, private observation receipt negatives, no-relatch controls, joined
cancellation, context-owned locks and the DNS/observation separation. The Linux
increment retains the actual controller staging, child/Stop join and restoration
fixture with the same mandatory physical-inventory flag. A native IPC fixture
is explicit evidence for the host protocol, not for OpenVPN TLS traffic.

The prepared native command has an additional exact 44-verdict inventory:
constructor (10), original tuple (18), caller context (4), mailbox (8), joined
cancellation (1) and actual TCP/UDP connected observations (3). It runs with
all production tags plus `routervpn_openvpn_remote_test`, requires
`ROUTERVPN_REQUIRE_IMPORTED_OPENVPN_OBSERVATION=1`, and rejects every missing,
skipped, duplicate, foreign, failed or prematurely completed verdict. The
actual connected fixture uses a real mutual-TLS/data peer and selected DNS;
its platform TUN readback and mapped physical tuple remain explicit fixtures.
The unchanged 13 native DNS verdicts run independently first.

Fresh builds and reused complete bundles must then pass the exact host
inventory and the full production CLI's `check -c` for all 108 OpenVPN graphs.
Original bundle receipts and graph bytes must remain unchanged before and
after parsing. Windows ARM64 preserves the existing race-toolchain exception;
every other matching host runs race detection. Gate regressions prove that
missing files/verdicts, symlinks, replacements, skips, errors and timeouts
prevent build/reuse success. Source registration checks bind the observation
implementation and both test templates to the actual native preparer. The
release-candidate source job invokes all three imported runner suites and the
complete heartbeat runner, including its new OpenVPN loop cases.

The November 7 development workspace passed the focused Go race suites, exact
26 graph checks with a freshly prepared pinned native CLI, and the Unix policy
regressions. That supplementary CLI omitted the optional PQ tag because the
workspace lacked the required Rust archive; none of these 26 graphs selects a
PQ mode. The full production native CLI parser remains mandatory in the release
gate. The packet extension also passed all 176 additional non-lifecycle host
verdicts under race detection and all 108 graph checks with that supplementary
CLI, alongside the unchanged 57 baseline non-lifecycle verdicts. Those executions
were on Linux; they do not establish Windows or macOS runtime acceptance.
The lifecycle tests could not run here because netlink interface inventory
was denied. The prepared native DNS mailbox and cancellation race cases passed;
the real Box uncached-query case failed during network-manager startup because
the workspace denied netlink sockets. That native query case remains mandatory
in the production gate. Verified Linux Swift 6.4.2 is available and has executed
the mobile source producers. The extracted desktop Swift profile callbacks also
passed 3,098 behavioral checks including the OpenVPN entry, and all 14 mutation
controls were rejected; their widgets and scheduling remain explicit fixtures.
The macOS SDK/AppKit build and PowerShell remain unavailable locally. Verified
Debian GTK headers, runtime and Xvfb have been extracted, but the executor
refuses Xvfb Unix sockets, so actual GTK execution remains unproved. These are explicit
remaining validation obligations, not successful installed-desktop acceptance.

The OpenVPN host extension also passed the exact combined 425 non-lifecycle
race verdicts (57 original, 176 WireGuard/AWG, 192 OpenVPN), and the supplementary
pinned CLI accepted all 108 newly emitted OpenVPN configurations. This parser
still omits the optional PQ tag and does not establish full-production bundle
acceptance. The native connected TCP/UDP and uncached-DNS cases compile but
remain blocked here by native Box network-manager netlink startup. The exact
native observation and DNS inventories remain mandatory in release builds.

## Remaining product scope

The wider shared OpenVPN compiler supports additional remote arrangements.
Desktop multiple-remote/failover and hostname-remote admission remain outside
this bounded single-remote unit. Live imported-path automatic MTU discovery,
Retest and cancellation of that MTU transaction remain unfinished. The public
Retest route rejects this imported multihop owner before native mailbox work;
initial automatic MTU transition also rejects an external entry. A validated
fixed/captured TUN value, native packet-capacity observation, observation
cancellation and fresh-child restoration do not implement that missing MTU
workflow. Ordinary paired-node MTU reader replacement remains unaffected.
Dynamic SOCKS UDP physical ownership remains unfinished. Additional paired final
families, Server/Compare for this direction, and complete graph parity remain
open requirements. Selected-path live proof, retained native lifecycle, package
verification and real installed-device acceptance are required independently
of source or configuration-parser success.
