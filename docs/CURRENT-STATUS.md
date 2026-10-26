# Current implementation status

Updated October 26, 2026 (UTC). This file describes committed source
and remaining delivery work. The binding scope is [REQUIREMENTS-RECONCILED.md](REQUIREMENTS-RECONCILED.md).
Source tests, native configuration tests and older releases do not establish
completion of the current commit's packages, physical devices or deployment.

## Current continuation

The PQ controller now separates its five-second connection admission bound
from the lifetime of an admitted native socket. Successful Xray/Hysteria/gVisor
packet dials can retain their owner context until controller shutdown; late or
cancelled returns still close before protocol or key adoption. Explicit
monotonic timing protects the bound even if a timer callback is delayed. The
existing repeated race gate, deadline enforcement, packet byte-count checks,
and authenticated readiness are preserved. The native AWG packet bind now
also retains a successful owner beyond its separate ten-second admission
budget, with monotonic late-return rejection and exact generation cleanup.
Its actual pinned package passes real I/O across that admission boundary.
Current packaged native traffic
and physical acceptance remain separate from these controller tests.

The DNS helper reserves one shared TCP/UDP endpoint with TCP ownership first,
including IPv6 and its captured zone. Only ephemeral requests retry a UDP
collision, at most eight times, releasing each partial owner before retry;
a fixed configured port is never substituted. Its process fixture now joins
stderr and the child exactly once and preserves early startup diagnostics.
The pinned module race suite and both Windows target compilations pass;
native Windows and selected-path DNS acceptance remain independent.

Desktop Router-to-Tor preparation now binds the physical firewall tuples to a
hashed runtime projection of the captured entry graph. Unix and Windows
wrappers check the exact host, port, network and order before protection;
the native compiler independently validates the complete graph. This is the
protection subset: public Connect and Speed Lab predecessor wiring are still
pending reconstruction, and physical/public-circuit acceptance is separate.

Tor selected-DNS proof now checks the exact native receipt and configuration,
including the resolver transport and captured entry/exit detour. Retained DNS
and measurement results bind the original entry assets, native owner, session
and network. Receipt validation supplies no fabricated DNS query timing.

The shared node compiler can now attach a complete MAX exit without bypassing
its PQ, SS2022, outer transport or optional Start Layer. Public packet/PQ
identities require the whole validated chain. Inner interface capacity and
the outer QUIC datagram envelope have separate checks. This prerequisite does
not expand the desktop catalog: host Server substitution, renewal/restoration
and native controls must adopt these exits before they are offered there.

Desktop Router-to-Router multihop now accepts seven native proxy exit families:
Shadowsocks, Hysteria2, REALITY Vision, PQ REALITY Vision, REALITY XHTTP, Naive H2
and Naive H3, plus WireGuard and AmneziaWG Fast/Strong packet exits and
SS-V2Ray, Split and MAX TCP/UDP composite exits, plus mandatory WG-PQ and
AWG-PQ packet exits. Native entry selection now preserves nineteen exact raw
Router transports, including proxy, PQ, composite and complete-MAX entries.
Local, Server and Compare retain
the captured exit transport, independent node credentials, Start Layers,
selected DNS and proof routes. Naive resolver bootstrap follows the captured
entry; replacing an exit Start Layer with an authenticated Server lease moves
only that layer's owned resolver edges. Windows, macOS and Linux controls,
complete profiles and Speed Lab retain all fifteen exit IDs and nineteen entry
IDs. An empty entry choice retains the existing saved mode/base fallback;
unknown or unavailable choices cannot silently become another transport.
Packet/PQ Server execution
requires an updated agent and a separately paired server client identity. The
canonical public key is checked against the local client, pinned during
authenticated discovery, enforced under the server lease lock, and retained
for renewal and restoration. A changed registry cannot silently replace it.
Local execution keeps the captured packet endpoint; Server execution removes
only that exit and its Start Layer from the client graph. Legacy Linux without the
native runtime still advertises only its implemented two-exit helper path.
AWG exits retain all eleven protocol parameters, independent keys and the
captured S4 transport padding. Nested MTU accounting includes that padding and
the selected Start Layer before alignment; a configured interface capacity is
not fresh path-MTU evidence. The pinned native WireGuard adapter publishes
dependency readiness only after its owned device starts, allowing an AWG exit
to open its protected UDP socket through a literal WireGuard entry. Failed,
cancelled and closed devices cannot publish readiness. Actual encrypted
WG-to-AWG Fast, Fast-to-Strong and Strong-to-Fast Local/Server TCP and UDP tests
pass, including wrong-key, padding and lease-credential rejection. The local
AWG test CLI omitted the Rosenpass C-library tag. The separate PQ verification
described below uses a newly built complete native engine with that factory;
complete current native packages still require exact-SHA CI.

The expanded entry compiler retains the whole captured engine, resolver,
bootstrap, cover and optional Start Layer closure when Server execution
substitutes the exit. Complete-profile Add/Update/Load preserves the raw entry
transactionally without copying credentials between nodes. Speed Lab captures
the visible control node's entry preference before changing its temporary
policy owner, restores the already-proved Local/Server winner and live MTU,
and rejects a same-ID replacement both before and after capture. The native
runtime base remains truthfully `native` for non-packet entry families.

The shared entry matrix passed 855 configurations; desktop host compilation
passed 1,710 Local/Server graphs and 114 checks with the actual complete native
runtime. Separate encrypted TCP/UDP tests passed for Shadowsocks, Hysteria2
and Naive H2/H3 entries in both execution modes, including wrong entry and
lease credentials followed by valid restoration. WPF, AppKit and GTK profile,
Connect and Speed Lab callbacks preserve the same modes through the actual Go
resolver. Their source/ownership tests do not establish physical acceptance or
encrypted traffic for every entry/exit combination. The package gate runs the
expanded entry matrix in its own bounded group; existing gates keep their
original budgets.

The current ARM64 release exposed two native-fixture issues after successful
engine builds: an initial WG response could be lost during UDP rebinding before
a Naive H3 test, and the growing aggregate exceeded its Windows ARM64 budget.
The fixture now proves an actual encrypted entry before the unchanged
four-second exit assertions and owns a separate WG server for each trial. A
deterministic dropped-first-handshake test reproduces the old failure and
passes the corrected path. The package gate accounts for every discovered test
exactly once across separate bounded graph, ownership and traffic groups.
Isolated Linux AMD64 race tests pass; the actual ARM64 jobs still must rerun.

Desktop WG-PQ and AWG-PQ exits retain mandatory native Rosenpass negotiation,
exact packet/AWG parameters, selected DNS, Start Layers and captured MTU bounds.
Server execution requires both an independently paired packet key and a
different PQ public identity. Compare retains the first captured identities
across trial teardown and winner reacquisition; a registry change cannot become
a new winner. Temporary restoration retains those pins and the already-proved
execution without rerunning Compare. MTU arithmetic validates the underlying
packet envelope without replacing its mandatory PQ owner.

A fresh complete Linux AMD64 native engine, the real pinned Rust ABI and three
independent disposable KEM keypairs passed the separate encrypted desktop PQ
gate: twelve Local/Server trials, both packet families, all three WG/AWG entry
variants, two real handshake epochs, wrong-peer rejection/restoration and lease
authentication negatives. The twelve trials delivered 120 TCP/UDP round trips
at 64, 1200 and 2000 bytes in 125.789 seconds with race instrumentation. The
existing native selector also passed in 152.686 seconds; both retain their
180-second bounds. These traffic trials use Start Layer Off; all three layer
choices and bounded MTU rejection also pass the captured graph/parser tests.
The physical/TUN boundary is adapted to loopback, including a test-only exact
destination datagram mapper using native SOCKS UoT v2. Production PQ write/error
checks and the independently authenticated Server lease are unchanged. The
mandatory package gate builds the separate reference and private disposable
keys outside the sealed bundle. Windows/macOS execution, exact-SHA packaging,
real off-LAN Server pairing and physical acceptance remain separate.

The three composite exits retain independent authenticated TCP and HY2 UDP
lanes. Both traverse the captured entry, or the one captured exit AES/XOR
Start Layer which traverses that entry. Their dispatcher never gains a generic
detour. Server execution validates and removes the entire local exit closure
before installing its authenticated lease; selected DNS/bootstrap, entry
policy and proof routes remain captured. Real encrypted Local/Server traffic
passes for all three modes, including wrong credentials, independent lane
failures and restoration. The native package gate requires this separate
traffic group alongside its existing native and AWG groups. This `max`
composite support does not close the distinct complete MAX packet/helper exit
graph. Complete-MAX exits and other requested graph combinations remain source
gaps; this extension does not establish full graph parity with the mobile hosts.

The authenticated router-agent HTTP decoder now carries the already-defined
packet identity pin through discovery, creation, renewal and deletion. It
rejects malformed, foreign and unowned pins without starting an engine.
Shared mobile Server execution now retains both the canonical packet public
key and, for PQ/complete MAX packet modes, the paired PQ public-key identity.
Discovery, lease creation/renewal and the native receipt share those captured
pins; a changed registry or replacement engine cannot silently substitute them.
The authenticated HTTP route applies the same strict field and mode rules.
Its isolated mobile/controller/relay/HTTP race suite passed 333 test and subtest
records. That is ownership evidence, not a new PQ dataplane or device claim.

Private PQ relay copies now accommodate the actual native Rosenpass public-key
size. Both WG-PQ/AWG-PQ and complete-MAX server paths preserve the exact private
key bytes and routing owners through Start Layers and relabeling. The ordinary
transport envelope remains limited to 256 KiB; validated PQ configuration retains
its existing 8 MiB aggregate and 2 MiB-per-key bounds, and complete MAX retains
its 4 MiB bound. Public lease/request limits are unchanged. Native-sized
serialization and strict oversize/owner negatives pass against an isolated
source overlay; these bounded tests do not replace actual PQ negotiation or
physical Server traffic acceptance.

Apple Speed Lab and startup Last now carry those public Server pins with the
exact original source hashes and the already-proved Local/Server selection.
The provider reapplies them before native startup, including across MAX
hostname preparation. Speed Lab checks the pins before stopping its original
session and after proving a fresh restored session. Schema-1 Local and proxy
receipts retain compatibility; an old unpinned packet/PQ Server receipt cannot
authorize restoration. Durable records contain public identities and hashes,
not private node credentials. Shipping Swift callback/store tests, malformed
receipt and guard-removal negatives, and the actual Go MAX launch compiler
passed. The native handle and OS boundaries are doubled in those tests; current
Xcode-generated binding/package and physical-device evidence remain separate.

Android temporary multihop tests now use an immutable runtime receipt for the
exact original source bytes, service/native owners, selected execution and
public Server identity pins. The service checks the captured path before and
after native readback. Restoration forwards the pins into the real preparation
metadata, requires the matching idle Home owner atomically at admission, and
checks the exact sources and pins again after fresh proof. A newer connection,
Disconnect or source replacement prevents stale restoration. Ordinary external
pairing retains its separate contract. Shipping Java service/callback and
Java-to-Go graph tests, including all nine packet/PQ/MAX pin paths and deliberate
owner/pin guard removals, passed. Android framework/native handles are doubled
in these tests; the full current APK and physical VPN behavior still require
independent evidence.

Windows private runtime handling now validates the actual opened file's ACL
instead of applying POSIX mode bits to Windows. Runtime directories receive
private ACLs before secret staging. DNS proof uses the same validated bytes,
file identity and connection owner, and rejects replacements or stale owners.
Linux race tests and both Windows compilations passed; actual Windows ACL
execution remains a current native-CI obligation.

Apple connection-profile schema 5 now captures Tor DNS, protection, LAN ranges,
MTU/Jumbo, startup and Router-entry preferences. Add/Update and Load run the
shipping native Tor validator, keep bridge credentials in the linked private
node store, reject a changed imported identity and roll back failed durable
writes. Old Tor selection-only records remain selection-only until explicit
Update. Loading a node with default/empty LAN ranges now clears the previous
node's ranges. The shipping-store/callback tests cover these paths; current
Xcode, signing and device evidence remain separate.

Desktop imported-node startup now uses the saved protocol and graph through
the interactive connection path's owned runtime and proofs. The delayed attempt
captures selection, credentials, policy and private entry assets; manual
Connect and Disconnect retire it. Last retains a matching proved Local/Server
choice without rerunning Compare, with fresh session proof still required.
Native Windows, macOS and Linux Settings now provide captured startup editing for
imported nodes using a captured node revision, preserving their private settings.
See [STARTUP-POLICY.md](STARTUP-POLICY.md) for the source contract and executable
checks. This closes a source gap found during requirement 116 reconciliation;
current native release and physical startup acceptance remain separate evidence.

Apple startup now captures the selected bundle, entry, generation and available
system VPN state through permission save/readback. Imported nodes use their
saved graph, and Last restores a matching proved Local/Server choice with fresh
native proofs. Startup cannot acquire a measurement hold on a replacement
connection, supersede a temporary test, or repeat merely because a view reopens.
The shipping Swift startup, strategy, receipt and ownership fixtures passed;
the current Xcode package and physical permission checks remain separate.

The Windows, macOS and Linux quick kill-switch controls now use a common
captured-node protection transaction for Router and imported nodes. Each action
captures the displayed node before reading its revision and submits only that
identity and the selected kill policy. The controller rejects changed source,
selection, busy state and malformed input, rolls back failed persistence and
preserves credentials, DNS, graph, MTU and concurrent measurement metadata.
Unavailable protection reads display an unknown disabled control on macOS and
Linux rather than reusing another node's checked state. The API race suite,
shipping PowerShell/Swift/GTK serializer checks and actual GTK build with its
product and shutdown ownership suites passed. Real Windows PowerShell 5.1 and
AppKit package verification run in their native workflows; physical tunnel
enforcement remains an independent acceptance requirement.

Apple external Settings now edits LAN access, kill-switch policy, IPv6 and
Auto/Fixed/Default MTU through the actual ordinary/Tor native validators and a
captured idle profile transaction. Startup saves remain separate. Android's
external quick control and complete editor now retain the selected exit's saved
protection independently from its entry and Android system lockdown. The VPN
service validates that policy against its captured private marker before launch.
These controls preserve protocol credentials, graph, DNS, startup and historical
measurements; invalid fixed MTU and stale editor saves remain rejected.

The desktop common device API now validates ordinary external LAN, protection,
IPv6 and Auto/Fixed/Default MTU against the actual native transport parser.
Its captured revision includes the independent entry and private source;
mutation rechecks selection, idle state and shutdown at persistence, rolls back
failed writes, and preserves DNS, credentials and fresh measurement metadata.
The GTK Settings dialog now exposes those controls and atomically includes
startup only when edited. Unchanged SMART AUTO aliases remain untouched; Manual
startup cannot enable auto-connect. The actual GTK form passed 461 checks and
seven deliberately broken variants, and the complete application and controller
cleanup suite passed. Windows and AppKit now expose the same captured device
transaction, including atomic startup changes only when edited. The shipping
PowerShell checks and actual WPF form have passed; a Windows-only error-format
matcher was repaired without removing its negative control. AppKit's shipping
Swift serializer/composition checks passed, while current native SDK/release
verification remains separate. Tor's separately captured native lifecycle and
DNS adapter are described below; ordinary-node forms do not establish the
remaining Tor graph and MTU capabilities.

Desktop DNS editors now load and save ordinary external and Tor policies
against the exact selected profile and saved entry. The saved transport,
address, port, TLS identity and path pass the same native policy validators used
by the running graph. Native controls preserve encrypted Home parameters rather
than resetting them through a UDP/TCP-only selector. Source/selection changes,
failed persistence and cancelled edits cannot rewrite private node state.
Explicit Rescue uses its actual named preset; missing Home entry/bootstrap or
unsupported transport is reported before connection rather than replaced.
Legacy external Fastest samples cannot authorize a different transport. The
ordinary desktop native runtime now measures twelve public resolvers through
its captured exit and separately queries the selected policy through the actual
DNS router with cache disabled. TCP, DoT and DoH comparisons use three successful
samples and their median; failed rows have no score. The native mailbox binds
source, configuration, session, generation and nonce. Cancellation and shutdown
retain the exact workers and sockets until confirmed drain, including queued
Start and renamed-workspace races.

Windows WPF, AppKit and GTK now provide modeless results panels, measured
sorting, public-only Fastest, explicit row selection and Cancel. Selection makes
an immutable resolver draft without changing active DNS. Saving requires explicit
Disconnect, exact source and entry, all six measured resolver fields, and a
two-minute result lifetime that cannot be refreshed by repeated selection. A
replacement connection invalidates the result; an explicit Disconnect can retain
it until expiry. Close waits for native drain and pending local requests.
Actual native/controller race suites, shipping UI ownership fixtures, loopback
cancellation and negative controls passed. The complete GTK application built
and its rendered panel was inspected; WPF/AppKit SDK and release checks remain
the current exact-SHA native workflow evidence, separate from physical devices.
Standalone desktop Tor now uses the same retained DNS measurement service
through its actual Tor Box owner. It captures the selected resolver and public
comparison transport, preserves the request generation across cancellation,
and cannot adopt a result from a replacement native session. Automatic loss of
Tor or ordinary external proof invalidates completed drafts even if the physical
network fingerprint is unchanged. Explicit Disconnect can retain an otherwise
valid draft within its original two-minute lifetime.

Desktop Tor bridge launch now stages five immutable private inputs, a fresh
session/isolation capture, and the exact standalone Tor executable digest. The
verified native command starts Tor with networking disabled, authenticates its
SAFECOOKIE control channel and actual PID, owns the Go pluggable transports,
and starts/proves one captured TUN, selected DNS and Tor exit. Checked native
drain and actual process exit precede controller-owned cleanup. Windows uses a
suspended child assigned to a private Job before execution; Unix replaces its
wrapper with the exact native process. A wrapper failure before native creation
uses a distinct no-native-process witness, accepted only after actual wrapper
exit and validation of the unused private workspace. Native crashes or ambiguous
shutdown do not acquire that exception.

Speed Lab captures this distinct Tor owner and restores the complete saved
policy through a fresh Tor session, isolation secret and proof. Its restoration
snapshot retains the actual measured interface value and completed Auto state;
saved historical MTU cannot substitute for that reader. The restored session
must pass fresh path proof and matching interface readback before restoration
succeeds. Failed fresh proof waits for the exact native rollback, and an old
transaction cannot send controls to a replacement connection. Executable
native-command, actual child-process, wrapper, DNS and Speed Lab race tests
cover these source paths; physical Tor circuits, kernel TUN acceptance and
current release packages remain separate evidence.

Desktop Tor Auto now starts with a conservative 1280-byte configured TUN and
measures HTTPS response time and transferred-byte download/upload throughput
at candidate interface MTUs. Retest and Cancel use the same captured native
lease, with fresh Tor/selected-DNS checks and monotonically bound interface
readbacks. A native interface change has a fixed, request-bound 15-second
transition window; its old proof cannot authorize a measured result or renew
that window. Normal heartbeat publication waits for the actual native reader
and authenticated control check. Cancellation retains the worker through exact
rollback, and persistence preserves the requested Auto policy and private node
identity. A successfully proved manual Retest also satisfies that connection's
pending Auto work, so releasing a DNS or Speed Lab measurement hold retains
the committed reader. Cancelled operations and failed saves do not claim that
completion. The reported interface value is not an authenticated UDP path-MTU
or ICMP measurement. Fixed and Default remain unmeasured interface choices.

Standalone desktop Tor now applies Jumbo as an exact 9000-byte virtual
interface, with native readback and a captured settings transaction in Windows,
macOS and Linux. Auto/Default preferences remain saved unchanged; a conflicting
Fixed MTU is rejected. Neither the native optimizer nor its parent can admit
an MTU mutation or measured receipt while this configured capacity is selected.
Restoring an already configured Jumbo reader requires fresh Tor/DNS path proof
without issuing a reader-change command. The actual child/controller and native
Box tests cover these boundaries, while physical TUN and network acceptance
remain separate. Virtual capacity does not assert 9000-byte packets on the
underlying network. Captured Router-entry Local Tor graphs now preserve their
private entry, selected DNS transport and independent native ownership. Tor
Server/Compare, ordinary external predecessors, exit-side desktop Tor padding
and dynamic-bridge strict protection remain requirements to implement.

Router Home DNS now retains UDP, TCP, DoT, DoH or DoH3 with the exact private
AdGuard address, port, TLS name and HTTPS path. The address must belong to the
captured node; missing or foreign addresses cannot become a public resolver.
The controller editor, saved complete connection profiles, shared native graph
compiler, Windows helpers and Unix helpers preserve that policy. New saved
profiles mark explicit Home captures so the older migration of stale preset
fields cannot erase encrypted settings; Load revalidates against the linked
node and rolls back a changed resolver. Legacy snapshots retain their existing
migration behavior. Tests exercise the real API, persisted profiles and all
existing Router predecessor families with each transport.

Selected-DNS proof now checks TLS identity and HTTPS path as well as address,
port and transport. Kernel hints record those fields and duplicate hint fields
are rejected. Home through an ordinary external exit uses its captured native
entry proof and exact graph identity; the controller does not replace that proof
with an ordinary-network lookup. Entry credential or policy changes cancel
in-flight work and retire retained proof. Native proof receipt processing is
not labelled as measured DNS latency. These are source and executable controller
checks, including isolated child-process fixtures; they do not establish live
AdGuard encrypted service availability or physical-device routing.

The raw kernel DNS proxy now owns an authenticated HTTP/3 transport for the
captured resolver's literal IP, port, TLS identity and HTTPS path. Its pinned
QUIC/TLS implementation does not redirect, use early data or downgrade to TCP.
Cancellation and shutdown join the owned request workers, listeners and QUIC
socket. Actual CLI, UDP/TCP listener, HTTP/3 server and kernel-proof tests cover
both address families, identity failures and drain. Windows raw WireGuard now
passes the selected H3 policy to this proxy; the required native-runtime matrix
executes the transport tests on all six desktop OS/architecture hosts. Package
builders use the pinned toolchain and include dependency/license receipts.
These source and executable checks do not establish live Home AdGuard HTTP/3
availability or physical routing. Unix launchers stop when DNS capture fails,
before inherited environment settings can reach the runtime. Windows and Unix
Home config writers require an owned tunnel outbound and never fall through to
direct DNS. Native sing-box paths retain their separate H3 implementation.

Compact desktop Home and Rescue actions now capture the displayed node before
reading its DNS revision. Re-selecting Home preserves an already-selected
encrypted Home transport, address, port, TLS name and path; changing back from a
different policy requests the linked Home preset without carrying that other
resolver. Configurable choices and Fastest open DNS details for explicit editing
or measured selection. Shipping composition tests cover the complete Windows
editor and compact control, AppKit mutation transforms, and GTK callbacks. The
updated transforms retain both the synchronous and asynchronous idle guards.

The current source also includes Apple candidate-measurement repair `7484eec1`
and macOS Tor editor integration `b94f5df9`. The Apple probe receives an immutable
Sendable target while private profiles remain on MainActor; its executable
fixture compiles the shipping files separately and rejects the original unsafe
actor crossing. The macOS builder now runs the Tor UI transformation after
session hardening and compiles the resulting Nodes controls. These source and
local-test results still require the current commit's Xcode/AppKit CI evidence.

The October 25 continuation adds paired OpenVPN Local/Server/Compare execution
through the shared native runtime, desktop controller, Android service and Apple
PacketTunnel. Local and Server use independently provisioned private client
profiles; the client bundle contains only the public identity of the server
session. Pairing validates certificate/key identity, exact inline credentials,
transport and response endpoint before committing the registry. Native imports
validate the complete raw JSON object before platform decoders can collapse
ambiguous duplicate fields. Existing proxy and WG/AWG leases also retain the
captured authenticated peer, manager epoch, fresh attempt and bounded deadline.
See [MOBILE-OPENVPN.md](MOBILE-OPENVPN.md) and
[MULTIHOP-EXECUTION.md](MULTIHOP-EXECUTION.md) for supported profiles.

Different-host OpenVPN fallback now supports Local, Server and Compare through
an exact private response map covering every original remote. The native engine
reports the established remote and physical-session generation; Server reads
require a fresh nonce from the captured private runtime. Reconnects and queued
callbacks cannot retain proof for the previous transport. DNS Retest, both
comparison probes, winner repetition, MTU and Speed Lab verify that generation
at their measurement and adoption boundaries. The original remote list, inline
credentials and independently provisioned Server identity remain captured.
Mapped exit AES and AES plus XOR now use a complete private per-host layer map
and the v6 authenticated lease contract. The native mapper preserves the original
ordered remote tuples and configured-event generations even when independent
providers share one private service address. It owns each encrypted child and
its pending sockets; a failed close retains ownership and blocks replacement.
Every host's layer secret is authenticated without copying independent provider
or pairing credentials between Local and Server. Off retains v5, and single-host
pairings retain v4. Entry layers remain separately captured.
Native OpenVPN teardown also drains its captured packet dispatcher before
gVisor stack shutdown. A reproduced lock cycle is covered by an actual-stack
regression and an original-order negative control; increasing the close timeout
is not part of the repair.

Desktop external paths now use their owned native runtime for Direct, Local,
Server and Compare both. Router VPN entries retain all 19 supported saved entry
modes, independent entry/exit Start Layers, DNS and device policy. OpenVPN can
also be an ordinary external entry or exit inside that runtime without taking
over a second system VPN. Physical firewall exceptions capture only the
transport actually leaving the device, including a bounded set of OpenVPN
fallback remotes; they cannot inherit another process's endpoint exceptions.
The legacy standard-exit API retains its separate seven-protocol entry contract.
The native external API exposes the implemented eighth protocol, OpenVPN.

Desktop native external MTU now has Auto/Fixed/Retest/Cancel ownership through
the actual TUN instance, immutable source/configuration and physical-network
identity. Provisional results require a parent profile commit before the child
retains them. Cancellation, failed proof, profile replacement and stale results
roll back only their captured owner. Speed Lab captures the effective live MTU
and the already-proved Local/Server execution; restoration reapplies that value
and proves the original path without running another comparison. A mandatory
Linux namespace job exercises actual kernel TUN replacement and rollback. It
passed with a real TUN on `3151083fc89b5670e98ad5a54c838425bb7a26ef` in
[release job 121032185604](https://github.com/Eabusham2/router-vpn/actions/runs/40147557862/job/121032185604),
including the same-name replacement and stale-owner cases. This verifies that
kernel transaction on that source; it does not establish Windows/macOS physical
networking or private-server performance.

Desktop Router-node paths and compatible Router-to-Router multihop now retain
their native system TUN for Auto/Fixed/Retest/Cancel. Windows, macOS and Linux
have native progress/cancel views tied to the exact request, session and profile.
Multihop measures the exit-path system TUN, retains both node identities and the
proved Local/Server choice, and persists only that exit's measurement fields.
The entry's MTU, selected DNS, credentials and physical firewall owner remain
captured. Native Auto resumes correctly when a temporary hold wins before view
registration or before the previous waiting worker finishes. See
[DESKTOP-MTU.md](DESKTOP-MTU.md) for the source and executable-test boundaries.

Speed Lab captures the actual ordinary-node/multihop TUN readback as well as
external native paths. Its restoration updates that TUN value within the
captured graph and retains the proved execution instead of rerunning Compare.
Native cleanup failure keeps an operation pending until the retained owner
closes. Controller and launcher exit now use the same checked drain; the
launcher requires its own nonce/PID receipt and actual child exit rather than
terminating the controller while rollback is pending. The expanded actual
native-command kernel gate is separate from earlier passed low-level TUN
evidence and requires the new commit's CI result.

Desktop measurements also use a separate fresh-path mailbox bound to the exact
session, source/configuration hashes, request nonce and generation. Its worker
does not block the native owner heartbeat. Delayed receipts, replaced workspaces
and cancelled requests cannot authorize a result. Failure to drain retains
cleanup ownership and protection while retiring only the captured native owner.
Fresh checks surround durable MTU persistence and commit, Speed Lab phases and
final adoption, including restoration of the already-proved execution choice.

Windows, macOS and Linux Speed Lab now send explicit entry-mode and execution
choices through their native forms to the real controller. Saved choices are
retained, and invalid choices cannot silently become a different path. macOS
owns and cancels its loopback URLSession and rejects stale UI completions.
Temporary tests restore the captured connection after traffic drains, while a
newer user connection or Disconnect takes priority. See [SPEED-LAB.md](SPEED-LAB.md).

Android temporary external tests also retain the selected Local/Server/Compare
execution and exact saved entry mode. The actual dialog, unified controller,
permission and restoration fixtures exercise the same captured request. The
previous overload forced Local; `3151083f` fixes that path and requires the
proved execution to remain unchanged through the test.

The real pinned native OpenVPN fixture transfers encrypted TCP and UDP with
Off, AES-256-GCM and AES-256-GCM plus XOR Start Layers. Wrong certificate,
control-channel key, remote identity and listener key cases must fail. Focused
race tests exercise replay rejection, cleanup, profile transactions, restoration
and native MTU mailbox ownership. At the published mapped-Off checkpoint
`f686454f`, both shipping Java and Swift producers supplied 1,683 captured graphs
to the actual pinned native runtime. Each accepted all 1,683 graphs and rejected
all 1,683 missing-engine controls with stable source, module and native-library
provenance. The current mandatory matrix adds 342 mapped exit-layer combinations
and requires all 2,025 graphs plus 2,025 missing-engine controls for each host.
These constructor gates remain separate from APK/Xcode builds and physical
traffic. The earlier 171 mapped-Off graphs preserve all 1,512 preceding
combinations. Real encrypted fallback tests
also exercise TCP/UDP, same-host reconnects, stale TLS callbacks and incorrect
certificates, names and keys. An initialized native DNS cache negative control
confirms that selected-DNS measurements require fresh routed answers.

Published desktop lifecycle work is in `f3beb47b`. Commit `d16b862a` fixes the
Windows built-in `kill` alias collision, OpenVPN named dispatch and canonical
cross-platform native source fingerprints. Commit `16070d14` gives the actual
Linux action harness a valid selected-node fixture. These changes preserve
negative controls; they do not replace physical-device or off-LAN acceptance.
Commit `9b8fce03` publishes the paired OpenVPN, native desktop MTU and desktop
Speed Lab changes. Commit `3151083f` also preserves PowerShell 5.1 JSON array
semantics for native firewall exceptions and updates the OpenVPN workflow's
helper-name guard without restoring the built-in alias collision.
Commit `90254368` aligns the macOS oversized-response fixture with the shipping
JSON endpoint while preserving an untyped partial-body case, and makes the
Windows test completion output compatible with its CP1252 console. Actual
Darwin/Windows CI remains distinct from local fixture verification.
Commit `6ef1079` preserves the router-agent's declared Go 1.24 support with
pinned-directory relay file operations, repairs Windows/Android test fixture
semantics and gives the Apple empty private-bundle fixture a fresh factory.
Exact-SHA CI for that repair was running when this checkpoint was recorded;
this document does not assert that all of its workflows or release assets passed.

The successful `745b3e41` release predates this continuation and does not certify
its packages. Exact-commit native packaging, release publication, private
deployment and device acceptance require their own evidence.

The source has advanced beyond the old WireGuard-only mobile multihop and
mobile-Tor exclusions. Those historical restrictions no longer describe the
application source and must not trigger reimplementation of committed work.

The October 22 continuation has published these bounded changes:

- Complete Android connection profiles and desktop connection profiles retain
  the captured external path and references to private credentials. Android
  measured hop selection uses a temporary owned entry, rejects stale results,
  and restores the captured session. Its quick candidate sample is separate
  from the durable 50-sample node benchmark.
- Desktop external paths preserve Home AdGuard as the default and capture its
  address from the Router VPN entry. A direct path without a usable selected
  resolver is rejected before stopping a working connection. Explicit Rescue
  and custom resolver choices remain explicit.
- Shared paired external Shadowsocks Server/Compare execution uses an
  authenticated isolated lease, an explicit TLS response endpoint, independent
  node/DNS/exit proof, the required comparison formula, and checked cleanup.
  Apple hosts now wire that path through PacketTunnel, all 19 supported entry
  mode families and their Start Layers, saved profiles and source-bound
  restoration of the already-proved winner. This does not establish server
  execution of every external protocol.
- The Apple MAX hostname handoff, captured LAN-policy fixtures, macOS session
  transform and Windows/macOS Tor composition checks have executable
  regressions. The current source does not need the old MAX hostname or
  composite-exit fixture patches reapplied.

Published references for these changes are `5dfc934a`, `520b50ba`, `e4f82958`,
`a6188b3d`, `75a90caf`, `b28178a1`, and `a444e6df`. Their local tests and source
integration do not certify another commit's native packages or device behavior.

The further October 22 continuation has published these source changes:

| Commit | Captured behavior and regression boundary |
| --- | --- |
| `34ab1386` | Requirement audits retain authenticated AES Start Layer and optional XOR whitening. |
| `23aced17` | The pinned native SOCKS UDP endpoint race is fixed in the owned source copy, with race-detector and unpatched negative-control evidence. |
| `e5495b8c` | Apple Tor Home drafts, DNS editing and runtime composition retain the complete captured predecessor. Native host/export source gates agree. |
| `de5cf026` | Android paired external Server/Compare reaches the real native lifecycle, preserves its permission/profile capture and restores the previously proved winner. |
| `0ec5a1c7` | The registered server HTTP boundary accepts and authenticates the captured external fingerprint/authentication pair; malformed and replayed requests remain rejected. |
| `453d1966` | Missing or blank mobile external-node DNS uses Home. Idle editing and runtime share the actual parser; explicit Rescue/custom choices are preserved. |
| `4a1f7cd6` | Android profile contracts verify execution retention at the actual new call site. The four previously failing source gates pass on this commit. |
| `0bfb3bf3` | Windows, macOS and Linux measure exit candidates through an owned native entry and validate current receipts before changing the exit picker. Generated full/split WG/AWG assets share one strict native parser. |
| `4485a69a` | Windows PowerShell 5.1 and isolated Unix MTU fixtures exercise the same production behavior with portable test inputs. |
| `70325a69` | Apple candidate measurement binds the entry, source, physical network and selection; waits for native socket drain; and restores captured state. Linked-node reads are pure, imports make one validated atomic commit, and ambiguous native cleanup retains ownership. |
| `3c46bc57` | WG/AWG assets must match the saved endpoint before bootstrap. Native candidate cleanup captures Windows directory identity eagerly and preserves replacement directories. Source audits follow the current Android execution and Apple atomic-link contracts. |
| `b2ae0257` | Repeated native preparation composes packet concurrency and UDP capacity fixes in one checksum-verified `sing` copy, including default/low-memory builds and verified upgrade of the earlier owned copy. |
| `f29b6d2d` | Android and Apple DNS comparison runs through the captured native external/Tor path, validates complete source-bound receipts, and retains cancellation ownership until actual native drain. |
| `1394ec8f` | Standalone native runners prepare their complete Tor/AWG policy dependency closure. Windows source checks normalize CRLF; TLS denial fixtures use real joined TCP connections; mobile MTU/proof fixtures include the owned DNS activation boundary. |
| `34fb6128` | Native vector maps, mobile telemetry/startup/update controls, captured desktop WG/AWG profiles and complete six-target runtime delivery are wired into the native application and release paths. The full Linux runtime producers passed on both architectures; the first cross-platform run exposed the preparation and fixture failures described below. |

This native UI continuation replaces the visible Apple stock map with a
shared opaque vector basemap. Both application packages ship the same pinned
land outlines; native MapKit still owns coordinate transforms, gestures and
annotations. Refresh preserves the custom base, date-line routes stay short,
and macOS map taps use guarded saved node selection without connecting.
The shared geometry passes 298 executable Swift checks, with route and
selection negative controls. Apple SDK compilation and real bitmap rendering
are mandatory in the native shipping lanes; the Linux run does not claim them.
See [NATIVE-VECTOR-MAP.md](NATIVE-VECTOR-MAP.md).

Android updates are reachable from Help → More → Updates even when notification
permission is denied. Discovery joins one owned worker, and download actions
require an unexpired receipt tied to the installed source and exact release
asset. The real provider/dialog source passes 117 executable checks with
Android and HTTPS boundaries doubled, plus installed-source and expiry
mutation controls. This does not establish a physical Android upgrade or a
production APK signing identity; see [AUTO-UPDATES.md](AUTO-UPDATES.md).

Android startup now executes the saved per-node policy once per cold app
process. Auto-connect defaults to Off; SMART AUTO, AUTO, Last / AUTO and Manual
are reachable settings. Permission recreation retains only a nonce referring
to the captured private request. Router and external paths preserve the saved
entry, exit, execution choice, credentials and policy; a foreign VPN, changed
selection/source, manual Disconnect or newer owner invalidates the request.
External choices retain the saved protocol and path, with fresh native proof.
Router Last / AUTO tries the last proved runtime only when it still satisfies
the current policy, then uses AUTO after ordinary failure and completed cleanup.
Resume/rotation never starts another attempt. Startup passes 899 executable
checks and two mutation controls; the real mode selector passes 70 scenarios
and 442 checks, including cancellation before late proof adoption. The complete
Android runtime contract passes all 44 registered executable fixtures in one
uninterrupted run against this continuation's source.

Mobile telemetry now separates direct probing, live routed RTT, current-path
throughput and saved 50-sample statistics. Android captures the exact native
VPN owner and physical network; iOS uses a provider-owned connection with
proof-before-token delivery. Both reject changed source/session/network state
and retain measurement/MTU ownership until native cleanup completes. Only a
complete 50-sample run replaces a durable record, including minimum, median,
average, 10% trimmed mean, p90, maximum and measurement date. A partial run or
failed write leaves the previous record and ranking intact. Android telemetry
passes 159 checks and nine negative controls; iOS telemetry passes 230 checks
and two controls. Its native read adapter additionally passes 21 signed-limit
and callback checks against the imported unsigned API shape; the historical
Int-to-UInt call fails compilation as expected. These executable tests double
the declared OS boundaries;
physical routing, endpoint throughput and network transitions remain separate.

The desktop candidate backend uses a private authenticated userspace lane with
real upstream TCP handshake timing, exact entry proof before and after samples,
captured private sources and physical-network validation. It changes no system
TUN or route. Results become selectable only after sockets and the owned process
have drained. Windows, macOS and Linux now follow the same saved Auto/WG/AWG
base decision as Connect. Complete captured Router profiles retain both hops'
DNS, cover traffic and authenticated Start Layers. The real complete Linux
engine accepts the 36 captured Local/Server WG/AWG graphs; stale proof/source
regressions pass with race detection. Quick samples do not overwrite direct
latency or the durable 50-sample benchmark.

Desktop delivery previously omitted the complete runtime despite having its
builder in source. All six native target producers now build/verify the engine,
its Cronet payload where required, licenses and exact source/target/file
receipt. Installed and Portable archives are checked after compression.
macOS signs a verified staged bundle and seals only its own signed result;
Windows/Linux installation and the same-image Windows download fallback carry
all required runtimes. The actual Linux engine passed 28 receipt/relocation
checks plus the graph gate, and its payload survived artifact extraction and
installed/Portable archive roundtrips. Delivery/signing boundary tests pass 375
checks. Windows runtime installation passes 205 filesystem checks and two
rollback mutation controls. Linux passes 15 transaction checks and actual
first-install and upgrade verification of all three built engines. These
transactions cover runtime directories, not every outer installer action.
A six-target packaged result still requires the new commit's CI.
See [NATIVE-DESKTOP-DELIVERY.md](NATIVE-DESKTOP-DELIVERY.md).

The `34fb6128` CI built, validated and uploaded the complete native Linux
runtime for both x64 and ARM64. Its first Windows and Apple runs exposed
platform-specific preparation and test boundaries: Windows text-mode source
copies changed canonical line endings, Cargo output was decoded with the host
code page and mixed progress into JSON, macOS bindgen lacked its SDK sysroot,
and the standalone Apple bitmap fixture used Quartz coordinates and a different
color space from the native map. The corrective continuation preserves copied
source bytes, separates strict UTF-8 metadata from compiler diagnostics,
supplies the macOS SDK explicitly, and gives the bitmap fixture the real map
transform and palette. The corrected geographic bitmap checks passed on the
`55c6a903` Apple runners. The next native check exposed the ineffective
`showsBuildings` setting with custom overlays, so the map now installs the supported
flat/muted MapKit configuration with traffic and points of interest excluded.
The opaque geometry renderer is unchanged; mirrored-land and omitted-map-policy
negative controls remain subject to the actual Apple SDK gate. Source audits
now follow the captured multihop proof implementation and require both owned
proof lanes at their current call sites. These corrections retain their
verification gates. The real Git checkout fixture also prevents detached
maintenance from racing its temporary-directory cleanup and verifies the
actual child-process trace. Windows/macOS packages and the downstream image/release
chain still require the corrected commit's native CI results.

The `55c6a903` run passed both complete Linux runtime producers, the Windows
native source contract, the full source/release audit and the native Xray,
MTU, Rosenpass and SIP003 interoperability gates. Its native Windows x64 link
then exposed a missing external `liboqs.a`; Windows ARM64 exposed the pinned
bindgen declaration bug under Clang 22. The corrective source stages only the
locked Cargo invocation's target-checked static OQS archive, including its
content receipt, and applies the upstream bindgen fix to a checksum-verified
private build-tool copy. The original ARM64 bindings reproduce the exact
one-byte-versus-88-byte layout failure locally. The fixed bindings pass the
unchanged Rust ARM64 layout assertions; independent C compilation confirms
the same size, alignment and callback offsets. These checks do not substitute
for the resulting native Windows package and installer runs.

The corrected desktop policy builds the complete Windows x64 engine locally
with the pinned cross compiler. An explicit `-loqs` link against its staged
archive succeeds; removing only that archive reproduces the CI linker error.
The complete Linux x64 engine also passes its native captured-graph/race gate,
28 receipt/relocation checks, 375 delivery/signing boundaries and actual
artifact/installed/Portable archive roundtrips with the corrected policy.
The Windows cross build does not claim execution on a Windows host.

That Windows link also exposed an undeclared `libunwind.dll` dependency that
the compiler's PATH could mask. The final build links its compiler runtime
statically and verifies ordinary and delay imports from both the engine and
the pinned Cronet DLL, including during foreign-host package inspection.
The rebuilt x64 engine has 18 OS/API-set imports and no `libunwind.dll` import;
both pinned Cronet architectures have 15 accepted OS/API-set dependencies.
Actual PE metadata from the compiler tools agrees with the new verifier.

The same run advanced macOS through Rust/PQ compilation and exposed missing
SDK flags in the final Go C compilation. The corrective source supplies the
selected macOS SDK to both C/C++ and the external link, preserves those flags
when adding the verified PQ libraries, and keeps foreign-bundle metadata
verification independent of Xcode. Actual macOS engine and package acceptance
remains with the corrected source's native runners.

The surviving `34fb6128` Apple producer completed the pinned Libbox
XCFramework and generated-API verification, then the full app compile caught
the telemetry adapter passing `Int` to an Objective-C `NSUInteger` parameter.
The adapter now checks and converts that bound to `UInt`, rejects nonpositive
limits before issuing a read, and preserves the callback. The existing real
iOS header/adapter typecheck remains mandatory alongside the full app build.

The `55c6a903` authoritative Android job reached gomobile after all 570 Android
and 570 iOS native graph cases passed, and
exposed a late Tor preparation step lowering the combined module's Go version
from 1.26.3 to 1.26.0. Host tests did not import the Android-only libXray bridge,
whose pinned module requires 1.26.3. Preparation now preserves the greater of
the existing Go requirement and the PT module's minimum. A replay against the
exact native core and libXray passes eight readonly Android target/build-tag
loads, repeated preparation and the original downgrade negative control
without changing the shipping module files. That check runs immediately
before gomobile and contributes to the AAR proof/cache identity. The resulting
APK and native device behavior still require their own build and execution.

The four `f71b33fa` Android APK lanes then passed those eight readonly target
loads and late-preparation controls, completed gomobile into `libbox.aar`, and
reached Java compilation. The compiler exposed a telemetry network matcher
using a `LinkAddress(String)` constructor absent from the public Android SDK.
The matcher now parses numeric CIDRs and compares complete address bytes plus
prefix lengths through the public address getters, retaining exact address-set
and unique-interface ownership checks. The corrected source compiles against
the actual Android 36 SDK; the exact previous source reproduces the reported
constructor failure against that same SDK. The telemetry fixture no longer
provides that hidden constructor and includes IPv6 spelling equivalence and
wrong-address/prefix/extra-interface rejection. Its 159 checks and nine
mutation controls pass. The full corrected APK remains an exact-commit CI gate.

The `f71b33fa` native Windows runners passed PQ compilation, final engine
linking, target metadata and PE dependency verification on both architectures.
Their next failure was the final builder's license-metadata reader decoding
Cargo UTF-8 through CP1252. That reader now joins binary stdout and decodes it
strictly as UTF-8, retaining separate diagnostics and its existing newline
behavior. Fifteen output tests include the actual license collection boundary,
legacy-code-page output, process failure and exact provenance.
The download fallback fixture also now supplies real PE headers and import
tables to the shipping verifier: all four archived Windows/Portable packages
pass, and 20 controls include correctly re-sealed ordinary and delay imports
of an unowned compiler DLL. Removing the dependency check fails the fixture
before controller compilation. The `f71b33fa` macOS Intel and Apple Silicon
producers completed their native builds and artifact uploads, confirming the
final SDK fix. The standalone native AppKit packages then passed their payload,
package and signature checks for both architectures, and both native GTK app
jobs passed. Its actual Apple SDK gates also passed the map bitmap/configuration
checks, including both negative controls, and the native telemetry adapter's
unsigned read-bound typecheck. Those results precede the final reader correction;
the resulting commit still needs its complete native/package/image/compose
release chain and the separately required physical/distribution acceptance.

The full `f71b33fa` iOS client lane also completed its pinned Libbox XCFramework
and project generation. Its Release iPhoneOS build then reached the application
target and rejected an internal coordinator property exposing the private map
annotation type. The packet property now has matching file-scoped visibility.
The existing map gate additionally typechecks the complete shipping iOS map,
annotations and coordinator against SwiftUI/MapKit, with only the application
model boundary substituted. A portable Swift compiler check preserves the
shipping access declarations and reproduces the original error as a negative
control. Full corrected SDK/app acceptance remains with the next exact commit.

The same Apple source gate subsequently exposed the Naive graph fixture's
120-second deadline. Its 178 graphs and 2,151 assertions launch 840 fresh Go
helpers; Foundation's polling exit wait added substantial per-call overhead.
The fixture now installs a completion handler before launching each process
and joins its signal, preserving the full matrix and the existing deadline.
A controlled local run fell from 46.9 to 5.6 seconds, and the complete edited
fixture passed in 8.7 seconds including compilation. Large pipe payloads,
nonzero exit diagnostics and executable-launch failure also pass; this is a
fixture synchronization correction, with no application or native policy change.
The later Xray exit fixture uses the same bounded completion join: all 87
graphs, 1,167 assertions, 538 fresh helper calls and its 90-second deadline
remain intact. Its measured local execution fell from 29.3 to 3.5 seconds,
with the full fixture and the same pipe/exit/launch controls passing.

The `94ecb55d` follow-up passed all six authoritative native runtime targets,
including actual Windows x64/ARM64 license collection, PE verification, receipt
and relocation checks, captured native connection graphs and archive roundtrips.
Its full source audit also passed, including all four Windows fallback archives
and 20 integrity/compile controls and the 159 Android telemetry checks with nine
negative controls. Both Linux GTK app packages passed actual rendered-layout,
responsive-dialog, cancellation and installed-runtime upgrade checks. Both macOS
AppKit packages passed native compilation, sealed-runtime and archive/signature
verification. The expanded complete iOS map/coordinator SDK check and original
access-error control passed on Apple runners, as did the unchanged Naive matrix.
The ARM64 auxiliary workflow built its actual init/proxy images and passed
authenticated router-local Portable downloads for both Windows architectures,
private-pairing checks and proxy-service smoke tests.

The same `94ecb55d` client iOS lane completed the full Release iPhoneOS app and
PacketTunnel compile/link, native runtime checks and unsigned re-signable IPA.
The downloaded finished IPA passed the shipping archive-provenance verifier
for the exact commit, repository and both app/extension families. This confirms
the previous map visibility and telemetry binding repairs in the actual app;
Apple distribution signing and physical-device networking remain separate.
Its Android native runtime, Java compilation and APK assembly also passed,
then the final Tor verification task rejected the runner's ambient NDK revision.
The native builder had selected the correct pinned NDK in its child shell, but
that selection was not supplied to the separate Gradle verification task.
The finalizer now resolves that same SDK's NDK from the canonical Tor source
lock and passes it explicitly; the AAR verifier also receives the selected path.
Seven actual Gradle task checks pass, including conflicting ambient NDKs, SDK
precedence/fallback, paths with spaces and missing/wrong revision or compiler
rejection. The exact previous task reproduces the CI failure. Eight fast native
contract tests also pass, including the real AAR shell call and its omitted-NDK
negative control. The Gradle regression runs before native preparation in every
APK build; it doubles payload inspection while retaining the shipping verifier
CLI and actual NDK validation.

The corrected authoritative Android lane on `1a459f4a` completed all seven
Gradle regressions, actual native compilation, Java compilation, APK assembly
and the real Tor checks in both the AAR and finished APK. Its downloaded
artifact matched GitHub's size and SHA-256, and the shipping archive-provenance
verifier accepted the finished APK for that exact commit and repository.
This is a debug APK; persistent production signing and a physical-device
upgrade remain separate requirements.

The later authoritative `94ecb55d` iOS build exposed a separate ordering race:
its provenance script ran before Xcode generated the app's `Info.plist`, then
the plist-generation task immediately followed the failure. The successful
client build and verified IPA remain valid evidence for their actual artifact;
both target stamp phases now declare the generated plist as an input. The
stamper remains unchanged and still rejects missing plists or invalid source
identity; it does not claim a second plist producer. All 34 portable checks pass,
including four missing/wrong dependency controls. Before framework preparation,
the client, release-candidate and iOS smoke lanes build a small actual Xcode
app and embedded extension using the shipping stamp phases. All three passed
on `1a459f4a`: clean and changed-SHA incremental builds verified the actual
generated and embedded metadata, and invalid source identity was rejected.
The client lane also completed actual native framework compilation, the full
iPhoneOS app and PacketTunnel build, and the unsigned re-signable IPA. The
downloaded finished IPA matched its artifact checksum and passed the unchanged
shipping verifier for the exact commit, repository and both packaged families.
These checks establish the corrected build ordering and package identity;
Apple distribution signing and physical-device networking remain separate.

Both `94ecb55d` Windows Portable consumers passed, including relocation. The
authoritative installed-package gates then passed the runtime-install fixture's
202 checks in PowerShell 7 but exposed the same directory-symlink cleanup error
in Windows PowerShell 5.1. That fixture now uses nonrecursive .NET deletion after
checking the link identity, then checks that the link is gone and the complete
target payload is unchanged. All 205 local checks pass; a target-byte mutation
fails the new retention assertion. On `1a459f4a`, the diagnostic and both
authoritative Windows architecture lanes passed all 205 checks in both
PowerShell 7 and Windows PowerShell 5.1. That repair changes test cleanup only
and retains the production install/rollback ownership checks.

The next actual Windows installation step exposed pre-main application hooks:
standalone runtime verification attempted to prepare an unrelated mode catalog,
and PowerShell 5.1 treated its stderr as an installation failure. The adjacent
trust hook could also modify or reject unrelated client configuration before
verification. Both operations now run explicitly after the two standalone
utility dispatches, retaining trust validation before catalog preparation for
normal application startup. A regression builds and executes the complete
controller for 64 utility invocations, checking exact stdout/stderr and unchanged
ambient or explicitly selected configuration. Normal-startup controls preserve
trust migration, malformed-config rejection and actual Windows catalog setup.
The fixture passes on Go 1.23 and 1.26; the old source fails six ambient-config
groups. Four actual complete native/AWG verifier calls also pass with malformed
unrelated configuration, clean stderr and unchanged files. The real Windows
startup regression now runs in the early native contract workflow; the next
commit still requires both installed-package consumers and the release chain.

The same `1a459f4a` source audit and all six authoritative native runtime targets
passed. Both Linux GTK packages passed rendered-layout, responsive-dialog,
cancellation and actual installed-runtime upgrade checks; both macOS AppKit
packages passed native compilation and sealed-runtime/archive verification.
The ARM64 auxiliary lane passed its actual image smoke tests, authenticated
fallback Portable downloads and private-pairing checks. These are results for
that exact commit. The new startup repair requires a fresh source-bound release
run, including the nine images, production compose and complete prerelease;
physical-device, distribution-signing and private deployment gates remain open.

Apple candidate measurement passed 240 executable Swift checks and two negative
controls. Persistence and native restoration passed 61 and 85 checks respectively;
the existing 433-check Speed Lab suite also passes. These tests exercise shipping
source with declared platform boundaries doubled, not physical-device routing.
This continuation also adds captured native DNS comparison for mobile Tor and
ordinary external paths. Both hosts retain the exact proved session and native
cleanup owner, validate complete results, and offer an explicit next-connection
DNS edit. The Apple hop-measurement handshake now also distinguishes the
provider epoch from the MTU session instead of rejecting valid sessions whose
identifiers differ. Executable fixtures deliberately use distinct identifiers.

The `3c46bc57` native matrix has passed the Windows installed/Portable packages
for x64/ARM64, macOS for Intel/Apple Silicon, Linux for x64/ARM64 and the ARM64
Portainer image/preflight job. Repeated native preparation then exposed a
competing `sing` replacement in the mobile build sequence. The current fix
composes the UDP buffer limits and packet-endpoint concurrency correction in
one verified dependency copy. Both preparation orders, repeated preparation,
default/low-memory capacity builds and the actual native UDP race regression
pass; unrelated or partially modified copies remain rejected.

Those earlier package results do not certify the newer source: its exact-SHA
APK, Xcode/IPA, desktop packages, server images, generated compose and
publication gates must run on the resulting source generation.

The `1394ec8f` run also passed its then-existing desktop and ARM64 preflight
gates, but mobile gates exposed stale Tor-MTU and Apple hop-proof fixtures.
The real Android native producer additionally emitted 570 external graphs
while its consumer still required 456. The corrected consumer requires all
456 Local plus 114 paired Server/Compare cases from each mobile host, and
Apple now exports those paired cases as well. No matrix entries are removed
to obtain a passing result. The real prepared native registry accepts all 570
graphs from each host and rejects every corresponding missing-engine control.
Earlier desktop success did not test the missing
complete-runtime delivery path described above.

The actual `1394ec8f` Xcode build also exposed a generated-binding mismatch:
native String-returning proof and MAX calls require an explicit NSError
pointer, as does the MAX DNS callback. The adapters now match headers generated
by the pinned gomobile version, preserve the native error domain/code, and
reject an errored result even when it contains nonempty proof text. The affected
full-engine, MAX and external-execution gates pass with these real API shapes;
the next exact-SHA Xcode build owns native SDK acceptance.

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
routes and destination retain the selected tunnel owner. Mobile ordinary
external and Tor policies now use the shared native validation and exact
predecessor capture. An unpaired Home draft may be edited, but it does not grant
runtime readiness or silently select a public resolver. Tor public DNS requires
a supported TCP transport; the selected resolver must pass the live proof.

Android and Apple now compare the twelve public IPv4/IPv6 endpoints of
Cloudflare, Google and Quad9 through the captured ordinary external exit or
native Tor connection. The user explicitly chooses TCP DNS, authenticated DoT
or authenticated DoH. Each public time includes a fresh TCP connection, TLS
setup where applicable and a matching usable DNS answer; all three samples
must succeed before a median is eligible. IPv6-Off prevents IPv6 socket attempts.
No ambient resolver, proxy, direct path, public UDP or HTTP/3 fallback can
silently substitute for the measured transport.

The separate Selected DNS row queries the actual native DNS router with local
caches disabled. It retains its own transport and route, including Home AdGuard
through the exact paired entry, and is labelled separately from the public
exit comparison. The existing Router VPN UDP comparison remains labelled as
app-originated queries following the device route and its exclusions; it does
not certify public DNS timing through a Tor or ordinary external exit.

Both mobile hosts reject changed sessions, saved sources, selections, physical
networks and expired results. A successful public row or the fastest eligible
row fills an explicit DNS editor draft with its protocol, address, port,
certificate name and path. The user must Disconnect and Save before that policy
can apply to a later connection. Comparisons never initiate Connect, alter the
active resolver or write the ambiguous legacy `fastest_dns_*` cache.

Cancellation retains late native sockets, failed closes and measurement/MTU
ownership until actual drain acknowledgement. Android retains its service
owner after UI dismissal. Apple reserves requests before acknowledging Info
and keeps the same app transaction visible after reopening the editor. If
system Disconnect removes provider messaging, an exact drained receipt can
recover cleanup through the shared App Group. It contains no credentials or
measurement results and cannot select a resolver. A single retained provider
timer retries native cleanup and receipt persistence after transient failures,
without another IPC request. Missing or failed evidence leaves cleanup pending;
an abrupt process exit before acknowledgement is not treated as proof.

Verification includes the complete Go suite and reconciled requirements audit,
Go race tests, actual prepared pinned-native factory and adapter tests, and two
native late-socket/failed-close negative controls. Android passes 261 DNS
ownership checks and 3,550 editor checks, including 200 real native compiler
roundtrips and the corresponding mutation controls. Apple passes 324 DNS checks
with four mutation controls, whole-engine runs of 382/382/383 checks, and 67
real-filesystem receipt checks with two mutation controls. Apple SDK compilation
is a separate Darwin gate. These are source/native boundary checks, not a
public Tor circuit or physical-device acceptance. See
[../internal/dnsmeasure/README.md](../internal/dnsmeasure/README.md).

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
Tor is not simulated by an ordinary SOCKS profile. Its native proof request
requires a live query through the exact captured DNS router before delivery;
both mobile hosts require that DNS confirmation. Home DNS traverses the
captured private entry, while an explicitly selected public resolver traverses
Tor. Entry credentials and policy are fingerprinted, and a retired DNS or entry
owner invalidates the proof. Native constructor and in-memory network tests do
not establish a public circuit or a physical device's routing. Imported values cannot
inject torrc commands or executable plugin paths.

Real Java/Swift graph fixtures cover 348 Tor variants per mobile platform.
The pinned native registry accepts those graphs and rejects corresponding
missing-Tor-engine mutations. These constructor/configuration checks do not
start a public Tor circuit or replace APK/IPA and device networking tests.

Windows x64, macOS and Linux use an owned standalone Tor process with the
packaged native Go transports and physical-network observer. Windows ARM64
uses verified Windows 11 x64 userspace compatibility for standalone Tor;
the app, transport/VPN engine and driver stay ARM64. Lyrebird is not launched
by this native connection path. Capability checks describe this accurately
and reject hosts without the required execution support.
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
