# Router VPN continuation — November 21, 2026

## Scope and starting source

This work continues `f387a543dbb5588ce61c6da3814418fc04d1123e` and the
[November 19 implementation](IMPLEMENTATION-2026-11-19.md). The requested
October 12 Chicago release remains
`7888812adad0101c768de09baf100d6d69eedf26`. The complete
[current requirements](CURRENT-REQUIREMENTS.md) and
[reconciled requirements](REQUIREMENTS-RECONCILED.md) remain binding.
The recovered original passages and private configurations are kept outside
the public repository.

The starting revision already contains the earlier Emergency Stop, execution
label, Android shortcut/settings, map, draft-picker and device-wide MTU
repairs. This continuation preserves those implementations and addresses
additional observed failures. It does not certify all requested features or
physical devices as complete.

## Repairs

| Area | Observed defect and correction | Verification boundary |
| --- | --- | --- |
| Desktop custom-entry response measurements | A supported independent SS2022 entry and middle followed by a paired final was refused by the older response-history meaning validator. The entry now retains its public HTTPS measurement, entry role and original position. Source-kind mismatches, unsupported public finals, stale generations and relabelled receipts remain refused. | Reproduced the failing original inventory; corrected inventory, history tampering and actual controller-fixture checks pass. The broader desktop ordered/selected latency regression also passes. Native tunnel traffic remains a separate gate. |
| Failed execution-candidate preparation | Three bridge constructors returned a typed nil pointer as a nonnil service interface. Failed preparation could then retain an uncloseable candidate. Each bridge now distinguishes an absent service from a real partially-created owner, preserving retirement for the latter. | The actual pinned native factory passes under the race detector for explicit Server and both Compare winners, including failed entry/interior preparation and joined cleanup. All 39 bridge preparer/runner checks pass. This is native factory evidence, not physical-device acceptance. |
| Android selected-response fixture | The generated Go fixture omitted the optional multi-import native type and its dependencies after the ABI expanded. The fixture compiles the actual type closure and preserves the legacy six-field product contract and explicit refusal of an unadopted family. | 1,073 compiled Java/Go checks and ten deliberately broken controls pass. This repairs verification; it does not implement the wider multi-import Server/Compare host. |
| iOS telemetry fixture | The Network Extension protocol double omitted the real `providerConfiguration` property consumed by the captured device MTU policy. | External benchmark: 264 compiled Swift checks and five broken controls pass. Unified telemetry: 265 checks, 21 adapter checks and its controls pass. This is not iOS SDK or device acceptance. |
| iOS Tor profile gate | Every negative variant unnecessarily ran the full positive matrix before its relevant refusal assertion. The same refusal groups run first; the unchanged positive inventory, witnesses and deadlines remain required. | The full gate passes 20,905 assertions over 768 transactions and all five negative controls. |
| iOS selected response history | Server/Compare measurement receipts identify the actual selected projection, while IPC ownership identifies its original preparation. The app previously confused those identities and expected ordinary Local labels. It now retains the exact native capture, validates selected labels and generation, requires the original facade's post-close proof before saving, and reloads both Compare winners without losing their route identity. | The failure is reproduced against the starting source. Compiled Swift app/host checks cover explicit Server, both Compare winners, all three positions, reopened history and changed/missing close proofs. Existing component, CONNECT/SOCKS/OpenVPN and mutation inventories pass. Shared Go projection, fifty-response, changed-epoch and retirement tests also pass. OS and native boundaries doubled by a fixture remain separate from device acceptance. |
| Linux enlarged-text layout | Fixed horizontal action rows forced the window wider than 640 pixels and clipped button labels at enlarged text sizes. The original widgets now reflow into available space, and the current full controller status is also available in its tooltip. The comparison fixture now includes the shipping async action's recursive header dependencies; scroll checks wait for a bounded GTK animation frame before testing the original exact allocation bounds. | The actual GTK composition is rendered across four window dimensions, three fonts and two label scenarios. All 24 combinations pass scrolling, action bounds and rendered Pango label-height checks. Normal and 20-point screenshots were inspected, including the lower Settings, Mode and DNS controls. The packaged layout and Speed Lab checks, eighteen loopback HTTP scenarios and GTK comparison with six causal mutations pass. This covers the Linux layout and captured HTTP fixture, not other platforms or live VPN traffic. |
| Android native-policy audit | Two older repository audits still expected the superseded controller call that selected only a profile MTU. The production controllers already use the captured device preference and the current interface-patching function. The audits now require that current call together with device capture, value selection, interface readback and revision validation. | The full-audit and native-policy contract reproduce the original mismatch and pass with the current implementation. The complete common-package suite passes in 62 seconds. Production MTU behavior is unchanged. |
| Windows ordered-editor fixture and help | The isolated Apply callback omitted the real adjacent draft-capture helper, so the intended route never reached Apply. The fixture now includes that helper and surfaces the original callback error. The app's help text now describes the implemented Hysteria2 layers and independent imported interiors. | The failure was reproduced. The repaired positive fixture passes 10,613 shipping callback checks and all 33 mutation controls with their original diagnostics and deadlines. Source-token replacement is rejected. Native WPF rendering remains separate. |
| Desktop native image fixture | The selected-latency projection omitted the new original multi-import HTTP helper and live/retirement observer methods. The projection and its source digest now include that exact dependency. | Generated fixture compilation and the original selected runtime test pass; the five runner checks require the dependency closure. All native release images still require their platform gates. |
| H3 and XHTTP workflow dependencies | Two workflow filters watched four router-agent files even though the builder now consumes all 81 Go files. The filters now follow the builder's exact source glob, and the tests verify every current source and missing-trigger refusal. | All nineteen H3 and eleven XHTTP workflow checks pass. Native encrypted references remain mandatory. |
| Native compiler selection | The ARM64 Linux build installed Go 1.26.3, then native C/Rust setup placed `/usr/bin` earlier on PATH. The main builder retained its verified `GOTOOLCHAIN` selection, but the nested relay and Server Tor preparation dropped that captured environment and invoked the distribution compiler. The original environment now follows the complete preparation chain, including its module edits. | The hosted failure is recorded in [the Linux native run](https://github.com/Eabusham2/router-vpn/actions/runs/44968461743). All fifteen Server Tor checks, the original stage-order/failure regression and a deliberately poisoned ambient compiler test pass. Fresh ARM64-targeted source preparation, actual module verification and Amnezia verification pass with the captured environment and without changing the caller's environment. Hosted native builds still need to rerun. |
| macOS socket fault injection | A deliberately failing assertion skipped explicit retirement of the original test-created socket. Cleanup now closes and retires that same creation before policy cleanup, including after an assertion failure. | Fixture/mutation wiring checks pass. Actual Darwin kernel positive and negative execution remains required. |
| macOS PF verification latency | A measured Intel grant exceeded its two-second budget while sequentially reading kernel rules and parsing already-captured expected rules. Those independent reads now overlap, share the same command admission budget and deadline, and both join before a verdict. | Focused race checks cover the shared deadline, matching values, both reader errors and joined cancellation. Both Darwin architectures cross-compile. Native timing and kernel acceptance remain unverified until hosted execution. |
| macOS native test-image helper dispatch | The installed native fixture is built with `go test -c`, so its Go test main replaces the program main. Its initialization dispatched the actual tunnel commands but omitted the socket guardian, creator and UID-observer commands that re-execute that same image. It now dispatches the registered helpers and probes all three roles before any PF or utun work. | The complete Darwin runner suite passes all 59 checks. A real compiled test image using the original initialization and inherited-channel validator reaches the exact pre-network refusal; removing the helper branch reproduces re-entry into the test main. Hosted preflight now probes its actual signed image with an invalid inherited channel. This establishes the harness defect and correction, not the sole cause of historical runner loss or native kernel acceptance. |
| macOS cleanup lock lifetime | The detached root guardian did not inherit the engine's original installation and process locks. An abrupt engine exit could release them while privileged cleanup still ran. The guardian now retains the same two validated lock descriptors through its own cleanup and explicitly passes them to fixed privileged utilities; creator and observer processes remain isolated. | Actual subprocess tests cover abrupt engine exit, a surviving guardian and utility, shared/exclusive lock exclusion, malformed descriptors and later reacquisition. Repeated race checks, three causal mutations, both Darwin test-image cross-compiles and 21 affected runner checks pass. Fresh pinned preparation verifies all 244 guardian source records. The portable guardian suite passes 66 of 67 checks; the unchanged AF_UNIX control-lifetime test is denied by this executor and remains required on the hosted platform. |
| Android saved-pair map animation | A disconnected saved pair still painted moving packets and scheduled redraws. The map now keeps its static preview, adopts animation only from the original proved connection, and stops an already-queued frame after that owner retires. Changing a selected draft cannot borrow a different connection's animation. | The shipping controller, map projection and draw methods pass 263 primary checks, 51 packet-entry and 61 SOCKS-entry checks, and all 26 causal controls. Ordered presentation, import callbacks, session ownership and 6,759 permission checks with twenty controls pass. These JVM drawing boundaries do not replace signed-device rendering. |
| iOS profile regression fixture | A negative case rejected a supported paired Hysteria2 final, and one mutation spanned two source-family methods. The fixture now round-trips the complete supported Server/Compare profiles, including independent imported interiors, while preserving unsupported interior refusals and an exact SOCKS mutation boundary. | All 242 compiled Swift profile checks and six causal controls pass. |
| Android older typed-host fixtures | The isolated SOCKS and CONNECT capture doubles omitted the new explicit `multipleImported=false` field read by the shipping host. Both doubles now declare their original source family. | Each family passes 671 compiled host and 114 restoration checks with three causal refusals. Both CONNECT final-layer suites add 342 passing checks. Product family guards are unchanged. |
| Native owner mutation inventory | Two older mutation strings matched both their original selected-DNS/retired-owner guards and newer candidate-permit code. Each mutation now identifies its exact original function boundary. | All 35 mutation sites have one source match. The actual pinned Box rejects both deliberately broken variants with their original selected-DNS and retired-receipt diagnostics under the race detector. The production guards are unchanged. |
| Windows imported-response gate inventory | The release runner still required an obsolete negative-case name and omitted an already-executed custom-entry layout, public-entry receipt and controller checks. It now requires all four original Go groups with 94 exact records. | The actual historical Windows transcript satisfies all 64 records in its inventory group, and the original controller image executes all 94 records across the four groups. Every individually omitted or duplicated record is rejected; all 38 runner checks pass. The Go tests and runtime behavior are unchanged. |
| Entry candidate proof fixture | A valid fifty-sample test could finish before its first five-second worker-proof refresh, making success depend on elapsed time. The fixture now delivers the same actual worker completion event immediately and retains its periodic refresh. | The immediate-event regression passes three times under the race detector; removing the initial event fails its original witness. All fifty-sample Server/Compare outcomes pass, with the Server case finishing in 3.46 seconds without weakening any freshness check. The original worker, fifty real TCP connections and joined service retirement remain required. |
| Native source audit after schema-six adoption | Exact function-body contracts still described four physical owners and the older imported-family dispatch. They now require the fifth original physical owner, exact multiple-import source and supported public capability, while preserving all prior owner checks. Three mutation fixtures also needed their original guard names and formatted public fields updated. | The full recovered native UI gate passes with its required Java and Swift toolchains. All 77 native shipping audit roots pass across the full run and the three corrected fixture reruns. Twenty-one new deliberately broken variants require the new family, original source and physical-owner contracts; comment decoys cannot satisfy them. These are source gates, not native kernel acceptance. |
| iOS saved-profile test dependency closure | The external profile test omitted the real selected-execution compiler now used by whole-path restoration. It now links the shipping Swift capture families and actual shared Go compiler. Focused Tor and legacy fixtures explicitly trap an unexpected selected-family call. | External profiles pass 1,373 checks, including Server/Compare Add, Load and exact five-position restoration with two independent imports. Damaged original packet configuration is refused without changing saved records. Removing only the typed preview causes its intended failure. The original entry guard control, 654 legacy checks with five controls and 20,905 Tor checks with all five controls pass. Apple SDK and installed-device execution remain separate. |
| Windows prepared WFP verification | The prepared handoff independently enumerated every host filter twice inside the same original read transaction: once for the empty lock sublayer and once for the exact baseline. One enumeration now proves both distinct sublayers, retaining complete baseline equality, bounds, duplicate detection and both security-descriptor checks. | The actual old and new enumeration functions pass fifteen scenarios repeated three times under the race detector. A valid 384-filter host requires four page RPCs instead of eight, with both ACL checks retained. Both Windows test images compile; 22 mandatory native roots and 22 causal variants remain required by the runner, including an added lock filter. Actual BFE acceptance must pass on Windows. |
| Windows MAX failure diagnostics | An intermittent native admission timeout cancelled its original owner without retaining which stage or worker remained. The unchanged timeout now records a bounded diagnostic snapshot immediately before cancellation. | Runner checks and both Windows images pass. Output is restricted to fixed phase/status/error classes and counter deltas; private exception strings are excluded. The original deadlines, credential checks and retirement witnesses are unchanged. An older independent run passed all ten suites, so the historical intermittent defect is not declared fixed without a fresh native verdict. |
| Android imported-schema negative control | A mutation intended to remove the older imported-family exception also removed the newer typed families, so its exact source anchor no longer matched. It now alters only the original schema-two exception. | All six original positive source families pass in separately bounded JVM invocations, with imported prefixes, exact native Last restoration, all three paired Hysteria2 layers and thirteen causal controls. The unsplit positive aggregate exceeded its unchanged local bound under load; the original hosted aggregate remains mandatory. |
| iOS comparison storage fixture | The comparison test modeled only main-actor journal storage, while the shipping device MTU preference opens a named app-group suite from the app and extension. The fixture now models that named suite separately using Foundation storage while retaining the original journal failure hooks. | Strict-concurrency compilation and all 361 comparison checks pass, including actual device MTU Save, a detached extension read and stale-revision refusal. All six existing causal controls pass. This repairs fixture coverage without changing the production storage or comparison code. |
| Encrypted packet-first reference peer | The encrypted device could read its route map while the test peer was still wiring its independent imported provider. Its packet classification and forwarding lookups now reject traffic until the original completed map is published through one synchronization latch. | The actual pinned native race image passes the publication test 25 times and the existing TCP/DNS transport test. Independent removal of either reader's publication guard fails the exact prepublication assertion. All 32 encrypted runner checks pass. The nine existing encrypted namespace cases remain mandatory on the native host. |
| Mobile execution-picker guidance | Both mobile editors still described independently imported interiors as Local-only even though their typed Server/Compare paths had been implemented. The visible guidance now describes the actual supported placements and preserves the literal-address, layer, hostname and imported-entry restrictions. | The Android shipping editor opens the execution picker and returns through its original callbacks; restoring the old displayed restriction fails the new check. The iOS shipping chooser passes 350 checks and all six existing causal controls; its old visible text independently fails the corrected assertion. Eligibility and native transport behavior are unchanged. |
| Android release-fixture dependencies and inventory | The Node Chain MTU fixture omitted the real fixed Xray source helper, an imported-prefix mutation matched an obsolete schema exception, and the shared test partition omitted six new typed execution roots. The fixtures now include the exact helper, alter only their original schema-two branch, and compare the complete discovered inventory with explicit root names. | The MTU fixtures pass 74 checks with twelve causal controls and 104 original MTU checks. All seven imported-prefix causal controls pass their original diagnostics. All forty partition self-tests pass; actual Go discovery contains 1,184 roots, including 28 explicitly listed typed execution roots. This discovery count is not a claim that the complete new shared inventory has executed. The unsplit imported-prefix positive aggregate retains its original hosted deadline. |
| Windows typed-candidate drain fixture | Both Windows architectures reported a missing replacement inode even though the replacement still existed. The fixture captured its identity using a path-based stat before renaming it; Windows resolved that identity lazily from the old pathname. It now captures both identities through the original directory handle, proves they differ before the rename, and checks both replacement identity and bytes after cleanup. | Both SOCKS and CONNECT pass their request- and inventory-replacement cases under the Linux race detector, with six terminal records. The production cleanup and all timing limits are unchanged. The repaired fixture still requires execution on Windows. |
| OpenVPN native-owner inventory fixture | An independent runner self-test still expected 44 roots and 181 records after the required original candidate-permit retirement regression was added. It now requires all 45 roots and 182 records and separately rejects omission of that regression's start or pass. | All twelve OpenVPN runner self-tests and fourteen original native-owner runner checks pass. The earlier hosted native image independently passed the actual 45 roots, 182 records and 35 causal variants before encountering this stale self-test. The corrected count preserves that strict inventory. |

## Independent imported interiors in Server and Compare

The schema-six foundation now has production worker, native Box, mobile-host
and desktop-host adoption for its supported paths. A paired packet entry can
retain independent literal Shadowsocks 2022 imports at interior positions,
with supported paired packet hops between them and a paired Shadowsocks final.
Every import retains its own original credentials and Start Layer Off. The
existing two-to-eight-member capability bound still applies. A custom imported
entry uses its distinct schema-seven Local implementation; this change does
not grant it Server or Compare capability.

The actual native construction retains the original preparation, per-position
Shadowsocks clients, managers, resolver and selected route. Desktop construction
also retains its original platform-specific physical owner, command capture,
reader and MTU transaction. Missing, copied, reordered or changed owners fail
closed. The worker derives its sparse paired packet key positions from the
same original inventory instead of treating imported credentials as packet
keys. Provisioning validates this typed source before writing private files.

Android and iOS use the typed native CommandServer constructor, preparation
and saved-choice factory. Windows, macOS and Linux enable the selected editor
path only when both the controller and every imported profile advertise the
specific capability. The generic execution capability cannot grant access to
this family.

Selected hop measurements carry the exact native seven-field capture, including
the original Local source identity and complete ordered imported-position
inventory. The UI and saved history preserve the actual Local or Server winner,
target, generation, labels and each source seal. The original measurement must
prove retirement while the MTU owner is still held before its receipt can be
saved. A saved Compare choice reopens that winner without rerunning Compare.
The legacy six-field capture retains its previous restrictions.

Repeated serialization of large immutable source strings exceeded the existing
mobile measurement admission budget. The original digest is now reused only
when every originally hashed scalar, string and copied short inventory still
matches. Mutable provider maps are freshly compared against independent decoded
copies. A copy can enable this comparison only if encoding it reproduces every
original byte; unusual numeric spellings, integer rounding and different Go
value types retain the original serializer as the fallback. Object keys, array
order, signed zero, nil versus empty values and every originally sealed scalar
remain significant. Live native and desktop physical ownership is freshly
validated. Authorized mobile projections and the final desktop physical
projection capture their own canonical snapshots after resealing. Changed-input
checks require the same digest behavior and refusal as the original serializer,
including values whose initial encoding cannot survive decoding as a
floating-point number. No product deadline was increased.

The desktop construction additionally consolidates repeated static checks into
one fresh complete validation per call, retaining the original preparation,
physical policy, source and native graph pointers plus the exact derived
configuration and metadata. Actual native observations remain bracketed by
their original source checks. An already-validated multiple-import family no
longer repeats the unrelated absent SOCKS and CONNECT family checks. Its
desktop preparation snapshot independently copies the mutable metadata
prefixes and roots, and saved-choice reconstruction refreshes that snapshot
only after the original final reseal. Changed owners, metadata and saved
choices still fail the original canonical validation.

The ordinary selected desktop packet path also keeps independent snapshots of
its original, derived and local graphs. The fast comparison retains every
original per-node position, source, mode, profile identity and proof identity
check. In particular, a Go named-string value can encode to the same JSON as
an ordinary string while failing the original runtime identity lookup; all
three such substitutions must still fail. Eighteen equivalence and changed-
input cases pass under the race detector, and removing the restored identity
checks reproduces all three failures. This optimization applies only to the
original ordinary desktop packet preparation and changes no capability or
timing limit.

An additional failed-measurement bug was reproduced: a nil concrete shared
measurement was converted into a nonnil interface and retained as a close
obligation. The bridge now normalizes that exact absent result; real partial
owners remain retained and must finish cleanup before another measurement.

The following evidence covers this implementation, with separate boundaries:

- The actual mobile core passes 56 mandatory race-test roots and 213 test
  records. All six projected outcomes (iOS and Android, explicit Server and
  both Compare winners) traverse independently authenticated Shadowsocks
  streams and selected HTTPS traffic, exercise the real exported execution
  method and typed CommandServer, and keep the original 1.5-second measurement
  factory admission. Controlled TUN/platform, packet-hop and remote-worker
  boundaries are not physical-device acceptance.
- A separate checksum-bound Box gate regenerates all eight original shared
  fixtures and passes one shared root with nine records plus six native roots
  with 38 records. It includes wrong-key rejection at both independent imports,
  sparse public positions, original-owner checks and joined retirement.
- The complete native desktop component gate passes nineteen roots and 166
  records under the race detector, including the preceding Box cases. Actual
  desktop Box and command preparation cover Linux, Windows and Darwin policies,
  six layouts, both requested execution choices, changed credentials and
  detours, resolver changes, physical-source substitution and wrong MTU/gate
  state. The child exercises original adoption/readiness, both saved winners,
  late constructor retirement and failed cleanup retry. Its longest original
  source observers finish in 3.38–4.74 seconds within the unchanged 45-second
  admission budget. These child lifecycle fixtures explicitly double the TUN,
  kernel and provider runtime; they do not certify an installed native tunnel.
- The desktop parent exercises all public positions on nine layout/selection
  combinations through its actual measurement mailbox, MTU hold and saved
  history. Twelve foreign-inventory faults are rejected for each selected
  execution. Both saved winners retain the same target and reopen without
  another comparison. The full common-package regression passes separately.
- Shipping desktop UI callbacks pass 10,751 Windows editor checks, 36,700
  macOS editor checks and 31,805 GTK editor checks. All 33 Windows and forty
  GTK editor mutations are rejected. Selected-history baselines and all
  thirteen Windows, seventeen Swift and seven GTK history mutations pass.
  GTK uses actual widgets under Xvfb; Windows and AppKit native control values
  are fixture boundaries, so these counts do not establish rendered native
  accessibility acceptance.
- Shared selected-source regressions pass 23 roots and 199 records. Projected
  snapshot equality and all seventeen altered-input cases pass separately.
  The complete shared package is also checked in eight bounded groups against
  its exact original root inventory: after correcting the entry-event fixture,
  1,171 roots pass and three existing native-fixture export roots are explicitly
  skipped, for 1,174 roots including the new immediate-event regression. Those
  three exports retain their separate native execution gates.
- The Android host executes Server and both Compare winners on four-, five-
  and eight-node routes, including 183 connection/restore and 99 cold saved-
  choice checks. Four compiled negative controls reject ordinary native
  factories, generic preparation, generic saved choices and removed original
  restore binding. Existing OpenVPN host cases and their controls still pass.
- The iOS shipping host and IPC fixture exercises seven members with imported
  positions one, three and five; original start, saved history, exact post-close
  capture, partial native-factory cleanup and retry remain required. Its seven
  causal controls and the previous SOCKS/OpenVPN inventories pass.
  The extended source enum and candidate-proposal switch are also checked by
  the real Swift compiler. The subsequent selected-candidate implementation
  and its separate ownership checks are described below.
- The worker's three actual Linux race-test images compile against the complete
  captured source inventory. The nine encrypted-namespace cases require
  distinct authenticated provider keys and selected DNS, TCP, UDP and UoT
  traffic. Their kernel namespace execution remains a hosted acceptance gate;
  the local executor refuses the necessary network namespace operations.

## Candidate timing through the selected packet prefix

The retained Server/Compare runtime now constructs candidate plans through the
same independent-import source registry. The chooser preserves the actual
packet positions, including packet hops after an imported transport. Every
candidate measures fifty TCP connection establishments. An imported proxy may
carry that route, but its lazy connection is not relabelled as a packet stop.
The original requested execution and selected winner remain unchanged; this
measurement neither repeats Compare nor replaces Last.

The Android and iOS app/host paths retain the exact original source, native
CommandServer, selection epoch, target inventory and entire proposed future
path. Their existing ordinary, SOCKS, CONNECT and OpenVPN owners keep their
separate capability rules. The desktop chooser preserves sparse positions and
allows an idle dialog to switch from a saved-prefix test to a connected-prefix
test. An active test or pending cleanup retains its existing dialog owner.

The desktop parent uses a two-stage native exchange. Prepare captures the
original selected publication and full source inventory; only the original
child can provide the live candidate capture. Start binds the exact published
metadata bytes and catalog generation. Results are considered only after the
original request has been consumed and every worker has joined. Source,
metadata, pulse, request and cancellation cleanup retains the producer's file
identity. A replaced file is preserved and keeps cleanup pending until the
original retirement can finish.

The child stages a result and publishes it without replacing an existing
receipt. It retains that original result's identity and bytes through cleanup
retry. The parent checks that the request has been consumed both before and
after reading a result, so a provisional result cannot be adopted while the
child still owns the request. It removes the original result only after the
other captured files have retired; a changed or foreign result keeps the
measurement pending. Independent controls reproduce both the old publication
overwrite and acceptance of a replaced result when their guards are removed.

Disconnect now recognizes the exact files produced by all three existing
desktop measurement exchanges, including the selected candidate result and
its narrowly defined staging names. Cleanup remains blocked until the native
owner has joined. Four filesystem cases exercise each measurement family and
foreign lookalikes; the original workspace code reproduces the refusal to
retire a valid selected-latency workspace. The corrected race test removes
the captured files and directory before releasing the held MTU transaction.

Candidate grant/status calls now share the selected attempt's lease RPC gate.
Cancellation can return promptly while retaining the original entered worker.
Another grant, status or renewal must wait for that same worker to join; the
authenticated candidate DELETE retains its independent stop capability.
Removing this retention reproduces the original ordering failure. Nine original
lease, proof-clock, renewal, status and cancellation roots pass with 64 distinct
race-test records after the change.

Explicit Save compiles the complete next path with the typed independent-import
constructor. Its policy record supports the same paired entry, independently
captured SS2022 interiors, paired final and supported layers as the live source.
Load verifies the linked original private records and restores the requested
execution without connecting. Imported-entry Server/Compare and other
unsupported shapes remain refused. The new six-root parent component passes
41 exact records under the race detector, including all three selected outcomes,
public Save and cold Load, 21 metadata refusals, pre-construction cancellation,
result replacement and exact-file workspace cleanup retry. The child publications
and kernel are modeled in this parent component;
native connection and physical acceptance are separate gates.

The native builder includes both selected-candidate gates and their complete
source and fixture inventories on every matching desktop host. The parent
runner requires all 41 records and rejects omitted, duplicated, skipped and
foreign records. The child runner preserves its original per-process limits
and verifies the original test image, projected source and private fixture
files before and after each phase. Replacing a file with identical bytes at a
different inode is also refused. All seven child-runner suites, three parent-
runner suites and five existing selected-latency runner suites pass on the
combined source. These runner checks verify gate behavior; actual native
execution and its original timing budgets remain required separately.

The pinned Linux child component subsequently passes all seven required phases
and 28 terminal records under the race detector with one Go processor, after
all performance and typed-identity repairs. Its four fifty-connection cases
finish in 75.19 seconds for Server, 64.24 for Compare retaining Server, 53.20
for Compare retaining Local and 33.25 for the ordinary entry. Eleven refusal
cases, original-generation exclusivity and six publication controls also pass.
A separately compiled guard-removal image fails the exact replaced-inode
assertion, which the strict runner requires. Source generation adds nine
passing records. This uses actual routed localhost TCP and native component
owners with modeled TUN, physical packet and remote-process boundaries; it
does not establish encrypted namespace or installed-device acceptance. The
separate Windows identity-fixture edit above changes the broader preparation
manifest and retains its own platform verification requirement.

## CI and queue evidence at the starting revision

The GitHub audit found 38 completed workflows at the starting SHA: twenty
successful and eighteen failed, covering 33 failed jobs. The authoritative
[aggregate run](https://github.com/Eabusham2/router-vpn/actions/runs/44613035097)
contained 59 successful jobs, eight failed, three cancelled and 45 skipped.
An unrelated successful audit cannot substitute for that release result.

GitHub also returned 257 old workflow records as queued. All 257 individual
jobs endpoints returned zero jobs. There were no current in-progress,
waiting or pending jobs. Cancellation was requested for every old record;
GitHub returned HTTP 409, stating that the run had not been queued yet.
A force-cancellation request returned the same result. Those historical
records were not deleted and are not reported as cancelled. They did not
contain allocated or waiting runner jobs at the time checked.

## Remaining validation and implementation

Physical-network inspection is denied for some existing controller fixtures
in the local executor; the tests and product guards were preserved. The
[hosted custom-exit run](https://github.com/Eabusham2/router-vpn/actions/runs/44966498118)
at `1484f8a901d557801787e5280abd2b17d4a45e60` completed all 2,453 controller
test roots, recording 19,459 passing test receipts and 25 explicit skips for
separate native gates. Its later common-package step failed on the two stale
Android audit markers corrected above. That controller result is not a pass
for the whole workflow or its skipped platform acceptance. Focused source,
compiled-host, race and cross-compilation results describe only the paths
actually checked.

The ARM Darwin ordered-child jobs lost contact with GitHub; the Intel jobs
reached the enclosing one-hour limit. The generated-child fixture exercises a
full-host firewall baseline, which can block the runner's own connection.
The missing terminal logs do not identify the exact failing native operation.
The production firewall and release gate remain intact; a successful build
or scoped component test cannot replace full native acceptance.

The supported multiple-import Server/Compare implementation above does not
finish arbitrary protocol, hostname, Start Layer or imported-entry placement,
longer ordered graphs, selected Server/Compare per-hop and final throughput,
or disconnected Server/Compare recursive draft measurements. The previously
documented graph-position and two-to-eight capability boundaries remain
implementation limits, not user-accepted final scope.

Final package, image and compose publication must come from one passing
source generation. Physical devices, off-LAN behavior, rendered accessibility,
private server and AI providers, legitimate iOS provisioning, deployment and
ASUS household preservation retain their separate
[live evidence requirements](LIVE-RELEASE-EVIDENCE.md).
