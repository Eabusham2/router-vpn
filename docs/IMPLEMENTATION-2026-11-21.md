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
matches. Mutable provider maps are serialized on every check, and live native
and desktop physical ownership remains freshly validated. Authorized iOS and
Android projections capture their own canonical snapshot after resealing.
Seventeen changed-input cases require the same digest behavior and refusal as
the original serializer. No product deadline was increased.

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
- The Android host executes Server and both Compare winners on four-, five-
  and eight-node routes, including 183 connection/restore and 99 cold saved-
  choice checks. Four compiled negative controls reject ordinary native
  factories, generic preparation, generic saved choices and removed original
  restore binding. Existing OpenVPN host cases and their controls still pass.
- The iOS shipping host and IPC fixture exercises seven members with imported
  positions one, three and five; original start, saved history, exact post-close
  capture, partial native-factory cleanup and retry remain required. Its seven
  causal controls and the previous SOCKS/OpenVPN inventories pass.
  The newly extended source enum is also checked by the real Swift compiler:
  its candidate-proposal switch retains an explicit refusal until that separate
  selected-candidate path has its own implementation and proof.
- The worker's three actual Linux race-test images compile against the complete
  captured source inventory. The nine encrypted-namespace cases require
  distinct authenticated provider keys and selected DNS, TCP, UDP and UoT
  traffic. Their kernel namespace execution remains a hosted acceptance gate;
  the local executor refuses the necessary network namespace operations.

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
longer ordered graphs, or all recursive candidate measurements. The previously
documented graph-position and two-to-eight capability boundaries remain
implementation limits, not user-accepted final scope.

Final package, image and compose publication must come from one passing
source generation. Physical devices, off-LAN behavior, rendered accessibility,
private server and AI providers, legitimate iOS provisioning, deployment and
ASUS household preservation retain their separate
[live evidence requirements](LIVE-RELEASE-EVIDENCE.md).
