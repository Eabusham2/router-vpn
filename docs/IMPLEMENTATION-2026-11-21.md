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
| macOS socket fault injection | A deliberately failing assertion skipped explicit retirement of the original test-created socket. Cleanup now closes and retires that same creation before policy cleanup, including after an assertion failure. | Fixture/mutation wiring checks pass. Actual Darwin kernel positive and negative execution remains required. |
| macOS PF verification latency | A measured Intel grant exceeded its two-second budget while sequentially reading kernel rules and parsing already-captured expected rules. Those independent reads now overlap, share the same command admission budget and deadline, and both join before a verdict. | Focused race checks cover the shared deadline, matching values, both reader errors and joined cancellation. Both Darwin architectures cross-compile. Native timing and kernel acceptance remain unverified until hosted execution. |

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

The broader multiple-import Server/Compare foundation still lacks complete
production worker/bridge/host adoption; accepting a JSON field alone would
not complete it. The previously documented graph-position and two-to-eight
capability boundaries remain implementation limits, not user-accepted final
scope.

Final package, image and compose publication must come from one passing
source generation. Physical devices, off-LAN behavior, rendered accessibility,
private server and AI providers, legitimate iOS provisioning, deployment and
ASUS household preservation retain their separate
[live evidence requirements](LIVE-RELEASE-EVIDENCE.md).
