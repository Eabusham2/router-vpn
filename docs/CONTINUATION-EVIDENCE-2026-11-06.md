# Router VPN continuation evidence — November 6, 2026 UTC

## Scope and source identity

This is an implementation and evidence ledger, not a replacement for the user's
original requirements. The live starting branch was
[`b04eccee94f4cf3e83f978cbb74504e796c056a6`](https://github.com/Eabusham2/router-vpn/commit/b04eccee94f4cf3e83f978cbb74504e796c056a6),
1,294 commits ahead of the older published `745b3e41` release. Old patches were
not replayed over that history. The published units below retain normal
`main` ancestry through
[`b53071d401c637e1f050335e29a00cf65c7f0474`](https://github.com/Eabusham2/router-vpn/commit/b53071d401c637e1f050335e29a00cf65c7f0474).
Each remote tree was compared with the locally tested committed tree, and the
remote branch was read back before adoption. A saved patch, local commit or API
schema was not counted as a successful push.

The November 5 recovery metadata remains intact. Six frozen Apple files could
be reconstructed and checked against their recorded hashes. Complete bytes for
the shared, Android, Windows and Linux drafts were not recovered from the old
workspaces. New work was made against current source and verified independently;
it is not described as an exact recovery of those absent drafts.

## Original requirement sources recovered

| Original source or passage | Recovered requirement authority |
|---|---|
| `mm.md`, including the August 11 product request and its surrounding conversation | Native daily-use applications, setup/application separation, complete profiles, measurements, protection, modes, DNS and deployment requirements. |
| `router_vpn_chat_audit_addendum_v2 (1)(7).txt` and `Router VPN Handoff Audit (1)` | Historical numbered audit, C1–C7 and later 32-item product/breakage request; the numbered audit is an organized index, not 356 verbatim user sentences. |
| `New chat (1)(1).md`, August 13/14 user passages | Imported/custom nodes, hops and exits, independent credentials and actual graph execution. |
| `Router VPN Progress Update (1)`, August 19 user passage | Map-first native application, Router/custom choice for hop roles, connection controls and interaction requirements. |
| Current user handoff and its later corrections | Exact Compare formula, independent Start Layers, READY retention, defaults, image-only production, direct-to-main publication and separate device/deployment acceptance. |
| Current `docs/REQUIREMENTS-RECONCILED.md`, `configs/current-requirements.json`, shipping source and executable gates | Implementation/configuration contracts to reconcile with the original user authority, not substitutes for it. |

Targeted original passages and surrounding text were read. This record does not
claim that every private conversation or every file in the project collection
was accessible or read in full. An unavailable source is not evidence that its
requirement disappeared. Original identifiers are retained where supported;
overlapping lists are not added into a completion denominator.

### Requirement-to-evidence ledger for this increment

| Requirement / correction | Platforms and shipping paths | Executable evidence | Remaining boundary |
|---|---|---|---|
| Router/custom entry and final roles; original #214–224; native single VPN owner | Android `AndroidImportedRouter*` helpers and multihop host; Apple PacketTunnel/imported runtime; `internal/mobilemultihop/imported_entry.go` | 190 preserved/extended source graphs, actual Java and Swift exports, pinned native parsing and encrypted peers | Other imported/final families, Server/Compare for this direction, complete native device/network acceptance |
| Original #229–240, Auto/Fixed/Retest/Cancel and later packet-envelope limits | `internal/awgpolicy/packet_*`, `internal/mobilemtu`, mobile compiler/metadata | Race tests; complete data/control/cookie/junk/Start Layer bounds; Fixed overflow rejection; full-size decrypted IPv4/IPv6 peer observations | Effective configured cap is explicitly unmeasured; physical PMTU, transitions and Jumbo acceptance remain separate |
| Original #200–224/#337, exact captured ownership and full temporary-test restoration | Windows retained desktop host, `desktop_external_owned_sources.go`, independent entry/final captures | Shared/client race tests, two architecture test-binary builds, 53 mandatory native leaves and two causal mutations | Hosted WFP runtime and physical acceptance remain separate; the exact Speed Lab/Always-to-Off fixture failures below now have published corrections |
| Selected DNS/Home AdGuard, LAN/IPv6 and original resolver authority | `internal/standardengine/resolved_*`, retained native resolver helper, finite kernel grants and single-scope caller | Canonical bounded frames, original-daemon local-only preflight, exact upstream port/TLS/link transport and active trust-anchor codec/race tests | Installed privileged composition, equal-best parallel scopes, full DNSSEC validation, opportunistic TLS and other remaining resolver branches are not closed |
| Later independent Off/AES-256-GCM/AES-256-GCM+XOR Start Layers | Mobile original sources, compiler and owned graph | Independent entry/final layer matrix and actual encrypted positive/negative cases | Broader graph/platform coverage remains required; Windows SS entry increment is both layers Off |
| Complete connection profiles; credential references; stale/cancelled operations cannot mutate a replacement | Typed Android/Apple captures; native retirement; Windows retained source owners | Actual saved-selection/startup fixtures, native retired-read race controls, exact restore-source checks | Full physical permission/reconnect/leak/off-LAN acceptance remains open |
| Original #335 | Optional Favorites, required latency and last-used ordering | Identifier reconciliation only in this increment | This number is not an MTU/Speed Lab identifier; prior mistaken citations are corrected without deleting measurement scope |
| Full original and later product scope | Native Windows/macOS/Linux/Android/iPhone/iPad; qualified additional Unix/BSD targets; Setup Center; server/router integration | Existing ledger and separate gates remain authoritative | No completion percentage or full-product acceptance is asserted |

Preserved exact contracts include SMART AUTO, IPv6 On, AUTO encryption and
obfuscation requirements Off, Home AdGuard, fifty node samples, and
`(last_node_response_time + external_server_response_time) / 2` through each
candidate using the same external endpoint. Invalid candidates have no score;
the winner must be rechecked and its captured execution restored. READY package
retention remains thirty minutes without extension; Cancel/Delete/shutdown clean
immediately. Blank AdGuard Allowed Clients remains unrestricted. Client kill
switch failure is closed; ASUS forwarding failure preserves household Internet.
Production remains exact-SHA ARM64 image-only, without Docker socket access.

## Published changes and focused validation

| Commit | Change | Observed verification and limits |
|---|---|---|
| [`11ae5cbd`](https://github.com/Eabusham2/router-vpn/commit/11ae5cbdd9ae61c1c3b5f316cc726759df707337) | Native MTU retirement runs with its original namespace authority; inherited mutation flags are cleared. | All 55 physical-routing runner tests pass. |
| [`f86d267b`](https://github.com/Eabusham2/router-vpn/commit/f86d267b363d25fa3cad1866e1135cd1af7253d0) | Darwin alias cleanup recognizes an exact default-derived WASCLONED cache only with the same gateway/interface and independent parent-default observation. | Twelve focused boundary tests pass. The full local runner is 37/38 because the real Unix-socket control is denied by the execution environment; no full pass is claimed. |
| [`045ddb10`](https://github.com/Eabusham2/router-vpn/commit/045ddb1079449803b56c8493a6731e0335cf0354) | Separates cold fixture compilation from the Windows cleanup runtime deadline. | Five focused tests pass. The actual Go deadline, race checks and eight runtime cases remain unchanged. |
| [`fb0e54b5`](https://github.com/Eabusham2/router-vpn/commit/fb0e54b52ae5504954346ced3ee717ccf2b85177) | Uses a public OpenVPN carrier fixture and independent fault owners; immutable graph compilation is shared without sharing runtime owners. | Twenty-four actual compiler combinations and focused OpenVPN/multihop tests pass. No private-network permission is added. |
| [`a46d536b`](https://github.com/Eabusham2/router-vpn/commit/a46d536b5fae4a6fa14f3296518dc3ed290cd896) | Windows OpenVPN fixtures wait for the authenticated response and keep the session alive for its actual proof/measurement lifetime. | Four contract and thirteen runner tests pass; native execution remains its own gate. |
| [`c62ebc3b`](https://github.com/Eabusham2/router-vpn/commit/c62ebc3b442dfb07bcd74e10cd174d6157f668b8) | Aligns paired-only Android Speed Lab fixtures with the new typed imported-entry surface while rejecting imported calls at that fixture boundary. | Actual Java execution: 3,174 checks and nineteen causal controls pass. |
| [`1a8b6008`](https://github.com/Eabusham2/router-vpn/commit/1a8b600830aa2e66bff9ba7f4963a1a35c8e2642) | Separates async imported Apple startup from the paired multihop assembly fixture; the separate imported execution gate remains required. | Actual Swift/Go MAX: 576 graphs, 192 assemblies, 16,615 checks; composite: 513 graphs, 297 assemblies, 16,958 checks. |
| [`83cbdaea`](https://github.com/Eabusham2/router-vpn/commit/83cbdaea64fe885ce56aae63cd04620afeb78a76) | Bounds nested packet capacity by authenticated data/control and outer transport envelopes. | `go test -race -p=1 ./internal/awgpolicy ./internal/mobilemtu` passes, including overflow and configured-versus-measured distinctions. |
| [`b3ad3682`](https://github.com/Eabusham2/router-vpn/commit/b3ad36823ca502a87311efafb4816b40380a5bd4) | Joins retired native AmneziaWG receive workers and rejects late packets from old connections/generations. | Actual encrypted nested-peer and retired-read race cases pass; the observed repeated-close delay is removed without granting stale reads authority. |
| [`ee361d00`](https://github.com/Eabusham2/router-vpn/commit/ee361d008a0a20af27a6ce251eb667c770066f18) | Preserves composed Windows SS entry authority in shared external-policy admission. | Full focused `TestDesktopExternal` race family passes. Shared admission alone is not host integration. |
| [`7c6da688`](https://github.com/Eabusham2/router-vpn/commit/7c6da688c9eaf2bc8275cd100392a825de906dd2) | Retains independent Windows SS entry and final sources through launch, DNS/protection, retirement and complete restoration. | Focused client/shared race tests and the full Windows AMD64 test-binary crosscompile pass. Local public lifecycle reaches a real Netlink permission denial, also reproduced by the old direct case. |
| [`892eeb42`](https://github.com/Eabusham2/router-vpn/commit/892eeb42634752dc1b395106f83c5532fe65ff6f) | Runs nested imported WG/AWG mobile paths, typed configured capacity, Apple selector adoption and exact restored metadata. | 190 shared + 190 actual Java exports: 382 exact pinned-native verdicts. Actual Swift exports: 191. Native encrypted suite: 75 leaves + six parents. Shared imported-entry race tests and Android/Apple startup/selection controls pass. |
| [`48db60e1`](https://github.com/Eabusham2/router-vpn/commit/48db60e134aedb302062734ec15c325cede05165) | Requires the new Windows entry host scope in standalone and authoritative release inventories. | All nineteen release-gate tests pass, including omitted-scope rejection and exact selection of the five new host tests. |
| [`9928a7f0`](https://github.com/Eabusham2/router-vpn/commit/9928a7f047221082502d4a23103ee263f6a49e73) | Preserves original systemd resolver scope and selected-server policy in canonical bounded frames. | Policy race tests pass. Manager ifindices must match independently captured link scopes; selected current servers remain separate from configured server lists. |
| [`1691c303`](https://github.com/Eabusham2/router-vpn/commit/1691c303e718a3cb556fb29c54ba11d6f2f5ea9a) | Adds independent Windows SS entry/final native references and bounded original-provider process/output joining. | Exact WFP-overlay AMD64/ARM64 binaries compile; all 39 runner tests pass; real child-process race cases pass; eighteen actual graph constructions pass; targeted packaging-order test passes. Actual WFP execution is required by CI. |
| [`0bed43a4`](https://github.com/Eabusham2/router-vpn/commit/0bed43a4d919db81acde2db98703e1f6edca8695) | Uses the exact Windows Speed Lab cancellation sentinel and selected final-profile fixture. | The restored-source fixture now reaches the intended path. It does not remove cancellation or replacement-owner protection; the separate Always-to-Off fixture is corrected below. |
| [`199e08ed`](https://github.com/Eabusham2/router-vpn/commit/199e08ed311ad185f477d6a63e1b3e70ccd18bbc) | Retries an exact empty macOS ESRCH image observation within the existing whole-inventory retry budget when independent live identity fences still match. | Sixteen image-ABI cases, fifteen causal controls and thirty-one inventory checks pass. Permission failures and malformed image snapshots remain rejected. |
| [`bd9da517`](https://github.com/Eabusham2/router-vpn/commit/bd9da517281013a6cbb7f4a93a20db2727c775b6) | Owns finite Linux bootstrap DNS grants on the original Netlink socket and namespace. | Atomic set/element/rule creation requires exact echo plus ACK; TTL is bounded by two seconds and half the remaining operation. Unknown receipts are resumed on the original socket, never resent or reopened. Race and native-tag compilation pass; kernel acceptance remains required. |
| [`ebb698ab`](https://github.com/Eabusham2/router-vpn/commit/ebb698ab2e255f326b3781a25656de7a5bfddda8) | Captures the original Linux resolver daemon, bus, process/namespace and physical observer through a sealed fixed helper. | Local-only NO_NETWORK/NO_CACHE/NO_SEARCH preflight and policy-change tainting are bounded by the original owner/deadline. Pure, prepared-command and reachable native cases pass; the full broker fixture reaches local protected-image ownership restrictions. |
| [`a66066d6`](https://github.com/Eabusham2/router-vpn/commit/a66066d6fda049fdf8888f18281a804a10b26fe8) | Makes the Windows paired Always-to-Off fixture execute the real durable recovery barrier. | Sixty-nine related journal/Off cases pass under the race detector. Failed durable commit still retains the original owner for retry; public native execution remains a separate CI gate. |
| [`1c984ade`](https://github.com/Eabusham2/router-vpn/commit/1c984ade3a511b47026b2498d7612e8d87a26d07) | Runs the macOS long socket-capacity fixture separately from the other native socket cases. | Twenty-six runner checks pass. Each required case still runs once with the same binary checksum and unchanged per-process twelve-minute deadline; the observed cumulative watchdog failure is not hidden by dropping cases. |
| [`b16b851a`](https://github.com/Eabusham2/router-vpn/commit/b16b851a284528cd89b4d6a45b513541311eb207) | Preserves the exact Linux idle-parent fixture executable as a protected private-namespace image. | Prepared-command race compilation passes. The actual local namespace case passes the former executable-identity boundary and then reaches the environment Netlink denial; complete native service acceptance is not claimed. |
| [`9bd46e4e`](https://github.com/Eabusham2/router-vpn/commit/9bd46e4e79a051f8dfb8a46d32c1ae175799d2bc) | Adds the Windows Local SS2022-entry to Hysteria2-final path with independent source/proof/DNS/protection ownership and both Start Layers Off. | Shared and client race families, twenty-four graph constructions, thirty-nine runner checks and AMD64/ARM64 native test-binary builds pass. The required native inventory now has fifty-three leaves and two causal mutations. A later physical-entry TCP omission found by cross-platform tests is fixed in b53071d4 below. |
| [`811c1970`](https://github.com/Eabusham2/router-vpn/commit/811c197032b625a3adf6394a7219f065449984f1) | Uses the captured Linux DNS port, UDP/TCP transport, strict TLS identity and link in finite bootstrap exchange. | Focused bootstrap race and runner gates pass. Eight native transport cases and three causal controls require nondefault ports, TLS identity/trust rejection, original deadlines and link ownership; privileged kernel execution remains separate. |
| [`f6a9ef83`](https://github.com/Eabusham2/router-vpn/commit/f6a9ef837a47ffe40f8bda6ce82389108c767f4d) | Selects original systemd-resolved routing scopes, current-server tuples and inherited policy by longest matching suffix. | Eight focused subcases plus their parent pass under the race detector. Equal-best scopes are preserved. A split-only link does not suppress the captured fallback for an unrelated name when no default/global scope is eligible. |
| [`14bc170a`](https://github.com/Eabusham2/router-vpn/commit/14bc170a77b6aaa92d378faaf14efd038e362b00) | Makes Tor publication pause/resume test reads retain native delete-sharing and captured-root ownership. | The retired network/profile/process race test passes, and the deterministic Windows DELETE-handle regression compiles. Actual Windows sharing behavior remains a native gate. |
| [`318212c8`](https://github.com/Eabusham2/router-vpn/commit/318212c83b88722040d8de55d6d9e563ba843ae2) | Adds an independent encrypted SS2022 to Hysteria2 reference provider for the desktop host gates. | Ten actual encrypted leaves cover three ciphers and seven negative cases; the combined SS/CONNECT/Hysteria2 race run passes. The TLS rejection requires a typed local verifier failure, peer packet evidence and absence of decrypted data. This provider prerequisite alone does not admit a macOS/Linux shipping path. |
| [`621b660a`](https://github.com/Eabusham2/router-vpn/commit/621b660a49554153608b6576b86ca4f80afb52e7) | Wires the supported Linux single-scope resolver caller to the original fixed helper and captures the same daemon's active DNSSEC anchors without an upstream lookup. | Isolated standardengine, systembootstrap and client race gates pass; prepared helper-command and actual godbus anchor-codec cases pass. Anchor records require the exact local authenticated trust-anchor flags, and revoked/foreign/cache/AD-only evidence is rejected. Loaded anchors are not full DNSSEC validation. Installed composition and the remaining resolver branches are still open. |
| [`b53071d4`](https://github.com/Eabusham2/router-vpn/commit/b53071d401c637e1f050335e29a00cf65c7f0474) | Preserves the independently required entry HTTPS proof transport in ordinary external physical-egress capture. | The isolated focused race family passes. SS before a Hysteria2 final retains exact entry TCP plus UDP; WG/AWG/Hysteria2 outer entries deduplicate their actual UDP transport. A direct Hysteria2 path gains no extra TCP authority, and neither final-node nor application-DNS addresses become physical exceptions. |

The native mobile results use the pinned production preparation chain, including
actual source/config equality and mandatory constructor/MTU parsing. They do
not substitute a copied miniature engine for the shipping composition. Actual
Swift execution found a missing runtime-selector admission and incorrect numeric
metadata conversion; both were repaired before the published matrix passed.

Windows native SS entry acceptance requires independent entry/final public TLS
proofs, different expected addresses, selected DNS, wrong-key and wrong-identity
rejection, cancellation, successor restoration and durable-commit refusal.
Both SS layers exercise all three ciphers with different credentials. The added
Hysteria2 final retains its independent password, TLS identity and trust bundle. A held
real final DNS TCP conversation makes the live physical-entry WFP grant observable;
already closed proof sockets are not evidence of current ownership. Two deliberate
production mutations must fail with their exact witnesses.

The provider cleanup fix authenticates the original receipt, drains at most
256 KiB of trailing stdout concurrently with joining that same process, and caps
diagnostics at 64 KiB. Both normal join and post-cancellation reaping are bounded.
Actual child-process tests cover a large trailer, overflow, failed exit and stalled
child. These portable tests and all seven native phases are mandatory in the
standalone Windows workflow and authoritative packaging path.

## CI and release state at this checkpoint

The authoritative release for `892eeb42`,
[run 42141215053](https://github.com/Eabusham2/router-vpn/actions/runs/42141215053),
exposed the omitted Windows scope inventory before native execution. Commit
`48db60e1` corrects that exact source failure. The six Windows host fixture
failures in [Custom standard exit contract, run 42141214762](https://github.com/Eabusham2/router-vpn/actions/runs/42141214762)
now have published Speed Lab (`0bed43a4`) and durable Always-to-Off (`a66066d6`)
corrections. The later `ebb698ab` MTU optimizer failure,
[run 42144526196](https://github.com/Eabusham2/router-vpn/actions/runs/42144526196),
was independently read and had the same Always-to-Off fixture cause. A failed
older source is not reported as a failure of its untested correction.

Other observed native failures now have separate source corrections: macOS
cumulative socket-fixture timing (`1c984ade`), Linux idle-parent executable
ownership (`b16b851a`), and Windows Tor publication delete-sharing (`14bc170a`).
Their latest native reruns remain required. None is repaired by dropping a
negative control, relaxing production ownership or inventing a network result.

The exact-`621b660a` Actions read observed 32 workflows: six completed
successfully and the remainder queued, pending or running. The authoritative
release [run 42147992593](https://github.com/Eabusham2/router-vpn/actions/runs/42147992593)
was pending. This is a dated observation, not a full green release; `b53071d4`
is newer. Current native builds, package/image identity, production compose and
final publication require fresh exact-SHA verification. The older `745b3e41`
release cannot close newer source. A separate isolated root-package compilation
at `892eeb42` passed with `go test -p=1 ./... -run '^$'`; that is compilation,
not the full runtime test suite.

## Remaining work and acceptance boundaries

1. Finish and execute the installed Linux resolver/helper/service composition.
   Original-daemon capture, local-only preflight, finite grants and the supported
   single-scope caller are now published. Equal-best parallel scopes, complete
   DNSSEC validation, opportunistic TLS, other unresolved source branches and
   privileged original-kernel/expiry/ACK-recovery acceptance remain open.
2. Finish macOS/Linux SS-entry to Hysteria2-final host admission and its mandatory
   native encrypted, policy, cancellation and restoration acceptance. The shared
   independent provider and corrected physical projection are prerequisites.
3. Resolve current native CI findings against the exact failing source and rerun
   authoritative package/image/compose/publication verification for the resulting
   commit. The older `745b3e41` release cannot close newer source work.
4. Continue the complete protocol/graph/platform ledger, including presently
   unsupported imported families, broader Start Layer compositions and applicable
   Server/Compare execution. Safe refusal is unfinished scope, not delivery.
5. Perform real-device permission, selected-path DNS/leak, reconnect, network
   transition, performance, visual/DPI/orientation/accessibility and off-LAN
   interoperability acceptance for the requested platforms and scenarios.
6. Complete production signing/distribution and real upgrade acceptance, including
   Apple signing/provisioning/notarization and persistent Android production keys.
7. With appropriate live-target authorization and access, verify exact-release
   private deployment, server benchmarking, connected-client/Stop/Emergency Stop/
   Resume/revoke controls, updater rollback, provider integration and ASUS
   forwarding/JFFS household fail-open behavior.

No router, AdGuard configuration, Portainer stack or private deployment was
changed for this source continuation. Missing live access does not close source
requirements, and successful source/build evidence does not close live acceptance.
