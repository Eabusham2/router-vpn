# Router VPN continuation evidence — November 6, 2026 UTC

## Scope and source identity

This is an implementation and evidence ledger, not a replacement for the user's
original requirements. The live starting branch was
[`b04eccee94f4cf3e83f978cbb74504e796c056a6`](https://github.com/Eabusham2/router-vpn/commit/b04eccee94f4cf3e83f978cbb74504e796c056a6),
1,294 commits ahead of the older published `745b3e41` release. Old patches were
not replayed over that history. The fifteen published units below retain normal
`main` ancestry through
[`1691c303e718a3cb556fb29c54ba11d6f2f5ea9a`](https://github.com/Eabusham2/router-vpn/commit/1691c303e718a3cb556fb29c54ba11d6f2f5ea9a).
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
| Original #200–224/#337, exact captured ownership and full temporary-test restoration | Windows retained desktop host, `desktop_external_owned_sources.go`, independent entry/final captures | Shared/client race tests, two architecture test-binary builds, 39 mandatory native leaves and two causal mutations | Hosted WFP runtime and physical acceptance; CI exposed six new fixture failures described below |
| Selected DNS/Home AdGuard, LAN/IPv6 and original resolver authority | `internal/standardengine/resolved_*`; subsequent native Linux capture/bootstrap work remains outside this cutoff | Canonical bounded policy frames, ordered scope/server preservation and negative/race tests | A frame does not authorize upstream traffic; original-daemon capture and expiring grants still require integration and privileged acceptance |
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
| [`83cbdaea`](https://github.com/Eabusham2/router-vpn/commit/83cbdaea64fe885ce56aae63cd04620afeb78a76) | Bounds nested packet capacity by authenticated data/control and outer transport envelopes. | `go test -race -p1 ./internal/awgpolicy ./internal/mobilemtu` passes, including overflow and configured-versus-measured distinctions. |
| [`b3ad3682`](https://github.com/Eabusham2/router-vpn/commit/b3ad36823ca502a87311efafb4816b40380a5bd4) | Joins retired native AmneziaWG receive workers and rejects late packets from old connections/generations. | Actual encrypted nested-peer and retired-read race cases pass; the observed repeated-close delay is removed without granting stale reads authority. |
| [`ee361d00`](https://github.com/Eabusham2/router-vpn/commit/ee361d008a0a20af27a6ce251eb667c770066f18) | Preserves composed Windows SS entry authority in shared external-policy admission. | Full focused `TestDesktopExternal` race family passes. Shared admission alone is not host integration. |
| [`7c6da688`](https://github.com/Eabusham2/router-vpn/commit/7c6da688c9eaf2bc8275cd100392a825de906dd2) | Retains independent Windows SS entry and final sources through launch, DNS/protection, retirement and complete restoration. | Focused client/shared race tests and the full Windows AMD64 test-binary crosscompile pass. Local public lifecycle reaches a real Netlink permission denial, also reproduced by the old direct case. |
| [`892eeb42`](https://github.com/Eabusham2/router-vpn/commit/892eeb42634752dc1b395106f83c5532fe65ff6f) | Runs nested imported WG/AWG mobile paths, typed configured capacity, Apple selector adoption and exact restored metadata. | 190 shared + 190 actual Java exports: 382 exact pinned-native verdicts. Actual Swift exports: 191. Native encrypted suite: 75 leaves + six parents. Shared imported-entry race tests and Android/Apple startup/selection controls pass. |
| [`48db60e1`](https://github.com/Eabusham2/router-vpn/commit/48db60e134aedb302062734ec15c325cede05165) | Requires the new Windows entry host scope in standalone and authoritative release inventories. | All nineteen release-gate tests pass, including omitted-scope rejection and exact selection of the five new host tests. |
| [`9928a7f0`](https://github.com/Eabusham2/router-vpn/commit/9928a7f047221082502d4a23103ee263f6a49e73) | Preserves original systemd resolver scope and selected-server policy in canonical bounded frames. | Policy race tests pass. Manager ifindices must match independently captured link scopes; selected current servers remain separate from configured server lists. |
| [`1691c303`](https://github.com/Eabusham2/router-vpn/commit/1691c303e718a3cb556fb29c54ba11d6f2f5ea9a) | Adds independent Windows SS entry/final native references and bounded original-provider process/output joining. | Exact WFP-overlay AMD64/ARM64 binaries compile; all 39 runner tests pass; real child-process race cases pass; eighteen actual graph constructions pass; targeted packaging-order test passes. Actual WFP execution is required by CI. |

The native mobile results use the pinned production preparation chain, including
actual source/config equality and mandatory constructor/MTU parsing. They do
not substitute a copied miniature engine for the shipping composition. Actual
Swift execution found a missing runtime-selector admission and incorrect numeric
metadata conversion; both were repaired before the published matrix passed.

Windows native SS entry acceptance requires independent entry/final public TLS
proofs, different expected addresses, selected DNS, wrong-key and wrong-identity
rejection, cancellation, successor restoration and durable-commit refusal.
Both SS layers exercise all three ciphers with different credentials. A held
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
`48db60e1` corrects that exact source failure; a local nineteen-test pass does
not assert that the subsequent full release passed.

The same source's
[Custom standard exit contract, run 42141214762](https://github.com/Eabusham2/router-vpn/actions/runs/42141214762),
job `127641698708`, exposed six newly added Windows host fixture failures in
Speed Lab restoration and Always-to-Off observation. At this document's source
cutoff their correction is being reviewed. Existing ownership assertions are
not removed to make those cases green.

The `9928a7f0` Actions observation showed completed source gates alongside queued,
pending and running native workflows. That observation is not a full green
release, and a later push can supersede it. Current native builds, package/image
identity and final publication require fresh exact-SHA verification. A separate
isolated root-package compilation at `892eeb42` passed with
`go test -p1 ./... -run '^$'`; that is compilation, not the full runtime test suite.

## Remaining work and acceptance boundaries

1. Finish the original-daemon Linux resolver capture/preflight and the owned,
   finite-lifetime kernel bootstrap grants. Pure policy/wire models do not prove
   the original namespace, daemon, kernel mutation, ACK recovery or expiry.
2. Resolve current native CI findings against the exact failing source and rerun
   authoritative package/image/compose/publication verification for the resulting
   commit. The older `745b3e41` release cannot close newer source work.
3. Continue the complete protocol/graph/platform ledger, including presently
   unsupported imported families, broader Start Layer compositions and applicable
   Server/Compare execution. Safe refusal is unfinished scope, not delivery.
4. Perform real-device permission, selected-path DNS/leak, reconnect, network
   transition, performance, visual/DPI/orientation/accessibility and off-LAN
   interoperability acceptance for the requested platforms and scenarios.
5. Complete production signing/distribution and real upgrade acceptance, including
   Apple signing/provisioning/notarization and persistent Android production keys.
6. With appropriate live-target authorization and access, verify exact-release
   private deployment, server benchmarking, connected-client/Stop/Emergency Stop/
   Resume/revoke controls, updater rollback, provider integration and ASUS
   forwarding/JFFS household fail-open behavior.

No router, AdGuard configuration, Portainer stack or private deployment was
changed for this source continuation. Missing live access does not close source
requirements, and successful source/build evidence does not close live acceptance.
