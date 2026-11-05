# Router VPN Requirements Reconciliation

This document records the current requirement precedence used by the source and release gates.

1. Later explicit user corrections refine the original requirements; shorter assistant handoffs cannot remove uncancelled scope.
2. Verified current source and exact-SHA evidence determine what is implemented, tested, built and published. They do not redefine what the user requested.
3. Requirements remain binding when they were never explicitly cancelled or replaced.
4. The final repository workflow is direct commits to `main`; old branch/PR instructions are cancelled.
5. The native Router VPN app is the map-first daily product. Setup Center remains private deployment, administration, download, recovery, and update infrastructure.
6. Source presence, shipping composition, native compilation, packaged artifacts, physical runtime, selected-path proof, and production deployment are separate evidence gates.

The reconciled scope includes the original 356 requirements, corrections C1–C7, later product/breakage additions, the unified map-first UI request, external node/hop/exit support where real, session and durable-state transaction corrections, exact-SHA release/update/recovery requirements, and ASUS fail-open household-network safety.

Setup Center package delivery is exact-SHA GitHub Release first, same-SHA Actions artifact second, then only a bounded local desktop/Portable fallback that the server can genuinely build. Android and iOS remain exact-SHA artifact-only. A generated package and its owned temporary build workspace are retained for retry for exactly 30 minutes from READY, without extending the deadline after download, then deleted. Explicit cancel/delete and shutdown clean them immediately.

Unsupported platform capabilities are disabled with a truthful reason; no UI may fake a working dataplane, route, DNS policy, exit proof, forwarding operation, multihop graph, or encryption layer.
Those capabilities remain unfinished requirements. A passing source audit,
successful build or published release does not establish all-device or private
deployment acceptance.

## November 5 mobile imported-entry source increment

The original August 19 Router/custom choice for each hop now has a first mobile
reverse direction: imported SS2022 or Hysteria2 entry → independently paired
Router Shadowsocks final, Local execution. The source preserves distinct public-entry
and private-final proof, independent Start Layers, complete captured policy,
selected DNS, typed measurements/MTU, permission ownership and exact restoration.
See [MOBILE-IMPORTED-ROUTER-PATH.md](MOBILE-IMPORTED-ROUTER-PATH.md) for source paths,
mandatory actual graph/peer gates and the separation of local evidence from
Apple/device/package acceptance.

The Hysteria2 increment retains verified TLS/password capture, all independent
Start Layers, captured-mode permission recreation and exact usage receipts.
Twenty shared and actual Android-produced source graphs pass native constructor,
parser and MTU planning; real QUIC/TLS→SS peer tests reject wrong certificate
identity, credentials and routing. Apple-generated graphs remain a native CI gate.

The remaining graph ledger is unchanged in scope: other imported protocols,
other paired final transports, Server/Compare and complete requested-platform
coverage still need implementation and verification. Local Android/helper and
pinned native graph results do not close the original full profile regression
that hit its unchanged local watchdog, Apple native execution, exact-SHA mobile
packages, physical/off-LAN/visual acceptance, signing or deployment. Those remain
separate gates; this increment does not reduce the original requirement set.

## Implementation reconciliation through 14dc92e3

The verified source cutoff is [14dc92e3](https://github.com/Eabusham2/router-vpn/commit/14dc92e32f788387b5f24b8c0ef505df9e50372a).
The [November 3 evidence](CONTINUATION-EVIDENCE-2026-11-03.md) records fifty-three
published implementation/verification units without converting them into a
requirements completion percentage.

| Recovered scope | Current reconciliation |
|---|---|
| Original minimum of 50 node samples, robust middle statistics and later Fastest placement | Main Router Fastest and explicit all-Router comparison now require 50 complete owned samples and trimmed ranking. Background current-path liveness remains a distinct measurement. Legacy saved-statistics eligibility and explicit via-entry candidate Fastest require separate reconciliation; their scope is not waived by this milestone. |
| #112, #200–213, #337 and native external execution | Windows HY2 AES/AES+XOR now reaches the public retained host and actual encrypted reference tests. Native WFP acceptance remains pending. Linux lower policy and public retained HY2 layer host are now published; installed TUN layer acceptance remains separate work. Mac native sealed-bundle acceptance is now an explicit mandatory CI gate for four On-connect protocols, with actual execution pending. Broader graphs, layers, predecessors and Server/Compare remain required. |
| #141–148, #222–223, #335 and measurements/restoration | Actual generated Linux TUN execution passes both architectures at b4f59bf4. Linux Compare preserves the captured graph startup budget and original generic timeout boundary. Complete GTK interaction/cancellation passes; physical device and off-LAN behavior are separate. |
| Native lifecycle, protection and delivery | APFS owned-directory growth preserves strict file/credential pins. Native ARM reaches a distinct final-frame fixture mismatch now corrected in abbda3e2; the Tor final-response/drain race is repaired in 59831c67 with deterministic and repeated race evidence. Current native workflows and full exact-SHA publication have not converged. |
| Original 356, C1–C7 and later full scope | No uncancelled requirement/default is removed. The release remains 745b3e41; complete original all-device graphs, Methods/recovery, signing, physical/visual/accessibility, providers and authorized ASUS/Portainer acceptance remain accountable. |

## Earlier implementation reconciliation through 9f779cf0

The verified source cutoff is [9f779cf0](https://github.com/Eabusham2/router-vpn/commit/9f779cf05766bf232d7ff13ee4697cd073b41671).
[The November 3 evidence](CONTINUATION-EVIDENCE-2026-11-03.md) records thirty-eight
published implementation/verification units. The full original requirements
and their distinct source/native/device/deployment acceptance remain binding.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and native external execution | The retained macOS direct Local SS/HTTP/HTTPS/Hysteria2 host is published for Start Layer Off and On-connect/Always. Actual inherited-child and sealed-bundle PF/utun acceptance remain open. Windows Hysteria2 AES/AES+XOR sealed policy is published; its host/runtime integration remains source work. Broader families, layers, predecessors and Server/Compare remain required. |
| Selected DNS, Home LAN and captured ownership | Linux retained SOCKS inventory is implemented. Both newer Windows WFP architectures pass the positive SOCKS cases including Home LAN Off. The separate refusal and cached-DNS retirement fixtures now preserve independent terminal/grant evidence and require the next new authenticated association; their latest native rerun is still required. Production DNS retry behavior is unchanged. |
| #141–148, #222–223, #335 and measurements/restoration | Actual generated Linux TUN acceptance passes both architectures again at 66c53d3a after the automatic IPv6 LOCAL repair. Windows packet/OpenVPN WFP acceptance is not inferred from preceding SOCKS successes. Exact fifty-sample measurement, MTU rollback, original Compare formula and captured winner restoration remain unchanged. |
| Native lifecycle, protection and delivery | The macOS child ownership failure remains diagnosed only to a generic pin; precise diagnostics are published. PF/account readback now shares its original deadline. Windows test partitions preserve full inventories and individual bounds. Their native outcomes, current release publication, signing and device/private-target acceptance remain separate obligations. |
| Original 356, C1–C7 and later full scope | No uncancelled scope or default is removed. The latest release remains 745b3e41. Original map-first product, all-device graphs, Methods/recovery, physical/off-LAN/visual/accessibility, provider and authorized ASUS/Portainer requirements are not closed by these milestones. |

## Earlier implementation reconciliation through 32b36a63

The verified source cutoff is [32b36a63](https://github.com/Eabusham2/router-vpn/commit/32b36a63952d92b70b10fb69f701aa8757ae6493).
[The November 3 evidence](CONTINUATION-EVIDENCE-2026-11-03.md) now records
twenty-nine published implementation/verification units. These rows supersede
the earlier pending statements for the same changes; they do not close broader
platform, graph or physical-device requirements.

| Recovered scope | Current reconciliation |
|---|---|
| Selected DNS, Home LAN policy and captured session ownership | The DNS fixture explicitly retires its original retained SOCKS association. Linux's complete retained running-inventory integration is published and passes actual namespace tests; every negotiated relay must join its selected TCP control, expiry and exact native policy. A distinct Windows refusal-observation failure remains under investigation. |
| #141–148, #222–223, #335 and MTU/restoration | The automatic IPv6 LOCAL route race is repaired in `ce53fca5`; actual generated-command/TUN acceptance passed on both Linux architectures. Windows OpenVPN WFP tests now require real selected DNS, fifty samples, Wintun MTU replacement/rollback and original restoration; their native execution remains pending. The original Compare formula and captured winner are unchanged. |
| Native installation and lifecycle | The inherited macOS GUI socket uses XNU readiness semantics while filesystem pins retain their exact permission/owner checks. Race tests and both application/generated package builds pass; the actual failed controller-child case requires rerun. Full retained Darwin host/PF integration remains source work. |
| #112, #200–213, #337 and native external execution | Published Windows OpenVPN acceptance covers all three ordered transport forms and both target architectures at compilation level. Darwin Hysteria2 now has a sealed lower policy with complete graph preservation; public retained host admission remains dependent on unfinished lifecycle integration. Broader retained Start Layers, predecessors and Server/Compare remain required. |
| Original 356, C1–C7 and later full scope | No scope or numerical/default contract is removed. The latest release remains `745b3e41`; current complete publication, original all-device acceptance, Methods/recovery, signing, private providers and authorized ASUS/Portainer deployment are not established by these source and native milestones. |

## Earlier implementation reconciliation through cea693a0

The source cutoff is [cea693a0](https://github.com/Eabusham2/router-vpn/commit/cea693a04faa9915430c3babffd6ebda8cd25199).
[The November 3 evidence](CONTINUATION-EVIDENCE-2026-11-03.md) preserves the
original recovered scope and records twenty-three implementation/verification
units. Later drafts are not included in this cutoff.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and native external execution | Retained Windows direct Local, Start Layer Off and On-connect/Always now includes bounded OpenVPN as well as WG/AWG, SOCKS, SS, HTTP/HTTPS and HY2. Application, exact captured policy and native startup are wired. New Windows WFP protocol fixtures and complete retained Darwin PF-host integration remain separate unfinished work. |
| Selected DNS, LAN policy and owned connection state | The Windows selected-private SOCKS relay exception preserves Home LAN Off without widening shared policy. All authenticated numeric relays retain the original TCP lifetime. Linux now independently proves original TCP state/descriptor, native nft expiry and joined UDP retirement; its complete retained running-inventory path is still being integrated. The Windows DNS fixture must explicitly retire its valid cached association before requiring zero grants. |
| #141–148, #222–223, #335 and measurements/restoration | Actual OpenVPN, WG/AWG and SOCKS encrypted/proof/MTU/fifty-sample cases preserve original profile, selected DNS, ordered remotes and restoration. Native build evidence is not physical-device acceptance. The original Local/Server/Compare formula, same endpoint, invalid-candidate exclusion and captured winner remain unchanged. Linux's newest MTU failure is narrowed to the captured automatic IPv6 LOCAL route; its source correction is not yet published. |
| Native installation and lifecycle | macOS first/legacy capture, same-PID bootstrap, retained application session and authenticated runtime-child foundations are implemented. Intel full-host installer acceptance passed. ARM exposed an invalid re-signed arm64e fixture, now corrected with ordinary architecture compilation. Windows actual child lifecycles and ordinary controls passed at 0cc0f8d9; the later aggregate CI timeout is addressed with four complete mandatory suites, pending native rerun. |
| Real route/protection and native evidence | Both full Darwin PF/socket/utun architectures passed at 99a87e31. Exact-run Windows bootstrap/controller/installed/Portable and Linux generated-TUN successes remain bounded to their source and cases. Source, native compilation, publication, deployment and physical acceptance are never interchangeable. |
| Original 356, C1–C7 and later full scope | All uncancelled platforms/architectures, map-first UI, full modes/graphs, generic installation/private linking, setup/admin/Methods/recovery, DNS/protection, signing and physical/off-LAN/visual/accessibility/private-target requirements remain binding. Current release has not converged; latest verified published prerelease remains 745b3e41. No safe refusal or smaller closure gate closes the full scope. |

## Earlier implementation reconciliation through ec25dc63

The source cutoff is [ec25dc63](https://github.com/Eabusham2/router-vpn/commit/ec25dc63ac517c8edae228ed6b72e61a3cebc40e).
[The November 3 evidence](CONTINUATION-EVIDENCE-2026-11-03.md) distinguishes
published implementation, actual local execution, foreign-target compilation,
native CI and release/device evidence. The original sources were recovered
again for this continuation without replacing their scope or adding overlapping
lists into a completion denominator.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and native external execution | Retained Windows direct Local SOCKS5, WireGuard and AWG fast/strong join SS/HTTP/HTTPS/Hysteria2 for Start Layer Off and On-connect/Always. Public application, eager endpoint, protection and restoration paths are wired. Linux encrypted execution and Windows builds passed; actual new SOCKS/WG/AWG WFP evidence remains required. Home LAN Off still needs the narrow selected-private-SOCKS-relay exception. Broader graphs and complete Darwin captured child/PF transition remain code work; existing generic Darwin execution is not erased. |
| Complete profiles, selected DNS, #141–148, #222–223 and #335 | Actual generated SOCKS/WG/AWG traffic, selected DNS/TLS/exit proof, MTU rollback, exact fifty-sample measurements and stale/cancel/replacement negatives pass on Linux. Public packet-path application race tests reject changed keys, peer, PSK, DNS and AWG parameters while retaining original protection/restoration. Windows compilation is separate from native traffic acceptance. The original Compare formula, same endpoint, invalid-candidate exclusion and captured winner restoration remain unchanged. |
| Native installation and lifecycle | macOS current/incoming image captures, legacy revalidation and same-PID trusted Python bootstrap are implemented. The original native application parent/session now joins dependents before releasing borrowed locks; isolated race tests and both complete target builds pass. Full-host native installation/session acceptance is pending. Windows real child launch still has an unresolved native deadline failure; later pending cancellation is not acceptance. |
| Real route/protection and native evidence | Darwin LOCAL routes remain observed; PF parallel readback keeps the original four-command cap/deadline, and first-loss diagnostics retain the failed phase without changing authority. ARM64 full PF/socket/utun passed at `99a87e31`, with full Intel pending. Both Linux generated-TUN targets passed at `bba34c46`; all six Windows bootstrap/encrypted-Node/startup jobs passed at `67028f29`, and the controller including actual PowerShell 5.1/7 passed at `bba34c46`. These exact-run results do not establish unrelated graphs or physical devices. |
| Setup teaching and defaults | Actual generated Apple guidance and known legacy page repairs now agree with current supported native paths. First connection recommends SMART AUTO. Unsupported combinations remain visible unfinished work; corrected guidance is not runtime acceptance. |
| Original 356, C1–C7 and later full scope | All uncancelled native platforms/architectures, map-first UI, full modes/graphs, generic installation/private linking, setup/admin/Methods/recovery, DNS/protection, signing and physical/off-LAN/visual/accessibility/private-target requirements remain binding. Current release publication has not converged; latest verified published prerelease remains 745b3e41. No percentage or smaller closure gate substitutes for full delivery. |

## Earlier implementation reconciliation through 60d91297

The verified source cutoff is [60d91297](https://github.com/Eabusham2/router-vpn/commit/60d9129777d453bfe8e98238c8b49316090d0c8c).
[The current evidence](CONTINUATION-EVIDENCE-2026-11-02.md) preserves source,
actual local execution, compilation, native CI and publication separately.
Original requirements are already recovered for the recorded collection.
These rows refine their evidence without shrinking scope or inventing a
completion denominator.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and retained native external execution | Windows direct Local Hysteria2 now joins retained SS/HTTP/HTTPS with Start Layer Off and On-connect/Always. Its lazy UDP socket uses the existing captured process/Job/journal and native protection owner. Linux OpenVPN/SOCKS and older families retain their existing evidence. Broader Windows protocols, Start Layers, predecessors, multihop and Server/Compare remain required. |
| Complete profiles, selected DNS and measurements/restoration | Actual local HY2 encrypted DNS/HTTPS, fifty response-time samples, MTU rollback, wrong credential/trust/DNS/exit and cancellation controls pass. The already-proved Local selection and original profile/controller are retained during restoration. All eight final Windows app/component images cross-compile; the real scoped WFP fixture compiles separately. None is relabeled as Windows installed/off-LAN/device networking. |
| Native route and lifecycle integrity | Darwin DUMP2 admits only an original private idle-cache proof bound to all public fields and an exact unique parent. Notifications and JSON cannot borrow it. New Linux TUN CI passed ARM64 but again rejected AMD64 MTU rollback at 37ddfe02; 60d91297 records missing owner/route fields and preserves the refusal. Prior exact-run Linux successes are not erased or generalized. |
| Native installation and delivery | The macOS bootstrap five-module layout and retained directory capture are fixed with actual import/help/negative execution and both target compiles; first/legacy activation remains open. Windows d4096487 Tor WPF passed both PowerShell versions, and 2471342e installed/Portable Session passed on the elevated fixture desktop. Its separate initial PowerShell pipe connection failed and remains under investigation. Current release publication has not converged. |
| Original 356, C1–C7 and all later product requirements | Preserve every uncancelled request, including all devices/architectures, map-first UI, full mode/graph execution, generic installation/private linking, setup/admin/Methods, recovery, selected DNS/protection, signing and real physical/off-LAN/visual/accessibility/private-target acceptance. Latest published release remains 745b3e41. No safe refusal, test count or prior release establishes full completion. |

## Earlier implementation reconciliation through d4096487

The current published evidence cutoff is [d4096487](https://github.com/Eabusham2/router-vpn/commit/d40964870c1277c5b420cfdac70c03bbbc0a47f1).
[The November 2 evidence](CONTINUATION-EVIDENCE-2026-11-02.md) records the
retained Linux OpenVPN/SOCKS units, Windows SS/HTTP/HTTPS integration, native
route and lifecycle repairs, and exact delivery limits. Original-source
recovery is complete for the recorded collection; these rows update evidence,
not the full requirement denominator or acceptance criteria.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and native external execution | Linux retained direct Local execution now includes the recorded OpenVPN and SOCKS additions. Windows SS/HTTP/HTTPS direct Local, Start Layer Off and On-connect/Always now have a coherent retained application/native journal path. Windows preserves the existing generic Off route with independently compiled policy checks. Other protocols, predecessors, multihop, Server/Compare, Start Layers and platforms remain required; older protected generic paths are not erased from history. |
| Complete connection profiles, selected DNS and asynchronous ownership | Windows stages before stopping the old path, authenticates its actual inherited parent/journal before private input, preserves distinct original/physical identities, joins child/Job before BFE settlement and restores the captured host with the proved Local choice. Earlier 403 app-model verdicts remain bounded prior evidence; the added Off cases, current 146 command and 157 physical verdicts, guard mutants and eight cross-builds supply separate current evidence. They do not establish native Windows networking. |
| #141–148, #222–223, #335 and measurements/restoration | The original exact-50 measurements, two-probe average, same external endpoint, failed-candidate exclusion and exact original/winner restoration rules remain unchanged. Linux SOCKS has 400 real routed HTTPS samples across its complete bounded Box gate. Windows source integrates its captured DNS and restoration owner; actual corresponding Windows measurement/traffic acceptance remains required. |
| MTU, protection and lifecycle | The f34 generated-TUN workflow passed six cases on both Linux architectures. A separate earlier cancellation race was reproduced and repaired without an EOF or ownership waiver; all ten actual generated no-TUN control cases then passed. Darwin scope derivation accepts only justified exact-parent flags and still requires native acceptance. Windows parser uniqueness, build-handle retention and strict missing-member rejection remain enforced. |
| Native installer, build and delivery | Windows source validation has its full 1,800-second aggregate while retaining all inner bounds and controls. macOS first/legacy ownership and PF acceptance, new Windows native completion and the original Tor editor deadline remain open. The diagnostic counter regression is fixed with actual PowerShell/Go execution on Linux, separately bounded from native WPF. Exact current packages, server images, compose, checksums and publication have not converged; the latest published application prerelease remains 745b3e41. |
| Original 356, C1–C7 and later full product scope | Every uncancelled requirement retains its original authority and evidence gate, including all requested devices/architectures, map-first UI, full modes/graphs, private generic linking, DNS, setup/admin/Methods, recovery, signing, physical/off-LAN/visual/accessibility checks, live providers, ASUS forwarding/JFFS and deliberate exact-SHA image-only deployment. Disabled capability, compilation and a prior release are not all-product completion. |

## Earlier implementation reconciliation through f2e750aa

The current published implementation cutoff is
[f2e750aa](https://github.com/Eabusham2/router-vpn/commit/f2e750aa458050106a9b7f509e2f08bba5580c8e).
[The evidence record](CONTINUATION-EVIDENCE-2026-11-02.md) preserves the new
WireGuard unit `a276af2c` and source units `6cff6226`, `ed8640dd`,
`ae43c489`, `bd3df93c`, `8e5a8b57`, `09f4dce1` and `f2e750aa`.
These units extend evidence and runtime coverage;
the original 356 requirements, C1–C7, later product/breakage, map-first,
external-node and lifecycle corrections retain their full authority.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and retained Linux ordinary external transitions | Direct Local WireGuard joins SS/HTTP/HTTPS/Hysteria2 for Start Layer Off and On-connect/Always protection. Public Connect/Speed Lab use the same retained host, session, journal, sole process waiter and complete original Router restoration. Captured private/public keys, PSK, AllowedIPs, MTU and keepalive remain exact; selected UDP DNS and HTTPS exit proof traverse one physical UDP peer. Further retained host coverage for other families, predecessors, Server/Compare, external Start Layers, unprotected admission and other platforms remains separately accountable. |
| Native policy ownership, selected DNS and asynchronous lifecycle | The actual WG handshake exposed pre-activation startup ordering. Only the sealed Linux WG lower tuple becomes eligible after the authenticated factory and deny baseline; ordered stages and full activation remain required for proof/TUN/measurement readiness. No keepalive, proof timeout or validation was relaxed. The actual five-family encrypted Box suite passes 76 subtest verdicts, including wrong peer/PSK, DNS/TLS/IP/truncated-response and cancellation/MTU-restoration cases. Its OS/TUN fixtures remain distinct from kernel and installed acceptance. |
| Complete profiles, public Connect persistence and temporary restoration | The installed inventory preserves all 317 earlier cases and adds eight WG cases, for 325. The exact peer compiles; 19 runner checks and the full readiness classification pass, preserving 87 original rejection cases. Public Connect persistence, source observation, On-connect/Always journal ownership, cancellation/replacement and exact original Router restoration remain actual installed assertions. Missing local TUN leaves those new scenarios unexecuted. |
| #141–148, #222–223, #335 and real measurements | All five admitted Box families now complete the actual exact-50 routed HTTPS benchmark against owned local responders, with selected DNS and source/session negatives. `ae43c489` retains safe fixed failure stages without raw private errors and does not change the scoring formula, sample count, metric label or no-score behavior. The latest Windows native50 logs report a combined duration/owner failure from after response validation; their older traffic counters describe the initial path proof, not individual benchmark samples. `8e5a8b57` supplies a genuine Windows QPC clock with exact integer deltas and separate duration/owner failure reasons; full shared race tests and both Windows checkptr compilations pass. A zero elapsed interval was not directly logged, and successful native Windows execution remains unproved. |
| Native MTU and delivery evidence | `bd3df93c` repairs deterministic exact-owner shutdown during heartbeat receipt readback; wrong Stop/source and malformed active evidence remain rejected. The latest exact bd3df93c generated-TUN CI passes six cases on both architectures, while the earlier intermittent active-receipt cause remains undetermined. `ed8640dd` adds diagnostics without replacing a failed verdict. The 74bd942a Linux native aggregate timed out at 900 seconds after baseline suites and before any compiled control verdict; that is distinct from failed native assertions or a green release. Published `09f4dce1` gives the complete Linux source gate 1,800 seconds, preserving serial execution, all 19 baseline suites and 48 compiled controls, every individual deadline and every required verdict. Windows keeps its 1,200-second source-gate bound. The two-test regression passes in 86.182 seconds across six targets and injected failure/timeout propagation; a new complete native gate result remains required. `f2e750aa` similarly raises only the two Windows diagnostic job aggregates to 30 minutes; all inner limits and required cases remain. Thirteen workflow contract checks pass, while actual completed jobs remain required. |
| All original and later requirements | Full installed acceptance, broader graphs/platforms/recovery, macOS image ownership, exact-SHA packages/images/compose/publication, signing, real upgrades, private targets, ASUS forwarding/JFFS, deliberate deployment and physical/off-LAN/visual/accessibility checks retain their own gates. Source, actual local traffic, kernel tests, compilation, runtime bundles, publication and live deployment are separate states. No percentage, reduced denominator or full-product completion is claimed. |


## Earlier implementation reconciliation through 55d9f285

The current published implementation cutoff is
[55d9f285](https://github.com/Eabusham2/router-vpn/commit/55d9f285ff6bae4c9f2d50ba4960ecd7c35020d4).
[The evidence record](CONTINUATION-EVIDENCE-2026-11-02.md) records this unit, Hysteria2 in `74bd942a`, and
`1720180d`, `90ffcbd2`, `296461bd` and `c7b03676`. These changes extend the existing
reconciled scope; they do not replace original sources, change defaults or
create a smaller completion denominator.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and retained Linux ordinary external transitions | Direct Local Hysteria2 now joins the published SS/HTTP/HTTPS retained app/session/journal path for Start Layer Off and On-connect/Always protection. Password/TLS identity, the sole physical UDP destination, selected UDP DNS, HTTPS exit proof, captured MTU and original Router restoration remain bound to the same owner. Other external families, predecessors, multihop/Server/Compare, ordinary external Start Layers, unprotected admission and other platform integrations keep their own unfinished requirements. |
| Complete connection state, selected policy and asynchronous ownership | Public Connect persistence and temporary Speed Lab restoration share the captured external owner. The installed inventory preserves all previous 310 cases and adds seven Hysteria2 cases, for 317. Wrong key/trust, DNS failure and cancellation must never report Connected or overwrite the original/replacement owner. The local absence of a genuine TUN leaves the new installed cases unexecuted. |
| Real graph execution and proof integrity | Actual encrypted peers exposed two pinned Hysteria2 EOF/close-contract defects. The repaired transport preserves literal EOF and only the same stream's typed remote code-zero close; all other reset/authentication/cancellation failures stay errors. Normal public-proof validation, truncated-body rejection and joined cleanup remain intact. Final Box and normal/low-memory transport race tests pass; the six-case real kernel lifecycle evidence uses unchanged lifecycle source from before these transport repairs. |
| Native build and fixture integrity | Shared launch-guard checks, Tor IPC observation time, exact routing-image staging and IPv6 veth readiness are repaired without changing production proof/routing acceptance. Five non-host transport targets compile; the local production-tag Linux AMD64 runtime bundle verifies against the 74bd942a feature source. The 55d9f285 network-cohort fixture additionally preserves exact-image/private-directory/namespace/deadline ownership and passes all eight actual network-event cases plus ten runner checks. The latest generated TUN CI alternates the MTU-rollback receipt failure between architectures at 296461bd and c7b03676; its cause remains under investigation. Compilation, runtime bundle verification, installed execution and application release publication stay separate. |
| All original and later requirements | Original 356-item scope, C1–C7, later product/breakage, map-first, external-node and lifecycle corrections remain binding. Broader graph/platform/recovery gaps, full 317-case installed acceptance, macOS ownership, current exact-SHA packages/images/compose/publication, signing, deployment and physical/off-LAN checks remain separately accountable. No complete current release or all-device acceptance is claimed. |

## Earlier implementation reconciliation through 34f65cb8

Original user passages, the complete addendum and later corrections were
recovered again from the available private source documents. Personal-context
retrieval was unavailable during this attempt; that does not remove an older
requirement or establish complete conversation access. The current source
cutoff is [34f65cb8](https://github.com/Eabusham2/router-vpn/commit/34f65cb827bd20e8681bfc2e003d77d883a5848e);
[the evidence record](CONTINUATION-EVIDENCE-2026-11-02.md) identifies all eleven
published units and their exact tests.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and retained Linux external transitions | Direct Local SS/HTTP/HTTPS now use the public app/session/journal bridge, preserving separate external and Router proof authorities, selected policy, original process ownership and captured restoration. The installed inventory contains 310 cases, preserving 299 originals and adding eleven. Local controller/native-command checks and a complete bundle pass; missing local TUN prevented all eleven new installed cases from running. Other families, multihop/Server/Compare, Always/torn/legacy recovery and physical acceptance remain open. |
| Selected DNS, complete connection state and asynchronous ownership | The new external DNS observer validates captured credentials/options and final application state. Stop/measurement/restore retain the same native session. Android fixture repairs exercise the actual production capture and statistics types; the public-SDK snapshot rejects incomplete copies. Existing benchmark sample counts, score formula, resolver defaults and winner-restoration rules are unchanged. |
| Native build and test integrity | Windows exact source closure and UTF-8 output, Linux namespace launch, Darwin watcher admission and complete bounded PF readback are repaired with executable negative controls. The Linux verdict runner now fits its original budget without deleting any of 1,482 missing-line checks. Local fixes are not blanket native package acceptance. |
| All remaining original and later requirements | The six existing generated Linux TUN cases passed both architectures at 11d4c86c, before the new public external bridge. Current exact-SHA release publication, macOS installer inventory, broader retained graphs, signing, deployment and physical/off-LAN acceptance retain their distinct unfinished status. No percentage or reduced requirement denominator is introduced. |

## Earlier implementation reconciliation through bbd684f8

Original requirement recovery remains complete for the recorded source
collection. The latest published source cutoff is
[`bbd684f8`](https://github.com/Eabusham2/router-vpn/commit/bbd684f860a4956e9f9d27d5c7c5d2faeeefb4c6);
[the continuation evidence](CONTINUATION-EVIDENCE-2026-11-02.md)
records the exact changes, tests and native CI. These updates refine evidence,
not the original requirement denominator or acceptance criteria.

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and retained Linux transitions | The generated protected-TUN gate now passes all six cases on both architectures at `9b53dbcf`; the earlier MTU routing-receipt failure is closed. `c318a79d` adds the distinct typed external native lifecycle, with real SS/HTTP/HTTPS namespace succession and retained-protection checks. The public app/session/journal transition remains unfinished. All 299 installed scenarios, broader graphs, Always/torn/legacy recovery and physical acceptance still need their own evidence. |
| #141–148, #222–223, #335, measurements and durable state | Existing captured fifty-sample external comparisons remain published. `cc72da36` repairs cancellation during the durable Router benchmark's save lock; `7b2eabab` preserves a private target replaced during final save admission. Exact original/winner restoration and successful rename semantics remain intact. `0248dfb0` handles validated atomic status replacement within the original owner/deadline; `00063c98` repairs only canonical fixture roots. Quick Router samples, durable TCP metrics, routed HTTPS metrics and the two-probe score remain separate. |
| Native observer and Windows launch evidence | Linux read-only observation and both generated TUN architectures pass at `9b53dbcf`. `bbd684f8` repairs the later namespace fixture launch without changing host policy or weakening native assertions. Actual Windows `49df6051` passes mandatory protected-global creation/cancellation and genuine Limited/normal runas Full lifetime checks. The exploratory GLOBALROOT no-child observation gives no launch authority. Full MAX, package composition, interactive/cross-account use and physical devices remain separate. |
| All original and later requirements | Preserve every uncancelled requirement and its existing source/native/live evidence. Current release publication, signing, private deployment and full physical acceptance are not established. Native prerequisites, truthful refusal and green individual jobs are not universal product completion. Stopped unpublished PQ work remains preserved and excluded. |

The actual `49df6051` installed/Portable Session gate additionally passes on
the elevated fixture desktop; normal Medium-user and interactive/cross-account
product acceptance remain distinct. The `bbd684f8` durable-state gate has a new
Darwin watcher retirement/startup errno-11 failure. Its cause is not yet proved,
and the gate remains required.

## Earlier implementation reconciliation through f103637f

The following table preserves its historical checkpoint. Current conclusions
above supersede the old unresolved-failure wording without erasing its evidence.

The original sources below have already been recovered. Continue their actual
implementation and acceptance work without replacing their scope or repeating
recovery. Published source through
[`f103637f`](https://github.com/Eabusham2/router-vpn/commit/f103637f63235872ba2c144dd87135d6a1832615)
and exact local/native boundaries are recorded in
[the current continuation evidence](CONTINUATION-EVIDENCE-2026-11-02.md).

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and later Start Layers | Retained Linux SS, Hysteria2, WG, AWG2 Fast/Strong and SS-V2Ray support Off/AES/AES+XOR. Preserve eleven AWG parameters, separate original/relay/outer sources, final-protocol DNS/proof and concrete composite cover ownership. Actual encrypted peer and rejection controls pass. Saved Off, settled-empty and complete same-boot On-connect release-intent recovery remain published. The installed gate now requires 299 scenarios; invalid older fixture MTU inputs were repaired without changing validators. The newer generated six-case gate fails MTU rollback's current receipt on both architectures at ce557096. Broader graphs, retained Node → external succession, Always/torn/legacy recovery and physical acceptance remain open. |
| #141–148, #222–223, #335 and August 10/19 node requests | Mobile and all three desktop apps now expose captured external comparison with fifty routed HTTPS measurements, metric-specific history, exact original restoration and fresh proof of the already-measured execution winner. Desktop native network observers and owned route/TUN receipts are published; focused race/action/namespace tests pass, with real MTU rollback failure retained separately. Quick live Router Fastest is distinct from the required durable 50–200 TCP benchmark and never writes its fields; the earlier blanket sample-count gap conflated the two. Quick samples do not satisfy durable benchmarking. Exact native packages, physical paths and unsupported retained transitions remain separate requirements. |
| #19–21, #26–30, #33–35, #265–269, selected DNS and Methods | Complete Hysteria CA/profile delivery now joins unchanged-client Shadowsocks, OverTLS TCP, SSR/Mihomo and manual SOCKS evidence. Preserve exact trust/auth/policy and real download bytes. Stock OverTLS UDP, finalized ARM64, C1 simple AWG and original off-LAN/device requirements remain. |
| Tor native composition and fixture integrity | 60de6b39 fixes test receipt timestamp ordering without changing production validation. Actual mobile Server Tor 28 subcases and desktop eight groups/21 subcases pass under race. Desktop Tor selected-path fifty-sample measurement and joined cancellation are now published. The updated ownership audit passes 42 regressions and the full local orchestration gate. Exact-SHA packaged, public-network and device acceptance remain separate. |
| Mobile UI and restoration gates | The comparison actions, terminal Apple native capture and moved Android dialogs retain their published source/compiled negative controls. b38a53be repairs the actual Swift 6.1.2 Sendable error; the old failure is reproduced and the repaired 433-check composition passes. Newer Swift passes 353 comparison checks and six compiled controls. Xcode/IPA and APK results remain separate. |
| Native macOS and Windows | Windows bootstrap's earlier two-architecture evidence remains historical. New real-account CI starts the genuine Limited primary and normal runas Full workers, then exposes a fixture's incorrect primary requirement for a linked identity observation. f103637f uses the retained authenticated parent's actual primary token, exact object/incarnation and private lifetime for the access test; all original cases remain and real retained-parent lifecycle is mandatory. Six policy groups/88 subcases, seven compiled defects and both pointer-check builds pass. The actual f103637f job then passed the genuine Limited/Full lifecycle and all original native cases, preserving the real denied elevated-thread access result. It later failed the separate GLOBALROOT file-not-found/zero-callback probe. Full MAX/Portable/5.1, interactive consent, cross-account product use and current release acceptance remain unproved. macOS first/legacy inventory and Intel managed CodeDirectory still fail; ARM64 managed inventory passed its bounded negatives. Signing and actual devices remain open. |
| All other original and later requirements | Retain their existing source/native/live evidence. No percentage, reduced denominator, full-release claim or physical deployment follows from these units. The stopped unpublished PQ fixture work remains preserved and excluded. |

## Original-source recovery refreshed November 1, 2026

The continuation recovered all 356 unique historical audit identifiers and
read the complete addendum containing 312–356 and C1–C7. These are an
assistant's historical organization of requirements, not 356 verbatim user
messages, and their old Done/Partial/Missing labels are not current verdicts.
Original user passages were also retrieved; the shorter handoffs were not used
as their replacement. The source dates below are those recorded in the copied
documents, without inventing a missing message date or timezone.

| Source | Original material recovered |
|---|---|
| `mm.md` | Audit identifiers 1–311 and the August 11 native application/product request. |
| `router_vpn_chat_audit_addendum_v2` (retrieved duplicate filename) | Complete August 11 addendum, identifiers 312–356 and C1–C7, including multiline platform details. |
| `Continue Storage Diagnostics.md` | August 10 original onboarding, Setup Center controls, multiple nodes, DNS and at-least-50-sample measurement request. |
| `Router VPN Handoff Audit.md` | August 12 original native/all-device, breakage, methods and separate generic installation/node-linking request. The distinct shorter `(1)` document was not assumed newer because of its suffix. |
| `Router VPN Progress Update.md` | August 19 original map-first layout, settings, measured paths, complete Add/Load/Update/Delete profiles and external-node request. |
| `Pasted text(20261019-065229)` | Original Local/Server/Compare request and surrounding same-endpoint/reproof rules. The copied passage does not retain an original message date beside it. |

Project/personal context was actively queried as a continuity index and the
original files were retrieved separately. This does not claim access to every
historical conversation. Current source and exact-SHA native/release evidence
are recorded separately in [the November 1 continuation](CONTINUATION-EVIDENCE-2026-11-01.md).
Private transcripts and account/file identifiers are not reproduced here.

### Corrections retained during implementation

| Reference | Surviving contract |
|---|---|
| C1 / #17 | The simple AWG method still needs real off-LAN third-party interoperability evidence. |
| C2 / #91 | Onboarding continues until completion, stores progress/completion and offers a permanent rerun. Setup Center and the native app teach their own tasks. |
| C3 / #63 | Multiple administrator accounts are optional; authentication and authorization for sensitive changes remain required. |
| C4 / #169 | A blank AdGuard Allowed Clients list is unrestricted. Never create a restrictive list just to add VPN subnets; an existing restrictive list must be read before changing it. |
| C5 / #101; C7 | Generic installed/Portable applications remain separate from private node bundles/pairing and support multiple nodes without reinstalling. |
| C6 | Production is exact-SHA, image-only deployment without the Docker socket. A bounded desktop-package fallback does not authorize building the production stack on the AI Board. |
| #324–325 | Portable relocation and clean exit must join owned processes and release their files. |
| #337 | Manual Disconnect and failure/reconnect protection have distinct ownership and release semantics. |
| #340–342 | MAX may not downgrade silently; ALL uses validated candidates; cover/padding remains bounded, private and non-amplifying. |
| Later comparison correction | Compare uses `(last_node_response_time + external_server_response_time) / 2`, one shared randomly selected external endpoint, each candidate's actual route and repeat proof. Invalid or stale candidates receive no score. |
| Later Start Layer correction | Off / AES-256-GCM / AES-256-GCM + XOR whitening; whitening supplements authenticated encryption. Capture entry and exit independently. |
| Later download correction | Keep the completed package and its owned workspace for 30 minutes from READY; repeat downloads do not extend it, and Cancel/Delete/shutdown clean immediately. |

The checked configuration still preserves SMART AUTO, IPv6 On, Home AdGuard,
Auto MTU and AUTO encryption/obfuscation requirements Off. No earlier default
was restored merely because it appeared in an old transcript. Older qualified
Unix/BSD requests and all required desktop/mobile architectures remain in the
scope even where their acceptance differs from the core native products.
