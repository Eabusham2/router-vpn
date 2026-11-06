# Router VPN product continuation evidence — November 6, 2026 UTC

## Scope and source cutoff

This ledger supplements [the earlier November 6 ledger](CONTINUATION-EVIDENCE-2026-11-06.md)
and [REQUIREMENTS-RECONCILED.md](REQUIREMENTS-RECONCILED.md). It does not replace
the original requirements or cancel an unfinished requirement. The recorded
published product work below ends at
[`3ac3542d3f492deaec271b11d14e736ac90cdc32`](https://github.com/Eabusham2/router-vpn/commit/3ac3542d3f492deaec271b11d14e736ac90cdc32).
This is a source/evidence cutoff, not a claim that the branch stops moving or
that this revision has completed its release gates.
Concurrent [`9ce0c64c`](https://github.com/Eabusham2/router-vpn/commit/9ce0c64c52619755aa87e9616c42bd17e059794e)
subsequently updates three Linux resolver compatibility files and is preserved
with separately attributed contributor evidence; it is not one of these 21 units.

The initial live reconciliation found
[`8f05dbe658fb6589e606e9995b613a3136a3d70e`](https://github.com/Eabusham2/router-vpn/commit/8f05dbe658fb6589e606e9995b613a3136a3d70e),
already **1,352 commits ahead and zero behind** the pasted historical release
`745b3e41e5a78d734391976af9b7cd0637660a0b`. The
[GitHub comparison](https://github.com/Eabusham2/router-vpn/compare/745b3e41e5a78d734391976af9b7cd0637660a0b...8f05dbe658fb6589e606e9995b613a3136a3d70e)
identifies that older release as the merge base. Historical fixes were not
replayed over this newer source. An active separate workspace contained newer
uncommitted work; this continuation used isolated checkouts and preserved those
files. Published commits were reconciled with the live branch before further work.

## Original authority recovered for this continuation

The complete binding scope remains the original user requirements indexed by
the historical **356-item audit**, **C1–C7**, the later **32-item product/breakage
request**, the later map-first prompt, external node/hop/exit requirements, and
all subsequent accepted corrections. These overlapping sources are not summed
into a completion denominator. The numbered audit is an organized historical
index, not 356 verbatim user messages. Prior evidence ledgers remain intact.

The following passages were recovered and reviewed during this continuation.
Line locators refer to the recovered source copies, not repository source lines.

| Original source | Recovered passage and authority |
|---|---|
| `mm.md`, from line 7753 | Original product request and surrounding context: native daily apps, Setup Center separation, whole-connection profiles, measurements, protection, modes, DNS and deployment. |
| `mm.md`, lines 8068–8422 | Historical numbered audit; retain the full original requirement index rather than using a shortened handoff. |
| `router_vpn_chat_audit_addendum_v2 (1)(7).txt`, complete 174-line recovered copy | Corrections/addendum read in full alongside the numbered audit and later product requirements. |
| `New chat (1)(1).md`, lines 7505–7634 | User authority for imported/custom nodes, independently configured hops/finals and actual graph execution. |
| `Router VPN Progress Update (1)`, August 19 user passage, lines 3814–3818 | Map-first native product and Router/custom role selection; preserve this later UI authority. |
| October 19 transcript, line 332 and its comparison context | Candidate comparison retains the required routed-response formula and same external endpoint. |
| Current handoff and later corrections | Direct coherent publication to `main`; independent Start Layers; truthful capability/readiness; exact-SHA downloads and production; separate native/device/private acceptance. |

This recovery does not assert that every private conversation or unavailable
attachment was read. The repository contracts remain implementation evidence,
not substitutes for original user authority. See also
[REQUIREMENTS-RECONCILIATION.md](REQUIREMENTS-RECONCILIATION.md).

Preserved product contracts include native Windows/macOS/Linux/Android/iPhone/
iPad apps; the custom VPN map, desktop dock/touch sheet and ordered controls;
separate Fastest selection and Connect; whole-connection profiles with private
credential references; SMART AUTO, IPv6 On, MTU Auto and Home AdGuard defaults;
AUTO encryption/obfuscation requirements Off; fifty node samples; and independent
entry/final Off, AES-256-GCM, or AES-256-GCM + XOR-whitening choices. Plaintext
proxy/bridge transport must not be presented as an authenticated encrypted VPN.

The comparison remains
`(last_node_response_time + external_server_response_time) / 2`, measured through
each candidate with the same external endpoint. Invalid candidates have no
score; adoption requires a fresh proof and restoration of the captured prior
execution. Live RTT, node statistics, current-path Mbps, hop Mbps and MTU
optimizer throughput remain distinct. No RTT-to-Mbps conversion is accepted.

Setup Center stays private and separate from the daily app. Generic packages
contain no private node secrets. READY output and its owned workspace remain
retryable for thirty minutes without extending the deadline; Cancel/Delete and
shutdown retire them immediately, retaining visible cleanup failures. The
bounded router-local package fallback is limited to the supported requested
Windows/Portable package; mobile packages require matching exact-SHA GitHub
delivery. Production remains exact-SHA ARM64, image-only and without Docker
socket access. ASUS forwarding failure withdraws only Router VPN exposure while
preserving ordinary household Internet and unrelated rules/hooks.

## Published product and fixture units

The validation below belongs to the named source unit and its stated boundary.
Counts are executable checks, not counts of completed user requirements.

| Published commit | Change and requirement connection | Observed verification | Remaining boundary |
|---|---|---|---|
| [`ae8ecead`](https://github.com/Eabusham2/router-vpn/commit/ae8eceada5c5c411e2ef6af4f26c81c5b8097f8b) | Apple imported-entry selection fixture now reflects the already-shipped SOCKS5 support. It executes SOCKS→SS/HY2/WG/AWG selection/capture and keeps unsupported HTTP CONNECT rejection, exact credentials, final layers and transactional failure checks. | Full Swift 6.4.2/Go 1.26.3 fixture passes 2,080 checks. Four targeted picker mutations reject removed SOCKS, SS2022 restriction, WG choice and invalid-saved-choice handling. | This repairs stale CI expectations; it is not new universal graph support or physical iOS acceptance. |
| [`0f194d9f`](https://github.com/Eabusham2/router-vpn/commit/0f194d9fa9ed2db91b874a9b3f576e1b14ac655d) | Setup Center guidance remains usable when browser storage cannot be read or written. Storage failure no longer prevents the guide from operating. | Six guide storage tests, three related checks and the entrypoint check pass. | Live browser/private Setup Center acceptance remains separate. |
| [`6d2d3ec6`](https://github.com/Eabusham2/router-vpn/commit/6d2d3ec6a3e40aba44219d4b92ae3db6a16fee3c) | Daily Android hop measurements use the owned cancellable operation and retained dialog. Entry/final identity, cancellation and result adoption stay bound to the original request. | 109 ownership checks and five negative controls; external checks 360, dialogs 346, permission/settings checks 4,623. | Physical VpnService routing, permission transitions and real through-hop measurements require device evidence. |
| [`8091ff7a`](https://github.com/Eabusham2/router-vpn/commit/8091ff7ac4a3ec4318e60f8869676ae85ab6f0fa) | Admin bans and server Stop guards replace nftables policy atomically, avoiding an intermediate absence of the intended guard. | Focused atomic-policy transaction tests and their race run pass. | These source/transaction checks do not establish private production nftables/forwarding acceptance. |
| [`cb455004`](https://github.com/Eabusham2/router-vpn/commit/cb455004ba38afa6f5bc53c8c1c80c92db8bd9b3) | Windows native fixture execution uses the retained original Windows Job owner before accepting a mutant failure or deleting its workspace. Failed status/output survive only after joined descendants and closed original handles. | Runner: 25 portable tests pass, one Windows-native test skipped locally. Shared owner: 15 portable tests pass, four Windows-native tests skipped locally. The new real Windows case requires child/grandchild completion, immediate locked-file unlink and survival of an unrelated same-image process. | All five locally skipped native tests remain unproved here; the existing AMD64/ARM64 CI gate must execute them. No deadline widening, deletion retry or process-name cleanup was added. |
| [`4b8c007a`](https://github.com/Eabusham2/router-vpn/commit/4b8c007a14efa8f3dacd43409c6168c0ae554d24) | Standalone desktop throughput now owns measurement admission and the captured MTU suspension for the real request lifetime. Cancellation and release must preserve the original owner. | Focused real-HTTP request/cancellation tests and race checks pass. | This does not prove every platform's Performance UI, physical path throughput or MTU optimization. |
| [`4d0e76de`](https://github.com/Eabusham2/router-vpn/commit/4d0e76defb97950d1b12225ec21a84bc3377e192) | The multihop replacement cleanup fixture uses a real tracker with explicitly scheduled observation. Requested and observed history are checked separately; the complete replacement state/session snapshot must survive old cleanup. The legitimate 100 ms tracker observer no longer races a synthetic history expectation. | The actual tracker observation race test passes in 1.032 seconds. The full handler now fails promptly at local HTTP 409 when physical network capture is unavailable, before reaching the cleanup proof. | Native CI must execute the actual Stop/replacement path. Local observation evidence does not establish that blocked handler path, and no source mutation of cleanup was counted as executed. Production capture and stale-cleanup code are unchanged. |
| [`a09d5482`](https://github.com/Eabusham2/router-vpn/commit/a09d548202d8feb875c7bb8375ce17d4f573a48b) | macOS Performance owns a cancellable request across live RTT, selected-node statistics, current-path throughput and active-graph hop throughput. Cancel/close retain ownership until the client request retires, reject stale callbacks and preserve the distinct backend cleanup boundary. Hop identity is read from the active graph. | The new real Swift HTTP/cancellation harness and three causal mutation controls pass. The four-file unit was cleanly rebased over concurrent `8c00e8e4` and the published tree verified. | Native AppKit/SDK, real tunnel measurements and physical UI acceptance remain separate. Client request cancellation is not a claim that backend transfer/MTU cleanup has already completed. |
| [`e0b769ff`](https://github.com/Eabusham2/router-vpn/commit/e0b769ff0367593a9d89365db7b8a30d2a571aec) | The independent SS Start Layer fixture compares persisted ports using the JSON numeric representation. Strict source equality and all layer/ownership assertions remain; the failure was `int` versus decoded `float64`, not demonstrated source corruption. | Nine JSON round-trip cases and actual SS independent-layer source race checks pass in 7.363 seconds. The old helper with the regression rejects the eight non-Off pairs. The published unit preserves concurrent resolver compatibility `50553102`. | The full public AlwaysOff lifecycle needs physical inventory unavailable locally; native CI must execute it. No production timeout, cancellation or persisted-source check was weakened. |
| [`8fdc2ef7`](https://github.com/Eabusham2/router-vpn/commit/8fdc2ef7118c00567a45b63619091c7ebff6b876) | Apple saved profiles capture per-hop safe settings and entry identity/proof while current private credentials/assets remain references. Load validates the staged entry/exit graph, makes one durable store commit and adopts the model once; preparation/source/graph/write failures preserve old store and selection. Older schemas without capture remain explicitly reference-only until Update captures them. | Actual shipping callback/model/store/graph/native validation passes 20,852 checks; ordinary external profile checks pass 1,285 with app/storage doubles; actual store transaction checks pass 105 with a durable-write boundary double. A second independent Swift run confirms all three. Shared-record handling and rotated current entry tokens are covered. | The Linux harness uses the existing OpenSSL-backed SHA256 helper. It does not execute actual Keychain, PacketTunnel or physical Apple device acceptance. |
| [`d19f25dc`](https://github.com/Eabusham2/router-vpn/commit/d19f25dc00779e7e5dc2d7e924cc32b3034d8a57) | Complete Android profiles capture independent Router entry/final padding rates. Explicit zero or 32–192 is retained; saved null captures absence; an omitted legacy field preserves the current rate. Current linked credentials and protocol assets remain references. | Independently repeated actual store harness passes 291 checks across 35 cases, with causal controls rejecting omitted capture and deletion of a legacy uncaptured value. | Runtime-source null remains rejected. This saved-profile unit alone does not change native readiness; the subsequent `7e6b7a16` row resolves enabled zero/default admission. Physical padding/throughput remains unproved. |
| [`5b32bcf5`](https://github.com/Eabusham2/router-vpn/commit/5b32bcf581eaff30fb8bc5b530cce1c723ba6ab0) | Apple Home DNS carries the exact owned private address/family, transport, port, TLS name and HTTP path through the app and PacketTunnel. Both use one shared validator. Captured Home profiles use schema 7; legacy snapshots retain their prior migration. | Independent Swift resolver/capability/graph harness passes 200 checks and rejects the original UDP/53-substitution mutant; shared native all-family compiler check passes. Existing Swift graph checks pass 2,311. Editor checks pass 676 with three controls; profile checks pass 20,905 and external profile checks 1,285. | Network-framework, storage and application boundaries in portable harnesses are stated doubles. Actual Keychain, installed PacketTunnel, physical selected-DNS proof and device behavior remain separate. |
| [`bd5d869f`](https://github.com/Eabusham2/router-vpn/commit/bd5d869ff7493e6d418add8fc988c34b307cb788) | The persisted-layer regression explicitly constructs validated Go integer ports inside that test. The shared JSON-compatible fixture remains unchanged; original integer/persisted float mismatch and changed-credential rejection remain asserted. | Original current-source failure reproduced in sixteen cases in 0.393 seconds. The repaired focused race run covers eighteen SS/Hysteria persisted variants, nine canonical round-trips and actual independent SS source checks, passing in 10.130 seconds. Read-only peer review approves the fifteen-line test-only change. | The observed failed CI run below remains history; this local fixture repair does not establish a new native/release pass. |
| [`7e6b7a16`](https://github.com/Eabusham2/router-vpn/commit/7e6b7a1644f9319578e1b46efbabab60615488ac) | Enabled Router padding profiles resolve the saved zero/default sentinel to 192 kbps at shared compiler admission; Android MAX readiness accepts the same saved default. Explicit rates and independent entry/final ownership remain unchanged. | Original enabled-zero compiler failure reproduced. Full shared performance race checks pass in 5.167 seconds; independent focused race run passes in 1.343 seconds. Actual Java/Go MAX harness passes 2,315 checks, including 72 existing graphs, twenty default/explicit-rate preparation cases and invalid-input controls. | Compiled runtime `CoverOptions` still rejects zero; generic number parsing and existing JSON-null behavior are unchanged. Physical padding, rate accounting and native/device acceptance remain separate. |
| [`a5000cc3`](https://github.com/Eabusham2/router-vpn/commit/a5000cc3636eea8b2a6e77bafd3477ca2ec84e6e) | The Apple Start Layer source contract now names shipping saved-profile schema 7 instead of stale schema 5. All layer and exact extension-source assertions remain. | Original focused failure independently reproduced in 0.011 seconds; three focused Apple contracts pass in 0.012 seconds after the one-literal correction. | This repairs a source contract, not native or physical Apple acceptance. |
| [`3341e6c2`](https://github.com/Eabusham2/router-vpn/commit/3341e6c28434aacef08ddcbb8dfb1ab8aacc7333) | The captured-directory Tor fixture waits for its exact Close request and completed publication before cancelling. A real publication-lock schedule retains the original claim when a 100 ms Close expires before request issue, rejects replacement and retries the same request identity/generation. The pinned-directory and replacement-sentinel checks remain. | Four focused lifecycle race tests pass in 4.019 and 4.026 seconds. A temporary replacement-path cleanup mutation makes the real test fail in 1.222 seconds with a directory-ownership/publication diagnostic. The mutation driver expected a different failure string and failed its extra diagnostic assertion; the underlying ownership negative did reject the mutation. Production was restored before the final passing run. | Production cleanup, deadline and cancellation code are unchanged. This is private IPC fixture evidence, not physical Tor traffic acceptance. |
| [`06615f64`](https://github.com/Eabusham2/router-vpn/commit/06615f64672cc8165357b42ea7f275c071edeee0) | Native SIP003 fixture Home cases now use the captured node-owned IPv4/IPv6 addresses. Other DNS modes retain public/hostname inputs; four public/foreign Home cases must fail in the Home-policy error domain. The default valid Home input prevents unrelated DNS rejection from masking protocol negatives. | Actual Swift SIP003 selection/DNS/credential checks pass 191 in a serial run. Independent review verifies the exact private addresses against the original fixture and inclusion of the shipping Home helper. Prior unchanged 90-second compiler timeouts occurred under concurrent compilation and remain unsuccessful attempts. | Production DNS validation is unchanged. Native Apple SDK, PacketTunnel and physical path acceptance remain separate. |

| [`1969d8c3`](https://github.com/Eabusham2/router-vpn/commit/1969d8c309ee67b69c0df50f6ce991e04e4dc556) | Windows Advanced Performance now retains one panel and its exact request owner through Cancel, title-bar close and Alt-F4. Closed or stale callbacks cannot adopt results; old panels cannot cancel another global operation. Hop tests capture connected active-graph identities before measurement instead of mutable selection drafts. | The actual complete UI transformation and existing async owner pass 32 callback checks with transport/WPF doubles and four causal mutations. Existing help composition passes 19 checks, routed candidates 197 and async ownership fourteen groups. Source/package readback confirms the new fixture ships in installed and Portable packages. | Local execution used PowerShell 7.6.9. Native Windows PowerShell 5.1 and WPF are required by the added CI/package gates. Backend graph validation remains separate; the status/read-to-request sequence is not claimed atomic. Physical throughput and UI acceptance remain unproved. |
| [`f4d222cb`](https://github.com/Eabusham2/router-vpn/commit/f4d222cb7bf8c730b36986e67e8e834af63fbb4c) | Android Home DNS preserves the selected current-node private IPv4/IPv6 address, all five transports, exact port, TLS name and HTTP path through Save/quick actions, native preparation and captured-profile restoration. A DNS sheet cannot adopt settings after its node/profile identity changes. | The original IPv6 HTTPS/5443 to IPv4 UDP/53 substitution is reproduced and rejected by two causal controls. Home checks pass 517; real-store checks pass 374 across eleven cases plus a node-validation control; existing graph checks pass 3,598. Both actual Android producers pass 15,121 checks and five controls; all 205 current captured inputs, source hashes and compiled graphs remain byte-identical using the same generated certificate inputs, without normalization. | Portable Java/Go execution does not establish actual VpnService, device selected-DNS proof or physical routing. This unit's exact 205-graph comparison does not establish the separate pending 235-graph feature. |
| [`775ac68e`](https://github.com/Eabusham2/router-vpn/commit/775ac68e333c3c74021b702733e1381233bcc3e7) | Checksum-owned pinned sing preparation initializes a UDP NAT connection before publishing it and retires a cache entry only when its pointer still matches the original owner. All three retirement sites use the cache's locked conditional deletion, preserving a replacement flow. | The full preparation suite passes 24 tests in 11.133 seconds. Exact constructor-publication and Ex/legacy post-cleanup witnesses reject three independent causal mutations without scheduling sleeps. The actual formerly racy wrapped-AWG relay-route case passes eight repetitions under race in 7.024 seconds. Independent source review verifies all six pinned initializer callbacks perform only context/writer construction. | This is the bounded fix for the race found by the mandatory SOCKS gate; the entire updated native gate still must pass. Whole-group source validation precedes sequential writes and interrupted partial states fail closed; the upgrade is not a filesystem-atomic multi-file transaction. Physical OS routing remains separate. |

| [`3ac3542d`](https://github.com/Eabusham2/router-vpn/commit/3ac3542d3f492deaec271b11d14e736ac90cdc32) | Android session audit now requires both captured node and profile identities, the shipping guard call and its updated warning. It replaces the stale profile-only warning expectation exposed by the Home DNS fix. | The original audit failure is reproduced; focused and full recovered native UI gates pass with the required Swift toolchain on PATH. The first full attempt lacked local `swiftc` and required no additional source correction. | This is a source-audit repair. It does not establish device UI behavior, VpnService DNS proof or a successful exact-SHA native release. |

## Unpublished integration — excluded from the source cutoff

The following row deliberately has no commit SHA. It is not part of the twenty-one
published units above and must not be treated as a shipped capability extension.

| Commit SHA | Pending unit | Evidence available so far | Required before publication |
|---|---|---|---|
| | Broader Local SOCKS entry/final independent Start Layers across SS, Hysteria2, WG and AWG Fast/Strong, with original authenticated TCP control owning its dynamic encrypted UDP relay. | Individual author runs pass all 45 native success combinations under race in 3.970 seconds and paired/packet negative inventories in 15.342/69.9 seconds. Independent lease scenarios pass under race in 1.124 seconds. The Apple 235-capture host run passes at its checked source digest. | The subsequent mandatory full native gate found a real pinned sing UDP NAT publication/replacement-owner race in the wrapped-AWG relay-route negative. Published `775ac68e` repairs that bounded cause, but the reconciled final 235-graph producers, exact source projection and complete updated native gate must pass before feature publication. No full-gate pass or physical OS acceptance is inferred from earlier individual runs. |

The Android Home DNS substitution previously listed here is now repaired in
published `f4d222cb`, with its exact scope and device boundary in the table above.
The broader SOCKS feature deliberately remains without a published commit SHA.

## Newer source supersedes specific earlier open descriptions

The earlier November 6 checkpoint through `7f801312` is retained as history.
The following updates supersede only its identified source-gap descriptions;
they do not erase remaining platform/graph/native acceptance requirements.

| Earlier description | Newer published source | Qualified current conclusion |
|---|---|---|
| Mobile imported SOCKS5 entry to paired Router finals unfinished | [`98d6af64`](https://github.com/Eabusham2/router-vpn/commit/98d6af646bf255e5b4906a49150b3752d7c232fd), [`95ffbb72`](https://github.com/Eabusham2/router-vpn/commit/95ffbb729460bea9826c076c93f8b1880b6eab4a) | Local SOCKS5→paired SS/HY2/WG/AWG source support is published. This does not establish every imported protocol/final, Server/Compare direction or physical mobile path. |
| Retained desktop SS-entry composition requires both Start Layers Off | [`8f05dbe6`](https://github.com/Eabusham2/router-vpn/commit/8f05dbe658fb6589e606e9995b613a3136a3d70e) | Independent SS entry/final Start Layers are published for the implemented desktop SS graph. Do not generalize this to every external protocol pair or platform. |
| Desktop SS/Hysteria independent Start Layers continued after the initial SS graph | [`8c00e8e4`](https://github.com/Eabusham2/router-vpn/commit/8c00e8e40829413fd7b40c5bed28e1cba1abc369) | This concurrent contributor unit was preserved when publishing `a09d5482`. Its own SS/Hysteria graph evidence must be evaluated separately; the macOS measurement tests do not certify it. |
| DNSSEC library ABI only, shipping authenticated integration/chain authority unfinished | [`c626af1f`](https://github.com/Eabusham2/router-vpn/commit/c626af1f2c29c59e1b496242de0896254bd7285e), [`90a7d70f`](https://github.com/Eabusham2/router-vpn/commit/90a7d70feb99cd12365a12f867349357db700061), [`693cc705`](https://github.com/Eabusham2/router-vpn/commit/693cc70526115f759c58fdbfdd2b521dc63a2446) | Newer source validates captured resolved answers through sealed DNSSEC children, proves original aliases and binds alias-proof queries to a separate protected resolver owner. Privileged installed/kernel composition, policy transitions and native delivery still require their own evidence. |

Concurrent [`50553102`](https://github.com/Eabusham2/router-vpn/commit/505531025a7852606c506ccf0ab7956912994b77)
retained-resolver-daemon compatibility was also preserved by a disjoint rebase
before publishing `e0b769ff`. This ledger records reconciliation, not independent
validation of that contributor unit.

## Current CI and publication evidence

After publication, the root publisher verified live `main` at `775ac68e` and
reported 26 queued/pending exact-SHA runs at approximately 05:54 UTC. Its
[authoritative release run 42171142958](https://github.com/Eabusham2/router-vpn/actions/runs/42171142958)
was pending. The release list still ended at the historical `745b3e41` prerelease
with twelve assets. That publisher read is separate from the independent snapshot
below; neither establishes a successful release for the new cutoff.

At **2026-11-06 05:54:03 UTC**, live `main` was `f4d222cb`. Its exact-SHA
query returned 28 attempt-1 runs: five successful, twelve queued, six pending and
five running. [Authoritative release 42170715529](https://github.com/Eabusham2/router-vpn/actions/runs/42170715529)
and [Windows native contract 42170715374](https://github.com/Eabusham2/router-vpn/actions/runs/42170715374)
were pending; [iOS compile smoke 42170715746](https://github.com/Eabusham2/router-vpn/actions/runs/42170715746)
was queued. This snapshot predates the published NAT repair `775ac68e` and does
not certify that later cutoff or establish package publication.

Two additional current-source investigations are retained. Historical Windows
[runtime run 42163791196](https://github.com/Eabusham2/router-vpn/actions/runs/42163791196),
job 127716080187, and [run 42166127106](https://github.com/Eabusham2/router-vpn/actions/runs/42166127106),
job 127724093769, report a UDP4 source receiving TCP `WSAPROTOCOL_INFO`: size
628/628 and family 2/2 match, but socket type is 1/2 and protocol 6/17. These are
reported failure evidence under investigation, not claimed fixed by the Windows
Performance UI unit. Current `f4d222cb` [UI run 42170715279](https://github.com/Eabusham2/router-vpn/actions/runs/42170715279)
also exposes a stale Android audit expecting the previous profile-only warning.
The publisher reproduced it and published `3ac3542d`, requiring the new
node-plus-profile guard, its shipping call and the matching warning. Focused and
full recovered native UI gates pass after adding the required local Swift PATH.
The first full attempt lacked local `swiftc`; it required no further source change
and remains an unsuccessful environment attempt.

The latest independently read native failure adds a distinct unresolved boundary:
[`a5000cc3` macOS physical socket run 42167793365](https://github.com/Eabusham2/router-vpn/actions/runs/42167793365),
Intel job 127728213683, fails `TestDesktopDarwinGuardianKernelSocketRetirementReusesCapacity`
at sequential owned socket 47. The original roughly two-second PF grant bound
expired in phase 3 after 725,571 microseconds of pre-work and 1,377,962 microseconds
of post-readback work. Diagnostics report ten readback checks and an unreadable or
earlier nonempty dispatch owner. The ARM ownership job and both native anchor-lifetime
jobs passed at that SHA. This is not dismissed as transient or claimed repaired;
its cause and current-source/native outcome require separate reconciliation.
The earlier [run 42162081948 at `693cc705`](https://github.com/Eabusham2/router-vpn/actions/runs/42162081948)
passed all four native jobs; its Intel log records this same reuse test passing
in 162.52 seconds and rejects the broken descriptor-retirement control. The
relevant module, runner, preparation, PF-mode and workflow sources are unchanged
from that revision through `775ac68e`. No newer standalone workflow follows the
failed run in the queried history; the earlier pass does not erase the failure.
The joined deadline diagnostic does not establish an actual foreign-rule change.
On **2026-11-06 05:58:19 UTC**, after one targeted rerun request for the failed
Intel job, GitHub reports run attempt 2 queued at the same `a5000cc3` SHA. The
new Intel job is 127740178604. This retry supplies no completed verdict yet and
will remain original-revision evidence, not current-SHA release acceptance.

Two newer completed custom-exit failures remain the already corrected schema
assertion: [`7e2a55fa` run 42167522113](https://github.com/Eabusham2/router-vpn/actions/runs/42167522113)
passes desktop `cmd/client` in 543.014 seconds, and
[`7e6b7a16` run 42167094820](https://github.com/Eabusham2/router-vpn/actions/runs/42167094820)
passes it in 505.003 seconds. Both fail only the old schema-5 source assertion in
`internal/common`, corrected by `a5000cc3`. Neither certifies the later cutoff.

At **2026-11-06 05:29:24 UTC**, the live branch had advanced to concurrent
`f8cd97905eee39dbcb9a7e31e5209bb3513e7d12`. The exact `06615f64` query returned
21 attempt-1 runs: fifteen cancelled, three queued and three running. Both
[authoritative release 42168566752](https://github.com/Eabusham2/router-vpn/actions/runs/42168566752)
and [iOS compile smoke 42168566455](https://github.com/Eabusham2/router-vpn/actions/runs/42168566455)
were cancelled. No successful native release or package publication at this
cutoff is established by that snapshot.

At that earlier read, the following completed failures repeated known causes:

- [`7e6b7a16` interoperability run 42167094726](https://github.com/Eabusham2/router-vpn/actions/runs/42167094726): Linux and macOS authenticated encrypted-traffic jobs passed; Apple host job 127725983969 failed the same SIP003 Home fixture corrected by `06615f64`.
- [`5397f23e` custom-exit run 42166757747](https://github.com/Eabusham2/router-vpn/actions/runs/42166757747): desktop `cmd/client` passed in 512.000 seconds; `internal/common` failed only the stale schema-5 assertion corrected by `a5000cc3`.
- [`bd5d869f` custom-exit run 42166349236](https://github.com/Eabusham2/router-vpn/actions/runs/42166349236): desktop `cmd/client` passed in 506.747 seconds; the same stale schema assertion failed. These whole-package results provide evidence for that source, including the earlier numeric-fixture repair; they do not certify a later SHA.

The local full `internal/common` gate also passed in 184.824 seconds with the
required JDK and Swift toolchains available. Its initial attempt lacked the JDK;
that environment failure required no source change and is not counted as a pass.

At **2026-11-06 05:14:17 UTC**, exact published `7e6b7a16` had 31 Actions
runs: seventeen queued, eleven pending and three running, with none completed.
[Authoritative release run 42167094891](https://github.com/Eabusham2/router-vpn/actions/runs/42167094891)
was pending. This snapshot establishes neither native success nor publication.

The completed [`d19f25dc` custom-exit run 42165623703](https://github.com/Eabusham2/router-vpn/actions/runs/42165623703)
had successful Windows and Android jobs, but desktop job 127721309970 failed.
Besides the subsequently repaired typed-port regression, it exposed two fixture
failures now corrected in named units above. The Apple Start Layer contract still
required schema 5; `a5000cc3` aligns it with shipping schema 7. The Tor cleanup
fixture expected a Close file after a 100 ms deadline that also covered pending
cancellation publication. `3341e6c2` adds a causal real-lock schedule demonstrating
that this interval can correctly end before request issue, then observes exact
publication before cancelling the captured-directory test. No runtime ownership
corruption is inferred from that historical failure.

The [`5b32bcf5` native interoperability run 42165908149](https://github.com/Eabusham2/router-vpn/actions/runs/42165908149)
failed Apple host job 127722214959 in the SIP003 Home fixture: public/hostname
inputs no longer satisfy the shipping private-node Home policy. `06615f64` repairs
those inputs and adds explicit foreign-Home rejection. These repairs close only
the identified fixture causes; no newer exact-SHA workflow or release pass is
inferred. No completed `06615f64` release result has been established here.

At **2026-11-06 05:02:18 UTC**, exact published `5b32bcf5` had 29 Actions runs,
all attempt 1: three successful, thirteen queued, ten pending and three running.
The successes were Repository state audit, Keep only main branch and Setup
Center release status. [Authoritative release run 42165908286](https://github.com/Eabusham2/router-vpn/actions/runs/42165908286)
was pending; [iOS compile smoke 42165908216](https://github.com/Eabusham2/router-vpn/actions/runs/42165908216)
was queued. No failed run existed at this exact SHA in that snapshot. The
release-list read still showed the historical `745b3e41` release below.

A newly completed post-fix failure must remain visible: [`e0b769ff` MTU optimizer
run 42164586401](https://github.com/Eabusham2/router-vpn/actions/runs/42164586401),
Unix job 127717958193, fails the added
`TestDesktopWindowsExternalSSEntryPersistedLayerSources` assertion at line 509.
Its sixteen non-Off SS/Hysteria cases expect the old fixture's integer port,
while the corrected shared fixture now deliberately uses JSON-compatible
`float64`. The failure was then reproduced and repaired in `bd5d869f` by explicitly
constructing the old integer form inside that regression. Strict source comparison
and changed-credential negatives remain intact. This was not evidence of
production persistence corruption. The
Windows job and earlier Unix MTU checks passed, but the workflow failed.

Concurrent authenticated-DNS compatibility unit `f8cd9790` and documentation
unit `01174631` were preserved before `1969d8c3`; their evidence remains
separately attributed. The earlier ledger file was not rewritten by this update.
Concurrent documentation unit `4e905017` was preserved before `d19f25dc`;
its graph/resolver evidence remains separately attributed. Concurrent
[`5ea5f09b`](https://github.com/Eabusham2/router-vpn/commit/5ea5f09bd0aa6bc18d571cdcae821992ed2a5e4d)
DNS alias-policy work was preserved by the disjoint rebase before `bd5d869f`;
this ledger does not claim independent runtime validation of that contributor unit.
Concurrent [`5397f23e`](https://github.com/Eabusham2/router-vpn/commit/5397f23e101762672bcee057b55d9c585206ca13)
Linux observed-server downgrade work was likewise preserved before `7e6b7a16`;
its contributor evidence is separate. Concurrent
[`7e2a55fa`](https://github.com/Eabusham2/router-vpn/commit/7e2a55fa0b55620210d4e575ef6a89f187fd0f86)
Linux root-DS decision work was preserved before `a5000cc3`. Concurrent
[`ad4da5e7`](https://github.com/Eabusham2/router-vpn/commit/ad4da5e75ec73ce9bea2bf9fe3ead5f7cd771750)
adds four provisioned SS/Hysteria final-layer captures behind an Off-layer SOCKS
entry and was preserved before `3341e6c2`; its contributor evidence is separate
from the broader unpublished 45-combination unit. Concurrent
[`dbb0a4ca`](https://github.com/Eabusham2/router-vpn/commit/dbb0a4ca2bde5ad4a7951a01f5b849f558d32229)
adds six provisioned WG/AWG packet-final layer cases. Together with `ad4da5e7`'s
four SS/Hysteria proxy-final cases, these form the published 205-capture baseline
used by the exact-input Android comparison; their contributor evidence remains
separate from the unpublished 235-capture extension. The earlier CI snapshots cannot
certify `06615f64`. Earlier `e0b769ff`
and `8fdc2ef7` authoritative release and iOS compile runs were cancelled as the
branch advanced; they cannot establish current native acceptance.


At **2026-11-06 04:49:13 UTC**, the live `main` read returned the exact cutoff
`8fdc2ef7118c00567a45b63619091c7ebff6b876`. Its Actions query returned 23 runs,
all attempt 1: twenty queued and three pending, none completed. The authoritative
[Build all Router VPN release gates run 42164668925](https://github.com/Eabusham2/router-vpn/actions/runs/42164668925)
was pending. [iOS native compile smoke 42164668537](https://github.com/Eabusham2/router-vpn/actions/runs/42164668537)
and [Native MTU integration 42164668804](https://github.com/Eabusham2/router-vpn/actions/runs/42164668804)
were queued. This is a bounded query snapshot, not a final workflow inventory,
all-green CI or packaged publication. The release list still showed the older
`745b3e41` prerelease below; no newer listed release certified this cutoff.

Earlier observations are preserved with their exact revisions:

At **2026-11-06 04:37:56 UTC**, the exact-SHA Actions query for `4b8c007a` returned
27 runs, all attempt 1: three successful, sixteen queued, six pending and two
in progress. The successful workflows at that read were Weighted release audit,
Recovered native UI exact-head gate, and Kill switch contract. The authoritative
[Build all Router VPN release gates run 42163418241](https://github.com/Eabusham2/router-vpn/actions/runs/42163418241)
was pending. This timestamped snapshot is neither all-green CI nor publication.

A later independent read at **2026-11-06 04:45:35 UTC** found concurrent
`8c00e8e4` with 37 exact-SHA runs, all attempt 1: three successful, nineteen
queued, eleven pending and four in progress, with no completed failure. This
precedes publication of `a09d5482`; it is not CI evidence for that newer commit.

At the earlier release audit, the most recent published release remained
[`router-vpn-sha-745b3e41e5a78d734391976af9b7cd0637660a0b`](https://github.com/Eabusham2/router-vpn/releases/tag/router-vpn-sha-745b3e41e5a78d734391976af9b7cd0637660a0b),
published October 24 at 03:29:25 UTC. It is a prerelease with twelve assets:
ten native packages, a release manifest and checksums. Its packages and older
image evidence cannot certify the current source. `/releases/latest` is not an
exact-SHA selector and the absence of a stable latest release does not erase
that older prerelease.

The closest diagnosed failures remain revision-specific:

- The `c626af1f` iOS compile-smoke job failed the stale imported-entry picker
  expectation; `ae8ecead` repairs that fixture and passes its local Swift gate.
- `8f05dbe6` Custom standard exit and MTU failures, followed by
  [the `6d2d3ec6` Custom standard exit run 42162916083](https://github.com/Eabusham2/router-vpn/actions/runs/42162916083)
  and [the `90a7d70f` run 42161828160](https://github.com/Eabusham2/router-vpn/actions/runs/42161828160),
  fail `TestDesktopWindowsExternalSSEntryAlwaysOffRetriesOriginalOwner` for
  the eight non-Off layer pairs at the persisted-source assertion. The original
  strict assertion has been reproduced: fixture Go `int` ports differ from JSON
  round-tripped `float64` ports. The fixture-only correction is published in
  `e0b769ff`, with the nine-case regression, causal old-helper failure and focused
  source race evidence recorded above. Its full public lifecycle remains for
  native CI. This evidence does not identify a production source-persistence defect.
- The earlier multihop replacement-history failure is addressed by `4d0e76de`
  with the precise observation/physical-capture boundaries in the table above.
- The Windows ARM fixture cleanup failure at `0dc57026` motivated `cb455004`.
  Its required native rerun is separate from the portable tests above.
- The older Windows legacy drain timeout is not treated as an outstanding
  current failure: the later [controller run 42158630649](https://github.com/Eabusham2/router-vpn/actions/runs/42158630649)
  passed, including the same cold legacy wrapper in 1.67 seconds under its
  unchanged eight-second bound. No prewarming or timeout extension was applied.

## Remaining implementation and acceptance

The complete original scope remains open. Apple captured per-hop profile
restoration, the persisted Start Layer fixture correction and macOS Performance
cancellation are now published with the bounded evidence in their rows. Other
original native UI, settings, Methods, recovery and graph requirements retain
their individual closure obligations; these twenty-one units are not a replacement scope.

The concrete Apple Home DNS substitution gap reported at `8fdc2ef7` is repaired
in `5b32bcf5` with the bounded evidence above. Intentional UDP/53 for Fastest node
measurement remains a different path. Android Home DNS now has its own published
repair in `f4d222cb`. Narrower provisioned SS/Hysteria final-layer SOCKS captures
are published in concurrent `ad4da5e7`; the broader 45-combination independent
entry/final layer feature remains unpublished pending the updated complete gate.
Its observed UDP NAT race has a published bounded repair in `775ac68e`, which
does not by itself close that feature or its native acceptance. The newly failed persistence regression fixture above is now repaired in source;
its new exact-SHA CI evidence remains pending.

In particular, support for one entry/final graph does not prove every requested
protocol pairing, independent layer combination, local/server execution or
platform. Supported source must still be connected to the actual daily app,
owned lifecycle, complete restoration, native engine and relevant negative
controls. Unavailable capability with an honest reason is safer behavior, not
completion of the corresponding requested capability.

Remaining evidence is tracked separately:

| Boundary | Still required |
|---|---|
| One current source generation | All required workflow attempts at the selected exact SHA, authoritative native package matrix, nine matching ARM64 images, source/security/preflight checks, exact compose, archive parity, provenance/checksums and publication. A different SHA's pass is not interchangeable. |
| Matching-host native integration | Windows WFP/Wintun/installed/Portable ownership; macOS PF/utun/installer and actual Swift/SDK boundaries; Linux installed/kernel/TUN/resolver composition; Android/iOS native build and VPN host integration for each claimed path. |
| Physical device and network behavior | Install/permission, DNS/IPv4/IPv6, route/leak negatives, reconnect/network change, sleep/wake/on-demand as applicable, complete temporary-test restoration, actual hop throughput and MTU behavior, off-LAN interoperability. |
| Native visual and accessibility acceptance | Map-first UI, DPI, responsive/orientation behavior, touch/desktop controls, real permission-based location and accessibility on requested targets. |
| Private server/provider validation | Live benchmark, forwarding, Stop/Emergency Stop/Resume, updater rollback, configured AI Help providers and server-side credential/context boundaries. |
| Distribution | Legitimate Apple signing/provisioning, macOS notarization where required, and actual installation/launch/distribution evidence. An unsigned resignable IPA is not this proof. |
| Production and household safety | One deliberate exact-SHA Portainer deployment, live health/path checks, ASUS exact-port/JFFS revalidation preserving household connectivity, then final regression. |

Use [LIVE-RELEASE-EVIDENCE.md](LIVE-RELEASE-EVIDENCE.md) and
`deploy/live-release-evidence.py` for SHA-bound hashed live evidence. No live
gate is marked complete by this document, and no completion percentage is used.
