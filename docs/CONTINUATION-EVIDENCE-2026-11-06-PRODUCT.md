# Router VPN product continuation evidence — November 6, 2026 UTC

## Scope and source cutoff

This ledger supplements [the earlier November 6 ledger](CONTINUATION-EVIDENCE-2026-11-06.md)
and [REQUIREMENTS-RECONCILED.md](REQUIREMENTS-RECONCILED.md). It does not replace
the original requirements or cancel an unfinished requirement. The recorded
published product work below ends at
[`cf4ea4b389ead8124b3db3f7002723b2ff6a466b`](https://github.com/Eabusham2/router-vpn/commit/cf4ea4b389ead8124b3db3f7002723b2ff6a466b).
This is a source/evidence cutoff, not a claim that the branch stops moving or
that this revision has completed its release gates.
Concurrent [`9ce0c64c`](https://github.com/Eabusham2/router-vpn/commit/9ce0c64c52619755aa87e9616c42bd17e059794e)
subsequently updates three Linux resolver compatibility files and is preserved
with separately attributed contributor evidence; it is not one of these 49 units.
The publisher also preserved concurrent
[`c6a33ff1`](https://github.com/Eabusham2/router-vpn/commit/c6a33ff145168ed1aadf2008b66191611fcedd7d),
eleven Linux private-domain DNSSEC files, with separate contributor evidence.
This ledger does not claim independent execution of that unit.
Concurrent [`090c09ec`](https://github.com/Eabusham2/router-vpn/commit/090c09ec54f875ad0bf0031a3b6da5d3a254dc4f)
subsequently adds joined resolver-owner handling before private-domain fallback.
It was preserved before `35725083`; its contributor evidence is separate.

The initial live reconciliation found
[`8f05dbe658fb6589e606e9995b613a3136a3d70e`](https://github.com/Eabusham2/router-vpn/commit/8f05dbe658fb6589e606e9995b613a3136a3d70e),
already **1,352 commits ahead and zero behind** the pasted historical release
`745b3e41e5a78d734391976af9b7cd0637660a0b`. The
[GitHub comparison](https://github.com/Eabusham2/router-vpn/compare/745b3e41e5a78d734391976af9b7cd0637660a0b...8f05dbe658fb6589e606e9995b613a3136a3d70e)
identifies that older release as the merge base. Historical fixes were not
replayed over this newer source. An active separate workspace contained newer
uncommitted work; this continuation used isolated checkouts and preserved those
files. Published commits were reconciled with the live branch before further work.

Further concurrent source was preserved before these newer publications:
[`64d58c6e`](https://github.com/Eabusham2/router-vpn/commit/64d58c6e862e552ddbf24e5a0c9348cb579b8b34)
adds Windows Router Server execution and relay ownership;
[`e4be2492`](https://github.com/Eabusham2/router-vpn/commit/e4be249231643daf20bc2653fe328ce0293654d7)
adds layered imported-SOCKS packet-envelope bounds; and
[`0a1fab52`](https://github.com/Eabusham2/router-vpn/commit/0a1fab52418fb4fdcc474bfbf1d49e24c9763310)
adds Linux private-domain native fixtures. Their contributor evidence remains
separate. This continuation did not independently rerun every contributor suite.

Later reconciliation also preserves `bc6cffef` (Windows paired Local execution),
`2d59d74e` and `fb465836` (private-DNS dependency ownership and native fixtures),
`12409a40` (invalid Compare candidate score removal), and their evidence record
`71bfaba7`. The concurrent Apple Tor manifest repair `d847152e` is independently
checked below; the duplicate local proposal was preserved in scratch and not
republished over that commit. None is counted as a new unit authored here.
Concurrent `3800b4ee` adds joined private-DNS dependency groups and is also
preserved with separately attributed contributor evidence.
Concurrent `9cf424f3` adds twelve bounded CONNECT captures to the 235 existing
graphs, with both layers Off and exact Home/custom literal TCP DNS. Its native
and host implementation is retained; datagrams, other DNS transports and
independent CONNECT layers remain separate work. Concurrent `c06e59be` adds
joined protected private-DNS resolution. Their contributor evidence is not
claimed as an independent complete rerun by this continuation.

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
| [`f4d222cb`](https://github.com/Eabusham2/router-vpn/commit/f4d222cb7bf8c730b36986e67e8e834af63fbb4c) | Android Home DNS preserves the selected current-node private IPv4/IPv6 address, all five transports, exact port, TLS name and HTTP path through Save/quick actions, native preparation and captured-profile restoration. A DNS sheet cannot adopt settings after its node/profile identity changes. | The original IPv6 HTTPS/5443 to IPv4 UDP/53 substitution is reproduced and rejected by two causal controls. Home checks pass 517; real-store checks pass 374 across eleven cases plus a node-validation control; existing graph checks pass 3,598. Both actual Android producers pass 15,121 checks and five controls; all 205 current captured inputs, source hashes and compiled graphs remain byte-identical using the same generated certificate inputs, without normalization. | Portable Java/Go execution does not establish actual VpnService, device selected-DNS proof or physical routing. This unit's exact 205-graph comparison is separate from the later 235-graph gate recorded below. |
| [`775ac68e`](https://github.com/Eabusham2/router-vpn/commit/775ac68e333c3c74021b702733e1381233bcc3e7) | Checksum-owned pinned sing preparation initializes a UDP NAT connection before publishing it and retires a cache entry only when its pointer still matches the original owner. All three retirement sites use the cache's locked conditional deletion, preserving a replacement flow. | The full preparation suite passes 24 tests in 11.133 seconds. Exact constructor-publication and Ex/legacy post-cleanup witnesses reject three independent causal mutations without scheduling sleeps. The actual formerly racy wrapped-AWG relay-route case passes eight repetitions under race in 7.024 seconds. Independent source review verifies all six pinned initializer callbacks perform only context/writer construction. | This is the bounded fix for the race found by the mandatory SOCKS gate; the subsequently reconciled full native gate passes as recorded under `a08d7d6f` below. Whole-group source validation precedes sequential writes and interrupted partial states fail closed; the upgrade is not a filesystem-atomic multi-file transaction. Physical OS routing remains separate. |
| [`3ac3542d`](https://github.com/Eabusham2/router-vpn/commit/3ac3542d3f492deaec271b11d14e736ac90cdc32) | Android session audit now requires both captured node and profile identities, the shipping guard call and its updated warning. It replaces the stale profile-only warning expectation exposed by the Home DNS fix. | The original audit failure is reproduced; focused and full recovered native UI gates pass with the required Swift toolchain on PATH. The first full attempt lacked local `swiftc` and required no additional source correction. | This is a source-audit repair. It does not establish device UI behavior, VpnService DNS proof or a successful exact-SHA native release. |
| [`880a865e`](https://github.com/Eabusham2/router-vpn/commit/880a865e9270cd91d26970cb0ff08285e90e5083) | Apple Router DNS editor Save now requires the exact profile captured when the editor loaded, extending the existing external-profile guard to Router profiles. Loading an unavailable selection clears the prior captured profile. | Actual Swift settings checks pass 694 with four causal controls; measurement checks pass 324 with four controls. A stale fixture's `@MainActor` spacing was corrected so the shipping declaration is extracted correctly. | This binds editor adoption to its captured profile; it does not establish physical device DNS proof, native UI accessibility or installed PacketTunnel behavior. |
| [`fde9861a`](https://github.com/Eabusham2/router-vpn/commit/fde9861ac524b01e813fc328cb4216e4d8598578) | The Apple Xray fixture expects the Home transport and port it actually requests: TCP on 5353. It no longer expects the obsolete silent UDP/53 substitution. | The actual Swift/native graph fixture passes 87 graphs and 1,167 checks. Selected address, resolver detour and the other DNS transport assertions remain. | Two fixture expectations change; production DNS code is unchanged. Native Apple SDK, physical traffic and release acceptance remain separate. |
| [`9afd2a32`](https://github.com/Eabusham2/router-vpn/commit/9afd2a32b6086c9c96fd347a7742d63b374cdcea) | Android daily Router DNS Retest owns its captured request/socket through cancel and dialog close. Result adoption binds the exact node/profile/source bytes, publication generation and latest operation identity across panels. Shared store locking prevents cross-instance selection between validation and publication; change-away/back, byte-identical replacement and rollback invalidate old captures. | Exact original shipping callbacks reproduce a first-node result being written into another node sharing the same profile ID. The repaired actual Java callback, real loopback HTTP and store harness passes 80 checks plus five causal controls: atomic publication, generation, latest operation, dismiss and cancel. A final small-token amendment passes the focused seven-check replacement fixture and its causal control. Session-mutation/numeric and node-store transaction contracts pass. | Android widgets, Libbox admission and private-file platform calls are explicit doubles. The existing VPN mutation guard still refuses unsafe persistence; completed queries then report results not saved. Global latest identity retains no completed private Job. Home-node query RTT remains separate from native selected-policy DNS proof; no device or current release pass is inferred. |
| [`80fefcc6`](https://github.com/Eabusham2/router-vpn/commit/80fefcc687cf6f8382ec0333e3f853b481688a2f) | Windows socket duplication retains and cleans an original duplicate on partial failure and adds strict creation/transfer protocol diagnostics. The new native cases cover four socket families and preserve two causal controls. | Actual identity test binaries crosscompile for AMD64 and ARM64 within the unchanged 90-second bound each. Six shared broker/actual Unix ownership race tests pass in 1.163 seconds; fifteen Python runner tests pass. | The historical UDP4 source/TCP `WSAPROTOCOL_INFO` mismatch is **not yet proved repaired**. The four-family native cases and two controls still require actual Windows CI; crosscompilation and portable ownership tests do not establish that runtime outcome. |
| [`35725083`](https://github.com/Eabusham2/router-vpn/commit/35725083aae6c921fd5be7eba3c4a5c1d8ac1a64) | Android comparison fixture compiles the complete shipping Home DNS validator and verbatim pure Start Layer selection dependency used by the actual saved-profile store. | The original harness reproduces both missing-validator javac errors. The repaired fixture passes 438 shipping lifecycle/store/usage checks and rejects all twenty existing causal controls within unchanged bounds. | This is a source-closure fixture repair, with no product or validation relaxation. Actual Android runtime, native SDK, device and current release acceptance remain separate. |
| [`14724aaf`](https://github.com/Eabusham2/router-vpn/commit/14724aaf4c2593c11fc5138bfd9642fc4f08f8ee) | Darwin SOCKS fixture failure cleanup remains with its original broker: two redundant blocking connection-close callbacks are removed, allowing the existing trace, bounded broker drain and policy retirement to run. All explicit normal-path Close/join/PF assertions remain. Timeout reporting preserves a bounded 4 KiB head and 8 KiB tail without changing deadlines, signal authority or failure status. | The portable harness executes the actual extracted broker helper and registration snippets with real testing.T cleanup under race detection. Baseline passes; historical control-only, relay-only and both-callback variants fail the exact ordering witness, then release and join. Twelve timeout diagnostics pass. The full runner passes 40 of 41 tests; the unchanged original-control lifetime fixture is blocked at Unix socket listen with EPERM before its assertions. | This repairs proven fixture cleanup ordering and evidence retention, not the unknown initial native association rejection. The Unix-listen boundary is unfinished, not skipped or passed. Actual macOS/PF execution of the repaired fixture remains required; no further native retry or all-green claim is recorded. |
| [`63644b70`](https://github.com/Eabusham2/router-vpn/commit/63644b703852357db8ef288acc9fceb49f25ecdd) | Android Tor form fixture compares an Entry copied with only its intended location fields cleared through the shipping serializer. It preserves the original captured-byte assertion and persisted credential/policy byte equality instead of JSONObject parse/remove key reordering. Production is unchanged. | The repaired full form passes 162 compiler round-trips across all nineteen modes and 7,267 checks. All twenty-two causal controls reject their intended mutation, including a new actual Save password-corruption control at the byte-equality assertion. Padding form passes 72 captures and 1,377 checks. | The earlier full Android runtime run at `35725083` failed at the location fixture while all 432 recorded source hashes remained unchanged. Exact parsed values were unchanged; helper serialization reordered two colliding key pairs. The repaired focused form pass and subsequent segmented child gates are not an uninterrupted full-runtime pass or actual device acceptance. |
| [`e7d2b366`](https://github.com/Eabusham2/router-vpn/commit/e7d2b3669ca9ea3eb54578a4fadf327c1e0cfbb6) | Apple profile fixture adds the existing safe `homeDNSCaptured` Boolean to its exact encoded-key whitelist and checks legacy false / captured true round trips. Production Codable behavior is unchanged. | The original actual Swift fixture reproduces the exact-whitelist failure. The correction passes all 105 checks. A causal shipping-model mutation that encodes an injected `apiToken` compiles and is rejected by the same exact whitelist; timeout is not accepted as evidence. | This repairs the fixture exposed after the Xray graph step passed at `fde9861a`. It is not an Xcode build, signing or device acceptance. |
| [`f97d9d60`](https://github.com/Eabusham2/router-vpn/commit/f97d9d60fc6f55698561dea9929993cf0f18dc20) | Rosenpass lifecycle fixture observes an independently copied key on the controller's next protocol poll, after delivery and deferred erasure have returned on that same goroutine. It no longer reads a buffer still lent to production. | The original read/erase race reproduces locally. The corrected focused race test passes 100 repetitions (1.206 seconds); the full lifecycle package passes 20 race repetitions (1.771 seconds), plus `go vet`. Removing production event-key erasure is rejected by the explicit erasure assertion; no race or timeout is accepted as that control. Production controller is restored byte-for-byte. | Production key erasure, protocol behavior and bounds are unchanged. The exact-source native macOS job must still rerun; these lifecycle tests are not new cryptographic protocol evidence. |
| [`e9810710`](https://github.com/Eabusham2/router-vpn/commit/e9810710a3081c15b7fda60b16ff49970ad1fdf5) | Android profile rollback fixture targets the exact rollback method's shared lock instead of requiring eight unrelated lock sites across the whole Node store. The atomic mutant now changes only rollback admission. | Rollback passes 21 checks in four cases and both source-owner / competing-store causal controls. The full profile harness passes Home DNS 374/11 plus one control; rate settings 291/35 plus two; preferences 30/5 plus three; apply 6/1 plus two; all nine imported families; and actual combined profile/node/exit stores 2,212/182 with the independent-Activity lost-update control. | This is a fixture correction after the newer DNS retention APIs correctly added two lock sites. Production is unchanged. Android runtime continuation remains segmented, with earlier failed invocations recorded separately; it is not an uninterrupted full-runtime or device pass. |
| [`dc4ab1c1`](https://github.com/Eabusham2/router-vpn/commit/dc4ab1c1cd1fc36e8e03ec1427b7f74155820e13) | Windows native and authoritative release gates partition Speed Lab into comparisons, remaining Tor, and remaining Speed Lab. Every process retains its 180-second bound. The authoritative release and exact gate inventory also retain the newer Router Server group from `64d58c6e`. | The prior gate reproduces its stale Router Server inventory failure. All 19 corrected workflow/package-binding tests pass, including omitted-group, widened-skip, extended-timeout and disabled-execution rejection. Dynamic source inventory selects all 250 matching parent names exactly once, including platform variants; the three Speed Lab groups contain 5, 19 and 69 source names. Independent review confirms disjoint selection and blocking failure behavior. | The old native job completed 69 parents totaling 178.61 seconds before exhausting the shared three-minute budget; no individual hang was established. Local workflow checks do not execute Windows tests. Actual matching-host completion of the new bounded groups remains required. |

### Units 34–40: published native prerequisites and Android host wiring

| Published commit | Change and requirement connection | Observed verification | Remaining boundary |
|---|---|---|---|
| [`8a71c473`](https://github.com/Eabusham2/router-vpn/commit/8a71c4732508b424a2df3b69ce3160ca1866f2a2) | Ordinary Shadowsocks native composition keeps its originally selected TCP DNS fixture. The newer Server fixture may still explicitly select its UDP responder. Production policy, selected destination and all proof assertions are unchanged. | Official pinned preparation, 689 source-closure records and actual native compilation pass. Matching Windows ordinary native composition subsequently passes on AMD64 and ARM64 at `bc6cffef`, including selected-DNS/exit proof and rejection suites. | Local execution stops at denied interface/netlink enumeration before traffic. The Windows ordinary composition uses explicit OS-permit/TUN fixtures; actual WFP and the separate historical UDP4/TCP descriptor issue retain their own gates. |
| [`6859097b`](https://github.com/Eabusham2/router-vpn/commit/6859097b0ce2d447cb3b91bae91f2f4e9997b33a) | The owned AES/XOR outbound can explicitly request authenticated UoT version 2 over its original TCP stream. Default behavior is unchanged and no imported graph is newly admitted. | Actual pinned SS2022 authentication, UoT decoding and the shipping whitening process retain TCP plus connected/unconnected 32-, 9,000- and 17,000-byte datagrams, original cancellation/close and replacement ownership. Final normal-source race pass is 1.073 seconds; low-memory pass is 1.055 seconds. Removing UoT dispatch or owned Close fails its intended assertion. Preparation passes eight checks. | This is a transport prerequisite, not a completed CONNECT graph. Actual full-Box UoT traffic subsequently passes Ubuntu and macOS; the extra macOS userspace fixture fails its bare provider socket at 17,000 bytes and is corrected separately by unit 38. |
| [`f194e094`](https://github.com/Eabusham2/router-vpn/commit/f194e094d2f49a33ac38258b172abd8f8d414ba7) | OpenVPN exposes bounded live capacity observations tied to the same authenticated remote receipt and connection generation. No imported-entry compiler or host admission is enabled by this unit. | Actual userspace TCP/UDP encrypted TCP and UDP traffic works before and after reconnect; live requested MTU 1,500 is read back as negotiated 1,280. Wrong-password authentication, cancellation and closed-owner refusals are retained. The mandatory Linux non-bootstrap runner records five exact verdicts (2.20-second parent; 9.143-second complete invocation), and 2,127 prepared source records remain unchanged. Observer races, six policy checks and two runner-contract tests also pass. | Original one-client provider helpers remain unchanged. The new UDP reconnect witness explicitly allows two provider sessions because the prior UDP session remains live; this does not prove server reclamation or saturated one-client reconnect. Physical/kernel OpenVPN composition is still blocked locally by netlink restrictions and remains separate. |
| [`95f36b95`](https://github.com/Eabusham2/router-vpn/commit/95f36b95f0e3c03da0d129ea5e89cdffb3c3d666) | Android Connect, Home transition, cold reattachment, startup policy and usage all use the existing captured imported-entry/final capability. Stale duplicated lists had still rejected SOCKS5 despite successful compiler/native graph matrices. OpenVPN and CONNECT admission was unchanged by this unit; the later bounded CONNECT addition is recorded separately below. | Whole runtime passes 1,586 checks across 200 cases plus fourteen controls. Runtime composed with the actual Home store passes 100 checks across 35 cases and three old-guard controls. Usage retains 213 prior checks plus forty packet and fifty SOCKS checks/twelve controls; startup, Home (7,829 checks/370 pairs/nine atomic races/three controls) and permission (4,938/nine controls) suites pass. | Native preparation/proof and Android OS boundaries are explicit doubles. The source cold-reattach contract passes; an earlier whole session-wrapper attempt failed missing JDK/JSON environment before its child, so no full-wrapper or actual APK/device pass is claimed. |
| [`1cac6bf7`](https://github.com/Eabusham2/router-vpn/commit/1cac6bf7beaedc795c6e0acacb41123c25ddca58) | The userspace UoT provider fixture applies the existing owned UDP buffer policy and reports provider errors. The 17,000-byte payload, deadlines, negative controls and production transport remain unchanged. | Normal and low-memory race passes are 1.060 and 1.059 seconds; a socket-setup rejection mutation fails the unchanged datagram assertion with its setup cause. All eight preparation checks pass. Exact-source run 42184535561 subsequently passes macOS, Ubuntu and Apple composition. | These matching native successes close the identified fixture failure. They do not establish CONNECT graph admission, every platform, packaged delivery or physical networking. |
| [`b25c93fb`](https://github.com/Eabusham2/router-vpn/commit/b25c93fbdfa04e87a3665f1046d8026a15f750ec) | The inherited Android startup-deadline fixture includes the actual shared imported capability method used by its unchanged whole runtime. It no longer leaves the source-inclusion placeholder empty. | The original five javac missing-method errors reproduce locally and in exact `95f36b95` CI. The one-line repair passes 3,785 checks / 1,089 cases: actual delayed native UP at 21.053 seconds, ordinary expiry at 20.033 seconds, cancellation/terminal failure, and all three original budget mutations. | Production methods and timers are unchanged. This is an executable Java boundary fixture, not a device timing result or uninterrupted full Android runtime pass. |
| [`9e0341f0`](https://github.com/Eabusham2/router-vpn/commit/9e0341f0ddd5614330e95564cbd8fa09857c7c3c) | Checksum-owned pinned HTTP CONNECT cancellation joins its original handshake socket's Close callback before returning, including a race with successful response publication. | All 26 preparation tests pass in 15.362 seconds. A deterministic actual pinned HTTP client over `net.Pipe` rejects the original source at the specific unjoined-Close assertion; timeout is not accepted as that result. Complete module checksum, cache preservation, pristine upgrade, partial/foreign source and hardlink controls remain enforced. | The controlled socket delays actual owned Close explicitly; this component test is not an entire CONNECT-to-paired-node graph or physical network test. This prerequisite did not enable host admission; the later concurrent TCP-only feature has separate evidence. |

The newer imported-SOCKS packet-bound core cases from concurrent `e4be2492`
were also checked at `8a71c473`: two named parents / 27 cases pass under race
in 1.622 seconds. This narrow core result does not certify all later Android
sources or the newer native peer templates.

### Units 41–49: published imported paths, service metadata and CI completion

| Published commit | Change and requirement connection | Observed verification | Remaining boundary |
|---|---|---|---|
| [`c70778ea`](https://github.com/Eabusham2/router-vpn/commit/c70778ea5e30d4d29c9490d3c04214cb9e592268) | Android cold startup compares captured CONNECT authority with the canonical protocol, preserving original stored `http`/`https` node kinds and private source bytes. Both startup admission and Attempt construction use the same canonical identity. | Actual startup checks pass 280 new assertions and all 21 causal controls alongside 3,674 existing assertions and earlier families. Actual saved-profile Load/Connect passes 110 checks in two cases. | Manual permission's existing raw/raw comparison remains consistent. Native proof and Android OS boundaries in the portable host fixture are explicit doubles; physical reattachment is separate. |
| [`a475f1ec`](https://github.com/Eabusham2/router-vpn/commit/a475f1ece892c1e812ef78dfdec33f7592c9e8cb) | The combined Runtime/Home fixture substitutes both shipping `supports()` and `protocol()` methods into the existing source placeholder. | Old javac missing-method failures reproduce. Actual Runtime plus Home passes 140 checks in 49 cases and all four old-admission/canonical-identity causal controls. | One fixture file changes. This does not claim an uninterrupted full Android runtime, APK or device pass. |
| [`3dbb286d`](https://github.com/Eabusham2/router-vpn/commit/3dbb286d46a28e30469c8c3d50ba147fcead9e47) | The actual Windows SOCKS WFP fixture enables bounded error-level native logging so sanitized public-proof failures retain their underlying test diagnostic. | All 41 then-current runner contracts pass in 4.838 seconds, including the race-instrumented observer. No production grant or DNS policy changes. | The earlier `bc6cffef` Home/LAN-off rejection remains unexplained. A later `9cf424f3` WFP run passes the entire SOCKS phase with those source files unchanged; neither that pass nor this logging change establishes a causal repair. |
| [`29bf1fb5`](https://github.com/Eabusham2/router-vpn/commit/29bf1fb50d86f690bc723dfe870139fa5e0036c3) | The generator atomically records the actual configured paired SS service capability and binds the private bundle declaration to node, endpoint, port, cipher, key/source hashes, image and UoT version 2. Unsupported image or absent declaration does not advertise capability. | Seven tests pass in 3.023 seconds, including actual Docker COPY-source projection, materialized service-image identity and atomic preservation. Existing private-bundle, setup/import and REALITY contracts pass. Four preexisting transport artifacts remain byte-identical. | These are producer/source tests, not execution of a Docker image or admission of a new CONNECT graph. The added asset initially exposed ordinary/start-layer consumer rejection; concurrent `0752df09` supplies that separate compatibility work. No private deployment changed. |
| [`803eabc1`](https://github.com/Eabusham2/router-vpn/commit/803eabc1f0e4383a703dfc5a3af52825ce284726) | Owned Stop fixtures wait for the actual child signal handler before Stop and require exact SIGTERM/SIGKILL outcomes. Malformed PID registries preserve the live process and registry; test teardown joins only the original child. | PID ownership and five registration checks pass. A deliberately wrong readiness handler is rejected and reaped. The complete 22-gate recovered map-first source/shipping invocation passes on frozen `803eabc1`. | Production PID birth/command hashes, four 30 ms observations and ownership checks are unchanged. The old CI missing-command-hash cause remains unexplained; unchanged old fixture also passed locally. This is not device visual acceptance. |
| [`3044f0b0`](https://github.com/Eabusham2/router-vpn/commit/3044f0b087c72b6ba5e42df2ccbb3cc92da2a061) | Imported OpenVPN entries execute Local graphs inside the existing Android/Apple VPN owner, with original TCP/UDP remotes, authenticated remote generation, live capacity and independent entry/final Start Layers. Five paired final families and all nine layer pairs add 90 captures while preserving the previous 247. | Final native gate passes 111 exact verdicts under race in 21.799 seconds: 90 encrypted traffic positives, three ordered failovers, fourteen observed refusals and four parents. Core OpenVPN passes 202 verdicts, layer-map 29 and runner 15. Actual Android producer passes 25,473 checks/337 captures/five causal controls; Swift producer passes 6,979/337 and picker 3,231. Daily Runtime passes 1,787 checks/243 cases/fourteen controls; Runtime plus actual Home passes 240/84/four. Final composed native parsers pass 676 source/Android and 338 Apple verdicts; all 674 host artifact hashes remain unchanged. | The composed parser source digest is `80db9bf9c8bb8566bd8423358f5b26fd1ed333fa0ba7b416bfe9241ddf749f73`. A killed cold parser build and interrupted parallel retry are not passes; the final serialized build succeeds under the existing runtime/process bounds. The supported OpenVPN profile subset, no second system VPN, original public receipt and separate layer authority remain explicit. This does not admit every final family, Server/Compare, physical MTU or device networking. |
| [`3ee47f8d`](https://github.com/Eabusham2/router-vpn/commit/3ee47f8de5876c9c685fc52ab901cc6888ad0d2f) | The Android connection-profile source contract includes the published OpenVPN help wording. | Exact line-129 failure reproduces and the corrected actual contract passes. The complete packet-capacity, Auto/Fixed and not-measured-MTU caveat remains required. | Production text is unchanged by this one-line fixture repair. Current native builds and the complete UI gate require their own evidence. |
| [`341f2c66`](https://github.com/Eabusham2/router-vpn/commit/341f2c6630e9654f537cc34dadb50288614277ab) | Windows native CI runs each of seven existing phases independently on AMD64/ARM64, keeping the 30-minute job cap and every inner compiler/test/cleanup limit. A required aggregate admits only fourteen successful exact-run/commit/architecture/image receipts and one comparable prepared-source closure per architecture. Default and packaging executions still require all seven phases. | All 42 existing runner contracts pass in 3.980 seconds, including observer races in 1.022 seconds. Nine new receipt tests pass in 0.156 seconds. Real Go parsing proves separate temporary roots compare identically while raw module bytes remain unchanged; changed module/dependency, foreign replacement, wrong source/run, missing phase/image and failed/cancelled/skipped job controls reject. Parsed workflow expands to fourteen native jobs. Independent source review and a real Linux prepared-tree scan confirm only `go.mod` among 2,138 records contains its preparation paths. | Each phase retains its original raw source digest. Only the validated owned sibling Xray path is normalized for cross-job comparison; full pinned Xray source hashes and all remaining module bytes are retained and checked before/after execution. Linux checks do not execute the actual Windows matrix. Run 42194122508 remains pending at the snapshot below. |
| [`cf4ea4b3`](https://github.com/Eabusham2/router-vpn/commit/cf4ea4b389ead8124b3db3f7002723b2ff6a466b) | The exact server Tor dependency inventory includes the private-DNS helper's existing `desktopnetwork.LockContext` dependency. | The original missing-member failure reproduces. The corrected source closure and eleven missing/foreign/substituted dependency controls pass in 0.861 seconds, including new private-DNS import and symbol mutations. | This repairs the fixture exposed by Xray run 42189911345. No production lock, dependency source or runtime behavior changes; a new native CI result is separate. |

These publications also preserve concurrent Windows Local/Server/Compare
unit `f0c3ea9d`, installed private-DNS evidence `75897b4d`, and their `2d697a3e`
record. Concurrent `66c81cde` revalidates configured SS generation during
preserved upgrades; `0752df09` adds ordinary, composite and Apple sidecar
compatibility. Their contributor evidence is separately attributed. Additional
paired node-binding and actual host store/reload regressions are being checked
against those published changes, without replaying superseded implementations.

## Published independent SOCKS layers — reconciled final evidence

This twenty-fifth unit replaces the earlier unpublished integration row. The
initial full native attempt found a real UDP NAT publication/replacement race;
that failed attempt remains evidence of the cause repaired separately by
`775ac68e`. The successful final gates below ran after that repair and after
reconciling the subsequently published final-only and entry-only layer cases.

The later composed Android host audit found that duplicate daily-runtime and
Home admission lists still blocked SOCKS5. Unit 37 (`95f36b95`) repairs those
shipping callers. The original producer and native-peer passes below remain
valid for their tested boundaries; they did not establish daily Connect/Home
admission, which now has its own composed evidence.

| Published commit | Change and requirement connection | Observed verification | Remaining boundary |
|---|---|---|---|
| [`a08d7d6f`](https://github.com/Eabusham2/router-vpn/commit/a08d7d6f387c3b55b3139de54ef567bd67e841f9) | Local imported SOCKS5 entries retain independently provisioned Off/AES/AES+XOR layers to paired SS, Hysteria2, WG and AWG Fast/Strong finals. All 215 published graph names remain; twenty both-enabled combinations complete 235 graphs, including all 45 SOCKS combinations. The original authenticated control owns its encrypted UDP relay through cancellation and worker retirement. | The exact mandatory gate passes 397 core verdicts and 651 native encrypted-peer verdicts under race detection. Android produces 235 graphs with 17,565 checks and five causal controls; shared plus Android captures pass 472 native parser verdicts. Apple produces 235 actual Swift graphs with 5,466 checks and 236 pinned native parser verdicts. Exact source checks pass before/after the gates. | These source/host/loopback-native results do not establish physical VpnService/PacketTunnel routing, current-SHA packages, signing/distribution or the broader imported-protocol/final/Server/Compare requirements. |

All **354** prior core verdict IDs remain within the 397-case inventory. The
newly published entry-only native family retains all **155** verdicts (54 proxy
children, 99 packet children and two parent tests), including authentication,
private-target, full-MTU packet and original-association retirement checks. The
prior final-only packet family retains all **94** verdicts and its actual padded
DNS/packet-capacity assertions. The ten entry-only `--entry-{layer}` filenames
and ten final-only filenames retain their upstream identities. Entry-only
captures retain their original credentials; both-enabled fixtures use distinct
entry/final layer keys.

| Exact final native group | Named verdicts, including parents | Package elapsed |
|---|---:|---:|
| Shared imported-entry compiler (`TestImportedEntry*`) | 397 | 8.519 s |
| SOCKS proxy paths, including retained final-only group | 152 | 18.358 s |
| SOCKS packet paths | 162 | 71.241 s |
| Retained imported paths and original relay/initial-packet retirement | 88 | 29.574 s |
| Preserved packet-final-layer family | 94 | 47.347 s |
| Preserved entry-layer proxy and packet families | 155 | 54.966 s |

The runner retains the original 60-second core and 90-second native process
limits and rejects missing, skipped, duplicate or foreign verdicts. Counts are
executable checks, not completed requirements. Test commands and exact sets are
in `deploy/test_mobile_imported_entry.py`; mutation coverage of that runner
passes eleven tests. Apple exact-manifest contracts pass four tests.

### Source and publication identities

- Native/core and Android completed on isolated `46efb57d5d5cb7e22aa507d5ec1733bdad272b03`.
- Final candidate `7778ec2af67b9cba8ff7c600f0019f6d81eb6700`, tree `fbcd8aa70efdcb34158c018dfe9b2aa3f2ea17a5`, differs only in one Apple fixture assertion: exact upstream entry-only credentials are accepted when the final layer is Off; independently enabled layers still require distinct fixture keys. Production, graph generation, native peers, compiler and Android inputs did not change. The final Apple gate passed on this candidate.
- Final candidate mobile source digest: `f68c7cca676d5d1a865ee9cbc78eb47c36895de53927db8db1069113acf5c4bf`.
- Apple gate source digest: `2135628f113ee5a13bf7cf2a41bbcfcb108eed45c393ac6a0525d4019e3fd4d5`, unchanged during the successful gate.
- The projected native module is pinned at `1ac1a339cb1223e9c70eae14c44411c75033c02d`; the source checker compares exact compiler, bridge and peer templates. This is an isolated owned projection, not a newly packaged device release.
- Publication `a08d7d6f387c3b55b3139de54ef567bd67e841f9`, tree `bb360c4d1bed8a09ed6ee4dd5aee6625c205c605`, parent `1066bfaf`, includes the feature and updated guide. The publisher verified its exact tree and remote readback. Candidate digests above identify the tested source closure, not a claim that every unrelated file in the published tree was retested.

The final local evidence files are `socks-entry-reconciled-native.log`,
`socks-entry-reconciled-records/native-manifest.json`,
`socks-entry-reconciled-android.log`,
`socks-entry-reconciled-records/android-manifest.json`, and
`socks-entry-reconciled-apple-final.log`. These identify the retained local
artifacts; they are not uploaded CI artifacts or evidence of release delivery.

Concurrent `ad4da5e7` contributed four final-only proxy cases, `dbb0a4ca` six
final-only packet cases, and `ea460eae` ten entry-only cases. Their source and
negative inventories are retained; this continuation adds the remaining twenty
both-enabled combinations rather than claiming those earlier cases as new.
Concurrent `ddbf7d3c` Windows Router Server physical-policy work and subsequent
disjoint source updates are preserved with their separately attributed evidence.

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

At **2026-11-06 09:20:31 UTC**, the release-list read still returned the October
24 `745b3e41` prerelease with twelve assets. No newer exact-source release or
private deployment is established. The `341f2c66` Windows phase workflow
[42194122508](https://github.com/Eabusham2/router-vpn/actions/runs/42194122508)
was pending. Its authoritative release
[42194122838](https://github.com/Eabusham2/router-vpn/actions/runs/42194122838)
was cancelled as the branch advanced; it is not a release pass.

At `9cf424f3`, actual WFP AMD64 job 127790169387 passed the complete SOCKS
phase, including Home DNS with LAN disabled, original TCP/UDP LAN denials,
retained denials and all six compiled controls. The five relevant SOCKS/policy
files were unchanged from the earlier `bc6cffef` failure, so its initial cause
remains unexplained. Both complete WFP jobs then ended cancelled at roughly
30 minutes (AMD64 30.233, ARM64 30.283), after multiple phases had passed. The
logs do not establish the unfinished phases. Unit 48 addresses that aggregate
CI boundary without weakening native operation limits or omitting a phase.
The later `f0c3ea9d` ordinary bootstrap jobs passed both architectures at the
subsequent read; its full WFP/startup jobs were still running.

The newly published OpenVPN head `3044f0b0` failed both recovered UI workflows
at the same old Android help-sentence assertion:
[map-first run 42192780099](https://github.com/Eabusham2/router-vpn/actions/runs/42192780099)
and [native UI run 42192780282](https://github.com/Eabusham2/router-vpn/actions/runs/42192780282).
Unit 47 repairs that precise contract; the frozen `803eabc1` full-gate pass does
not certify the later source. Separately,
[Xray run 42189911345](https://github.com/Eabusham2/router-vpn/actions/runs/42189911345)
at `3dbb286d` passes its Apple graph job but fails the Android/native job's
server dependency inventory. Unit 49 repairs that inventory while keeping
strict source/import/symbol rejection. Neither local correction establishes a
successful rerun or all-platform publication.

Newer completed native evidence closes two of the bounded pending items above:

- Exact `1cac6bf7` [whitening run 42184535561](https://github.com/Eabusham2/router-vpn/actions/runs/42184535561)
  passes macOS job 127781652916, Ubuntu job 127781653120 and Apple composition
  job 127781653100. The previously failed userspace provider case remains in
  the suite; its payload and deadlines were not reduced.
- At `bc6cffef`, [Windows run 42182258201](https://github.com/Eabusham2/router-vpn/actions/runs/42182258201)
  passes ordinary bootstrap on AMD64 (127778848205) and ARM64 (127778848071).
  Both complete logs confirm the actual command, generated factory, Box and
  HTTP/HTTPS CONNECT/SS/Hysteria2/SOCKS/WG/AWG selected-DNS and rejection suites.
  Their OS permits and TUN are explicit fixtures. At this read, the separate
  actual WFP jobs are still running; no WFP/device acceptance is inferred.

Exact `95f36b95` [Android runtime run 42183836516](https://github.com/Eabusham2/router-vpn/actions/runs/42183836516),
job 127779386219, passed the updated startup and composed runtime/Home gates,
then failed to compile the inherited deadline fixture. Unit 39 repairs that
specific dependency. A frozen standalone `9e0341f0` checkout subsequently passes
all nine following child gates and four final contracts (13/11/8/4 tests), with
all tracked source hashes unchanged. This includes 3,174 Speed Lab restoration
checks and nineteen controls, plus 145 whole-service retained-winner checks,
four owner controls and three exact MTU-retirement controls. The run records
and hashes are in `android-runtime-tail-9e0341f0-records`; this segmented
continuation does not certify an uninterrupted complete runtime run or every
newer source dependency.

At **2026-11-06 08:09:14 UTC**, the exact `71bfaba7` read returned nineteen
attempt-1 runs: seven successful, eight queued, three in progress and one
pending. The authoritative
[release run 42185197816](https://github.com/Eabusham2/router-vpn/actions/runs/42185197816)
was pending. The latest published release was still the October 24
`745b3e41` prerelease with twelve assets. This is not a completed current release.

Additional exact-source results and repaired blockers:

- [Windows MAX run 42174525230](https://github.com/Eabusham2/router-vpn/actions/runs/42174525230)
  at `80fefcc6` passes all ten AMD64/ARM64 jobs. The
  [Windows PQ run 42175078784](https://github.com/Eabusham2/router-vpn/actions/runs/42175078784)
  at `fe914aaf` passes both architectures. These do not certify the separate
  descriptor identity suite or a later all-platform release.
- [Darwin run 42175862403](https://github.com/Eabusham2/router-vpn/actions/runs/42175862403)
  at `14724aaf` passes the ARM PF/socket/utun ownership job 127754058819,
  including actual SOCKS IPv4/IPv6 and original-permit-expiry control. The other
  three jobs are cancelled. The earlier Intel setup cause remains unresolved.
- [Native whitening run 42181797321](https://github.com/Eabusham2/router-vpn/actions/runs/42181797321)
  at `6859097b` passes Ubuntu and Apple composition. The macOS log explicitly
  passes `TestWhiteningUoTActualPacketsRetainTCPAndOriginalOwner` in 0.13 seconds,
  then fails the separate userspace provider's 17,000-byte datagram with EOF.
  Unit 38 retains that case and repairs its socket setup; the job is not green.
- [Android diagnostics run 42177942443](https://github.com/Eabusham2/router-vpn/actions/runs/42177942443)
  at `e9810710`, job 127760903668, passes the actual 68,661-check Apple Tor
  exporter but fails its receipt consumer before native parsing: the consumer
  omitted compiled `IOSHomeDNSPolicy.swift`. Concurrent `d847152e` adds the
  dependency and independently derives actual producer inputs in its contract.
  Root's frozen `1cac6bf7` Swift/Go producer independently passes all 68,661
  checks. The published consumer accepts all 396 Local and 528 padding graphs
  (901 and 1,201 asset records); missing/changed policy hashes fail four controls.
  All twelve published consumer contracts pass in 6.391 seconds. Native Tor
  parsing, Android packaging and a current release are not rerun by this check.

The two Windows controller failures at `0a1fab52` and `64d58c6e` were exact
Router Server preflight-inventory mismatches, repaired by unit 33. They are not
evidence of a native ALL runtime failure. The subsequent contributor Local
group from `bc6cffef` is retained; all nineteen release gate tests also passed
after that reconciliation at `95f36b95`.

At **2026-11-06 07:05:40 UTC**, the exact `dc4ab1c1` Actions read returned
22 runs: six successful, four in progress, two queued, one pending and nine
cancelled. The authoritative
[Build all Router VPN release gates run 42178231924](https://github.com/Eabusham2/router-vpn/actions/runs/42178231924)
was in progress, attempt 1. This is a bounded query snapshot, not a complete
release verdict. The release list still returned the October 24 `745b3e41`
prerelease with twelve assets as its newest published release.

Newer completed results supersede the older in-progress observations below:

- [Apple graph run 42172902311](https://github.com/Eabusham2/router-vpn/actions/runs/42172902311),
  job 127746006854 at exact `fde9861a`, passed all 87 Xray graphs / 1,167 checks,
  then failed the profile fixture's exact serialization whitelist. `e7d2b366`
  repairs that fixture with the secret-rejection evidence recorded above.
- [Native Rosenpass run 42174357635](https://github.com/Eabusham2/router-vpn/actions/runs/42174357635),
  macOS job 127749272182 at exact `a08d7d6f`, passed the pinned native protocol
  step (2.446 seconds), then failed the lifecycle race step on the fixture's
  borrowed key read versus deferred production erasure. `f97d9d60` repairs that
  observation; the production erasure remains intact.
- [Windows native run 42168681000](https://github.com/Eabusham2/router-vpn/actions/runs/42168681000),
  job 127732013613 at `f8cd9790`, later failed the aggregate Speed Lab bound.
  `dc4ab1c1` preserves all cases in bounded groups; this earlier source does not
  test the newer protocol/descriptor ownership correction.
- [Windows physical run 42176531078](https://github.com/Eabusham2/router-vpn/actions/runs/42176531078)
  at `64d58c6e` failed ordinary Shadowsocks selected-DNS admission in both
  AMD64 job 127757087134 and ARM64 job 127757087101. Wintun IPv4/IPv6 retirement
  and three causal controls had passed first. Both ordinary paths reached no
  peer/proof traffic. Inspection found the shared fixture selector had changed
  ordinary SS DNS to UDP while that fixture still owned only its TCP DNS path;
  a focused correction was still in progress at that earlier cutoff and is now
  published as unit 34, `8a71c473`, with the bounded evidence above.
  This is not evidence that the historical UDP4/TCP identity mismatch is fixed.

Android runtime verification subsequently completed as a **segmented
continuation**: all 53 child gates have successful results and all four final
contract suites pass (13, 11, 8 and 4 tests). The actual Speed Lab restore harness
passes 3,174 checks and nineteen negative controls, including forty ordinary
graph restores and eight cancellation phases. The original full run at
`35725083`, the Go VCS-discovery interruption and the later rollback fixture
failure remain recorded failures, not an uninterrupted full-runtime pass.

The original and final 432-file source manifests differ only in the two intended
fixture repairs (`test_android_tor_form.py` and `test_android_connection_profiles.py`).
Comparing that tested checkout to committed `dc4ab1c1` confirms the Android Java
and harness files are identical, but two existing compiler files (`imported_entry.go`
and `plan.go`) differ and `e4be2492` also adds the imported SOCKS bounds source and
test. Its newer native peer retirement/template updates are outside this
segmented result. Thus the 53-child evidence does **not** certify the newer SOCKS
packet-bound calculations, a complete current-head Android/native build, or a
physical device. Original/final manifests and the reconciled child inventory
were retained with the run records.

At **2026-11-06 06:41:00 UTC**, the Windows runs containing the published
protocol/duplicate repair had not produced native acceptance. The original
`80fefcc6` [native run 42174525567](https://github.com/Eabusham2/router-vpn/actions/runs/42174525567)
and [physical run 42174525473](https://github.com/Eabusham2/router-vpn/actions/runs/42174525473)
were cancelled while pending, as were later pending descendants
`42175289916` (`e0d7b59d`) and `42175078761` (`fe914aaf`). These cancellations
are superseded pending work, not executed test failures. At this read the newest
pending runs were [Windows native 42175862508](https://github.com/Eabusham2/router-vpn/actions/runs/42175862508),
[Windows physical 42175862464](https://github.com/Eabusham2/router-vpn/actions/runs/42175862464)
and [macOS physical 42175862403](https://github.com/Eabusham2/router-vpn/actions/runs/42175862403),
all at `14724aaf` and all attempt 1.

Older active runs retain their original source boundaries:
[Windows native 42168681000](https://github.com/Eabusham2/router-vpn/actions/runs/42168681000)
at `f8cd9790` was running the Tor wrapper ownership step; both build-command
ownership jobs had passed. [Windows physical 42173507764](https://github.com/Eabusham2/router-vpn/actions/runs/42173507764)
at `c6a33ff1` had passed both native bootstrap jobs while its encrypted WFP and
captured Node startup jobs were still running. Neither revision includes
`80fefcc6`, so these outcomes cannot establish that the historical UDP4/TCP
protocol mismatch is repaired. No post-fix failing job log for these two Windows workflows was available
at this cutoff. The definitive macOS retry failure and its remaining unknown
setup error are recorded immediately below.

The later **attempt 2** of [macOS run 42167793365](https://github.com/Eabusham2/router-vpn/actions/runs/42167793365),
Intel job 127740178604, completed with failure on original `a5000cc3`.
The socket-retirement baseline passed in 257.25 seconds and the complete
IPv4/IPv6 SOCKS association baseline passed in 40.92 seconds. Kernel-identity
and permit-sequence mutations were rejected. The permit-expiry mutation then
failed during selected-private UDP association setup before its intended
assertion. A direct test cleanup Close blocked ahead of the existing bounded
broker/policy cleanup; the run reached its unchanged 730-second outer timeout.
At timeout the original test process was a zombie and exact-binary descendants
were in another process group within its original session; killing the original
group returned PermissionError. This observation does not prove those children
remained after the root fixture's final cleanup. The initial setup error was
lost from the bounded output tail, so its cause remains unproved. The narrow
fixture cleanup/evidence repair is now published as `14724aaf` (unit 28), with
the bounded portable results and Unix-listen EPERM limitation above. The initial
setup rejection remains unknown; no further native retry, deadline increase or
successful macOS release is claimed.

At **2026-11-06 06:18:53 UTC**, an independent read found live `main` at
`c6a33ff145168ed1aadf2008b66191611fcedd7d`. The exact published `9afd2a32`
query returned 28 attempt-1 runs: seven successful, fourteen cancelled, six
running and one queued. [Authoritative release 42173361380](https://github.com/Eabusham2/router-vpn/actions/runs/42173361380)
was running; [iOS compile smoke 42173361103](https://github.com/Eabusham2/router-vpn/actions/runs/42173361103)
and [Windows native contract 42173361263](https://github.com/Eabusham2/router-vpn/actions/runs/42173361263)
were cancelled. [Recovered native UI 42173361163](https://github.com/Eabusham2/router-vpn/actions/runs/42173361163)
passed at `9afd2a32`; the earlier [UI run 42171426259](https://github.com/Eabusham2/router-vpn/actions/runs/42171426259)
also passed at `3ac3542d`. These are specific workflow successes, not a completed
native release or certification of the newer live branch.

The single targeted macOS Intel retry is still running at that read: run
42167793365 attempt 2, new job 127740178604, at original `a5000cc3`. Its original
failure and earlier unchanged-source pass remain below. No retry success or
current-SHA release evidence is claimed. The Windows protocol-readback/partial
keeper repair was unpublished at that observation and is now published as
`80fefcc6` with the bounded evidence above; its actual AMD64/ARM64 kernel tests
remain required. The historical wrong-protocol
failure is not declared resolved by source diagnostics alone.

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
from the later complete 45-combination unit recorded above. Concurrent
[`dbb0a4ca`](https://github.com/Eabusham2/router-vpn/commit/dbb0a4ca2bde5ad4a7951a01f5b849f558d32229)
adds six provisioned WG/AWG packet-final layer cases. Together with `ad4da5e7`'s
four SS/Hysteria proxy-final cases, these form the published 205-capture baseline
used by the exact-input Android comparison; their contributor evidence remains
separate from the later published 235-capture extension. The earlier CI snapshots cannot
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
their individual closure obligations; these forty-nine units are not a replacement scope.

The concrete Apple Home DNS substitution gap reported at `8fdc2ef7` is repaired
in `5b32bcf5` with the bounded evidence above. Intentional UDP/53 for Fastest node
measurement remains a different path. Android Home DNS now has its own published
repair in `f4d222cb`. The full 45-combination SOCKS layer feature is published
in `a08d7d6f`, preserving the final-only and entry-only contributor units. Its
updated complete native and host gates pass as recorded above; the separate
NAT repair `775ac68e` alone was not treated as feature acceptance. The newly failed persistence regression fixture above is now repaired in source;
its new exact-SHA CI evidence remains pending.

In particular, support for one entry/final graph does not prove every requested
protocol pairing, independent layer combination, local/server execution or
platform. Supported source must still be connected to the actual daily app,
owned lifecycle, complete restoration, native engine and relevant negative
controls. Unavailable capability with an honest reason is safer behavior, not
completion of the corresponding requested capability.

Concrete source implementation gaps remain in this same mobile imported-entry
direction: the newer concurrent `9cf424f3` supports CONNECT to paired SS2022
only with both layers Off and exact selected literal TCP DNS. CONNECT datagrams,
other DNS transports and independent layers, other paired final families and
Server/Compare still need implementation and evidence. The bounded OpenVPN
entry direction is now published as unit 46 with its exact graph/native/host
evidence above; it must not be carried forward as wholly absent.
They are not merely live-access or device-evidence gaps. See the
[precise open graph boundaries](MOBILE-IMPORTED-ROUTER-PATH.md#open-graph-requirements)
for the capability and selected-DNS constraints that a further implementation
must resolve without weakening original authority.

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
