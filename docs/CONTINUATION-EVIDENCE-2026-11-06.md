# Router VPN continuation evidence — November 6, 2026 UTC

## Scope and source identity

This is an implementation and evidence ledger, not a replacement for the user's
original requirements. The live starting branch was
[`b04eccee94f4cf3e83f978cbb74504e796c056a6`](https://github.com/Eabusham2/router-vpn/commit/b04eccee94f4cf3e83f978cbb74504e796c056a6),
1,294 commits ahead of the older published `745b3e41` release. Old patches were
not replayed over that history. The published units below retain normal
`main` ancestry through
[`75897b4d7099b500762b6402ed967d4442f2705d`](https://github.com/Eabusham2/router-vpn/commit/75897b4d7099b500762b6402ed967d4442f2705d).
For the local publication units, each remote tree was compared with its local
committed tree; exact validation cutoffs are recorded below. The later fixture-only
reconciliation during the workspace outage uses remote source review and CI,
without a claim of unavailable local execution. The remote branch was read back before adoption. A saved patch, local commit or API
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
| Router/custom entry and final roles; original #214–224; native single VPN owner | Android `AndroidImportedRouter*` helpers and multihop host; Apple PacketTunnel/imported runtime; `internal/mobilemultihop/imported_entry.go` | 247 preserved/extended source graphs, actual Java and Swift exports, pinned native parsing and encrypted peers; subsequent rows retain their exact source and verdict counts | Other imported/final families, CONNECT datagrams/layers, Server/Compare for this direction, complete native device/network acceptance |
| Original #229–240, Auto/Fixed/Retest/Cancel and later packet-envelope limits | `internal/awgpolicy/packet_*`, `internal/mobilemtu`, mobile compiler/metadata | Race tests; complete data/control/cookie/junk/Start Layer bounds; Fixed overflow rejection; full-size decrypted IPv4/IPv6 peer observations | Effective configured cap is explicitly unmeasured; physical PMTU, transitions and Jumbo acceptance remain separate |
| Original #200–224/#337, exact captured ownership and full temporary-test restoration | Windows retained desktop host, `desktop_external_owned_sources.go`, independent entry/final captures | Shared/client race tests, two architecture test-binary builds, mandatory native verdict inventories and causal mutations; bounded Windows Compare is recorded below | Hosted WFP runtime and physical acceptance remain separate; the exact Speed Lab/Always-to-Off fixture failures below now have published corrections |
| Selected DNS/Home AdGuard, LAN/IPv6 and original resolver authority | `internal/standardengine/resolved_*`, retained native resolver helper, finite kernel grants and parallel equal-best scope caller | Canonical bounded frames, original-daemon local-only preflight, exact upstream port/TLS/link transport and active trust-anchor codec/race tests | Installed privileged composition and kernel execution remain unaccepted; captured DNSSEC child/cohort, cross-domain alias caller, bounded authenticated compatibility fallback and typed root collector are published; remaining semantic branches and installed native acceptance are still required |
| Later independent Off/AES-256-GCM/AES-256-GCM+XOR Start Layers | Mobile original sources and retained desktop SS-entry graphs | Independent entry/final layer matrix and actual encrypted positive/negative cases; SS and HY2 desktop finals now have nine-mode native inventories | Broader graph/platform coverage and actual Windows WFP/macOS PF/Linux TUN acceptance remain required |
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
| [`a2e4f201`](https://github.com/Eabusham2/router-vpn/commit/a2e4f201f0e29f09c9aa9cf773f4c282456426d2) | Admits retained SS2022 entry to Hysteria2 final in macOS and Linux hosts with independent sources and original protection ownership. | Focused host/provider and runner checks plus native compilation support the source increment. Actual PF/TUN, selected DNS, cancellation and restoration acceptance remain required. |
| [`133a5505`](https://github.com/Eabusham2/router-vpn/commit/133a5505ec035a9de4b4c57cc13285446cd45f6c) | Preserves the verified native library when launching the original resolver helper. | The helper retains its required Cronet/native-library environment instead of losing it at launch; actual installed composition remains a separate gate. |
| [`bc85b1f9`](https://github.com/Eabusham2/router-vpn/commit/bc85b1f96bc0bcef2606cfb1e2e070ec6dd1a752) | Runs concurrent captured resolver scopes through one original baseline reservation and generation ledger. | Bootstrap race tests pass; native-tag compilation and mandatory overlap/loser-cancellation/unknown-receipt controls are present. Partial transactions retain the original descriptors; kernel execution is not claimed locally. |
| [`1eeddc44`](https://github.com/Eabusham2/router-vpn/commit/1eeddc44bed21fe87302fc801ce8b6201b559bbe) | Retains resolver authority beyond successful helper RPC retirement through the original installed boot operation. | Original deadline, successful RPC retirement and cancelled/failed-owner controls remain distinct. Installed service transfer must reprove the same original authority; privileged execution remains required. |
| [`1026a2d8`](https://github.com/Eabusham2/router-vpn/commit/1026a2d8ecf6502c159f06caed2929ac0b4f6f9d) | Wires equally preferred original DNS scopes into concurrent caller execution with joined cleanup before adoption. | Focused race and response controls pass. Negative/invalid siblings cannot cancel a valid winner; helper frames serialize within the original context. Actual installed parallel peers remain mandatory. |
| [`25ec89f9`](https://github.com/Eabusham2/router-vpn/commit/25ec89f93c956e2c350e3c9f724ee2b4c263fe18) | Adds the pinned libunbound/OpenSSL private DNSSEC validator ABI prerequisite. | Real signed/forged/negative-answer and cancellation controls exercise the isolated ABI. This library is not yet loaded by shipping runtime: authenticated child/broker, original anchor and NTA policy, chain-query ownership and integration remain unfinished. It is not full DNSSEC delivery. |
| [`fe0fcc28`](https://github.com/Eabusham2/router-vpn/commit/fe0fcc285ca2349327029da3cefb08592f44454c) | Adds a captured-policy opportunistic TLS-first transport with bounded pre-DNS failure fallback and exact UDP/TCP/port/SNI preservation. | All bootstrap race tests pass (1.240s), native compilation and mandatory inventory pass. Eleven actual peer cases are required, including strict certificate rejection and no fallback after TLS success, cancellation, owner loss or expired grant. The subsequent shipping adapter is recorded below. |
| [`7481239c`](https://github.com/Eabusham2/router-vpn/commit/7481239c353fa359e71beacacf78fef89cc2b4e1) | Shares identical PF inventory reads within each fresh bounded macOS inspection. | The source correction addresses repeated inventory cost without treating a prior inspection as current ownership. Exact-head macOS runtime remains pending evidence. |
| [`3b0c08f3`](https://github.com/Eabusham2/router-vpn/commit/3b0c08f38a06b37b3c383efb64a7e1e4816c0921) | Recycles only joined, unpinned bootstrap members after original removal ACK, generation and exact absence proof, then descriptor closure. | All bootstrap race tests pass (1.254s); native compilation and inventory pass. The real three-attempt TLS/UDP/TCP case must leave one retained member. Unknown receipts remain owned. Historical admissions are bounded at 771; the existing concurrent inventory/FD limits are unchanged. No full 257-scope physical execution is asserted. |
| [`199e62e8`](https://github.com/Eabusham2/router-vpn/commit/199e62e88308edc71c3701feb186b50d636c02d9) | Joins cancellation mailbox retirement before releasing original Latency and DNS measurement owners. | Both isolated old-code red cases failed, independently reproducing the late-cancellation race. The corrected focused race run passes (12.770s). A drained worker receipt cannot hide a pending original cancellation input; foreign inputs are never deleted. |
| [`58f6b0de`](https://github.com/Eabusham2/router-vpn/commit/58f6b0de65dce91970efc5c1db2b73c8bcfa39b2) | Includes the exact standardengine dependency in prepared server native sources. | All 14 preparer tests pass (19.913s), including actual generated mobiletor/standardengine compilation, network race tests and missing/foreign dependency rejection. Exact source/member/digest assertions and unresolved-import rejection remain enabled. This fixes the preparer failure below; a fresh native run must establish runtime acceptance. |
| [`7f801312`](https://github.com/Eabusham2/router-vpn/commit/7f80131297c2a350d9f297fc2388c6f99c7b2adf) | Wires captured opportunistic policy into the installed Linux startup resolver and preserves original shared-frame completion when a losing scope is cancelled. | Exact staged-source privileged client/model race tests pass (2.036s/1.089s), prepared fixed-helper observations pass, and six installed composition cases are mandatory. The original deadline remains unchanged; bounded sequence capacity now covers all allowed scope checks. Actual installed TLS/fallback kernel execution remains pending. |

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

## Published continuation after the 61a06f86 evidence checkpoint

The following milestones extend the historical table above. Earlier statements
that a prerequisite was not yet wired describe that commit's boundary; this
section records subsequent source delivery without treating a local draft as
published. Publication through `8c00e8e4` preserves the seven independently
published commits from `ae8ecead` through `4d0e76de`; no history was overwritten.

| Published commit(s) | Delivered source and evidence | Remaining limit |
|---|---|---|
| `80e2b0c6`, `4a996840` | Captured original DNSSEC trust inputs and cancellation before anchor admission; packaged the pinned validator in native Linux runtimes with source/library provenance checks. | Packaging and anchor capture alone do not establish installed validation. |
| `8829f9fb` | Preserved the exact Linux build guard while projecting the resolver peer template. All 47 projection/refusal checks passed; removing the clause reproduced the actual CI preparation error. | Correct projection is not privileged runtime acceptance. |
| `0dc57026`, `50fbdfc2` | Isolated the native validator behind an owned query broker and constrained callbacks to the original address question and DNSSEC ancestors. | Actual namespace/kernel execution remains mandatory. |
| `35ffeb18` | Transferred the pinned cached initial packet before concurrent retirement, then joined blocked readers. Actual SOCKS peer and cache-retirement race run produced 26 passing records with no failures or skips. | This fixes the observed provider race without granting stale packets authority. |
| [`98d6af64`](https://github.com/Eabusham2/router-vpn/commit/98d6af646bf255e5b4906a49150b3752d7c232fd) | Connected imported mobile SOCKS5 entries to paired SS/HY2 Local finals, both layers Off. Preserved 190 graphs and added two: actual Java/Swift 192 exports, shared 296 race verdicts and exact staged native peer gate with 107 required verdicts. | Other layer modes and Server/Compare for this direction remain open. |
| `c8f1232e`, [`8f05dbe6`](https://github.com/Eabusham2/router-vpn/commit/8f05dbe658fb6589e606e9995b613a3136a3d70e) | Added independent SS entry/final Start Layers to retained desktop hosts. Independent provider exercised 81 mode/cipher successes, nine negatives and nine IPC cases. Windows source compiled for AMD64/ARM64 and its runner passed 39 tests. | Actual WFP/PF/TUN execution remains required. The persisted-profile fixture failure below was found after this publication. |
| `76d850cc`, `039a372a` | Added authenticated sealed-child DNSSEC execution and bounded retirement, plus real unsigned-delegation and captured-negative-anchor controls. | A validator's authenticated result must still be bound to the selected captured resolver policy. |
| [`95ffbb72`](https://github.com/Eabusham2/router-vpn/commit/95ffbb729460bea9826c076c93f8b1880b6eab4a) | Extended the imported SOCKS5 path to paired WG and AWG Fast/Strong, both layers Off. Preserved 190 plus five graphs: actual Java/Swift 195 exports, shared 309 race verdicts and native 149 required verdicts. Java/native combined parsing had 392 verdicts; Swift/native had 196. | Independent SOCKS authentication, UDP association, encrypted packet peers, DNS, MTU and retirement are exercised; device/network acceptance remains separate. |
| `88c84a27`, `c626af1f` | Bound DNSSEC callback queries to the original protected resolver cohort and wired the sealed validator child into the startup caller with captured original policy/trust inputs. | Full alias traversal and DNSSEC allow-downgrade handling are not closed by this increment. |
| `90a7d70f`, `693cc705` | Added original DNS alias proof in the sealed validator child and a separate protected CNAME proof owner. Actual C crypto alias cases passed; exact-source library pins were updated coherently. | This prerequisite did not yet deliver the parent alias caller; that bounded caller is subsequently published in `5ea5f09b` below. |
| `ae8ecead`, `0f194d9f` | Extended Apple selection coverage to supported SOCKS entries and kept Setup Center guidance usable when browser storage is unavailable. | These preserved upstream source changes do not establish full device/UI acceptance. |
| `6d2d3ec6`, `8091ff7a` | Added owned cancellable Android hop measurements and atomic replacement of admin bans/server Stop guards. | Live Android and router/server acceptance remain separate. |
| `cb455004`, `4b8c007a`, `4d0e76de` | Joined owned Windows fixture descendants, retained standalone throughput/MTU suspension ownership and observed replacement history explicitly in multihop cleanup regressions. | These upstream commits were preserved during publication; no blanket runtime pass is inferred from ancestry. |
| [`8c00e8e4`](https://github.com/Eabusham2/router-vpn/commit/8c00e8e40829413fd7b40c5bed28e1cba1abc369) | Delivered independent desktop SS-entry/HY2-final layers across all nine mode pairs, retaining a UDP-only final wrapper. Actual independent peers passed 27 cipher/mode successes plus 11 negatives; shared policy and host source/restore race tests passed. Windows AMD64/ARM64 full composition binaries compiled and all 39 runner tests passed. The persisted-profile fixture correction passed all 18 local restoration cases. | Windows HY acceptance now requires 32 records, including nine mode/restores, six layer negatives, trust/authentication controls and an actual forbidden-TCP probe with zero final-wrapper TCP receipts. Privileged platform execution remains pending. |

The subsequent verified publication
[`50553102`](https://github.com/Eabusham2/router-vpn/commit/505531025a7852606c506ccf0ab7956912994b77)
adds the original-daemon negotiated-server-state observer and its fixed-helper
protocol, including strict null refusal and namespace-aware original PID mapping.
Model/client race gates passed in 1.029s/1.024s, the prepared fixed-command gate
passed in 1.387s, and all eight actual PID-mapping cases passed in 1.013s.
The eight Unix monitor cases encounter local EPERM and remain mandatory in CI;
no actual monitor-socket acceptance is claimed locally. Publication preserved
the additional upstream macOS Performance change `a09d5482`.
At that monitor-only checkpoint, the fallback consumer and alias caller were
not yet wired. Their subsequent bounded shipping integration is recorded below.

The mobile 205-graph gate below supersedes the earlier 190/192/195/199 counts; these are
successive matrices, not additive completion totals. Desktop independent SS/HY
layers now have production admission plus independent provider and mandatory
native inventories. They are no longer listed as unimplemented source paths.
Neither expansion closes all imported protocols, every layer combination, or
Server/Compare behavior across the original platform scope.

## Published alias, compatibility, root-trust and mobile-layer increments

| Published commit | Bounded delivery and observed evidence | Remaining boundary |
|---|---|---|
| [`4e905017`](https://github.com/Eabusham2/router-vpn/commit/4e905017b1e55c092a82d9899ac5a432c787a520) | Published this evidence ledger through the original-daemon server-state observer, preserving historical scope and native acceptance limits. | Documentation is not independent runtime proof. |
| [`5ea5f09b`](https://github.com/Eabusham2/router-vpn/commit/5ea5f09bd0aa6bc18d571cdcae821992ed2a5e4d) | Follows DNS aliases through separately selected original scopes and independently captured trust/NTA plans. Every physical cohort joins before the next; final adoption rechecks retained digest checkpoints rather than retaining all prior full anchor plans. | Bounded source delivery does not prove every DNSSEC semantic branch or installed kernel composition. |
| [`5397f23e`](https://github.com/Eabusham2/router-vpn/commit/5397f23e101762672bcee057b55d9c585206ca13) | Added the guarded compatibility prerequisite with 21 focused leaves. A validator/IPC/retirement failure is not an incompatibility observation; strict policy and merely transient failure counters cannot authorize fallback. | This commit alone was unwired; actual caller activation follows in `f8cd9790`. |
| [`7e2a55fa`](https://github.com/Eabusham2/router-vpn/commit/7e2a55fa0b55620210d4e575ef6a89f187fd0f86) | Captures a typed original root DS decision without inventing a NoSource miss: exact positive, mode-specific synthetic unsigned, or strict no-trust outcome. Isolated model/client races passed in 1.017s/1.025s. Mandatory native inventory adds seven error leaves and eight original-broker cases; two focused runner tests passed. | Full original D-Bus broker and privileged installed acceptance remain required. |
| [`ad4da5e7`](https://github.com/Eabusham2/router-vpn/commit/ad4da5e75ec73ce9bea2bf9fe3ead5f7cd771750) | Enables provisioned paired SS/HY final layers behind ordinary SOCKS entries: 199 shared/Java/Swift graphs. Android: 16 phases, 14,691 checks and five causal controls; combined shared/Java pinned parsing: 400 verdicts. Actual Swift/pinned parsing: 200 verdicts. Encrypted native gate: 198 exact verdicts, including 44 new SS/HY layer leaves. | SOCKS entry layer remains Off; Server/Compare and real-device acceptance remain open. |
| [`f8cd9790`](https://github.com/Eabusham2/router-vpn/commit/f8cd97905eee39dbcb9a7e31e5209bb3513e7d12) | Activates authenticated compatibility in the shipping DNSSEC caller only after successful natural child retirement, State 3, captured allow-downgrade and exact sticky PacketDoOff. A bounded 257-scope ledger rechecks immutable original server-state digests after all children/group join and again at alias adoption. Type 5 uses a separate protected purpose and never grants AD. Exact seven-file audit: 99 focused race verdicts in 1.113s, including 15 strict shipping and 22 prerequisite records; budget tests passed in 1.015s and two inventory checks in 0.099s. | Installed original-monitor/kernel execution remains mandatory. BadOpt/RRSIGMissing/transient transport history alone still does not grant fallback; remaining semantic branches are unfinished scope. |
| [`dbb0a4ca`](https://github.com/Eabusham2/router-vpn/commit/dbb0a4ca2bde5ad4a7951a01f5b849f558d32229) | Enables provisioned WG/AWG final layers behind ordinary mobile SOCKS entries: 205 shared/Java/Swift graphs. Android: 16 phases, 15,121 checks and five causal controls; shared/Java pinned parsing: 412 verdicts. Swift/pinned parsing: 206 verdicts. Encrypted native acceptance: 292 exact verdicts, preserving the original 198 plus 94 in a separate bounded process; new packet-layer suite includes 85 leaves and passed under race in 47.697s. Eleven portable controls passed. | All five paired final variants support Off, AES-256-GCM, and AES-256-GCM + XOR whitening; SOCKS entry layers remain unimplemented here. Full-MTU DNS/no-fragment peer observations are not a measured physical MTU or a device VPN permission grant. |
| [`fdc0d786`](https://github.com/Eabusham2/router-vpn/commit/fdc0d78639e19a905c4b44e526ddbf5328ebeffd) | Wires typed root decisions directly into the trust collector and complete canonical rechecks. Explicit original synthetic unsigned root can export zero trust anchors only when every positive observation is absent; closer DS/DNSKEY trust islands remain retained. Strict missing-root authority is not silently downgraded. Isolated model/client integration races passed in 1.148s/2.129s; two inventory checks passed in 0.040s. Eighteen actual authenticated child cases cover the root/island paths, including secure, forged and missing-signature controls; premature clean exit is rejected before adoption. | This closes the bounded root-collector source gap, not every resolver semantic branch or native service/kernel acceptance. |

Concurrent upstream history was preserved, including
[`b1a6353f`](https://github.com/Eabusham2/router-vpn/commit/b1a6353fb0a450e4bc286768f2c62413e5305331)
(product/evidence reconciliation),
[`d19f25dc`](https://github.com/Eabusham2/router-vpn/commit/d19f25dc00779e7e5dc2d7e924cc32b3034d8a57)
(Android captured padding rates),
[`5b32bcf5`](https://github.com/Eabusham2/router-vpn/commit/5b32bcf581eaff30fb8bc5b530cce1c723ba6ab0)
(Apple Home AdGuard transports),
[`bd5d869f`](https://github.com/Eabusham2/router-vpn/commit/bd5d869ff7493e6d418add8fc988c34b307cb788)
(explicit legacy integer-port regression),
[`7e6b7a16`](https://github.com/Eabusham2/router-vpn/commit/7e6b7a1644f9319578e1b46efbabab60615488ac)
(saved padding defaults),
[`a5000cc3`](https://github.com/Eabusham2/router-vpn/commit/a5000cc3636eea8b2a6e77bafd3477ca2ec84e6e)
(Apple schema-seven Start Layer contract),
[`3341e6c2`](https://github.com/Eabusham2/router-vpn/commit/3341e6c28434aacef08ddcbb8dfb1ab8aacc7333)
(exact Tor cleanup publication observation), and
[`06615f64`](https://github.com/Eabusham2/router-vpn/commit/06615f64672cc8165357b42ea7f275c071edeee0)
(node-owned Home DNS in the SIP003 fixture). Recording their exact ancestry and
commit subjects does not claim an independent audit of all their behavior.

## CI and release state at this checkpoint

### Source delivery after the root-trust checkpoint

The following published increments supersede only the corresponding older
source gaps. They do not close other graph families, native execution, signing,
physical devices or private deployment. The immutable source snapshots used
for publication excluded unrelated concurrent drafts; each published tree was
compared with the tested local commit before the remote branch was read back.

| Published commit | Delivered behavior and focused evidence | Remaining boundary |
|---|---|---|
| [`9ce0c64c`](https://github.com/Eabusham2/router-vpn/commit/9ce0c64c52619755aa87e9616c42bd17e059794e) | Binds resolver compatibility to the original best feature level: UDP+EDNS0+DO without DoT, or TLS+EDNS0+DO with required/opportunistic DoT, retaining the exact sticky PacketDoOff observation. Focused and legacy race checks pass in 1.069s/1.086s; inventory checks pass in 0.059s. | Lower, higher or unknown levels, strict DNSSEC and transient transport counters cannot authorize fallback. Installed original-monitor execution remains separate. |
| [`ea460eae`](https://github.com/Eabusham2/router-vpn/commit/ea460eae005fb8ae7225c3dc17aa00dd991f2135) | Adds provisioned SOCKS entry Start Layers with paired final layers Off. The preserved 205 graphs expand to 215; shared/Apple/Android exports, 216 Apple and 432 combined Android parser verdicts, and 447 encrypted native verdicts pass. | This was the entry-only layer increment. The later concurrent `a08d7d6f` delivers both-enabled pairs and supersedes its graph-count boundary. |
| [`ddbf7d3c`](https://github.com/Eabusham2/router-vpn/commit/ddbf7d3c80e7da97ec8900555b1f94fbbad882a1) | Derives the captured Windows physical lower policy for paired Router WG entry to an external SS2022 Server exit, retaining the complete selector and original lease/policy. Focused race checks pass in 8.035s and preparation projection passes. | This was a policy prerequisite; retained public host integration follows in `64d58c6e`. |
| [`c6a33ff1`](https://github.com/Eabusham2/router-vpn/commit/c6a33ff145168ed1aadf2008b66191611fcedd7d) | Captures an immutable private-domain DNSSEC proof tied to original policy/plan/candidate digests, two-label A/AAAA name, scope/resolver and purpose. Eighteen existing authenticated child cases and eight new secure/forged/expired/insecure/NODATA/wrong-name/NTA/alias cases pass; a premature clean child exit is rejected. Pure race checks pass in 1.056s/1.012s/1.033s and strict inventory/source checks pass. | It requires secure root NXDOMAIN and an unsigned positive original candidate, preserves unrelated NTAs, and excludes non-root positive trust islands. This prerequisite alone did not enable a caller. |
| [`090c09ec`](https://github.com/Eabusham2/router-vpn/commit/090c09ec54f875ad0bf0031a3b6da5d3a254dc4f) | Wires the private-domain fallback only after the ordinary cohort and validator children join. The full original plan and physical owners are rechecked before a distinct auxiliary proof and again after its children/group join. Ordinary positive/negative answers win; failed auxiliary proof preserves the original error and never grants AD. Four focused parents/32 leaves pass under race in 1.313s, related resolver tests in 2.430s, and source/inventory checks in 0.074s. | The existing 32-slot budget and all deadlines remain unchanged; only the exception is unavailable without its extra slot. Installed privileged execution and deeper-name/other resolver semantics remain separate work. |
| [`fe914aaf`](https://github.com/Eabusham2/router-vpn/commit/fe914aaf314b1188d602a4a464e2d2c002cb779f) | Refuses private-domain bootstrap groups without their typed denial proof before allocating a physical member. Related bootstrap/DNSSEC/private-TLD races pass in 1.080s; removing the guard fails the intended private direct/opportunistic cases while mixed ordinary controls pass. Inventory/source checks pass in 0.085s. | This closes a capability API gap without broadening ordinary DNSSEC authority; it is not installed kernel acceptance. |
| [`64d58c6e`](https://github.com/Eabusham2/router-vpn/commit/64d58c6e862e552ddbf24e5a0c9348cb579b8b34) | Enables the retained Windows Router WG to external SS2022 Server host, both layers Off and On-connect/Always. It retains paired assets, entry identity, complete selector, final DNS/proof and source fingerprints. Restoration keeps the proved Server choice with a fresh authenticated relay session. Exact host/source restoration race tests pass in 1.209s, all 40 runner tests pass in 3.905s, and the final generated native composition crosscompiles for AMD64/ARM64. | Twenty-two native Server/association verdicts and ordinary-UDP/missing-durable-intent causal controls are mandatory in Windows CI, with a separate host scope. Actual WFP execution is unproved locally; public lifecycle reaches the real unavailable physical-network capture boundary. Local/Compare and broader graphs remain requirements. |

The Windows independent provider uses the production relay lease manager, real
WG and SS transports, selected final DNS and TLS proof. Its UDP workers belong
to the original SOCKS control and process, with exact pointer checks before
admission. Process/control retirement joins those workers before releasing the
downstream association/listener. Compilation of that provider is not a passing
Windows kernel test.

Concurrent source through `04c3e2cb` was preserved, including Android/Apple Home
DNS and captured request changes, the 235-graph independent SOCKS layer unit
`a08d7d6f`, Windows duplicate ownership `80fefcc6`, Android comparison/form
fixture corrections and Darwin bounded cleanup `14724aaf`. The older local
sixteen-file 235-graph draft was compared against the newer upstream source and
not replayed. Upstream preserves stronger relay ownership and its existing
verdict inventory. The separate additive mobile packet-bound and retirement
increment is now published in `e4be2492`, with its exact evidence below.

The Darwin native Intel failure at `a5000cc3`, attempt 2,
[run 42167793365/job 127740178604](https://github.com/Eabusham2/router-vpn/actions/runs/42167793365/job/127740178604),
timed out after the selected-private SOCKS association assertion, while an
unbounded per-connection cleanup blocked the original bounded broker cleanup.
The missing original error text does not establish its underlying cause.
Upstream `14724aaf` removes the redundant cleanup callbacks and retains bounded
head/tail diagnostics. Independently rerunning its cleanup and timeout classes
passes 13 tests in 1.588s, including the correct cleanup order and all three
historical premature-Close variants as rejected causal controls. The prior
local full runner remains bounded by Unix-socket EPERM; no complete local or
macOS-native pass is inferred. A functionally equivalent local one-file draft
was not published over that stronger upstream change.

### Additive mobile bounds and private-domain negative answers

| Published commit | Delivered behavior and focused evidence | Remaining boundary |
|---|---|---|
| [`e4be2492`](https://github.com/Eabusham2/router-vpn/commit/e4be249231643daf20bc2653fe328ce0293654d7) | Preserves all 235 imported SOCKS graphs and 651 upstream native verdicts, adds configured packet-envelope bounds for both Start Layers, and joins both original raw peer workers before closing the decorated authenticated connection. All 925 mandatory native verdicts pass, comprising the preserved 651, 271 added bounds/ownership cases and three retirement regression verdicts. Actual Apple exports pass 5,466 checks with 236 pinned parser verdicts; Android passes 17,565 checks with 472 combined parser verdicts. All seventeen portable controls and the original NAT causal prerequisite pass. | The initial 922-verdict run exposed a real independent-peer first-response race and is retained as a failed run. Its premature-close mutant is rejected after the repair. Configured MTU bounds remain explicitly unmeasured: this is not physical PMTU, device Retest, VPN extension or network-transition acceptance. |
| [`0a1fab52`](https://github.com/Eabusham2/router-vpn/commit/0a1fab52418fb4fdcc474bfbf1d49e24c9763310) | Adds two installed private-domain cases: independent root-signed private-TLD denial, with and without an unrelated retained NTA. The peer owns the signing key; the original broker receives only the public root DS and serves both D-Bus and monitor observations. A compiled-peer causal variant changes signed NXDOMAIN to signed NODATA and must fail the exact denial predicate. The controller and pinned native peer compile, all 47 runner tests pass in 124.226s, and the final five causal/cleanup checks pass in 0.076s. | Actual privileged installed execution remains mandatory. This environment has neither root nor usable passwordless sudo. The causal checker requires exit 1 plus original account-cleanup and namespace-child join receipts; a later crash, timeout or retirement error cannot count as an expected rejection. |
| [`61e7cdeb`](https://github.com/Eabusham2/router-vpn/commit/61e7cdeb76b4836399754ce3019dacae8be4f2e8) | Adds a distinct inert constructor for unsigned original NXDOMAIN/NODATA A/AAAA candidates at the existing exact two-label boundary. The positive constructor still rejects negative answers; complete framing, absent answer/alias/signature records, copy ownership and cleared AD remain required. The actual authenticated child passes the original eighteen cases in 23.12s, eight private-domain cases in 9.75s and four new negative cases in 6.09s. Premature clean child exit is rejected. | This prerequisite alone did not activate negative retention in the shipping caller. Its four child cases run in a separate mandatory process with the unchanged 55-second test and 65-second wrapper limits. |
| [`3ba9b7bf`](https://github.com/Eabusham2/router-vpn/commit/3ba9b7bf4ae05a08e33bbbd747bdcae99f385174) | Retains original negatives only after successful natural child retirement, State 3 and exact packet/verdict agreement. The ordinary cohort still joins before auxiliary proof. Both NXDOMAIN and NODATA wait for an eligible positive equal-best scope instead of cancelling it. The exact isolated complete `TestResolved` race suite passes in 2.580s and two inventory checks in 0.129s. Restoring the old NOERROR classifier fails the intended positive-sibling witness. | Existing scope, cohort, query and deadline bounds are unchanged. This proves the bounded caller source, not deeper-name semantics or installed kernel/device execution. Installed original-negative acceptance is the next separate fixture increment. |

Newer concurrent changes were compared and preserved rather than replayed:
`e7d2b366` repairs the Apple Home DNS serialization whitelist; `f97d9d60`
repairs the Rosenpass fixture's borrowed-key observation; `e9810710` targets
the Android rollback fixture's exact shared lock; and `dc4ab1c1` partitions
Windows Speed Lab into three bounded groups while preserving the Router Server
release inventory. The exact clean upstream Windows gate passes all nineteen
local tests in 0.270s. Its 250 source parent names are selected exactly once;
this is workflow coverage, not Windows execution. The later documentation
commit `03dc520f` was preserved before publishing `3ba9b7bf`.

The Windows physical run at `64d58c6e`,
[42176531078](https://github.com/Eabusham2/router-vpn/actions/runs/42176531078),
failed ordinary Shadowsocks selected-DNS admission on both architectures.
The shared fixture selector had switched that ordinary TCP-only DNS fixture
to UDP. Concurrent `8a71c473` restores its TCP selection and admits SS UDP
only in the separate packet receiver whose provider actually serves it. That
exact source correction was inspected and preserved. Actual Windows rerun
acceptance and the historical socket identity finding remain separate
obligations. The original relay challenge and stop-receipt provider correction
is now published in `bc6cffef`, with its bounded evidence below.

### Retained Windows Local execution and deeper private DNS

| Published commit | Delivered behavior and focused evidence | Remaining boundary |
|---|---|---|
| [`065de80d`](https://github.com/Eabusham2/router-vpn/commit/065de80d00ca285443b54c6ddbcf77a193d580b2) | Adds four installed original NXDOMAIN/NODATA A/AAAA cases while retaining the eleven existing cases. Before Connect, the original authenticated bootstrap RPC must return the exact no-address cause, retire its registration and preserve the original durable Always owner. Both families have explicit peer receipts; only the acknowledged original negative completion releases that namespace's peer for the normal Connect/Disconnect sequence. The final controller and pinned peer compile, and seven exact frozen-source controls pass in 0.082s. | Actual privileged installed execution remains required. The local run stops at the missing root/passwordless-sudo boundary. The missing-denial causal check requires the exact refusal and original cleanup/join, and cannot count a crash, timeout or missing-family observation as success. |
| [`bc6cffef`](https://github.com/Eabusham2/router-vpn/commit/bc6cffef5276ab63b88094655828c549028ed778) | Enables the retained Windows paired WG to external SS2022 Local path with both layers Off and On-connect/Always protection. The named paired-execution adapter retains the selector, original node assets and proof, selected DNS and physical root; its sealed restoration preserves Local without rerunning Compare. The provider now uses the production packet-challenge discovery and exact original-session stop receipt. Focused shared and host races pass in 1.418s/1.678s; sixty runner/inventory tests pass in 4.641s; the final frozen composition crosscompiles for AMD64 and ARM64. | The mandatory Windows inventory contains 23 Server/API/association verdicts and fifteen Local verdicts, including zero relay traffic for Local. Actual Windows WFP execution is separate. A portable projection reached the real Manager/Box but failed at unavailable Netlink creation, so it is not counted as a passing native API test. A later optional host-race refresh was compiler-memory-killed, not a test pass. Broader graphs and the Windows Compare host remain open at this cutoff. |
| [`2d59d74e`](https://github.com/Eabusham2/router-vpn/commit/2d59d74efa5a5a0165d7bc606e80a0608a05cbc3) | Adds an inert exact three-label private-DNS candidate and separate ordered DS-dependency purpose. It binds two exact unsigned empty IN DS responses to the original scope/plan/current-server/candidate digest and requires a separate authenticated secure TLD NXDOMAIN. Positive DS, signatures, aliases, malformed query/response framing, foreign authority, relevant NTAs and closer positive trust islands reject. All 143 required executable verdicts pass under race, including 71 new leaves and unchanged two-label controls; two inventory tests pass in 0.054s. | This model does not authorize a socket or activate shipping lookup admission. Raw packet bytes and a caller-supplied digest are insufficient protected-transport evidence. The original two-label API, strict DNSSEC, AD behavior and existing budgets remain unchanged. |
| [`fb465836`](https://github.com/Eabusham2/router-vpn/commit/fb46583682ba334849d8afbc18ce2ae777351fff) | Adds nine mandatory real authenticated-child cases. Deep original A/AAAA answers remain State 3 with their exact data; a secure root denial plus two independent unsigned DS replies completes the typed model, while forged root, positive/signed/aliased/SERVFAIL/foreign-question dependencies reject. Existing eighteen, eight and four child cases pass in 22.97s/9.63s/5.94s; the new nine pass in 12.66s. Premature clean child exit remains rejected. | Child ownership, terminal receipt and natural exit are exercised. DS packets use a direct independent fixture exchange here; this is not the shipping protected transport/caller. The 55-second test and 65-second wrapper bounds are unchanged. |
| [`d847152e`](https://github.com/Eabusham2/router-vpn/commit/d847152e8dd49865277d706923d3f77bf6bfd391) | Includes the actual compiled `IOSHomeDNSPolicy.swift` in Apple Tor/padding native source receipts. Independent extraction of the real emitter's source declarations reproduces the old omission for Local and Server; all twelve corrected native-gate contracts pass in 6.278s. Missing and altered Home policy receipts are rejected. | This fixes the precise source-ownership mismatch exposed by the Android diagnostic build. It does not replace actual native compilation, APK publication or device acceptance. No producer hash is normalized or ignored. |
| [`12409a40`](https://github.com/Eabusham2/router-vpn/commit/12409a40b5e271d02180060666ca0cdaa4b5504b) | Retires a failed final activation's previously displayed Compare score only for the original candidate and active controller. Terminal failure/cancellation clears incomplete trial eligibility without rewriting a previously completed comparison's historical measurements. Actual Controller.Run HTTP/lease witnesses reproduce both stale-score bugs when the correction is removed; the isolated focused race suite passes in 1.444s with candidate/generation/operation controls. | The scoring formula, shared random target and repeated winner probes are unchanged. This is a shared progress correction, not evidence that every platform's Compare host is complete. |

Concurrent `f194e094` adds bounded authenticated-generation OpenVPN capacity
observations, and `95f36b95` replaces Android imported-entry allowlists in
runtime, startup, Home and usage paths with the captured capability predicate.
Their current bytes were preserved. These commits do not by themselves imply
that every imported OpenVPN graph is admitted or that a configured interface
capacity is measured physical PMTU.

### Captured CONNECT and shipping deeper private DNS

| Published commit | Delivered behavior and focused evidence | Remaining boundary |
|---|---|---|
| [`3800b4ee`](https://github.com/Eabusham2/router-vpn/commit/3800b4ee9e24b43a95492c279bab017d8277a1f7) | Adds opaque protected DS reply/chain ownership. Exact two-question dependency groups must close before a root group can inherit the original context, lease and protection. Direct and opportunistic ordinary APIs cannot bypass the dependency purpose. The related private/DNSSEC/opportunistic race run passes in 1.204s; strict dependency inventory and both source/registry checks pass. The held-mutex cancellation witness returns before release and joins. | This prerequisite alone did not activate shipping lookup. Raw model packets cannot manufacture protected reply tokens; installed kernel execution remains distinct. |
| [`9cf424f3`](https://github.com/Eabusham2/router-vpn/commit/9cf424f3a24665bf048bb543921ab9bcd978f219) | Adds twelve HTTP/HTTPS CONNECT → paired SS2022 Local graphs, both layers Off, retaining exact Home/custom literal TCP DNS and independent source/proof identity. The inventory grows from 235 to 247; the complete encrypted peer run passes 976 verdicts. Actual Swift/Go producer checks, Apple parsing, Android/shared parsing, saved profiles and runtime/Home integration pass with the precise cutoffs in `MOBILE-IMPORTED-ROUTER-PATH.md`. Final merged race checks preserve the published Compare-progress fix. Current Android startup timing additionally passes 3,785 checks/1,089 cases and three causal controls. | TCP-only capability is explicit. Default Home UDP, UoT, Start Layers, datagram finals and Server/Compare remain unfinished for this direction. The full 976 run predates the explicit UoT-field refusal/progress merge; all twelve complete CONNECT captures remain unchanged. Native package/device acceptance is separate. |
| [`c06e59be`](https://github.com/Eabusham2/router-vpn/commit/c06e59bebaf4a98effa8a1327c9834e0fe6a3114) | Wires the three-label candidate into the shipping Linux lookup after the original cohort joins. Two protected DS replies and a separate authenticated root verdict must retain the exact original plan, candidate and current physical owner. Workers/child processes/groups join successfully before final proof adoption. Full `TestResolved` race passes in 3.158s; strict new caller and transport groups pass in 1.568s/1.046s; two inventory checks pass in 0.105s. Positive equal-best siblings, provisional negatives, invalid/incomplete dependencies, cancellation and stale ownership are covered. | No original deadline, query budget or 32-cohort bound increases. Only available auxiliary capacity is used. Actual installed deep-private RPC/kernel execution remains required. |
| [`ad8a1f25`](https://github.com/Eabusham2/router-vpn/commit/ad8a1f25b10e6fd4fa2d48de81f5ee9f2904ad25) | Repairs the exact Android Home fixture composition failure exposed by run 42186961587 at `9cf424f3`: the extracted imported capability now compiles with the actual external `supports` and `protocol` methods. The complete shipping Home store/controller fixture passes 7,891 checks, 372 identity pairs, 24 no-write rejections and nine serialized adoption races; the transaction-lock and both old-admission mutants still reject. CONNECT identity and unsupported finals are explicit cases. | Production admission is unchanged. Android OS/native handles remain explicit boundaries in this host fixture; actual APK/native CI and device behavior remain separate. |

### Windows Compare and installed deep-private acceptance gate

| Published commit | Delivered behavior and focused evidence | Remaining boundary |
|---|---|---|
| [`f0c3ea9d`](https://github.com/Eabusham2/router-vpn/commit/f0c3ea9d1440eb4ab8f88ec207464c9b49062caa) | Enables Compare for the captured Windows paired-WG to external SS2022 path, with both Start Layers Off and On-connect/Always protection. Requested `auto` remains separate from the actual Local/Server winner; sealed restoration pins that proved winner with its new owned lease instead of rerunning Compare. Frozen shared/client races pass in 1.752s/2.073s; the actual portable TLS/HTTP provider passes seven leaves plus parent under race in 1.133s. All 42 physical-runner and nineteen release-inventory checks pass. Correctly prepared AMD64/ARM64 compositions crosscompile in 55.163s/52.436s, with all 2,149 source records and 540 shared/template projections verified before/after. | Frozen validation is based on `9cf424f3` plus the 21 files. Earlier compiles with stale shared prerequisites are explicitly discarded. Concurrent `3dbb286d` adds five SOCKS-only native diagnostic lines in one overlapping fixture; those were preserved when publishing after the frozen build. Twenty-two Compare verdicts, the existing 23 Server and fifteen Local verdicts, and both WFP causal controls remain mandatory native execution. No actual Windows WFP/device pass is claimed here. |
| [`75897b4d`](https://github.com/Eabusham2/router-vpn/commit/75897b4d7099b500762b6402ed967d4442f2705d) | Extends the installed resolver inventory from fifteen to twenty cases: exact three-label positive and NXDOMAIN/NODATA A/AAAA paths must observe both original auxiliary DS exchanges. The missing-parent control must return the intended RPC rejection after acknowledged original cleanup, retain all eight failed-phase trust observations, make no TUN DNS mutation, and acquire no root-proof owner. Successful-path thresholds remain unchanged; receipt banners require their prerequisites. The exact corrected controller compiles and executes seven predicate leaves plus parent. Peer/overlay compiles remain valid with unchanged source hashes. Earlier fifty runner checks and eight targeted inventory/receipt checks pass; the final three affected Python controls pass in 0.029s after review corrections. | Frozen source is based on `761b75c8` plus seven files. Two resource-killed controller attempts are not passes; the corrected compile exits zero in 139.324s with 1,270,496 KiB maximum RSS. The exact compiled image supplies the eight predicate verdicts. Actual installed kernel/namespace execution still requires the explicit root/sudo fixture, unavailable locally. A failed test cannot pass merely by printing the intended cause alongside an unrelated plan, mutation or cleanup assertion. |

Concurrent [`c70778ea`](https://github.com/Eabusham2/router-vpn/commit/c70778ea5e30d4d29c9490d3c04214cb9e592268)
retains the canonical captured CONNECT protocol during saved Android startup;
[`a475f1ec`](https://github.com/Eabusham2/router-vpn/commit/a475f1ece892c1e812ef78dfdec33f7592c9e8cb)
projects the actual external policy into the composed Home fixture. Both were
preserved. [`3dbb286d`](https://github.com/Eabusham2/router-vpn/commit/3dbb286d46a28e30469c8c3d50ba147fcead9e47)
adds native SOCKS error logging to the actual WFP fixture without changing grants.
Its cancelled native attempts provide no acceptance result. At 08:49 UTC,
`f0c3ea9d` had 38 exact-source runs: three successful, seventeen queued,
thirteen pending and five running. Its Windows physical and WFP runs were
pending, so the older Home-LAN-off DNS failure remains unresolved.

Concurrent [`29bf1fb5`](https://github.com/Eabusham2/router-vpn/commit/29bf1fb50d86f690bc723dfe870139fa5e0036c3)
captures a private SS service-capability sidecar from matching generated
server/client configuration and the configured production image. The sidecar
binds the node, original source/key hashes, endpoint, port, method and UoT version;
it does not establish live receiver readiness or change ordinary SS transport
bytes. Its generation and bundle changes were preserved. Ordinary consumer
adoption and CONNECT UoT execution still require subsequent integration at this
cutoff; no competing unpublished capability asset is treated as delivered.

Concurrent `b25c93fb` includes the actual imported capability in the startup
deadline fixture. Concurrent `9e0341f0` joins the original CONNECT handshake
socket close before returning a cancelled response, with a deterministic actual
protocol witness and guarded pinned-source preparation. Both were inspected and
preserved before the CONNECT publication.

The actual macOS whitening job at `bc6cffef`,
[run 42182257699/job 127774343908](https://github.com/Eabusham2/router-vpn/actions/runs/42182257699/job/127774343908),
failed the independent userspace UoT provider's 17,000-byte datagram with EOF;
the separate real Box provider passed. The post-decryption fixture UDP dial
omitted the bounded socket-buffer control already used by the shipping relay
and echo listener. Concurrent `1cac6bf7` installs that control and retains the
actual provider error in diagnostics. Its diff was inspected and preserved;
the equivalent unpublished local edit was not duplicated. The exact `1cac6bf7`
[rerun 42184535561](https://github.com/Eabusham2/router-vpn/actions/runs/42184535561)
now passes macOS, Linux and Apple composition. The macOS log explicitly records
the previously failing userspace packet case as passed. This fixture correction changes no system-wide socket
settings and does not relax the datagram size or deadline.

At `bc6cffef`, the
[generated Linux command/TUN workflow 42182258166](https://github.com/Eabusham2/router-vpn/actions/runs/42182258166)
completed successfully on both AMD64 and ARM64. The actual logs show encrypted
TUN traffic, selected DNS, MTU rollback, pre-acknowledgement TUN closure and
original namespace cleanup/join. This is the generated-command namespace gate,
not the separate installed resolver-service/private-negative suite and not
physical-device or private-network acceptance.

At the same `bc6cffef` source, Windows physical-composition run 42182258201
has successful native bootstrap and captured startup jobs on AMD64 and ARM64.
The subsequent 08:27 UTC read reports AMD64 actual WFP job 127778848122 failed
and ARM64 WFP job 127778848079 cancelled. The observed failure is the SOCKS
`home-lan-off` selected-DNS proof after its ordinary TCP/UDP deny controls passed;
the normal On-connect/Always SOCKS cases pass. The provider observed a control
association but no UDP DNS. The underlying per-socket cause requires diagnosis;
neither the earlier four successes nor a proposed filter explanation establishes
WFP acceptance.

**Release observation at 2026-11-06 09:00:39 UTC:** the exact `75897b4d`
query returned 32 runs: two successful, eighteen cancelled, six pending, three
queued and three running. Authoritative release run
[42191376254](https://github.com/Eabusham2/router-vpn/actions/runs/42191376254)
was cancelled, attempt 1. Newer `main` was `803eabc1`; its one-file owned-stop
fixture correction was read and preserved. The releases collection still ends
with the October 24 `745b3e41` prerelease and twelve assets. Source publication
is established for the new units; a new complete release is not.

**Release observation at 2026-11-06 08:04:06 UTC:** remote `main` was
`12409a40`; the releases collection still ended with the October 24
[`745b3e41` prerelease](https://github.com/Eabusham2/router-vpn/releases/tag/router-vpn-sha-745b3e41e5a78d734391976af9b7cd0637660a0b)
and its twelve assets. No new complete all-platform release, manual retry,
signing or private deployment is asserted.

**Earlier exact-source observation:** at **2026-11-06 07:17:24 UTC**, the
all-events query for `3ba9b7bf4ae05a08e33bbbd747bdcae99f385174` returned
28 runs: four successful, seventeen cancelled, three pending, three queued and
one running. Its authoritative
[release run 42179599971](https://github.com/Eabusham2/router-vpn/actions/runs/42179599971)
was cancelled, attempt 1; newer `main` was `8a71c473` when read immediately
afterwards. The release collection still ended with the October 24 `745b3e41`
prerelease and twelve assets. No new complete release or manual workflow retry
is claimed.

**Earlier exact-source observation:** at **2026-11-06 06:48:05 UTC**, the
all-events Actions query for `64d58c6e862e552ddbf24e5a0c9348cb579b8b34`
returned **34 runs: three successful, sixteen queued, twelve pending and three
running**. The authoritative
[release run 42176531240](https://github.com/Eabusham2/router-vpn/actions/runs/42176531240)
was push, attempt 1, pending. Windows native run 42176530971, Windows physical
bootstrap run 42176531078 and Linux generated TUN run 42176530938 were pending.
There was no failed run for that SHA at this read and no complete release.
The releases collection still ended with the October 24 prerelease for
`745b3e41e5a78d734391976af9b7cd0637660a0b`, containing twelve assets. No workflow
was rerun or cancelled for this observation. The older snapshots below remain
historical rather than the current release state.

### Historical failure and release observations

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

The earlier exact-`621b660a` read observed 32 workflows, six successful and the
remainder queued/pending/running. Its release run 42147992593 was pending; that
historical observation is not a green release for newer source.

At source `fe0fcc285ca2349327029da3cefb08592f44454c`, Linux native app
[run 42152791722](https://github.com/Eabusham2/router-vpn/actions/runs/42152791722),
jobs 127680221513/127680221518, and generated Node TUN run 42152791758 failed
before runtime at `prepare-server-tor.py`: `Server Tor shared import closure is
incomplete: routervpn/mobiletor/desktop_standard_linux_bootstrap_opportunistic.go`.
The same failure was read on exact `7481239c353fa359e71beacacf78fef89cc2b4e1`,
[run 42153121604](https://github.com/Eabusham2/router-vpn/actions/runs/42153121604),
jobs 127680847447 (amd64) and 127680847630 (arm64). The exact dependency projection
is corrected by `58f6b0de`; these earlier failures do not demonstrate that the
corrected native runtime has passed.

**Bounded fresh Actions observation:** at **2026-11-06 02:57:56 UTC**, one
all-events repository Actions read filtered by exact
`58f6b0de65dce91970efc5c1db2b73c8bcfa39b2` returned **24 workflows**, all push
runs, attempt 1. None had completed: 23 were queued/pending and one was running.
The authoritative [release run 42153553151](https://github.com/Eabusham2/router-vpn/actions/runs/42153553151)
was pending; [Linux Node TUN run 42153553031](https://github.com/Eabusham2/router-vpn/actions/runs/42153553031)
and [Native MTU run 42153553164](https://github.com/Eabusham2/router-vpn/actions/runs/42153553164)
were queued. This is a single snapshot, not an assertion that additional
workflow-call runs cannot appear or that the exact head is green. No cancellation
or rerun was requested for this observation.

**Latest concrete CI finding and correction:** exact `8f05dbe6` failed
[Custom standard exit run 42161616437, job 127708379137](https://github.com/Eabusham2/router-vpn/actions/runs/42161616437/job/127708379137)
and [MTU throughput run 42161616188, job 127708378759](https://github.com/Eabusham2/router-vpn/actions/runs/42161616188/job/127708378759),
both attempt 1. The eight non-Off SS layer cases in
`TestDesktopWindowsExternalSSEntryAlwaysOffRetriesOriginalOwner` reached the
persisted-source comparison and failed with `paired Off changed its persisted
original sources <nil>`. The corrected persisted-profile fixture is included
in `8c00e8e4`; all 18 local SS/HY restoration cases pass. This is local correction
evidence, not a claim that those earlier failed runs passed afterward.

**Exact-source snapshot before the subsequent monitor publication:** at **2026-11-06 04:43:07 UTC**, the all-events
Actions query for `8c00e8e40829413fd7b40c5bed28e1cba1abc369` returned 37 runs:
14 pending, 21 queued and two running; none completed. Authoritative
[Build all Router VPN release gates, run 42164067421](https://github.com/Eabusham2/router-vpn/actions/runs/42164067421)
was pending, attempt 1. This snapshot does not claim a successful release,
native kernel acceptance or stable final run count. No workflow was rerun or
cancelled for this observation. The later `50553102` publication has no completed
exact-head release evidence in this ledger; the `8c00e8e4` snapshot cannot establish
its release or runtime acceptance.

At **2026-11-06 04:54:20 UTC**, the fresh read found remote `main` at
`b1a6353fb0a450e4bc286768f2c62413e5305331`, including the additional imported-JSON
fixture correction `e0b769ff`, Apple preference transaction `8fdc2ef7`, and separate
product evidence document `b1a6353f`. These fourteen upstream paths did not overlap
the pending resolver and evidence work and were preserved. The `50553102` query
then showed 32 runs: two successful, 24 cancelled, two queued, three pending and
one running; its authoritative run 42164545820 was cancelled. The `8c00e8e4`
query showed 37 runs: nine successful, 23 cancelled, two queued and three running;
its authoritative run 42164067421 was cancelled. Neither exact SHA had a failed
run at this observation. The new `b1a6353f` authoritative
[run 42164895972](https://github.com/Eabusham2/router-vpn/actions/runs/42164895972)
was pending, attempt 1. These states do not establish a completed new release.

**Latest exact-head Actions observation:** at **2026-11-06 05:39:13 UTC**,
remote main was `fdc0d78639e19a905c4b44e526ddbf5328ebeffd`. Its all-events Actions
query returned **32 runs: three successful, 17 queued, ten pending and two
running**, with no failed runs in that snapshot. Authoritative
[Build all Router VPN release gates, run 42169516542](https://github.com/Eabusham2/router-vpn/actions/runs/42169516542)
was **push, attempt 1, pending**. No failing job logs were available from this
exact-source snapshot. Earlier cancelled gates remain cancelled, not green;
neither the pending authoritative run nor these local tests establish a new
complete release. No workflow was cancelled or rerun for this observation.

Current native builds, package/image identity, production compose and final
publication still need exact-SHA verification. The older `745b3e41` release
cannot close newer source. The earlier isolated root-package
`go test -p=1 ./... -run '^$'` result at `892eeb42` is compilation evidence,
not a full runtime test pass.

## Configured SS source and Apple runtime DNS follow-up

The configured SS declaration introduced in `29bf1fb5`, preserved-upgrade
verification in `66c81cde`, and native asset compatibility in `0752df09` bind the
original private source bytes to their captured node. Subsequent upstream
`3f9701e3` and `fd48f71c` add independent paired-owner validation and real
generated-store/capture fixtures. These changes remain in normal `main`
ancestry; this Apple follow-up was reconciled on `df96e9cc` without replacing
those newer paths.

Apple DNS preparation now validates the configured declaration before use and
keeps the original SS source unchanged. PacketTunnel verifies that source again,
then applies the saved resolver only to its runtime projection. An unset DNS
selection retains the complete original resolver, including its TCP port or
encrypted hostname/bootstrap graph. Explicit Home, custom, DoT, DoH and DoH3
policies use their captured transport, port, TLS identity and request path.
Resolver hostname bootstrap stays inside the selected proxy.

Manual Xray startup now carries its resolved AES source with the selected
candidate. The extension compares the complete candidate with the original,
allowing only the SS server-address resolution. Keys, ports, protocol fields,
DNS and other graph contents cannot be substituted; an already literal server
must retain the same IP identity, including equivalent IPv6 spellings. The
passive declaration is consumed only in that verified runtime projection.

Focused executable evidence for this follow-up:

- `deploy/test_ios_ss_service_dns.py`: **522 checks passed** using the shipping
  Swift DNS/capture/graph code and exact extracted PacketTunnel/launch bodies.
  This includes independent layer selections, IPv4/IPv6 Home transports,
  encrypted-hostname bootstrap, unset and explicit resolver policies, paired
  final graphs, malformed/stale/foreign metadata, and resolved-candidate
  credential/graph substitution controls. Two separately compiled source
  mutants were rejected for rewriting the original source and omitting the
  selected runtime DNS policy.
- `deploy/test_ios_xray_start_layer.py`: the existing actual Swift plus shared
  Go compiler suite passed **754 checks** with the updated launch handoff.
- `ios/RouterVPN/test_dns_policy_contract.py`, Python syntax checks and
  `git diff --check` passed. The macOS authenticated Start Layer workflow now
  requires the new Swift regression alongside its existing cases.

The local Linux Swift fixture uses the existing IP parser boundary and a real
Go SHA256-backed CryptoKit test module. It does not start NetworkExtension or
prove asynchronous host ownership, native packaged execution, peer traffic,
physical DNS/leak behavior, or Apple signing. Those gates remain separate.

### Android companion and resolved-candidate follow-up

The Android picker, ordinary native startup and Start Layer consumer now validate
the original two-asset SS declaration through a passive shared API. A hostname
can retain its captured service identity without being admitted as an unresolved
physical transport. The existing owned Xray resolver still performs resolution.
Its AES result stays with that candidate and is checked against the complete
original graph before attachment and again before consumption. A different
valid key, port, protocol or unrelated graph field cannot replace the original.
Only the verified runtime projection is staged; the saved private source remains
unchanged. Existing paired factory ownership checks are preserved.

The final focused shared race run passed in **3.231 seconds**, including the
published paired-owner controls. Actual shipping Android Java plus the shared
Go helper passed **77 checks**, including valid alternate-key substitution and
failure without staging. The existing no-sidecar Xray path passed **690 checks**.
Earlier compiler/javac processes were killed and are not counted as passes; the
final runs completed sequentially with bounded compiler/JVM heaps. The new Java
and shared checks are mandatory in native Xray CI. Existing Android OS doubles
remain explicit; a generated AAR, packaged application and device network run
still require their separate native evidence.

## Native SS reply fixture overflow

Exact-source Windows phase run `42194825405`, SS-entry job `127815824195`,
failed at `3f9701e3` because the independent DNS peer allocated prefix space
and payload bytes but no trailing authentication-tag space. The pinned SS2022
server then panicked while appending its 16-byte AEAD tag. This was a concrete
fixture failure before the required native path proof, not a successful rejection
or evidence that the complete SS graph worked.

The peer now obtains both front and rear space from its actual wrapped writer
and bounds both before allocation. `deploy/test_ss_packet_reply_headroom.py`
extracts the complete fixture method and runs the pinned SS2022 client/server.
Direct and CachedPacket/udpnat encrypted DNS replies decrypt to the original
question and expected answer; a modified tag fails real authentication. The
three-case race run passes in **1.013 seconds**. A separately executed old
allocation reproduces the exact `serverPacketWriter.WritePacket` overflow
requesting 16 bytes, and the regression runner then exits successfully.

No production transport, firewall grant, rejection witness or native timeout is
relaxed. The full Windows phase still needs execution at the repaired source;
the local encrypted round trip does not stand in for WFP or device acceptance.

## Native follow-up and current fixture reconciliation

This additive record retains the original requirements and all earlier evidence.
The following source changes were committed, published directly to `main`
with normal ancestry, and independently read back from the remote branch during
this continuation. The later `25d0354f` hop-observation change and
`b792e879` performance-fixture correction were preserved, not overwritten.

| Published commit | Change | Observed verification | What remains unproved |
|---|---|---|---|
| [`6e903116`](https://github.com/Eabusham2/router-vpn/commit/6e903116717ea5a979fbadd207a7faf2320ff097) | Includes the shipping captured SS source helpers in the standalone Apple provider compile fixture. | The original missing-method Swift compile failure reproduced; the complete extracted provider fixture then compiled with both helpers. | This compile-only check does not execute Tor, NetworkExtension, a packaged application or a physical device. |
| [`0978f794`](https://github.com/Eabusham2/router-vpn/commit/0978f794d7ebf4ac05fd37f3755f3013964527b4) | Retains original and returned Windows socket observations after duplicate protocol rejection, without replacing the original refusal. | AMD64 and ARM64 test binaries compiled with four actual Winsock cases. Fifteen runner controls retain required parent/leaf receipts. Assertions use kernel protocol readback rather than merely obtaining a RawConn. | Actual Windows execution is required; cross-compilation does not explain or repair the observed UDP/TCP mismatch. |
| [`e2a43e58`](https://github.com/Eabusham2/router-vpn/commit/e2a43e5896217d21ba0e83e4a961cf0e8f60026d) | Records original, returned and imported endpoint observations after the native fixture's original inspection fails. | The exact fixture and existing peer overlays compiled for AMD64 and ARM64 alongside the preceding socket cases. | These are observations after failure, not admission authority or proof that the OpenVPN WFP endpoint failure is repaired. |
| [`3ba4b5ea`](https://github.com/Eabusham2/router-vpn/commit/3ba4b5eac1a20786a222c82cb8eca15f9104c751) | Preserves the first private Server API/operation rejection and first underlying Start failure in the authenticated native fixture receipt. Redacts captured secrets before bounded rendering and handles absent providers. | The complete extracted receipt methods, actual production Manager and pinned Box dependencies pass the focused race run in 1.034 seconds. Seven runner inventory checks pass. The mandatory baseline now includes `lease-failure-diagnostic`, giving 24 Server verdicts. | The focused test does not prove a successful Box startup, native WFP path or real private-server connection. The original native rejection still needs a diagnosed and verified repair. |

Production validation, firewall admission, retry behavior and runtime deadlines
were not relaxed by these diagnostic and fixture changes. The exact local
manifest recorded for the two-architecture socket observation build has SHA256
`a3f088df3092efb87cc61d32ed7caba11c0fe064da9b46ced34b825cc485e30d`.
The final Server diagnostic manifest has SHA256
`37c5789edd6d9fac74b4ad9b71353e998318716736098a24a0a4d0397fde30a5`.
These identify previously recorded local evidence; a hash is not a substitute
for retrieving and inspecting its associated artifact.

### Current source-contract failures

At `25d0354f2462c85fd016a954f77e6269f958d1d3`, the MTU contract
[run 42203546383](https://github.com/Eabusham2/router-vpn/actions/runs/42203546383),
job `127844460187`, reached the actual performance shipping fixture and failed
because its sparse checkout lacked `daemon/`. The real preparer writes the
caller-bound instance observer there. Concurrent
[`b792e879`](https://github.com/Eabusham2/router-vpn/commit/b792e879dcbe32856c99521cfab6e5a98b9cff15)
already repairs that fixture and verifies both observer files' input membership
and exact projected bytes. That published repair is preserved without replay.

The Multihop, recovered-requirements and release-gap runs at the same SHA
reported the same two obsolete `internal/common` source markers:

- The Apple contract required the old direct `layeredProfile` assignment.
  The shipping compiler now validates the original SS declaration and selects
  `capturedSSProfile` for Shadowsocks, while retaining the ordinary
  `layeredProfile` branch. The corrected contract requires all four current
  statements; existing Start Layer, MTU, engine/proof ordering and seventeen
  MAX/composite mutation controls remain intact.
- The native owner contract required the old
  `StartedService.Instance()` call. The corrected contract requires the
  captured engine, original bounded context, exact service/Box and
  `IdentityContext` checks, plus the daemon's cancellable lock/unlock and
  context result. It explicitly rejects restoration of the old uncancellable
  getter in that bridge.

These are fixture corrections against inspected shipping code, not changes to
production routing, credentials, source validation or cancellation. The execution
workspace became unavailable before a local Go/Python run of these corrections.
Only source review is established at publication; exact-commit CI must execute
the corrected tests.

The actual Windows native engine jobs in Aux proxies
[run 42203545965](https://github.com/Eabusham2/router-vpn/actions/runs/42203545965),
jobs `127848549346` and `127848549200`, separately executed and failed three
desktop MTU cases: applied-cancellation restoration did not reach a candidate,
physical-path replacement did not reach a candidate, and the mailbox case
reported a captured runtime failure. Both architectures' failures are separate
from the source markers above and remain open at this record.

### Unpublished source and verification boundaries

No unpublished draft below was imported into `main` merely to report progress:

- **CONNECT UoT:** twenty-two prepared paths retain 337 existing captures and
  add six bounded Local captures, for 343. The focused shared race test passed
  in 1.176 seconds and twenty-one inventory/receipt checks passed. Fresh desktop
  and mobile source projection completed. The full native run then stopped
  during compilation with `signal: killed` in pinned sing-box and sing-openvpn
  packages, before accepting any of the 1,162 encrypted-peer verdicts.
  The 688 shared/Android and 344 Apple parser verdicts remain pending.
  Original TCP-only graphs, UDP Home policy, exact service authority and the
  upstream caller-context changes must remain preserved.
  The focused race pass predates the upstream context merge; it is not a pass
  of all later merged source. The frozen final run starts from historical local
  `ddd40fff61876ba609994e9b475fbff712ceca07`, not a published commit.
  Its recorded production-equivalent publication is `3ba4b5ea`; the subsequent
  `25d0354f` hop changes were not applied during the run. The twenty-two draft
  paths are listed below to locate the work, not reconstruct unknown bytes.
- **Windows independent final layers:** the reviewed twenty-file draft covers
  paired WG entry with its entry layer Off and independent SS2022 final
  AES/AES+XOR layers across Local, Server and Compare. The proposed native
  inventory adds 111 verdicts; those are required cases, not an executed pass.
  Review revision two preserves the 24-case Server baseline and adds direct
  candidate-row checks plus two focused comparison-removal controls.
  Its source manifest SHA256 is
  `1e1c160ded079ce0c50d2ee7c8a03eef6aad1b8e848661682cc8bab4cb879abc`.
  The focused race and actual mutation-control execution remain pending.
- **Second SS forward reply buffer:** this is distinct from the published
  `7b516259` DNS-peer allocation repair. The draft exposes the downstream
  writer's headroom and reserves bounded front/rear capacity around the full
  UDP payload. A saved partial log contains eighteen passing encrypted cases.
  The runner's final exit and required causal controls were not established
  before access to the workspace was lost, so the draft remains unpublished.
- **Linux resolver ancestry:** the eighteen-file draft has focused model,
  candidate and transport race evidence, but no completed client/installed
  composition result. Two compiler-killed client attempts and unavailable
  further validation do not establish its required acceptance.

The workspace disconnected after these drafts were prepared. Their last
recorded local names include `connect-uot-ddd-review-files.json`,
`connect-uot-ddd-gate-inputs.json`,
`windows-layer-review-fixes-manifest.json` and
`resolved-ancestry-review-manifest.json`. They must be located and checked
against their recorded bytes and newer `main` before any restoration. This
document does not assert that the unavailable workspace or full draft bytes
have been independently backed up or are currently downloadable.

The unpublished UoT path inventory is:

```text
android/app/src/main/java/com/eabusham/routervpn/AndroidImportedRouterPath.java
android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java
android/test_android_connection_profiles.py
android/test_android_imported_router.py
deploy/prepare-desktop-external.py
deploy/test_ios_imported_router_pinned.py
deploy/test_ios_imported_router_pinned_contract.py
deploy/test_ios_tor_pinned.py
deploy/test_ios_tor_profile.py
deploy/test_mobile_imported_entry.py
deploy/test_mobile_imported_entry_runner.py
internal/mobilemultihop/imported_connect.go
internal/mobilemultihop/imported_entry.go
ios/RouterVPN/App/IOSMultihopExecution.swift
ios/RouterVPN/App/IOSMultihopView.swift
ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift
mobile/desktop/node_external_ss_entry_test.go.tmpl
mobile/desktop/node_imported_connect_entry_test.go.tmpl
mobile/routervpn_imported_entry_native_test.go.tmpl
internal/mobilemultihop/ss_uot_asset.go
internal/mobilemultihop/imported_connect_uot_test.go
mobile/desktop/node_imported_connect_uot_test.go.tmpl
```

The UoT manifest's own checksum and individual file hashes were not retained in
this text record; they must be read from the recovered manifest. The prepared
serial compiler warmup was never started and has no timing or memory receipts.

The newest listed release at this observation remains the older twelve-asset
`745b3e41` prerelease. None of these newer source changes establishes a complete
new native/package/image/compose release, production signing, private deployment
or physical-device acceptance. No router, AdGuard or private server configuration
was changed.

### Remote native follow-up after workspace disconnection

- `40567e35d625a6620d3bc3e43dce4142d938f0c5` published the two source-contract fixture corrections described above. Its Multihop contract workflow `42206637830`, attempt 1, completed successfully on that exact commit. This is the bounded workflow result, not a full release.
- Concurrent `20f1e423a90c039cf0380d7821c57e55d720fee1` supplied the optional MTU context-capture availability contract. The MTU policy job `127862467552` in run `42208772950` passed on descendant `2a164e3fab1ad4a7130b033f2be393d901f30066`, including the shared race packages and Android/performance shipping checks. The Apple job in that run was cancelled as main advanced; the whole workflow is not recorded as successful.
- The Linux AMD64 and ARM64 native jobs `127860854329` and `127860854456` at `20f1e423` both reached the routing-runner receipt check and failed its obsolete `27 != 15` expectation. `09ad1cb89aa7919f47bc4c6b0cc552cc690ecdde` changes only the expected shared/native MTU verdict counts from 15/7 to 27/8. Missing, duplicate and foreign verdict controls remain required. Local execution was unavailable; native verification after that change remains required.
- `503caa850da968b463e6ab4aec3d4eebb042ee2c` fixes the diagnosed Windows Server fixture registry omission. The actual packet job `127855162775` at `40567e35` reported `default DNS server fallback: transport type not found: local` before traffic proof. The fixture now registers the same local transport that the pinned packaged core includes. The compiled external relay still rejects domain targets and uses destinations resolved by the captured client's selected DNS policy. Existing Server/Compare/DNS/credential/retirement cases are preserved and must execute successfully after this repair; earlier negative passes during the common startup failure are not independent causal evidence.
- The same Windows run's OpenVPN job `127855162880` failed during child provider startup. The strict reply reader discarded a child test failure line and printed a nil ReadSlice error. This increment adds safe startup-phase diagnostics without relaxing the reply protocol, transport checks, retries or native negative cases. This does not yet establish the provider's root cause or a working OpenVPN path.
- The separate SS forward-buffer overflow is confirmed in actual Windows job `127855163058` at `40567e35`: the packet writer requires 42 bytes of header space. It is distinct from the earlier published 16-byte DNS-reply tailroom repair. Its draft remains unpublished with incomplete required validation as recorded above.

These GitHub publications were verified by normal-parent commit reads, compare-and-swap updates of main, and exact source readback. They are source-reviewed remote publications; no local build result is claimed after the workspace became unavailable. The broader unpublished source drafts and live/device acceptance items remain open.

### Exact-current native successes and the remaining SOCKS exchange failure

At `7f94ebdbf6e11150c5828e56c5073722c5213e60`, Linux generated-command/TUN run `42211427100` passed on AMD64 and ARM64. The actual six-case suites include selected DNS and encrypted TUN traffic, captured MTU and rollback, resolver failure, wrong key, and pre-ACK close. MTU policy job `127871330656` also passed its shared race, Android fixture and shipping checks. Paired native OpenVPN job `127871326142` in authoritative run `42211427108` passed actual native owners, mapped TCP/UDP AES and AES+XOR Local/Server paths and replay/ownership controls, and uploaded its exact-SHA artifact. These are bounded results; the Windows external-OpenVPN WFP composition, complete release, physical devices and private deployment remain separate.

Windows SOCKS `home-lan-off` failed in ARM64 job `127855163138` at `40567e35` and AMD64 job `127872067780` at `7f94ebdb`. Each independent provider receipt recorded an association but no UDP client or payload. The original DNS exchange error is discarded before the shared generic failure and cancellation, so those receipts do not establish where packet delivery failed. This increment adds a pass-through diagnostic at the original exchange: it captures the same router method and logger, calls once with identical arguments, and returns the exact answer/error. It logs only a fixed class and numeric errno, never raw errors, requests, answers, addresses or credentials. Classifier cases cover wrapped errors and errors that panic if rendered. No resolver, grant, LAN policy, deadline, cache behavior, proof check, return or cleanup is relaxed. Local execution remains unavailable; compilation, classifier execution and the existing complete Windows SOCKS acceptance remain required.

### Current Windows results and bounded Server logging

The `7f94ebdb` AMD64 OpenVPN job `127872068533` passed all nine TCP cases, all nine UDP cases, and eight of nine mixed cases. The remaining mixed/control-key case failed native ALE endpoint inspection; original, returned and imported socket views retained IPv4/stream/TCP protocol identity while endpoint queries returned invalid-argument errors. The earlier provider-startup failure did not recur, which does not establish that diagnostic-only logging repaired its cause. The mixed failure and its unexecuted downstream causal controls remain open.

The `7f94ebdb` AMD64 packet/Server job `127872067799` passed the WireGuard, AWG2-fast and AWG2-strong packet suites, then reached Server selected-DNS proof and failed. The prior missing registry transport was no longer the startup boundary. Some authentication/cancellation negatives correctly refused to pass because this earlier DNS failure prevented their intended witness. The empty lease-failure diagnostic is not evidence that lease creation never occurred.

`cfb1a8123d3335ccfdbb501ed7d800896b98d14d` published the bounded exchange observer and ten classifier cases described above. This fixture increment enables its existing error-level logger only for explicit Server captures with a paired entry identity, in addition to the existing SOCKS condition. Ordinary SS-entry, Local and Compare logging is not broadened. No selected policy, grant, proof or verdict changes. The original exchange observer is silent if failure occurs instead in identity or DNS-response validation; native execution must establish the next boundary.

`547a5d27daa5fbe11521d8b108214924ca7686af` adds `mobile/externalpolicy/**` and `mobile/strategy/**` to the push/PR filters of the existing Windows physical, PQ and MAX workflows. The desktop preparer compiles both directories, while a policy-only change previously did not trigger those standalone runs. Jobs, permissions, matrices, commands, receipt requirements, concurrency and deadlines remain byte-identical. All three standalone workflows were scheduled on that commit; their execution is separate from confirming source filters.

### Captured mixed OpenVPN remotes and provider retry witness

The mixed Windows OpenVPN fixture constructs an ordered original profile with an unavailable TCP remote followed by the real UDP provider. Its control-key rejection observer incorrectly required every active grant to equal the final provider, despite the first tuple being present in that same captured profile. The rejection helper now receives the existing parsed remote list, checks each grant against that exact tuple set, and verifies the final captured tuple against the independent provider declaration. Only two distinct, nonempty final-provider socket identities can satisfy its retry witness; any number of initial TCP observations cannot do so. The snapshot error, prepared target, capture, kernel owner, single-grant bound, native status, deadlines, proof rejection and unproved-traffic checks remain required. This is a fixture correction, not a repair or suppression of the separate AMD64 ALE endpoint inspection failure.

The completed ARM64 OpenVPN job `127872067654` at `7f94ebdb` passed the TCP and UDP families and the first three mixed cases. Its remaining six mixed cases failed provider startup. The earlier bounded diagnostic identified `unavailable-port-reservation`, numeric Winsock error `10013`; that distinct reservation failure remains open. The AMD64 mixed/control-key failure remains the invalid-argument ALE inspection described above. Neither failure is accepted as a valid rejection witness.

This increment was reviewed against the exact current source and its existing parsed-profile caller. Local compilation and execution remain unavailable. The existing full native Windows OpenVPN case and downstream causal controls must execute successfully before this path can be accepted.

### Subsequent bounded native results

At `547a5d27`, AMD64 SOCKS job `127888715514` passed its complete existing phase, including home-LAN denial, selected DNS, restoration and negative controls. AMD64 node-controls job `127888715589` rejected all four required causal mutations, including ordinary UDP denial. Their earlier failures did not recur in these runs; the intervening exchange observer is diagnostic-only and is not evidence of a functional repair. At `98f08601`, Linux generated-command/TUN jobs `127888868351` (AMD64) and `127888868512` (ARM64) passed selected DNS, encrypted traffic, captured MTU/rollback and pre-ACK close. These exact-run results do not establish a complete native release or physical-device acceptance.

### Native build-orchestration DNSSEC fixture boundaries

The authoritative `7f94ebdb` source-gate job `127871326178` ran 58 native-toolchain tests with four errors: the two reused Linux bundle fixtures reached the real DNSSEC receipt reader without a validator receipt, and the two simulated Linux host fixtures reached the real producer with a deliberately minimal environment or the wrong physical architecture. The production environment copies the real environment; these errors were caused by incomplete orchestration fixtures, not evidence that production should weaken cache, architecture or receipt checks.

The fixture now models the producer boundary with explicitly labeled dummy payload bytes, validates the exact namespace and command gate arguments/environment/deadlines, and requires their order after the Box suite and before the existing final compiler boundary. Earlier failures must not reach the producer. Reused-bundle tests still execute their actual builder control flow while modeling the DNSSEC verifier boundary; they require exactly one verifier call after successful stock DNS, no call after stock-DNS failure, and preservation of the original verifier exception. A new test covers refusal, subprocess failure and timeout on both Linux architectures and requires that none emits the successful reuse-publication message.

Only `deploy/test_desktop_native_toolchain.py` changes for this correction. Actual DNSSEC production, architecture restrictions, native verifier, receipts, package gates and negative controls remain unchanged. The proposed file contains 59 test methods; this is source inventory, not an execution result. Local Python execution remains unavailable; the complete file must pass in CI before claiming the four errors resolved.

### OpenVPN provider port-selection diagnostic

ARM64 OpenVPN job `127872067654` reached `unavailable-port-reservation` with numeric error `10013`. The helper first opens a TCP listener on port zero, then probes UDP on that assigned numeric port; either operation can fail under the same existing phase label. Both probes are closed before the helper returns, so its integer `used` map is not a retained kernel reservation. The log does not establish which operation failed, an excluded-port range, a privilege problem, or a WFP defect.

The fixture startup diagnostic now appends only allowlisted network (`tcp`, `tcp4`, `udp`, `udp4`) and syscall-operation (`socket`, `bind`, `listen`, `setsockopt`) labels, defaulting to `unknown`. It preserves the numeric errno, original diagnostic prefix and exact returned error; no arbitrary error text, endpoint or credential is emitted. Port probing, retries, timeouts, protection and ownership are unchanged. No exact-line consumer was found in the current runners. Native execution must still identify the failing operation; this change is not a port-selection repair.

### Native TCP connector completion observation and refusal regression

The Windows importer calls its native connector outside the identity gate and publishes the result through `finishNativeTCP` afterward. The existing actual successful-transition test deliberately exercises the interval in which the connector has returned while the stored phase is still Pending. Therefore the earlier AMD64 failed-inspection `phase=0` alone does not establish that Connect was still running. No causal repair is inferred from that ambiguity.

The original imported I/O object now retains a non-authoritative, mutex-protected copy of connector entry/return, fixed result class and numeric errno. Classification occurs outside the I/O mutex; only assignment/copying holds it, and the writer releases it before the existing finish hook. The fixture's failed-inspection diagnostic includes this observation and closing/closed flags. These diagnostic reads happen after the original inspection failure and are not an atomic record of that earlier instant. No observation field participates in admission, identity transition, cancellation or retirement, and no independent `SO_ERROR` read is added.

`TestDesktopSocketWindowsIdentityObservesRefusedConnectBeforePublication` keeps a TCP/IPv4 destination exclusively bound without listening, requires the original connector's actual refusal `10061`, and holds the identity gate until the returned observation is visible. It requires the original pending owner, refuses premature source close, and rejects any connected inspection. A nil inspection error must still supply the complete original bound identity; an actual ALE error is observed without being rewritten into success. The test then requires the original partial owner/error, failed-phase publication, joined close, keeper close and exact retirement. An actual retirement failure remains a required test failure.

The test is appended to the mandatory native inventory, preserving every existing positional mutation selector; the runner also checks its unique presence. The source inventory becomes 22 required native parent cases and 16 Python runner methods. This increment is six source/test/runner files plus this evidence entry, reviewed by two Astra agents and the parent. No local compilation or execution was possible. Actual Windows AMD64/ARM64 execution, including the new IPv4 refusal case and all existing ownership controls, remains required; it does not establish equivalent IPv6 refusal coverage or resolve the earlier OpenVPN WFP failure.

### Provider-join compiler and execution budgets

At exact `c602cecf0eebca46a52884886f9c4d0760952732`,
[Windows AMD64 job 127907229930](https://github.com/Eabusham2/router-vpn/actions/runs/42220220946/job/127907229930)
stopped in `deploy/test_windows_external_provider_join.py` before its native
SOCKS command. Python timed out the combined `go test -race` command after
60 seconds. The log did not contain a Go test-start record, case verdict or
15-second Go test-timeout panic. The recorded one test was the Python unittest.
Buffered output prevents assigning the elapsed time conclusively to compilation,
linking or execution; it does not establish an actual provider join failure.

The existing fixture now compiles its exact test binary in a separately bounded
180-second phase and executes that binary with the original 15-second Go test
deadline and 60-second outer execution limit. The compiler allowance is an
explicit bounded policy choice, not a measured duration from the failed job.
Phase labels distinguish build failure from execution failure. The existing
architecture-specific race selection, two-second helper deadline, trailer,
overflow, failed and stalled child cases, original-child join assertion,
bounded-diagnostics case and temporary-workspace cleanup are unchanged.
Production helpers and native SOCKS verdict requirements are unchanged.

Validation before publication was exact-source review and a single-statement
replacement check during the workspace outage. No local build, native execution,
passing provider-join verdict or SOCKS acceptance is claimed for this correction.
Its next CI execution must supply those distinct results.

### Standalone Windows provider prerequisite trigger

The published provider-join correction in `4299db39` did not schedule the
standalone Windows physical-bootstrap workflow. Its current workflow runs
`deploy/test_windows_external_provider_join.py` before the native matrix phase,
but neither its push nor pull-request path list included that consumed file.
Both lists now include the exact prerequisite path. Only those two filter
entries change; jobs, matrices, permissions, concurrency, commands, receipts
and all execution deadlines remain unchanged. The workflow's existing self-path
also schedules this correction. Scheduling evidence is separate from a passing
provider fixture or native network verdict.

### Completed notices fixture captures its DNSSEC dependency boundary

[The exact c602 source-audit job](https://github.com/Eabusham2/router-vpn/actions/runs/42220221127/job/127900721659)
completed the preceding native-toolchain suite with **59 tests, OK**, in
258.662 seconds at 13:06:16 UTC. The next command,
`deploy/test_desktop_native_dependencies.py`, ran 18 tests and failed two
Linux subcases: its deliberately modeled host entered the real DNSSEC producer,
which correctly rejected the foreign native architecture. This was not a
production DNSSEC verification failure.

The existing completed-build/notices fixture now models that producer and
verifier explicitly, with exact owned dummy payload bytes. The real outer
builder, staging, complete payload receipt, actual PT notices, `N.reuse`
verification and atomic publication remain exercised. Assertions require the
captured Linux target, producer arguments and environment, the namespace and
command checks in order before the final compiler, their exact arguments and
900-second wrapper limits, the sealed library hash/size linker values, and
verification of the staged and published payloads. Other targets must make no
DNSSEC calls. The 18-test inventory and remaining methods are unchanged.
Grouped patches preserve the previous static nesting depth.

Validation before publication was root review plus an independent Astra review
against the production builder and verifier call sites, with exact original
method/file-boundary checks. Local Python execution remained unavailable.
The earlier 59-test success is actual CI evidence; the corrected 18-test suite
still requires execution. Modeled dependency bytes are not a validator binary,
cryptographic test result, native architecture proof or installed DNS acceptance.
Production DNSSEC checks were not modified.

### Generated Apple app fixture retains its qualified CryptoKit dependency

[The c602 iOS job](https://github.com/Eabusham2/router-vpn/actions/runs/42220221012/job/127900661526)
failed before Xcode compilation in `test_ios_owned_strategy_app.py`.
Its generated `AppTests.swift` could not resolve the two
`CryptoKit.SHA256.hash` calls used by the shipping configured SS source/key
validation. The fixture strips all source imports while retaining
`#if canImport(CryptoKit)`; that condition is true on the Apple host, so the
qualified implementation was compiled without importing its module.

The fixture shim now carries the same conditional CryptoKit import as the
shipping source. Its existing unqualified strategy-digest double remains
separate from the module-qualified production SHA-256 calls. The generated
shipping source, all eight mutation definitions, execution limits and
production source/key validation are unchanged. Platforms without CryptoKit
retain the production validator's explicit refusal for this operation.

Root and independent Astra source reviews confirmed the import-stripping cause
and matched the generated fixture dependency to the shipping conditional import.
Only the shim import and its explanatory comment changed. No local Swift
execution was available; the app fixture, its negative controls, and subsequent
Xcode app/PacketTunnel build remain separate CI results to obtain.

### Windows Server fixture projects the original UDP relay onto its WG host

[The c602 AMD64 packet/Server job](https://github.com/Eabusham2/router-vpn/actions/runs/42220220946/job/127907229708)
passed the WG/AWG packet families and the six existing association-retirement
leaves, then failed Server selected-DNS proof. Its new original-exchange
observation was `class=deadline errno=0`. That result alone does not locate the
missing packet or identify an SS forwarding defect.

A separate address-path review found an invalid fixture projection before the
final SS handler. The fixture changes the captured relay listener from
`10.78.0.1` to local `127.0.0.1`, but had forwarded the real SOCKS UDP
reply's loopback bind address unchanged. The pinned
[sing client](https://github.com/SagerNet/sing/blob/v0.9.4/protocol/socks/client.go)
dials that returned address literally; its
[server handshake](https://github.com/SagerNet/sing/blob/v0.9.4/protocol/socks/handshake.go)
advertises the actual local UDP listener. The pinned
[WireGuard stack](https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/transport/wireguard/device_stack.go)
uses the default
[sing-tun IPv4 stack](https://github.com/SagerNet/sing-tun/blob/v0.9.3/stack_gvisor.go).
Its pinned
[gVisor IPv4 receiver](https://github.com/SagerNet/gvisor/blob/v0.0.0-20260727.0-sing-box-mod.1/pkg/tcpip/network/ipv4/ipv4.go)
rejects loopback source/destination packets on that non-loopback interface.
The current source pin and all dependency versions were checked directly.

The fixture now maps only the already validated UDP reply's IPv4 address back
to the exact captured lease host. It captures that host under the existing
process ownership locks and retains the authenticated response status, real
UDP port, original control/process association and expiry. The CONNECT branch,
destination admission predicates and network-stack loopback protection retain
their existing behavior. This reverses the fixture's listener-address mapping;
it is not a new production routing policy.

The existing mandatory `api-original-challenge-and-stop-receipt` leaf now
performs a real authenticated UDP association through the same fixture bridge,
checks the captured host and original owned port/control, and verifies bounded
control drain after Stop, withdrawn packet admission and removal of the UDP
tuple. It sends no SS payload. Existing parent/leaf inventories remain unchanged.
The old address forwarding would fail the new host assertion by source analysis;
an executed old-source causal control is not claimed.

Both affected proof failures now print a fixed numeric projection of their
single existing stats reply alongside the original lease diagnostic. Labels
distinguish attempted relay UDP writes, final-peer packet arrival and decoded
DNS counters; local-lane counters are also included. No extra probe or new
success criterion is introduced, and private node identities or credentials
are not added to output.

Root and two Astra reviews checked the pinned source path, reply validation,
lock order, exact port ownership, channel-synchronized join result and cleanup.
No local compile or native execution was available. The actual association
test and full Server DNS/WFP path must still execute on the published source;
the projection correction alone does not establish Server acceptance.

### Android SS fixture owns its actual JSON dependency

[The bab34 Android/native-parser job](https://github.com/Eabusham2/router-vpn/actions/runs/42226553733/job/127922137133)
passed the Xray consumer fixture with 87 graphs and 1,777 executable checks,
then stopped before the SS service fixture could compile its Java harness:
the real Android JSON jar was unavailable in that second Python process.

The preceding Xray fixture correctly owns its checksum-pinned temporary JSON
artifact and restores its process environment when it exits. That ownership
does not transfer to the next command. The SS service fixture now uses the
same existing `android_json_dependency` helper in its own temporary lifetime,
covering the complete Java/Go execution and restoring any original
`ANDROID_JSON_JAR` value in `finally`. Explicit overrides retain their
authoritative failure behavior; the helper still checks bounded file contents,
pinned download identity/checksum and required unique JSON classes.
The complete Java harness and negative cases are byte-identical.

Validation before publication was root and Astra source review against the
already executed Xray wrapper and shared dependency helper. No local execution
was available. The earlier Xray result is actual evidence; the repaired SS
consumer fixture still needs its own execution result. This does not add a
dependency or substitute a JSON implementation in the shipped Android app.

### Bound the complete Go suite separately from its operation deadlines

Two bab34 workflows reached Go's default ten-minute package alarm:
[Multihop job 127921401276](https://github.com/Eabusham2/router-vpn/actions/runs/42226553468/job/127921401276)
ended at 600.024 seconds while its current ViaEntry leaf was one second old;
[Release gap job 127921567146](https://github.com/Eabusham2/router-vpn/actions/runs/42226553522/job/127921567146)
ended at 600.027 seconds in a different, newly started Speed Lab leaf.
Neither log identifies the same stalled test. Earlier complete c602 runs passed
in
[547.867 seconds](https://github.com/Eabusham2/router-vpn/actions/runs/42220221024/job/127900246657)
and
[565.829 seconds](https://github.com/Eabusham2/router-vpn/actions/runs/42220220780/job/127900299457),
already close to the aggregate limit. No client/shared Go source or module
dependency change was introduced between those checkpoints by the fixture work.

Only the two observed workflow commands now append `-timeout=15m` to the same
complete `go test ./cmd/client ./internal/common` invocation. Fifteen minutes
is an explicit bounded allowance for the whole package, not a new product
latency or connection deadline. Every test and negative case remains selected;
the five-second Speed Lab proof context, ViaEntry request/cleanup limits and
all other operation deadlines retain their source values. The existing full
audit command prefix is also preserved. Other workflows were not changed
without a corresponding failure.

Root and two Astra reviews checked the failed stacks, earlier successful
durations, workflow contents and audit marker. Apart from the appended package
budget and its comment, the workflows are byte-identical. No local execution
was available; the complete suites must still pass under the recorded bound,
and a future test-specific stall must be investigated as such.

## Remaining work and acceptance boundaries

1. Finish and execute the installed Linux resolver/helper/service composition.
   Original-daemon capture, local-only preflight, finite grants and the supported
   parallel equal-best scope caller and joined group retirement are published.
   Privileged original-kernel/expiry/ACK-recovery and installed service acceptance
   remain open. Opportunistic transport and its shipping startup adapter are
   published. Captured DNSSEC child/cohort integration, cross-domain alias
   traversal, authenticated sticky-DO compatibility continuation, and the typed
   root-trust collector are now published bounded paths. Remaining DNSSEC
   semantic branches still require implementation/evidence. The exact three-label
   DS model, authenticated-child controls, original protected transport and
   shipping lookup caller are published. The twenty-case installed inventory
   and missing-parent causal gate are also published; their actual privileged
   execution is still pending. Transient monitor
   fields or generic bogus/transport results are not fallback authority. Actual
   Unix monitor, original D-Bus broker and installed native acceptance remain
   pending. A configured mode or unauthenticated snapshot is not negotiated-state
   proof.
2. Execute macOS/Linux SS-entry to Hysteria2-final mandatory native encrypted,
   policy, cancellation and restoration acceptance. Host admission is now published
   in `a2e4f201`; source/provider success does not establish PF/TUN acceptance.
3. Resolve current native CI findings against the exact failing source and rerun
   authoritative package/image/compose/publication verification for the resulting
   commit. The older `745b3e41` release cannot close newer source work.
4. Continue the complete protocol/graph/platform ledger, including presently
   unsupported imported families, broader Start Layer compositions and applicable
   Server/Compare execution. Mobile SOCKS5 to paired SS/HY/WG/AWG Local paths and retained desktop SS-entry
   independent layers to SS/HY2 are now published as bounded increments. All five
   paired mobile finals support Off, AES-256-GCM, and AES-256-GCM + XOR whitening behind ordinary SOCKS; the independent entry/final layer matrix and its bounded packet envelopes are now published. Server/Compare remain open for this imported-entry direction.
   Twelve mobile CONNECT-to-SS2022 Local graphs with selected literal TCP DNS
   are published; CONNECT UDP/Home DNS and independent layers remain open.
   Wider graph/mode coverage must still be implemented and verified. Safe refusal is
   unfinished scope, not delivery. Windows paired WG to external SS2022 now has
   bounded Local, Server and Compare host integration with both layers Off.
   Independent Windows layers and actual WFP acceptance remain open; broader
   imported graph directions retain their separate requirements.
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

## 2026-11-06 — Complete Android runtime contract job budget

The Android runtime-truth job for source `9a558ef5873ad7bba983e0a568a2748dd99ea41e` (run 42229596587, job 127931769287) was cancelled near its configured 15-minute job limit: it started at 13:56:45 UTC and logged cancellation at 14:11:58. It had completed script 36 of the runner's 53 sequential executable-contract scripts. Seventeen scripts, four subsequent pinned/graph-host checks, and the final Android SS host-capture command remained. The generic cancellation log alone does not identify the cancelling actor.

The later completed source audit on `0ab1606cf663c7faf215e2a804a76ed652f76322` independently establishes the full workload: Android syntax first reported at 14:25:09 and the complete runtime-truth child passed at 14:48:48, approximately 23 minutes 39 seconds later. It includes the final actual SS source-capture positive and negative controls. This observed complete run exceeds the standalone job's old 15-minute allowance.

Only that standalone job's aggregate allowance changes to 30 minutes. The entire command, all scripts and assertions, existing operation deadlines, and final host-capture command's 300-second bound are unchanged. A new standalone run must still establish sufficiency with job setup included. No production timeout or Android device claim follows from this change.

### Completed evidence for the parent source and related native runs

- The authoritative source audit on `0ab1606c`, job 127932408608, completed successfully. It records all 59 toolchain tests passing in 363.221 seconds and all 18 dependency tests passing in 17.623 seconds, including the corrected all-target notice producer boundary. Its full cmd/client invocation passed in 565.790 seconds. Repository, accounting, and Setup Center/AI steps all completed.
- The two separately revised Go jobs on `0ab1606c` passed: Release gap cmd/client took 541.159 seconds; Multihop cmd/client took 547.531 seconds and all 26 Python checks passed.
- Native-Xray job 127932639050 on `9a558ef5` completed successfully. It includes 77 Android SS service checks, the two actual SS source race cases, the native engine build, and validation of 174 Android and 174 Apple graph files through the actual native registry. Graph validation does not establish physical networking.
- Both AMD64 and ARM64 Server jobs on `bab34e59` passed all six association leaves. Five positive cases reached teardown after actual selected DNS/public proof and native ownership checks. Seven cases per architecture then failed authenticated lease cleanup. The production cancellation/cleanup ordering remains open; no cleanup guard was relaxed.
- Windows native job 127923331079 on `bab34e59` ran and passed the new refused-Connect observation case and rejected all 18 existing identity mutants. It later failed the first live MTU fixture at its unchanged 25-second subprocess limit. That later failure remains a separate investigation.

The complete source audit is a source and executable-contract result. Native release failures, wider source requirements, package publication for this continuation, private deployment, and physical-device acceptance remain separate.

Evidence: [completed source audit](https://github.com/Eabusham2/router-vpn/actions/runs/42229778982/job/127932408608), [standalone Android cancellation](https://github.com/Eabusham2/router-vpn/actions/runs/42229596587/job/127931769287), [complete native Xray validation](https://github.com/Eabusham2/router-vpn/actions/runs/42229596513/job/127932639050), [Server AMD64](https://github.com/Eabusham2/router-vpn/actions/runs/42226553516/job/127927707983), [Server ARM64](https://github.com/Eabusham2/router-vpn/actions/runs/42226553516/job/127927707569), [Windows native identity and MTU](https://github.com/Eabusham2/router-vpn/actions/runs/42226553579/job/127923331079).


## 2026-11-06 — Owned unavailable TCP reservation for Windows OpenVPN

The AMD64 native OpenVPN job on `bab34e59` (127927707989) passed all nine TCP and all nine UDP leaves, then its first mixed-transport positive leaf. Eight later mixed leaves failed during fixture startup with `unavailable-port-reservation errno=10013 network=udp4 operation=bind`. The unavailable TCP address allocator unnecessarily probed UDP and returned a port after closing both temporary listeners. This is separate from the pending-connector inspection in the wrong-control-key case.

The Windows fixture now retains an exclusive IPv4 TCP socket bound to the unavailable port without calling listen. It owns its Winsock lifetime, verifies the exact bound address and non-listening state, and keeps the reservation until the corresponding provider and reference peer have closed. There is no UDP probe for this unavailable TCP candidate. The production provider-port allocator and non-Windows fixture default are unchanged.

A mandatory native alias leaf checks the actual refused TCP connection, rejects a competing bind while the original reservation is owned, releases and rebinds the exact port, and verifies that closing the retired owner again cannot close its replacement. Close is synchronized and idempotent. The reservation callback is private to this fixture invocation; it cannot change an unrelated test's allocator.

All 27 existing TCP, UDP and mixed-transport verdicts and the strict ALE/WFP ownership controls remain mandatory. The alias inventory increases from ten to eleven and keeps the existing rejection of missing, duplicate, counterfeit-prefix, failing, skipped and race-affected output. This change does not reinterpret a pending connector, accept an incomplete native snapshot, or claim the wrong-key witness failure is solved.

Validation before publication: root and two independent Astra reviews of the exact candidate; pinned Windows syscall signatures and Winsock constants checked against their primary source; original provider allocator and existing transport-case bodies confirmed unchanged; preparer inputs and phase hashes checked to include the actual modified templates and runners. The complete five-file candidate was also independently read from an unreferenced review commit. No local compile, native execution or new causal-control pass is claimed for this change. Exact new Windows runs remain required.

Evidence: [AMD64 native OpenVPN run](https://github.com/Eabusham2/router-vpn/actions/runs/42226553516/job/127927707989). The existing Server lease cleanup and pending mixed wrong-key inspection failures remain open independently.


## 2026-11-06 — Preserve the failing Windows MTU live-fixture phase

Windows native job 127923331079 on `bab34e59` passed 107 shipping MTU source checks and then exceeded the unchanged 25-second subprocess bound in its first PowerShell live case, `accepted`. The captured command output was discarded when Python raised TimeoutExpired, so that failure did not identify whether startup, UI creation, dispatcher work, measurement, cancellation, or cleanup consumed the budget. The HTTP server's connection reset was logged at child termination and does not establish the original cause.

The Python wrapper now prints a bounded tail of captured stdout and stderr before re-raising the original TimeoutExpired exception. It prints at most 8,192 bytes or characters from each stream and never prints the command arguments. Diagnostic output errors cannot replace the original timeout. Normal command handling is unchanged.

The PowerShell fixture adds fixed live-phase markers around source loading, owner/panel creation, status acquisition, retest and cancel dispatch, terminal observation, and drain/close. These markers carry no credentials or dynamic connection profile. Removing the markers reproduces the original PowerShell executable lines and assertions exactly.

The 25-second process bound, 8-second live bound, HTTP bounds, all accepted/cancelled/stale/failure expectations, and every existing causal mutant remain unchanged. The same relevant source previously completed both PowerShell 7 and PowerShell 5.1 live cases on `98f08601`; elapsed time alone does not justify increasing a leaf deadline. This commit supplies the missing phase evidence for the next actual Windows run; it does not claim the underlying delay is fixed.

Validation before publication: root and independent Astra source review, exact original-line preservation, and fixed-input/output-bound inspection. No local execution is claimed. Evidence: [actual failed native MTU job](https://github.com/Eabusham2/router-vpn/actions/runs/42226553579/job/127923331079).


## 2026-11-06 — Compile iOS MAX with its actual captured SS helpers

Both the standalone iOS smoke job 127932413496 and authoritative iOS job 127932408863 on `0ab1606c` failed in the MAX fixture's generated Swift compilation because its extracted startMultihop implementation calls validateCapturedSSSource and capturedSSProfile, but the fixture omitted those shipping methods. The earlier owned-strategy CryptoKit correction had already allowed 117 owned, 77 provider, and 53 driver checks to pass.

The MAX fixture now extracts the existing contiguous shipping range beginning at validateCapturedSSSource and ending before strictKillSwitchRequested. That range contains exactly the two missing captured-source helpers and the already included layeredProfile parser. It is the same helper range used by the existing SS DNS fixture. Both referenced helper types are already part of this fixture's Swift compilation.

All following cases and mutations are unchanged. The composite fixture imports the same MAX prefix and receives the same real methods. No production source, mocked replacement helper, weakened validator, extra lifecycle behavior, or new compile dependency is introduced.

Validation before publication: root and two independent Astra source reviews, exact extraction boundaries and compiled helper inputs verified, and the remainder of the fixture confirmed byte-for-byte unchanged. A fresh actual Swift/native run remains required; this source correction alone is not an iOS package or device result.

Evidence: [standalone iOS compile failure](https://github.com/Eabusham2/router-vpn/actions/runs/42229778716/job/127932413496), [authoritative iOS compile failure](https://github.com/Eabusham2/router-vpn/actions/runs/42229778982/job/127932408863).


## 2026-11-06 — Bound the complete Windows ALL positive composition suite

The authoritative AMD64 ALL job 127932408655 on `0ab1606c` reached Go's four-minute aggregate alarm while running the four positive composition parents in one process. The first three parents had passed in 92.50, 73.33, and 18.92 seconds, leaving approximately 55 seconds for all four restoration leaves. The alarm caught the second restoration leaf ten seconds after it began. Its stack was inside actual durable Windows file-store work; that snapshot does not demonstrate a stuck syscall or a failed per-operation deadline.

The exact same source's ARM64 job 127932408807 passed all 26 required positive verdicts and all eight causal controls. Its four positive parents took approximately 129 seconds in total. The suite retains real store ACL, flush and rename operations alongside virtual operation timers, so aggregate wall time varies with native filesystem work.

Only the complete positive ALL process allowance changes from 240 to 360 seconds, with the existing 15-second process-management margin producing a 375-second outer bound. This matches the runner's existing bounded baseline-group policy. Compilation remains bounded at 240 seconds; each separate mutant remains at 60 seconds with a 75-second outer bound. All 26 verdicts, eight mutants, production deadlines and individual operation timers are unchanged.

The runner's six positive-branch budget expectations change together with the single positive duration expression. Root and independent Astra review checked the exact branches, original source preservation outside those replacements, and both completed native logs. No local execution of the changed runner is claimed. A fresh AMD64 pass and repeat ARM64 execution remain required; this change does not turn controller composition into actual WFP/PQ or device acceptance.

Evidence: [AMD64 aggregate alarm](https://github.com/Eabusham2/router-vpn/actions/runs/42229778982/job/127932408655), [ARM64 complete ALL pass](https://github.com/Eabusham2/router-vpn/actions/runs/42229778982/job/127932408807).


## 2026-11-06 — Complete macOS native-sockets job allowance

The Intel native-sockets job 127932408888 on `0ab1606c` started at 13:59:35 UTC and logged cancellation at 14:34:48, near its configured 35-minute job limit. It passed the 41 runner tests, completed the positive native cases, and rejected 42 of the runner's 44 causal mutations. The last completed control was quick-deny-before-foreign-pass at 14:33:27. Per-socket retirement and descriptor-finish acknowledgement controls remained. No completed assertion failure or Go package alarm appears at that cancellation boundary; the generic cancellation message alone does not independently identify its actor.

The native-sockets matrix job now has a bounded 45-minute allowance so the complete existing sequence can finish. No case, mutation, command or individual deadline changes: each native case keeps its 12-minute Go alarm and the wrapper keeps its 730-second bound. The separate anchor-lifetime job remains at ten minutes. A complete fresh Intel and ARM64 run must still verify this aggregate allowance.

This change does not address the separate ARM64 retirement failure in job 127932409218. That run exhausted the existing 12-minute individual case bound while waiting for original socket/guardian retirement. The same capacity case previously passed on the same recorded OS/image/toolchain in standalone job 127900106780, and its relevant source inputs did not change. The authenticated revoke-rejection lifetime defect and native diagnostics are being repaired separately; no native ownership check is relaxed here.

Validation before publication: root read the completed Intel log and exact runner/workflow; independent Astra review reconciled the full 44-control inventory and prior ARM64 result. Only the one job allowance and explanatory comment change. No local execution is claimed.

Evidence: [Intel job cancellation](https://github.com/Eabusham2/router-vpn/actions/runs/42229778982/job/127932408888), [separate ARM64 retirement failure](https://github.com/Eabusham2/router-vpn/actions/runs/42229778982/job/127932409218).


## 2026-11-06 — Retire an invalid Darwin guardian channel after revoke rejection

An authenticated revoke rejection already invalidated its captured policy, but callLocked closed the original control channel only for a rejected grant or malformed/mismatched reply. Socket drain kept retrying revoke while exceptional PF cleanup required the original guardian to join. Leaving the rejected channel alive could prevent that existing cleanup path from progressing.

The production predicate now closes the same original channel for an authenticated rejected revoke as well. It retains the attempted request sequence and all reply authentication, admission and ownership checks. EOF affects only the original guardian. Revoke/Release still require actual guardian join and independently verified removal of the old PF generation before releasing bound descriptors; a replacement dispatch and the fail-closed baseline remain protected.

The first native PF rejection that triggered the earlier ARM64 capacity hang is still unknown. This commit repairs the separately established channel-lifetime defect, without claiming that every intermittent native cause has been identified.

### Required regression coverage

The existing mandatory native StaleCaptureAndReplacement case now creates an actual owned UDP exchange, captures its acknowledged grant under the existing lock order, installs a fixture-owned reference to the old generation and a separate replacement dispatch, and requires the original guardian's authenticated PF-owner rejection. It then checks channel closure and actual guardian join. A still-retained old namespace must continue to block broker completion and source-port reuse. Only after removing that exact additional reference may the old descriptor drain and its port become reusable; the replacement namespace, dispatch and baseline must remain unchanged.

A new native causal mutation restores precisely the old revoke-channel behavior. The fixture records that defect, closes only its own original channel for cleanup, and fails its dedicated assertion after cleanup. A timeout, panic, unrelated failure or leaked recovery remains insufficient evidence. Native required positive inventory stays at 35; the mutation inventory increases from 44 to 45.

The portable extracted-shipping-method fixture preserves all six scenarios, including non-retiring probe rejection and successful grant behavior, while separately rejecting broken grant and revoke retirement. It now executes the baseline plus four causal variants. The runner still has 41 unittest methods.

The capacity case retains all 130 actual socket iterations. A 15-second fixture-only close bound reaches its existing bounded read-only first-loss, last-failure, descriptor and PF diagnostics before a package alarm can hide them. It does not release a descriptor, return fake close success or alter a production deadline. The existing 12-minute native package bound and 730-second process wrapper are unchanged.

Validation before publication: root traced the actual production call, revoke, close, PF absence and broker-drain paths; a second Astra agent independently reviewed the exact five-file candidate, native types, lock order, cleanup references and original-owner preservation. All five source files were reread at the parent and preserved exactly outside the reviewed changes. No local compilation, native execution or causal-test pass is claimed. New exact-source native runs remain required.

Evidence: [earlier ARM64 retirement hang](https://github.com/Eabusham2/router-vpn/actions/runs/42229778982/job/127932409218), [prior c602 ARM64 run that passed capacity and its retirement control](https://github.com/Eabusham2/router-vpn/actions/runs/42220221121/job/127900106780).


## 2026-11-06 — Bound and serialize the actual OpenVPN provider IPC lifecycle

The native OpenVPN fixture previously wrote requests without a shared operation deadline and then started a separate read timeout. A pipe blocked during Encode could outlive the observation, and simultaneous observers could consume each other's replies.

The original provider process now owns one serialized request/reply permit. The same absolute caller deadline bounds queue admission, write, strict reply framing and the successful worker join. Cancellation while queued does not write a request or stop the active caller. Once an exchange has entered, a failed write, read, frame or deadline irrevocably poisons that original process: cancel the child first, close both owned pipes, and join its worker and process under a separate bounded cleanup context. No replacement reader or process adopts the operation. Idle Close retains graceful EOF cleanup; active Close cancels first, and repeated Close is idempotent.

Existing 16 KiB newline framing, exact transport and original tuple checks, AppID attribution, provider lifetime and the 10-second initial/observation budgets remain unchanged. Error reporting records fixed failure classes and context errors without dumping requests or private configuration.

The existing mandatory provider-join tests remain intact. Eight additional real-pipe and owned-subprocess regression leaves cover normal/idempotent use, a genuinely queued deadline while the active exchange is latched, blocked reads, a 2 MiB blocked write, active Close, malformed replies, oversized replies and changed transport identity. The runner requires exactly one PASS for the parent and each leaf and rejects missing, duplicate, skipped, failed, race, panic or build results. Each failure checks that the original worker/process has joined and that its reader cannot be reused.

Validation before publication: root inspected the actual prepared source and original baseline; a second Astra agent independently reread the concrete two-file review commit and confirmed the original source semantics, cancellation ordering, queue latch and exact eight-leaf inventory. The execution workspace remains unavailable, so no compilation or regression execution is claimed for this change. Actual CI must execute it.

Separately verified upstream native evidence: both Windows ALL jobs at 101aa60e completed all 26 required positive verdicts and eight causal controls. The 6aac340a AMD64 OpenVPN job passed the new unavailable-TCP reservation leaf, all nine TCP cases, all nine UDP cases and eight mixed cases. Its remaining mixed/control-key failure still reports the initial TCP socket's strict native readback error; the final UDP MAC-rejection witness is separate pending work. These results do not establish completion of the newer IPC source or all product requirements.

Evidence: [Windows ALL AMD64](https://github.com/Eabusham2/router-vpn/actions/runs/42238536335/job/127962465505), [Windows ALL ARM64](https://github.com/Eabusham2/router-vpn/actions/runs/42238536335/job/127962465697), [6aac340a OpenVPN AMD64](https://github.com/Eabusham2/router-vpn/actions/runs/42238149378/job/127961121286).


## 2026-11-06 — Witness the actual OpenVPN control MAC rejection on the final UDP path

Both 6aac340a native jobs now independently pass the unavailable-TCP reservation regression and 26 of the 27 transport leaves. Their remaining mixed/control-key failure inspected the initial pending TCP socket while trying to establish the final UDP authentication rejection. That observation is not evidence that the final provider actually rejected a control MAC.

The Windows OpenVPN phase now installs explicit compiler-only instrumentation into the verified pinned OpenVPN module. The original codecs retain their signatures, cryptography, replay and short-packet behavior. An observer runs only after every MAC candidate failed. A private provider-context collector records at most 64 immutable metadata events, detects overflow or original-owner changes, and rejects new observations after cancellation. Accepted server protection immediately drops its per-packet callback, so it cannot retain or later misattribute an earlier packet.

A separately captured initialized client session supplies its original packet object, fresh session token, transport generation and actual local/remote tuple. The clear session token is correlation data, not authentication. The native wrong-key test waits for the actual final UDP session, obtains the real provider MAC event through its original bounded IPC process, brackets that observation and the strict native snapshot with the same client view, and matches the original source address, native grant and socket. Two observations must use higher transport generation, a different session token, a different native SocketID and a later genuine provider event. Retransmission, port reuse by an old socket, stale history and a replacement session cannot become another successful retry.

Every native inspection error remains fatal. The native snapshot retains its complete WFP/ALE checks; only acquisition of its same existing composition mutex becomes context-aware in the owned compiler copy. Existing context-aware remote and newly bounded equivalent status observations preserve the pinned status classification. The ten-second observation deadline, two-second snapshot context and one shared five-second proof-join allowance remain distinct from existing synchronous cancellation and bounded IPC cleanup. Final checks require actual network retirement and zero DNS, TLS or public traffic.

### Required executable coverage

All 27 existing TCP/UDP/mixed transport leaves and both original native causal controls remain. The added witness process requires 24 real-codec leaves across tls-auth and tls-crypt, plus 20 correlation/ownership leaves: 48 exact verdicts including parent/group results. The codec cases include successful primary and fallback candidates, wrong MAC, truncation, replay, authenticated malformed bodies, actual rate limiting, original server attribution, callback detachment, collector capacity, owner collision and cancellation. The fallback case first demonstrates a real failure using only the first distinct key candidate, then requires the full original decoder to accept its valid second candidate without emitting a rejection.

Two added causal builds deliberately suppress the actual MAC callback or remove the session-matching guard. They must fail their exact assertion; a timeout, panic, skipped case or missing verdict is insufficient. Existing executable hash checks remain, and the phase receipt now records all five compiled images. The phase command sum includes five compilations and nine executions without changing any individual native-case deadline or the workflow's 30-minute job cap.

Six additional compiler-composition tests verify original source/map preservation, changed-source and existing-owner rejection, exact causal overlays and unknown-control rejection. The complete Python runner has 48 test methods. The original prepared module is verified against its pinned official h1 and canonical additions before and after creating compiler overlays outside both source trees. Production sources and the module cache are untouched.

Validation before publication: root reviewed the pinned codecs/parser and actual shipping fixtures, then incorporated independent Astra review of all eight files, API/lock/cancellation boundaries, unique replacement anchors, source ownership and command/verdict inventories. Exact review files were read back remotely. No local compilation, regression execution or native witness pass is claimed; the execution workspace remains unavailable. Exact-source CI must establish those results. This is a targeted verification repair, not full product, release or device acceptance.

Evidence: [6aac340a AMD64 native job](https://github.com/Eabusham2/router-vpn/actions/runs/42238149378/job/127961121286), [6aac340a ARM64 native job](https://github.com/Eabusham2/router-vpn/actions/runs/42238149378/job/127961121250), [pinned raw/static-key parser](https://github.com/SagerNet/sing-openvpn/blob/103eb5fe5eb69b8e747971eaaf0185a6618b7da7/data_codec_static.go).


## 2026-11-06 — Preserve independent Windows provider images with smaller copy writes

The 6aac340a AMD64 packet suite reached its three-minute alarm while wireguard/reject/exit had spent about 83 seconds in provider setup. The stack was inside a single WriteFile request for 106,627,584 bytes, before the provider process and its own context were created. The fixture reread and recopied the parent executable for each reference peer. The log does not establish whether storage, scanning or another OS cause produced that delay.

The fixture now captures the original regular executable once per parent process, checking opened/named file identity, size and modification time around the read. The fixture cap is 512 MiB. Only an immutable string, exact size and SHA-256 remain cached; no executable path, descriptor, provider process or mutable byte slice is shared.

Each peer still receives a fresh file in its own TempDir, created exclusively with O_EXCL and the existing permissions. Copy writes use a reusable 64 KiB buffer, explicitly avoiding a whole-image fast path. Exact write counts and the captured digest must agree. A short write, changed bytes or unacknowledged close prevents launch. The original writer remains available to cleanup for a failed Close; cleanup runs before its own directory removal. Every original AppID, provider process/context, protocol assertion and native deadline remains unchanged.

Three extracted-shipping-helper regression leaves exercise independent file identity and exact bytes, refusal to adopt an existing file, captured source stability after path replacement, bounded write sizes, retained/idempotent close, short writes, write errors, tampering and failed-copy handle cleanup. The runner requires the parent and all three leaf verdicts. Existing provider-join and OpenVPN IPC classes are preserved byte-for-byte.

Validation before publication: an Astra agent traced the actual timeout stack and prepared the exact two-file unit; root independently read its full diff and source, checked existing caller behavior and unchanged earlier test classes, and verified both parent files before publication. No local execution or native improvement is claimed. Chunking limits bytes per write, not OS wall time; exact-source CI must show whether the observed packet-suite timeout is resolved.

Evidence: [actual AMD64 packet timeout](https://github.com/Eabusham2/router-vpn/actions/runs/42238149378/job/127961121154). The separate ARM64 job passed all three ordinary packet-family suites before reaching the independently tracked Server lease-cleanup defect: [ARM64 packet and Server job](https://github.com/Eabusham2/router-vpn/actions/runs/42238149378/job/127961121533).


## Windows native preflight fixture correction — November 6, 2026

Current-source evidence: Windows physical composition run [42248724369](https://github.com/Eabusham2/router-vpn/actions/runs/42248724369), source `df24940ec1e9fac935ab896f183acfa3e5c4965d`, failed in the shared scope/source preflight before the affected native phases could execute. The directly read AMD64 node-baseline job was [128010294640](https://github.com/Eabusham2/router-vpn/actions/runs/42248724369/job/128010294640). Its runner reported 48 tests with three failures and three errors. No OpenVPN witness or executable-copy native pass is inferred from this attempt.

The OpenVPN witness fixture already supplied the original native observer mapping, but built its keys from an unresolved temporary path. On Windows, the temporary directory can use a short user-profile alias; the composition helper independently resolves the real source path before requiring the exact observer key. The fixture now resolves its temporary workspace before deriving every captured path. The helper's exact-key and original-byte checks are unchanged. Two added cases explicitly reject a missing observer mapping and changed observer source.

The independent packaging expectation now requires five OpenVPN executable receipts: the original image and all four controls. The existing manifest already required those five images; the stale test expected three. Other phase counts and all negative receipt cases are preserved.

Validation before publication: root and an independent Astra reviewer compared the exact candidate with the current runner and composition helper; all changed bytes were fetched back from the review commit. There are now 50 runner test methods. No local Python or native execution is claimed while the execution workspace is unavailable. Fresh exact-source CI remains required.

### Separately observed completed checks

- The requirement-closure workflow on `df24940e`, [42248724078](https://github.com/Eabusham2/router-vpn/actions/runs/42248724078), completed successfully. The actual job log includes root `go test ./...` and that workflow's selected audits; it does not execute every generated Box/native composition fixture.
- Windows native contract run [42240610019](https://github.com/Eabusham2/router-vpn/actions/runs/42240610019) on `e7178b18` completed successfully, including job `127972588957` and both command-ownership architecture jobs. The prior MTU stage completed. This is distinct from the still-failing or pending physical/bootstrap packet and OpenVPN phases.
- Darwin guardian run [42243235694](https://github.com/Eabusham2/router-vpn/actions/runs/42243235694) on `44999fe7`: the Intel positive socket-retirement case passed, but the per-socket descriptor-retirement mutation lost a control reply at socket 35 and failed cleanup before its expected capacity assertion. A more direct retained-tuple regression is under review; neither the full guardian gate nor a complete release is established.

The Windows Server lease-cleanup production unit is still unpublished and undergoing exact-source/native-inventory review. Broader source, native, release, signing, deployment and physical-device requirements remain open as recorded above.

## Darwin original-descriptor retirement witness — November 6, 2026

This increment strengthens the actual `SocketRetirementReusesCapacity` fixture and its causal verdict. It preserves all 130 positive capacity cycles and the existing 15-second per-close diagnostic. After every joined connection Close, the fixture must bind and close the same original UDP source tuple. Application-side closure alone no longer supplies the positive evidence.

The deliberate missing-`ReleaseSocket` variant must now expose the retained tuple on iteration zero. Its accepted failure requires `EADDRINUSE`, a still-current original policy, successful bounded release of the exact captured `DesktopSocketCreation`, actual rebinding of that tuple, and closure of the rebound socket. Only after that recovery does it emit the required failure witness. A different owner, late capacity exhaustion, earlier timeout, or failed recovery cannot satisfy this control. The original guardian still checks the complete captured creation and absence of its grants before releasing its descriptor.

Mutation verdicts also reject the existing native broker-drain and guardian-close error diagnostics. The original positive inventory and all 45 causal controls remain present. Production Darwin control deadlines and behavior are unchanged. This is a more direct causal test; it does not establish why the earlier control reply exceeded its budget or claim that every transient native delay is resolved.

### Executed validation and limits

The execution environment became available again in a fresh workspace. The previous scratch checkout was absent there, so a new clean checkout was made from verified main and the review commits were tested separately. Go `1.26.3` was installed from its official release archive, checked against the official SHA-256 `2b2cfc7148493da5e73981bffbf3353af381d5f93e789c82c79aff64962eb556`. No earlier private or unpublished scratch recovery is inferred.

- Root and an independent Astra reviewer examined exact review commit `1562a8212cdc86af20976f9bece4ec213da269bc`.
- The four actual `DarwinMutationOverlays` Python regressions passed in 0.046 seconds, including the new first-tuple/cleanup rejection cases and exact source-mutation checks.
- The full Darwin Python runner executed 42 tests: 41 passed; the existing actual control-channel regression failed because this executor denied creation of its AF_UNIX listening socket with `operation not permitted`. That required test was neither skipped nor weakened. The full suite is not recorded as passing.
- The updated native Go test source parsed successfully with the pinned Go formatter. Native PF behavior and the new real tuple witness still require macOS CI.

### New bounded Windows evidence

The completed AMD64 job [128010294640](https://github.com/Eabusham2/router-vpn/actions/runs/42248724369/job/128010294640) at `df24940e` contains successful compilation and execution before its later scope-fixture failure: all eight extracted-source OpenVPN IPC cases, all three independent provider-image cases, all four original-provider-join cases, and bounded diagnostics passed. This establishes those specific executable ownership checks. It does not establish the full OpenVPN wrong-key witness, actual packet graphs, or elimination of the earlier large-image native timeout.

The separate Windows Server production candidate remains under validation: its 14 shared lease test parents and 21 child verdicts passed under Go `-race` (2.025 seconds), and 32 targeted Python runner/scope tests passed. Generated Box compilation and actual Windows native execution remain separate gates. No complete release, private deployment, or physical-device acceptance is declared.


## 2026-11-06 17:15 UTC — preserve the original Darwin operation failure when its reply cannot be delivered

The exact `17ccb6ac0e7d3a1409d2abb95e274619522d5477` macOS physical ownership run
`42256007996` completed with the Apple Silicon guardian job `128023266275`
successful and both single-filter anchor jobs `128023265375` /
`128023265738` successful. Intel guardian job `128023266105` failed in the
ordinary positive `SocketRetirementReusesCapacity` case at sequential socket
24. Its first recorded loss was `control-receive-probe` after 2,020 ms, with
no pending control frame. The guardian's only final transport diagnostic was
`write unix: sendmsg: broken pipe`. This is not a passing Intel capacity test,
and the successful other jobs do not close it.

The guardian already placed an operation failure, including bounded native
readback progress, into `reply.Error`. If the parent had retired that exact
channel, the failed send returned only the transport error and discarded the
original operation error. `desktop_socket_darwin_helper.go` now joins both
errors on that existing failed-send branch. It still returns a nonnil error,
performs the same original cleanup, and changes no admission, frame, proof,
freshness, deadline, or retry behavior. If the operation error is nil, this
change supplies no invented cause.

Validation: independent review of the switch's assignment, callers and error
handling; `git diff --check`; Go 1.26.3 Darwin/AMD64 non-CGO package test-binary
cross-compilation, exit 0. That cross-compilation does not execute macOS or
validate the native CGO PF implementation. The exact operation failure and
any corrective production change still require subsequent native evidence.
No new release or deployment is established by this diagnostic change.


## 2026-11-06 17:19 UTC — retain authenticated Server cleanup through terminal data retirement

This unit addresses the observed Windows Server cleanup failures by separating
terminal ordinary-data retirement from the original lease's fixed authenticated
stop operation. The reviewed source is
`b05511a520229ce8a7166f71bbf8112ef35afb42`, following
`7516473e7b66ea91a40bf85d611825aba215e054` and
`459e0beceae362915b10add2f82f0067590073ba`.
Its twenty-one source/test files are applied to the current normal ancestry
after `cffeed1211f539e9d38eab3a5b39dc6b12be6754`, preserving the separately
published OpenVPN fixture and Darwin corrections.

Before the final challenged PUT can have a server-side effect, the controller
seals an argument-free DELETE capability bound to the original private API,
token, proposal, challenge, node, session and entry. It does not expose a new
address-, method-, or body-taking control interface, borrow the ordinary system
resolver, follow redirects, or accept a different node/session acknowledgement.
A timed-out PUT retains that original cleanup owner. Active comparison release
and subsequent reacquisition keep their original separate captures.

The Box lifecycle now arbitrates Active, Terminal and Failed transitions
atomically. Terminal retirement closes ordinary admission and joins its
original native retirement barrier and entered data I/O before the captured
stop request can run. A stale observation which began before Cancel cannot
destroy that separately retained terminal capability or publish a late
ordinary identity. Genuine owner loss or replacement still fails closed and
immediately denies admission, including while physical retirement is blocked.
Windows retirement proves the original TUN/WFP keys absent and the baseline
present; it cannot rebind the retired TUN. A failed or expired barrier does not
authorize DELETE. A failed close, ambiguous acknowledgement, or unfinished
original operation retains the owner for cleanup rather than substituting a
new stream or declaring that expiry proved success. Non-Windows behavior where
the native barrier is not required remains separate.

The shipping generated-source checks include the exact new lease files and
their existing fixture dependencies. The Windows gate preserves its Local
and Compare inventories and the current twenty-five Server verdicts. Six
causal variants are registered: four portable Box lifecycle controls and two
actual native Server/WFP controls. Every control rejects unrelated panic,
race, timeout and cleanup failures as substitutes for its intended witness.
No production or per-process test timeout was increased.

**Executed validation, with its limits:**

- Shared lease tests under Go 1.26.3 `-race`: fourteen parent tests and
  twenty-one child verdicts passed in 2.025 seconds at `7516473e`. The
  successor changes only a generated Box test's join ordering.
- Fresh official desktop preparation at the reviewed `b05511a5` source
  verified all 2,179 captured source records. Pinned core
  `1ac1a339cb1223e9c70eae14c44411c75033c02d`, Xray
  `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`, Go 1.26.3; desktop input
  digest `a918385cfbfa9bfaae4dc1ab3ac2ec56a41ba9f367dfa73ba14d1bad3b3f0781`.
- The real generated Box compiled with its pinned feature tags and
  `-race -mod=readonly` in 49.662 seconds. All twenty-one required
  `TestRouterVPNExternalLease` verdicts passed in 1.462 seconds.
  The 137,446,584-byte baseline image has SHA256
  `2cc16d613944cf2e6356f7ff6e85488b1017074f9b4cbc759f3198bd14620abc`.
- Four independently compiled broken Box variants were rejected for the
  intended missing Cancel join, terminal arbitration, final identity guards,
  and immediate Failed-state admission. Their seven designated leaf failures
  all appeared without cleanup errors or panic. Compile durations were
  44.842–49.468 seconds; executions were 0.064–3.075 seconds. These are
  Linux/AMD64 Box/control results, not executed Windows WFP evidence.
- Twenty-four selected runner scope/orchestration/OpenVPN witness tests and
  eight native-node source-scope tests passed. Windows AMD64 and ARM64
  `internal/mobiletor` test binaries cross-compiled successfully with
  CGO disabled. Cross-compilation does not execute either native platform.

The first missing-final-identity causal attempt correctly exposed a test
cleanup defect: its fatal assertion ran before the original cancellation
worker joined. The final review moves that join before evaluating the
captured failure result, without changing production behavior; all corrected
controls were rerun. A full-preparer re-entry also proved non-idempotent after
its final module tidy and left an incomplete MTU projection. That tree was
not compiled or accepted. A fresh official checkout/preparation supplied the
verified final tree; no checksum or generated-source check was weakened.

The two actual Windows Server/WFP causal controls and complete native packet
execution remain pending exact-source CI. No all-platform release, private
deployment, or physical-device acceptance is established by these local
results. The larger requirement ledger remains open.


## 2026-11-06 17:44 UTC — Windows paired entry with independent final Start Layers

Seven exact reviewed files from `3b3c39ee8c89e063e71b3db63cd89799484382e5`
(tree `6cd3caa8ac2d837f7325e9007ba715f82427991f`, following
`e86535ed8c9d2efd9359ff0f96911d8e47fad310` on `de796794`) form this
bounded source implementation. This is fresh work against current source;
the unavailable historical twenty-file draft was not reconstructed.

The shared compiler already generated independent final layers for the paired
WireGuard-entry graph. Four Windows integration gates rejected that result:
the adapter's Off-only/three-row assumption, the client profile predicate,
physical-policy adoption, and protection selection. These gates now retain a
paired WG entry with its layer Off and an SS2022 final with its independently
captured AES-256-GCM or AES-256-GCM + XOR whitening layer, across Local,
Server and Compare. The entry-layer restriction remains an unfinished scope
item; this change does not claim independent entry-layer delivery.

The adapter derives expected inner and optional outer rows only from the
original sealed profile, using the existing transport compiler and
`WrapStartLayer`. It requires complete row equality, unique exact tags and
row counts, original credentials and tuples, the entry detour, authenticated
relay credentials, and the captured selector. Candidate rows cannot provide
their own expected authority and are not resealed. Physical preparation and
protection selection retain that exact typed policy and source/config/session
identity. The published Server cleanup implementation is unchanged.

Actual Go 1.26.3 race-instrumented validation, with the existing 60-second test
bounds:

- Shared Windows Router policy suite: nine parent and 109 subtest verdicts
  passed; package time 2.920 seconds.
- New client source/protection/measurement-capture/restoration suite: four
  parent and 102 subtest verdicts passed; package time 8.215 seconds.
- Existing Off Server/Local/Compare source and restoration regressions: five
  parent and twenty-five subtest verdicts passed; package time 1.652 seconds.
- An isolated overlay removed only the exact inner/outer row comparison.
  AES and AES+XOR with substituted inner and outer keys produced exactly four
  intended credential-substitution failures, without panic, race or timeout.

These are test verdict counts, not a requirement denominator. The client
matrix covers both final layer choices, all three inner SS2022 ciphers, both
required protection settings, Local/Server/Compare, and restoration of an
already-proved winner with a fresh session/lease proposal. Source replacement
controls and failure when the restored physical policy is missing remain.
Actual tests first exposed the old rejection, then the additional missing
physical-adoption and protection-selection gates; all assertions were kept.

Independent source review accepted both exact revisions. The final seven
source hashes and `git diff --check` passed. The frozen verification manifest
SHA256 is `b64ca845411b7816cb4cd439c7dff655c40af9bb8dc7e86bab4f3b2817e92212`.

No encrypted SS provider or native Windows WFP operation was executed for
these new layered scenarios. Native wrong-key, selected-DNS, cancellation,
restoration and original-owner cleanup acceptance remains required. Existing
native Off fixtures cannot establish the new final-layer scenarios. This
source milestone does not close the broader native, release, device or
deployment ledger.


## 2026-11-06 17:47 UTC — configured CONNECT UoT and captured mobile-host adoption

This fourteen-file unit uses reviewed source
`b27e8c4277560b1e2bef25fc503cb7ec65f4379a`,
tree `354a3b28fd6abbd34e00a77d90373eb491ed9ae2`, following
`7950cd1f`, `b3029eff` and `b4cdc2b7` on the recorded `17ccb6ac` base.
Its source manifest SHA256 is
`0292269b219e667ed6042ac8d744fb173f531c8ffdb85cb556736eac0b72b654`.
It is applied after the separately published Server cleanup and Windows
final-layer units, without overlapping their changed paths. No unavailable
historical CONNECT draft was reconstructed.

An imported HTTP/HTTPS CONNECT entry still has its Start Layer Off. The shared
compiler can now derive UoT v2 for an SS2022 final only when that paired final
carries its exact validated original service declaration. The existing
authority validator binds the original node, source/key hashes, endpoint,
port, configured image and UoT version. The derived graph receives UoT;
original source bytes, companion hashes and captured fingerprint are retained.
A present malformed, foreign or stale authority fails, including when the
otherwise-selected DNS would permit a TCP-only path. Missing authority keeps
the existing unlayered TCP-only behavior and UDP refusal.

Authorized configurations preserve the selected Home/custom literal UDP or
TCP resolver and independently provisioned final Off/AES/AES+XOR layer.
Android validates the original final files and checks the returned transport
capability; its existing restoration re-derives the captured graph. Apple
passes the original final profiles through all three actual selection,
capture and PacketTunnel callers. Missing/empty transport defaults to UDP
only for authorized Home DNS. Custom DNS still requires an explicit
transport, and malformed present types/containers are refused.

The new explicit matrix is HTTP/HTTPS × three final-layer choices ×
Home/custom × UDP/TCP: twenty-four configured cases. This is an implementation
matrix, not an invented recovery of the historical six unnamed captures.
The original 337 exported captures and fifty-one TCP native-peer verdict
inventory remain separate and unchanged. The additional pinned-parser
inventory requires its twenty-four uniquely named sources plus parent;
each label is bound to its actual transport, layer, saved DNS and compiled
resolver tuple.

**Actual execution:**

- Pure imported compiler gate: 501 exact parent/leaf verdicts passed.
  Focused CONNECT race execution passed in 1.735 seconds.
- All twelve original TCP-only exported source/capture/digest/config arrays
  are byte-identical to the `17ccb6ac` baseline.
- Android host execution used an actual checksum-verified JDK 17.0.21+9 and
  the pinned JSON dependency: 972 checks and five existing causal controls
  passed.
- Actual Linux Swift 6.4.2/Foundation host execution passed the unchanged
  3,231-check baseline and 336 additional checks covering all twenty-four
  configured cases. This is not an Xcode/Apple SDK, device or tunnel run.
- The first combined Swift execution exceeded the existing thirty-second
  process bound and was retained as a failure. The fixture now runs the six
  added transport/layer groups separately, each with the same thirty-second
  bound. It requires the exact single baseline verdict and every unique
  fifty-six-check group verdict. The original baseline body is byte-identical
  to `17ccb6ac`; two RouterProfile fixture values use their actual
  JSONEncoder representation. After successful real Swift execution, the
  final Python-only acceptance change passed seven controls using the
  captured outputs and invalid/missing/duplicate/foreign/failure cases.
- Seventeen imported-driver inventory tests passed.
- A fresh pinned mobile core, prepared through the official mobile OpenVPN,
  multihop, Tor and Apple Xray chain, passed 363 exact CheckConfig parser
  verdicts: original 337 captures plus parent, and new twenty-four plus
  parent. Parent execution times were 1.06 and 0.06 seconds; package time
  1.149 seconds. All 3,332 generated/source/module hashes remained unchanged
  before and after compilation/execution. Only parser parents were selected;
  no encrypted provider, peer or tunnel was started.

The official Swift 6.4.2 Debian 13 archive used for the host checks has SHA256
`8b6fde775b7cfc7a3758739d8abb09bb6fba519c6532d6b1a47faff791646c64`.
Public signature verification exited 0 against the official Swift 6.x release
key `52BB7E3DE28A71BE22EC05FFEF80A866B47A981F`; the actual compiler reported
`x86_64-unknown-linux-gnu`. This toolchain observation is separate from
native Apple build identity.

**Combined current-source integration also passed.** An isolated checkout
contained exact `de796794` Server lifecycle source plus the seven frozen
Windows final-layer files and these fourteen CONNECT files. Go 1.26.3
`-race -mod=readonly` selected the Windows Router, Imported and ExternalLease
families: seventy parents and 869 parent/leaf verdicts passed in 15.072 seconds,
with none missing, duplicated, skipped or failed. All twenty-one frozen file
hashes matched before and after. The union source manifest SHA256 is
`982416e40c00612f5f934de2faf9e3aff431d5b7614293dd386f8c23c95590c6`;
the exact verdict log SHA256 is
`e97c10295e6554176b0a51c32b5ada77e5b4d352158db16669fa102d44c6915c`.
These verdict counts are not a measure of requirement completion.

This establishes configured compilation, captured host adoption and pinned
parser acceptance for the stated scope. Encrypted end-to-end UoT traffic,
live receiver readiness, physical-device behavior, measured PMTU and native
Apple/Android package acceptance for the resulting publication remain
separate requirements. Independent entry layers and other DNS/graph
combinations are not silently closed by this bounded unit. No private
deployment or new complete release is claimed.


## Windows native retirement control scope — 2026-11-06

The exact-`de7967946d89015ac1e0bb489910c2ef4e12615f` Windows physical-bootstrap run `42260613712` failed the runner prerequisite on AMD64 job `128048387415` and ARM64 job `128048387814`. The Server terminal-cleanup implementation legitimately added another tunnel name/index guard. The Wintun stale-reader negative control still demanded that its guard substring occur once in the entire production file, so it raised an exact-boundary error before the actual Wintun control could execute. This was not a native Wintun acceptance result.

The control now uses the existing strict function-scoped mutation helper and changes only `DesktopWindowsSocketPolicy.RetireTunnel`. The terminal cleanup guard and all production source bytes are preserved. Runner checks require byte-identical code outside that original method, retain the terminal guard, and reject missing or duplicated guards inside the intended method. All 16 focused runner checks passed on the source based at `c76eeadc1c69fb8bcccecad687332f67a267f585` (Python, 0.110 seconds), and `git diff --check` passed. Actual Windows Wintun/WFP execution of the repaired control remains pending the new exact-SHA workflow. No native success is inferred from these Python checks.

Separately, the complete macOS ownership workflow `42260031241` at `cffeed1211f539e9d38eab3a5b39dc6b12be6754` has now passed all four Intel/Apple Silicon anchor and guardian jobs. Intel guardian job `128037223072` completed at 17:48:50 UTC, and its full log verifies rejection of all 45 deliberate broken controls, including descriptor retirement, native finish acknowledgment and authenticated revoke-channel retirement. This is evidence for that exact source and workflow, not an all-platform release of the newer head or proof of physical-device acceptance. The diagnostic change preserves the original inspection error; the passing run alone does not identify a stochastic failure's cause.


## Preserve Windows native timeout evidence through failed cleanup — 2026-11-06

At exact `de7967946d89015ac1e0bb489910c2ef4e12615f`, Windows physical run `42260613712`, Node-controls AMD64 job `128048388271`, rejected the first three deliberate controls but did not establish the `missing-loopback-ipc` rejection. Its test binary had a 90-second native test bound and a 105-second parent bound. The parent timed out; `taskkill.exe` then returned 255 and temporary-directory cleanup reported files still in use. The runner lost the captured test output behind the secondary termination exception, so those observations do not identify the underlying native cause and are not an accepted causal rejection.

The shared Windows runner now retains the first `TimeoutExpired` and its captured output. It still targets only the process tree of its own newly created process. If tree termination fails and that original process remains live, it attempts termination through the same retained Popen process handle. Termination failures and the existing bounded final pipe drain are secondary diagnostics; none can turn the timeout into a success. An already exited process is not terminated again. The original 90/105-second test and parent bounds, 10-second cleanup bounds, 32-KiB output tail and all native rejection checks are unchanged. There is no Windows networking or production-policy modification.

All 24 Windows identity runner tests passed (0.648 seconds), including eight focused timeout/error cases covering the actual status-255 failure, exit races, an unavailable termination command, refused owned-handle termination, a retained child pipe, empty/failed output reads, and bounded output. These are runner behavior tests with modeled process errors; they do not constitute actual WFP or loopback acceptance. `git diff --check` passed. A new exact-SHA Windows run is still required to expose and diagnose the underlying loopback control failure; no native fix is claimed here.


## Selected encrypted DNS through captured CONNECT — 2026-11-06

Review `9ab7a7c7bd85c4d2dd9000f04ac32209725870de` (tree `fd5541a9c10e8f96eda691d81b6974e0510a6b41`, base `c76eeadc1c69fb8bcccecad687332f67a267f585`) extends the existing service-authorized CONNECT compiler and native host capture. Selected TCP, DoT and DoH retain their complete final-route policy over the captured stream. UDP and DoH3, including a UDP bootstrap resolver, require the exact validated final-node UoT service. Resolver hostnames retain the explicitly captured literal bootstrap, transport, TLS identity, path, port and query options. Home DNS retains its private node address; explicitly chosen Rescue and captured Fastest retain the shared builder's existing semantics. There is no inferred public resolver, transport downgrade or fabricated native readiness.

The new carrier check consumes the already built DNS closure and reuses the existing strict transport/query validators. A stale predecessor query allowlist was also corrected: it previously rejected valid `timeout` and `disable_optimistic_cache` options accepted by the shared builder and pinned runtime. The existing full query validator now retains valid options and rejects malformed Boolean, TTL, subnet and unknown fields. Entry/final assets and independent layer credentials remain unchanged. Apple preflight admits the corresponding selected transports; actual Java and Swift capture tests preserve the original profile and bootstrap through restoration.

Executed evidence: imported compiler race suite 566 verdicts (9.319 seconds), existing imported OpenVPN compiler suite 202 (4.433 seconds), predecessor/query-option race suite 30 (1.457 seconds), Android 1,162 captured-host checks plus all five original causal controls, and actual Swift 6.4.2/Foundation execution retaining the existing 3,231 + 336 checks plus 44 accepted encrypted-DNS captures and four no-service H3 refusals. Driver inventory: 18 tests passed. Fresh pinned mobile CheckConfig passed all 408 unique verdicts with no skips/failures (1.289 seconds): 337 original captures plus parent, 24 existing service captures plus parent, and 44 new DNS captures plus parent. This is parser execution, not encrypted provider traffic.

All 337 original captured arrays recompile to their exact prior digest and configuration; the 24 deterministic service captures remain byte-identical. The first attempted comparison regenerated Hysteria certificates and therefore could not validly establish byte preservation; that failed harness receipt is preserved. The accepted comparison uses the original captured inputs and prior manifest without normalizing certificates or substituting expectations. The only post-execution source delta is an explanatory comment identifying an existing H3 negative as missing TLS identity; its assertions are unchanged.

Root read back all 12 review files and verified their Git blob identities against `source-manifest.json`, SHA256 `578ccc9af0b64d6a93323d95eccc45a43b778a92f1cf8706ece5c55951810874`. Parser log SHA256 `53eff6ea038463d709ecf63a9a3136f5c810a60f18571b9183ae8c4a1cd8f35f`; Android receipt `3106fdbeb3d344a14b4664905d75ec08f683abf2559bccc3b62ef8837cbcd3c0`; Swift receipt `47e0dd8507aa193e80b1dc078e65eea3c8712597100fddf65ffa7f4e9428923c`. Encrypted peer traffic, receiver readiness, PMTU, physical devices, native package/release and live DNS acceptance remain separately unproved for this addition.


## Fresh trial proof and owned Windows fixture cleanup — 2026-11-06

Exact-`de7967946d89015ac1e0bb489910c2ef4e12615f` Windows physical run `42260613712`, packet job `128048388022`, passed the explicit Server root and its 17 leaves, and the Local root and its 14 leaves. Compare then failed its existing independent receipt assertion: the winner had two node responses, four measurements and one nonce-bearing proof, rather than two node responses, two measurements and three proofs. The cancelled-Server-proof case also completed without entering the intended proof hold. The initial defect is separate from terminal lease cleanup: `verifyExternalTrial` still sent its two public address proofs to plain `Targets[0]`, making them indistinguishable from response measurements. The final proof already used the strict fresh-nonce primitive.

Trial verification now uses that same strict public-address proof primitive with the original selected tag and expected address. Required entry authentication, selected DNS proof, final selector checks, captured generation validation and scoring formula remain intact. The random common measurement endpoint is unchanged. The pre-existing package-private TLS test roots remain nil in every shipping host bridge; actual test peers use that established seam to execute TLS rather than returning a synthetic proof.

The shared execution fixture now owns separate encrypted proof listeners and plaintext response-measurement listeners. It records proof nonces separately from measurement targets, requires a fresh distinct 16-byte nonce for every trial/final proof, verifies the exact proof host/path and no leaked private token, and preserves the original DNS, wrong-address, TLS, cancellation, selection, lease, OpenVPN remote and restoration negatives. Existing protocol/packet/OpenVPN assertions now address their explicit measurement receipts and independently require the proof receipts. The Windows native `2/2/3` assertion and cancelled-Server-proof hold are unchanged.

The secondary fatal-teardown error was also traced: Go cancels `t.Context()` before `t.Cleanup`, while the Windows Box fixture derived its full native session from that context. Cleanup therefore arrived after the fixture itself had invalidated its captured source. The fixture now owns a context until bounded proof/Box cleanup is attempted, with unconditional final cancellation in its cleanup callback. Explicit failed-close retries continue to retain their original context until the test's final cleanup. Production context, native identity and terminal lease checks are unchanged.

Go 1.26.3 race verification passed all 45 affected parent groups and 429 unique verdicts in 22.413 seconds. A causal overlay restoring only the old trial-proof function caused exactly the intended endpoint/proof-receipt failure in `TestExternalExecutionRunsOwnedLeaseExactScoreRepeatAndPolicyProof`, with no panic, race, skipped test or build failure. Positive log SHA256 `cc39030a42fe80fe4ce8ef4afb03044aeb1a4a590a453d60ea289c0cfe6d9347`; causal log `2d87d97036d5f078b02f69ad3557880c3b4aaed4b09dcd00f417c22f98062c3a`. The compiled shared source included the exact previously published CONNECT-DNS files. These tests execute routed local HTTP/TLS peers and ownership models, not encrypted VPN providers or native Windows WFP. New exact-SHA Windows Compare, cancellation, cleanup and the subsequent terminal-barrier causal controls remain required.


## Preserve the first native socket-retirement failure boundary — 2026-11-06

Exact-`de7967946d89015ac1e0bb489910c2ef4e12615f` Windows Node-baseline job `128048387920` in run `42260613712` failed `TestRouterVPNDesktopNodeWindowsWFPCompositeWrongCredential/split/off/xray-user` when the original broker close wait reached its deadline with kernel permits/sockets retained. The fixture caches the first Box close result, so its later cleanup message repeats that same error; it is not proof of a second failed close attempt. Box subsequently closes endpoints/outbounds, and the existing output does not identify which resource prevented the earlier broker join. The cause remains unassigned.

Reviewed source `6da7b15ea1ad696c1b111fb002cdb46ba7ead728`, with preparation correction `a51ac7f2cad86c9953970f4658ba50608b75b31f`, adds a diagnostic at the original `DesktopSocketBroker.Close` deadline. It preserves the original error and freezes a value snapshot before later Box stages can change state. Fixed broker/socket stages and bounded first-error classes distinguish constructor, entered-I/O, permit revocation, native close, source release and policy/monitor joins. Snapshot acquisition uses TryLock, visits at most 128 sockets, stores at most eight distinct errno values, makes no native calls, invokes no arbitrary error methods, and exposes no private addresses, tuples, credentials or session identifiers. Unknown error wrappers remain an explicit generic class. Admission predicates, cleanup sequence, retries, deadlines, fixture first-error caching and failure retention are unchanged.

The focused actual-loopback race suite passed four parents and two read/write leaves (1.416 seconds), including held I/O followed by held revocation, retained original socket/permit ownership, an immutable earlier timeout snapshot after later cleanup, contention, output bounds and safe error classification. The first failed test expectation assumed an opaque joined error would be unwrapped; it was corrected without changing the deliberately bounded classifier, and the failed output was retained. Receipt SHA256: `203e6c0a7dd14079ee73d36edc7dd97da41c388a27bbb1599a9c6838a2b0431d`.

Source review caught a real packaging omission before publication: the desktop preparer's explicit test allowlist needed the new retirement test. The one-line correction preserves its existing mode and exact-source copy checks. The actual copy loop verified the new production and test bytes, and the complete existing Windows identity runner passed all 24 tests in 0.756 seconds against the frozen combined source. Its receipt SHA256 is `b1b792ea7ef622c65bfd112534f4f74c1203482363660794e67206ced6c2ad50`. Desktop, server, mobile exclusion and portable-observer source-copy boundaries were reviewed. New native Windows evidence is still required to locate the Xray-user retirement cause; this diagnostic is not a functional shutdown fix or an accepted native pass.


## Independent paired Router entry Start Layers on Windows — 2026-11-06

Review `6cf801d1201174c52b041761f560a4be1bc8f118` (tree `0d9d31e6adfd8d94c714d39a2f15d25bcd2fc639`, base `d7e0a7c28703fd77334c3f9bece409863ca4aacc`) closes the next paired Windows source path: entry AES-256-GCM or AES-256-GCM+XOR independently of the final layer, for Local, Server, Compare and restoration of a proved winner. The host captures the selected Router entry's WG and Start Layer assets separately and clears each owned buffer. It preserves node references, final credentials, DNS, protection and MTU through the existing retained-source checks.

The shared compiler reports the Router predecessor's actual entry layer. Windows lowering reconstructs both the inner WG endpoint and its namespaced outer AES/XOR row from the sealed original predecessor; candidate graph rows cannot supply their own expected credentials, detours or physical tuple. Only the outer entry wrapper becomes the physical root, while the final keeps its original private detour and independent key. Optional sealed metadata identifies the distinct inner WG startup endpoint. Native initialization admits its required early lower socket phase only after the original factory has retained the source and deny baseline; proof, TUN and Connected readiness remain separate. Lazy ordinary transports retain their prior startup behavior.

The host asset tests use the existing private preparation pattern with a modeled network observer. The shipping wrapper always passes `physicalNetworkIdentity`, initial/final checks use that same callback, and the callback is not retained or exposed through a native API. Empty/lost/changed network and controller/package/source replacement cases still fail without changing active runtime state.

Executed Go 1.26.3 race checks: shared paired policy 13 parents + 205 children (5.376 seconds package execution), prior predecessor/layer coverage 9 + 919 (10.671 seconds), and client 4 + 272 (24.590 seconds). Client children cover 108 independent entry/final/method/protection choices, 144 fixed-winner restores and 20 host asset/lifetime/network cases. Removing only the inner original-WG equality rejected all four intended key/peer substitutions; removing only the outer equality rejected four outer-key/cross-node-key substitutions. Neither causal run had a panic, race, skip, timeout or unrelated failure. Initial failed fixtures remain preserved: a final-Off value bypassed normal profile normalization, and a late-host-error assertion misread the existing candidate-plus-error return contract. The corrected fixtures retain strict source equality and require returned host captures to be invalid when the final check fails.

Official pinned generated desktop preparation, module verification and 699 exact source records passed for the entry review. The generated desktoppt race compile passed (138.038 seconds), and the parent plus 14 existing Linux fake-OS startup leaves passed (1.419 seconds); their image/source records remained unchanged. The Python bootstrap runner passed 27 cases, with its one existing actual-Windows-process-handle case skipped on Linux. These are bounded generated/fake-OS results, not Windows or encrypted-path acceptance.

Two new Windows leaves are mandatory in native CI: `TestRouterVPNExternalPhysicalStartupSocketPhase/router-entry-aes` and `/router-entry-aes-xor`. The missing-eager-phase control requires each new leaf's own unique RUN, FAIL and intended phase witness; an old direct-WG failure cannot certify them. Neither new Windows leaf nor its native control executed in this local environment. Entry verification manifest SHA256: `49dedd5de2cf79aef324156e94cd0936493060ea5dee952342736bcf57b2a327`.

### Verified combined source before entry publication

The isolated integration source contains exact `9e746ff0a5ad99621a2b4002c49e30b6b1e0d16b` plus the seven Compare files, four retirement diagnostic/preparer files and fourteen entry-layer files. All 25 paths are distinct, matched their review Git blobs before application, and retained their hashes afterward; the previously published CONNECT/DNS files remain exact. This set passed 93 shared parent groups / 2,328 unique verdicts (44.856 seconds), the four client entry-layer parents / 276 unique verdicts (23.598 seconds), and all 24 Windows identity/source-copy runner tests (0.756 seconds). No failed, skipped, duplicated or missing run-to-pass verdict occurred in these combined checks.

Combined source manifest SHA256: `92dfe1a6a8266054d8c4c1b328611d1560718522016ba4fa16f23ec36ac88f83`; shared JSONL `4bd0b92fd96317e0f33b3df3149e43225d255eb96f336e03dc6856dad368dbc4`; client JSONL `d0b9368d4c5e17b553c562a280bd4e08d403b21af1376793d5c77c899d14661a`. These counts are test verdict inventories, not a product-completion denominator. Actual encrypted Windows paths, new native startup controls, physical-device behavior, exact-SHA release and deployment remain separate requirements.


## Imported SOCKS5 to paired REALITY/Vision: shared source and mobile capture

This unit is based on published `e7a9d65e06eeee6502c55e37c71c7260819a0e0d`. It combines the six-file shared
review `804d5366c6ff4e46fecb7836e0c3860e449316f4` with the thirteen-file
Android/Apple review `46e181a5c0207e28e293f7f4ea0548eb4b48190b`.
The publisher fetched every actual source file from those immutable objects
and independently recomputed all nineteen Git blob identities before composition.
The reviewed paths do not overlap. Existing work on main is retained.

The original imported/custom entry and independently selected paired final
requirements remain the authority. This bounded addition admits exactly an
imported SOCKS5 entry followed by a paired `reality-vision` final, Local
execution, with both independently captured Start Layers Off. It does not
waive unfinished entry kinds, Xray families, layer combinations, Server or
Compare execution.

The shared compiler parses the original seven input strings, compiles the
original external entry and complete paired-node asset map, and validates
the exact single native Xray transport before adding its owned entry detour.
It keeps separate imported public-entry, selected-DNS and authenticated
paired-final proofs. Original source/configuration identity, DNS selection,
LAN/IPv6 policy, MTU and cancellation/replacement checks remain enforced.
Valid provisioned layers and other valid graph families are explicit refusal
controls for this bounded implementation; malformed input is not their only
reason for rejection.

Android now carries this exact path through its picker/compiler, imported
source capture, service admission and restoration. Apple carries it through
its picker, runtime selector, original Xray asset capture and restoration.
The hosts retain the complete seven-input capture and never turn a saved
selection into proof that a tunnel is connected.

Executed evidence before publication:

- Final shared Go 1.26.3 race suite: seven parents and sixty child verdicts,
  sixty-seven unique passes. Its log SHA256 is
  `5797aa3de1a02ec3a5f54cce8cc159ec3142435de0c0d2b53d8ca02138a7eb47`.
  Source tests cover exact Xray bytes/detour, all captured inputs, selected
  Home/custom/encrypted DNS, policy preservation and valid unsupported graphs.
- The shared runtime cases use real TLS/HTTP over owned pipes to require the
  entry, selected-DNS and paired-final stages and to reject cancellation,
  replacement and stale retained operations. These are scoped engine-boundary
  fixtures, not an encrypted SOCKS/Xray peer.
- Three scoped causal variants produce the intended failures when original
  admission, valid entry-layer refusal or imported-entry proof is removed.
  The Python imported-entry runner passes twenty tests.
- Actual Android Java-to-Go captured-graph validation passes 110 checks and
  five existing causal controls. The shipping runtime/Home composition passes
  260 checks across 91 cases plus four causal controls; OS/preparation/proof
  boundaries in that fixture remain test boundaries.
- Actual Swift selection runs pass the original 3,231 checks and thirty-nine
  new REALITY capture/selection checks, with the existing 336 configured
  CONNECT checks and forty-four accepted/four refused selected-DNS captures.
- The actual Swift-to-Go producer passes 338 exports and 6,996 checks. It
  retains the original 337 names and adds only
  `socks5--final-reality-vision.json`. Four Apple inventory controls pass.

The host manifest SHA256 is
`d83d01573620095df8f9e350df064e4eeb066687103f6cd33284ff66966d60ba`.
Initial fixture failures are retained in the local evidence: source-test
assumptions about the existing health exception/combined route rules,
standalone AWG transport-only DNS projection, helper-only VCS stamping, and
an omitted local CryptoKit helper. Their corrections do not remove assertions
or change production retry/proof behavior.

Generated native parser execution for the newly extended aggregate inventory,
an actual owned SOCKS-to-Xray reference peer, native app builds, physical-device
networking and release acceptance remain separate required evidence.
The execution workspace disconnected during follow-up validation; no parser,
Windows compilation or device result is inferred from an unfinished process.
This publication is a tested source/capture unit, not complete multihop,
all-platform, release or deployment acceptance.


## Current Apple and Android regression-fixture repairs

Exact `e7a9d65e06eeee6502c55e37c71c7260819a0e0d` release jobs
[iOS/iPadOS 128075169220](https://github.com/Eabusham2/router-vpn/actions/runs/42270932446/job/128075169220)
and [Android 128075169476](https://github.com/Eabusham2/router-vpn/actions/runs/42270932446/job/128075169476)
failed in their existing host fixtures. The publisher read both actual failure
logs: the Apple comparison fixture omitted `IOSMultihopStartLayer`, and the
Android CONNECT profile fixture required a `TCP only` caption that the current
product summary no longer renders.

The reviewed correction `ea6c503436bb194a589b5d7c426dc68ee26af2f6` is applied over
`c8a0ba7c02d2b5700e9ad7ec89e05919f006d08f`, preserving its unrelated source.

- Apple includes the complete shipping `IOSMultihopStartLayer.swift`
  declaration outside the existing import-stripping loop. Its conditional
  CryptoKit import remains intact; no replacement validator is introduced.
  The six existing comparison mutations and operation bounds remain unchanged.
- Android compares the exact captured entry/final names and HTTP/HTTPS CONNECT,
  Shadowsocks and Local labels. Its explicit saved TCP DNS/Off policy,
  credential references, refusal, source identity and rollback assertions
  remain unchanged. This fixture does not claim configured-UoT acceptance.

Both complete candidate files were read back and proved to differ from the
current source only at those exact boundaries. Independent source review is
clear. The executor is unavailable at this checkpoint, so no repaired Java or
Swift execution is claimed; the exact-SHA CI reruns remain required.


## Windows independent-entry-layer fixture: restore original Home DNS

The exact `e7a9d65e` complete Windows native-engine jobs
[AMD64 128083504163](https://github.com/Eabusham2/router-vpn/actions/runs/42270932334/job/128083504163)
and [ARM64 128083504096](https://github.com/Eabusham2/router-vpn/actions/runs/42270932334/job/128083504096)
both failed before native startup in
`TestRouterVPNExternalPhysicalStartupSocketPhase/router-entry-aes` and
`router-entry-aes-xor`. Actual logs reported:
`WireGuard exit requires one literal selected DNS resolver`.

The new fixture's original `wg.conf` omitted DNS, while its independently
captured Router profile already selected Home resolver `10.77.0.1`.
Reviewed correction `6fd482190d5541260a2c510259de3fe79a7d554c` adds exactly
`DNS = 10.77.0.1` to that original Interface section. It changes one fixture
line only. Credentials, endpoints, fingerprinting, layers, startup checks,
native verdict inventory and missing-eager controls remain intact.

The production single-resolver guard in `internal/mobilemultihop/wireguard.go`
and its existing missing/multiple-resolver negative controls are unchanged.
The publisher compared complete original/review file bytes and confirmed
this is the sole substitution; independent source review is clear.
No new Windows execution is claimed while the executor is unavailable.
Both actual startup leaves and their native causal controls remain required
at the resulting published SHA.


## Android CONNECT chooser: explain current DNS and layer support

The chooser still described the older TCP-only, both-layers-Off subset after
configured final UDP-over-TCP and selected encrypted DNS support had shipped.
The one-string correction is based on reviewed source object
`51ff05283f33a54afc8d0d8e7aab687512419755`, with two plain-language refinements
recommended by the independent reviewer.

The text now identifies the paired SS2022 final and Off entry layer, selected
TCP/TLS/HTTPS DNS, and the final Router node's required UDP-over-TCP service
configuration for UDP/DoH3 and supported final AES/AES+XOR layers. It explains
that a DNS hostname's saved lookup resolver needs a compatible transport and
that the saved DNS selection is preserved. This matches
`importedCONNECTCapture`, `importedCONNECTDNS` and
`externalDNSValidateTransport` at parent
`55712b0a966c8ad5b26830a560338172d539d73c`.

Only the existing explanation in `ProductActivity.java` changes. Root compared
the complete original and revised files: line 395 is the sole changed line,
with no admission, runtime, fixture or assertion changes. Independent source
review is clear. No execution is claimed for this wording-only correction;
native builds and rendered-device acceptance remain separate evidence.


## Windows OpenVPN mixed retry: transport observation and original pending proof

The actual AMD64 and ARM64 OpenVPN physical jobs at
`de7967946d89015ac1e0bb489910c2ef4e12615f` failed the mixed
`reject/control-key` case because two original UDP MAC-rejection sessions were
not observed within the fixture's ten seconds. The original transport's mixed
unavailable-TCP/UDP backoff reaches its second UDP session beyond the production
proof's unchanged 45-second lifetime. Extending observation while starting that
proof immediately would therefore observe a correctly retired owner.

This four-file fixture repair is reconstructed from the recorded design and
preserved in review objects `134ac9a2ea06d61bdecaf16b964886f47be258ee`,
`2a3bd7cb28344c35a1247d1fe47d1cdbbbe4f029`, and
`a93aab45c876a67f837064b1fa6524b5917351fa`. The publisher read all four complete
files and independently verified their Git blob identities. The final source
differs from the last review only in its control-explanation comment.

For the exact original mixed remote sequence, transport observation now precedes
proof execution and has a 90-second child bound under the provider's existing
100-second lifetime. UDP-only retains its original concurrent proof and ten-second
observation. Both paths still require two distinct initialized original UDP
generations, actual provider MAC failures, independent session/socket correlation
and strict native WFP/TUN readback. No production timeout or retry changes.

After that evidence, the fixture requires a fresh actual `OpenVPNRemote` call
from the original proof to return its raw zero receipt and pending error. The
test-only compiler overlay captures its atomic observer registration before the
real endpoint call and verifies that same registration and exact route owner
afterward. Direct fixture getters cannot supply this witness. The original proof
must remain pending; the same second session brackets another strict native
inspection before cancellation and the original bounded join. Observer removal
uses CAS only after that Run joins.

Review found that the same original socket's valid permit renewal can advance
`DesktopSocketGrant.Sequence`. The comparison now requires one acknowledged
grant in each snapshot and a nondecreasing positive sequence, privately copies
the later grant slice, and normalizes only that sequence for whole-readback
equality. Capture, binding, socket, tuple, WFP owner/options, construction count
and TUN identity all remain exact. A mandatory ownership leaf checks three
accepted sequences, nineteen changed-field refusals, zero original sequence and
preservation of both input snapshots.

The runner retains all nine original mixed leaves, executing eight together and
the unchanged control-key leaf in a separate invocation with exact hierarchical
Go run/skip expressions. Alias/witness limits remain 60 seconds and network
invocations remain 180 seconds. A fifth scoped causal image removes only the
proof-read observer and must fail its exact UDP control-key leaf with the required
missing-observation message. Six image receipts and the corresponding aggregate
budget are mandatory. Duplicate, foreign-partition, missing, skipped, failed and
aborted results cannot close the gate.

Independent source review is clear. The reconstructed runner tests cover partition
and dispatch, exact budgets/inventories, source ownership, atomic observation,
guard-only mutation and compiler-owner collision refusal. **These final four-file
bytes have not been executed:** the earlier fifteen Python passes and standalone
Go partition experiment belong to an unavailable earlier local draft and are not
transferred to this reconstruction. Its interrupted Windows crosscompile has no
known result. Publication submits the reviewed test repair to mandatory exact-SHA
CI; Python execution, Windows AMD64/ARM64 compilation, native cases and causal
controls remain required evidence.
