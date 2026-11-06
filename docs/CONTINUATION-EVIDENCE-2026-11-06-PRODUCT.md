# Router VPN product continuation evidence — November 6, 2026 UTC

## Scope and source cutoff

This ledger supplements [the earlier November 6 ledger](CONTINUATION-EVIDENCE-2026-11-06.md)
and [REQUIREMENTS-RECONCILED.md](REQUIREMENTS-RECONCILED.md). It does not replace
the original requirements or cancel an unfinished requirement. The recorded
published product work below ends at
[`8fdc2ef7118c00567a45b63619091c7ebff6b876`](https://github.com/Eabusham2/router-vpn/commit/8fdc2ef7118c00567a45b63619091c7ebff6b876).
This is a source/evidence cutoff, not a claim that the branch stops moving or
that this revision has completed its release gates.

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
their individual closure obligations; these ten units are not a replacement scope.

A concrete **Apple Home DNS settings gap** remains open at this cutoff. The
shipping Home path reproducer requests HTTPS at `[fd12::53]:5443` but resolves
to UDP at `192.168.50.133:53`, although the shared native configuration supports
all five exact transports. The settings-to-shipping-path propagation is being
repaired separately and is not included in `8fdc2ef7`. Intentional UDP/53 for
Fastest node measurement is a different path and is not this defect.

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
