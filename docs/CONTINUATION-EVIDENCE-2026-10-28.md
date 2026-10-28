# Router VPN continuation evidence — October 28, 2026

This record supplements the original requirements, the
[reconciled contract](REQUIREMENTS-RECONCILED.md), and the
[October 26](CONTINUATION-EVIDENCE-2026-10-26.md) and
[October 27](CONTINUATION-EVIDENCE-2026-10-27.md) evidence ledgers. It preserves
their requirement identifiers and the user's later corrections. Overlapping
lists are not added together or turned into a completion percentage.

## Recovered authority and initial repository state

The current user instruction is to finish the requirements and commit/push each
coherent finished change directly to `main` after reconciliation. The pasted
handoff's `5967e9c3` and the published release at `745b3e41` are historical.
The live branch at the start of this continuation was
`dbff30e8a83048f312e8c90a0e29d49569921b40`, 231 commits ahead of that release and
zero behind. No old recovery package was replayed over this newer source.

Personal/project context was actively searched. The named private project
sources were then located and read, including the complete numbered audit
1–311 and addendum 312–356/C1–C7. Those numbered documents are historical
assistant audits of the chat; they are not misrepresented as 356 verbatim user
messages. Original user passages were separately recovered and reconciled:

| Original source | User passage recovered | Requirement significance |
|---|---|---|
| `Router/mm.md` | August 11, 2026, 21:53:19, followed by the user's request to do both fully at 21:55:11 | Native full-device Windows, Android and Apple tunnels; real multihop and kill switch; download progress; AI Help; teaching onboarding; simple interoperable Methods; administration; map/DNS/MTU controls; generic installation with separate node linking; actual SOCKS/OverTLS/Shadowsocks breakage. |
| `Resume Router VPN.md` | August 13, 2026, 20:50:57 | All-device functionality and imported/custom protocol nodes remain part of the full product, beyond a successful source release. |
| `New chat (1).md` | August 14, 2026, 01:39:44 | OpenVPN and non-platform custom nodes, hops and exits; earlier agreed requirements are not removed unless explicitly abandoned. |
| `Router VPN Execution Handoff (2).md` | August 16, 2026, 23:45:03 | Map-first daily app, integrated dock/sheet, role-colored hops, CUSTOM presets/builder, SMART AUTO default, complete settings, per-configuration MTU retest, IPv6 On and AUTO requirements Off. |
| `Router/Pasted text(20261019-225900).txt` | Preserved original user comparison wording; original message date is not supplied by that excerpt | Local and Server each measure the last node and the same random external endpoint, divide their sum by two, and disqualify timeouts. |

The numbered addendum preserves C1–C7: real off-LAN Methods evidence; onboarding
completion/reopen behavior; authenticated sensitive mutations; unrestricted
blank AdGuard Allowed Clients; generic package fallback; image-only production;
and separate private node linking. Later explicit instructions preserve
30-minute retention from READY and the AES-GCM plus XOR-whitening option.

The named user passages and full numbered audit lists were recovered. This is
not a claim to have read every message in every historical conversation or all
private project files. No original passage recovered here specifies a distinct
Tor-specific last-relay measurement, an exact additional Tor padding protocol,
or a numerical arbitrary-hop limit. Those details must not be invented or
attributed to the user. General multihop, compatible Jumbo and bounded padding
requirements remain binding.

Private transcripts and credentials stay outside the public repository. Source
titles and message dates above provide continuity without publishing the raw
private history.

## Published source changes

Every commit below was published on its current `main` parent without force.
A fresh remote reference read verified each result, and the local Git tree was
matched while preserving other unfinished work. Passing local tests are bounded
to their actual toolchain and runtime; they do not certify a packaged device.

| Published commit | Concrete change | Focused evidence and limits |
|---|---|---|
| [`37950ee3`](https://github.com/Eabusham2/router-vpn/commit/37950ee34704722c16479a3ae61f3d58808ab320) | Make common Tor receipt fixtures available under the production Go 1.24.13 toolchain instead of hiding them in a Go-version-gated test file. | Original production-toolchain failure reproduced; receipt tests pass under Go 1.24.13 and the Tor race suite under Go 1.26.3. No receipt validation was removed. |
| [`ea31bcb0`](https://github.com/Eabusham2/router-vpn/commit/ea31bcb04aaf4ae0ad66e7f3e83749c1811ed0d1) | Repair the Android external-session fixture's no-op substitution so it actually exercises retryable failed close. | 300 executable checks and ten rejected production mutations. The original fixture failure was reproduced. |
| [`4ed4b725`](https://github.com/Eabusham2/router-vpn/commit/4ed4b725d4567087184870b3dc401149b40f4498) | Update Apple lifecycle fixtures for the current Tor execution owner and complete MAX route captures. | 570 Swift lifecycle checks and two rejected owner mutations; 24 actual Go launch graphs and 278 source/DNS/lifetime checks. Production admission remains strict. |
| [`985ae720`](https://github.com/Eabusham2/router-vpn/commit/985ae720f8d8ace693170d1bd44a360b621bc400) | Repair pinned Windows Tor cross compilation: confined target metadata, explicit threaded static OpenSSL, and the verified Windows SHLWAPI system import. | Actual pinned C helper/test binaries compiled and passed package validation; 257 checks retain rejection of dynamic crypto/event/pthread and unknown imports. Hosted cross compilation later passed; actual Windows execution remains distinct. |
| [`99c7b6a4`](https://github.com/Eabusham2/router-vpn/commit/99c7b6a4c9448493bd78676895f36db4607ff752) | Restore Apple Tor Speed Lab sessions from their captured Tor entry slot. | 193 Swift checks and three rejected mutations; original cancellation failure reproduced. The already-proved Local/Server selection is preserved. |
| [`a3b6a501`](https://github.com/Eabusham2/router-vpn/commit/a3b6a5011b846abe6a92f73999ae866809e9108c) | Expose typed ordinary predecessor capture to mobile Tor, recompile original source, and bind native proof/MTU ownership to the same Box. | Shared race suite, generated mobile copy closure, actual pinned native constructor/proof/DNS/MTU tests and Libbox linkage. Ordinary public-IP proof cannot grant private Router, Home AdGuard or Server authority. Host adoption follows separately below. |
| [`8180cfce`](https://github.com/Eabusham2/router-vpn/commit/8180cfce366f43c35c7f8ee11ec53af34a81bb67) | Carry eight ordinary import families through Apple Local Tor picker, complete profiles, Startup Last, PacketTunnel preparation and final proof receipt. | 48 added provider-to-Tor graphs; 41,233 Swift/Go provider checks retain the existing graph/policy inventories. Selection, startup, profile CRUD and native-engine lifecycle suites include negative ownership controls. Xcode packages and devices remain separate. |
| [`6f25191f`](https://github.com/Eabusham2/router-vpn/commit/6f25191feda705b9754171c642c5fe65aaaf9c66) | Make native Tor Server TLS test roots portable to Darwin in the isolated fixture child. | All 28 actual native Box/Server cases pass with race detection on Linux: 12 positive paths, 11 rejection cases and five lifecycle cases. Trusted wrong-host and untrusted matching-host certificates fail real TLS proof. Production TLS is unchanged; Darwin execution remains CI evidence. |
| [`846f23f0`](https://github.com/Eabusham2/router-vpn/commit/846f23f0efde3cd3e349a1977b148690e7d8ba0d) | Carry eight ordinary import families through Android Local Tor picker, immutable preparation, permission, profiles, startup and Speed Lab restoration. | Schema 5 retains the established file location, migrates versions 1–4 and rejects unknown future versions. Typed node-kind references prevent same-ID Router/external confusion; transactional restore preserves concurrent edits and never duplicates credentials. Java/Go graph, form, permission, profile, startup, protection and restoration suites pass. Profile/durability audits pass. APK/device evidence remains separate. |
| [`479759b1`](https://github.com/Eabusham2/router-vpn/commit/479759b175133ead23e3ee695a088e12d8ee963c) | Align shipping audits with plain Tor and all current Apple captured compiler paths. | Both source audits and ten audit-test groups pass; added mutations reject dropping plain or bridge Tor. Subsequent hosted weighted/recovered gates passed at this SHA. |
| [`ed2c46a1`](https://github.com/Eabusham2/router-vpn/commit/ed2c46a19760b0ec49b89a17bb753b0e9158b63c) | Include ordinary entries in mobile Tor per-hop measurement using their actual captured lower route. | Actual native Box race tests plus three rejected mutations cover entry/exit separation, provider reproof, selected DNS, stale owners and cancellation/drain. Controlled failed dials remain failed measurements; no successful latency or throughput is fabricated. |
| [`ab145b54`](https://github.com/Eabusham2/router-vpn/commit/ab145b54be998e549297c6c9e7a6f04c1f8fcbdf) | Preserve compatible imported proxy Jumbo capacity, including a proxy predecessor of Tor, without enlarging packet transports. | The old compiler reproduced the ordinary-entry mismatch. Shared external/Tor race regressions and the actual pinned native constructor pass. Five proxy families, inherited choices, fixed conflicts, malformed booleans and raw packet rejection are covered. MTU 9000 is virtual interface capacity, never a fresh PMTU result. |
| [`28ebd790`](https://github.com/Eabusham2/router-vpn/commit/28ebd790f5c4171e0012f3adccd01e4cc99338d5) | Cancel superseded diagnostic matrices on the same branch. | Parsed workflow comparison retains every trigger, permission, platform, job and step; three existing workflow audits pass. This prevents future accumulation, not proof that older queued runs were manually cancelled. |
| [`ab7bf7f7`](https://github.com/Eabusham2/router-vpn/commit/ab7bf7f7c4cbb5a94b97968957a0f66a6afc63c9) | Use production TCP-first listener reservation in two DNS cancellation fixtures. | Actual Windows failure identified UDP-first ports rejected by TCP. Production already reserved correctly. Focused real local H3/socket ownership tests pass three race runs; Windows execution of this new commit remains pending. |
| [`82292d1d`](https://github.com/Eabusham2/router-vpn/commit/82292d1df96a51659050285947b9d7b03421f8a8) | Add shared immutable native padding receipts and exact source/session/rate/counter/freshness validation. | Padding receipt/control/lease race suites and the generated mobile copy closure pass, including missing-source and desktop-copy rejection. Enabled Local admission stays closed until host integration is complete. |
| [`a1c91d7b`](https://github.com/Eabusham2/router-vpn/commit/a1c91d7ba8296ca74a93eed5b43ed51268b7e6d3) | Bind Android VPN permission to the exact process-owned request and saved selection, with unique prompt codes, rotation transfer and terminal cancellation. | Shipping permission 3,361 checks/seven rejected mutations; startup 1,362/three; Speed Lab restore 1,709/fourteen; profiles 2,177 checks/179 cases plus lost-update mutation. The session mutation audit passes. Physical Android permission UI remains separate. |
| [`ee1e60ea`](https://github.com/Eabusham2/router-vpn/commit/ee1e60ea7144093512d9141456a410e3ab3d2539) | Capture desktop padding policy, exact standalone native owner and separate paired DNS/exit proof lifetime. | Desktop policy/session/padding and controller native-proof/Server-cover suites pass with race detection. One lease claim binds private SOCKS isolation; stale, changed or regressing receipts fail. Enabled Local admission remains closed. |
| [`15b988c6`](https://github.com/Eabusham2/router-vpn/commit/15b988c654160a2d85f1e154a4947aea91683729) | Keep the native runtime argument array nonempty for macOS Bash under `set -u`. | Actual Darwin diagnostic failed on the empty optional array. Executing the revised workflow shell with argument capture validates all six desktop targets; three workflow audits pass. Actual macOS execution remains pending. |
| [`a5876568`](https://github.com/Eabusham2/router-vpn/commit/a587656821e45b9f129800acdf734504f19089cc) | Compare Tor package metadata within each path/handle API while preserving cross-API file identity. | Actual Windows ARM64 diagnostic failed the old cross-API timestamp comparison. CPython 3.12.10 source and upstream issue 157671 establish distinct Windows ctime meanings. All 273 package checks pass; the old reader fails the new stable-file regression, and removing handle-tamper protection is rejected. Current Windows execution remains pending. |
| [`e5b2d191`](https://github.com/Eabusham2/router-vpn/commit/e5b2d1916c7e6f606db3996cc503300afe67bf4b) | Expand both shipping mobile native parser gates to all 738 captured graphs, including ordinary predecessors and OpenVPN. | Each complete gate passed against the pinned native Xray/OpenVPN/C Tor composition and rejected all 738 missing-engine controls. Apple shipping provider/Server assembly passed 41,233/6,824 checks. Contract suites and Tor shipping audit pass. No VPN or public circuit was started; SDK builds and devices remain distinct. |

### Subsequent committed repairs and native padding work

| Published commit | Concrete change | Focused evidence and limits |
|---|---|---|
| [`0aa36b50`](https://github.com/Eabusham2/router-vpn/commit/0aa36b50b9955b269c950b87c66ee208dcfd9d3a) | Supersede older push runs in four accumulating contract workflows. | Parsed triggers, permissions, jobs and steps remain identical; manual MTU runs keep independent identities. Four workflow audits pass. Older runs without these groups are not retroactively cancelled. |
| [`456c4e1f`](https://github.com/Eabusham2/router-vpn/commit/456c4e1ff79cf41fb47bedac182f578853c53e34) | Complete the Android Layered service fixture's JSONObject boundary. | Full shipping Java compilation and four negative controls pass; a subsequent hosted run passes this step and exposes the separate external-policy fixture below. |
| [`aa2328e1`](https://github.com/Eabusham2/router-vpn/commit/aa2328e1d9bfd7cbb42704d422131e5aa03f1468) | Reconstruct Local padding's complete source and expose a pure expected-source digest. | Shared race and generated source-closure tests pass; ordinary providers retain public authority. This descriptor alone grants no socket, proof, lease or public admission. |
| [`cbb2ce0b`](https://github.com/Eabusham2/router-vpn/commit/cbb2ce0b1b890f810d0ce40a624e4a0b97dbe126) | Reserve paired TCP/UDP WFP fixture ports with bounded retries and complete partial-owner cleanup. | Actual local PowerShell IPv4/IPv6 collision, retry-bound and cleanup cases pass; portable C#5 policy gate passes 1,283 checks. Hosted WFP enforcement subsequently passes at `18a77fd5`; later Windows job steps are separate. |
| [`68dfd230`](https://github.com/Eabusham2/router-vpn/commit/68dfd230206e8493d9d5c152534aebb4075ca023) | Keep shared padding receipt peers visible to Go 1.24 and use its supported WaitGroup API. | Focused padding tests pass under Go 1.24.13 and the Go 1.26.3 race toolchain; deterministic newer-toolchain lease tests remain intact. |
| [`18a77fd5`](https://github.com/Eabusham2/router-vpn/commit/18a77fd5647634a8464f7cdf9b9bcdff5bbe6c31) | Resolve the Windows Tor form fixture root after parameter binding. | Actual PowerShell callbacks pass 3,478 checks, six rejected mutations and the Go importer locally. The exact-SHA desktop Amnezia workflow then passes all three Windows/macOS/Linux jobs. |
| [`c71ccbe3`](https://github.com/Eabusham2/router-vpn/commit/c71ccbe3879f2b0f8f5513a8b04364093696e592) | Avoid replacing the actual Android external-policy class with an inherited Tor fixture stub. | An isolated current-main source copy passes all 2,025 ordinary external graphs and 18,747 checks. The pending padding feature was excluded from this repair's commit and verification. |
| [`799cab98`](https://github.com/Eabusham2/router-vpn/commit/799cab98fc7d0620dc2d20050a7a407b78446f8c) | Use transport-compatible Apple Jumbo positives and explicit invalid packet/fixed-size negatives. | Isolated current-main shipping editor/native policy tests pass 489 checks and six rejected mutations. No production Jumbo validation was weakened. |
| [`5e6aa4a7`](https://github.com/Eabusham2/router-vpn/commit/5e6aa4a7d41dc2c661e977223ecc8910856c8e33) | Enable bounded outgoing Local Tor padding through the desktop's actual application and selected-DNS paths, with transactional settings. | Focused working-tree native Box, private command, PT/data owner, route and controller/editor race suites passed, with the companion mobile proof API present. Exact `5e6aa4a7` Linux CI subsequently exposed that the companion `RouterVPNTorProofRequest.padding` field was absent from that intermediate commit; `057957b7` publishes that dependency. Current combined native composition passes. Native PQ archive, platform release builds and physical/public-network cover acceptance remain separate. |
| [`06a19480`](https://github.com/Eabusham2/router-vpn/commit/06a194800c6dd39d49d39ba1f6334651e3e709d8) | Make claimed Apple Tor/external proof cancellation win the completion callback transaction. | Exact shipping finish/cancel methods pass 64 held-native-Cancel races per class, plus completed-before-cancel cases. Both former-defect mutations fail at the intended callback assertion. The actual external execution owner passes 131 checks. |
| [`057957b7`](https://github.com/Eabusham2/router-vpn/commit/057957b7cc2224d49641360b0b52a1016cf6cac1) | Add guarded mobile native padding API, actual proof refresh, per-stream ownership and independent native-grant expiry. | Real pinned DSO constructors and generated Libbox linkage pass. Protocol and actual Box DNS/TLS/proof/MTU race suites pass. Four integration mutations fail the intended expiry, late-dial, completed-proof-pool and in-flight-I/O assertions. Public mobile admission remains closed until host and enabled-graph coverage joins it. |
| [`943aa117`](https://github.com/Eabusham2/router-vpn/commit/943aa117191f79837e38f99f2cebf61bf68990a9) | Retarget desktop Tor maintenance mutations to the actual padding-aware failure and adoption guards. | All 36 audit tests and the complete recovered map-first UI gate pass locally. The hosted map-first gate also passes at `d2bc4f7b`; no rejection condition was removed. |
| [`15b67f3e`](https://github.com/Eabusham2/router-vpn/commit/15b67f3ecd56426ca709a9bb91c08a4a80a958db) | Exercise actual selected DoT and HTTP/2 DoH pools across initial proof, two refreshes and ordinary reconnection. | Actual pinned transports, verified TLS and wire DNS pass with race detection. Untrusted certificates, stale proof tokens and retained old pools reject; removing cleanup fails both transport cases. Final Tor circuit/control are explicit doubles, not public-network evidence. |
| [`d2bc4f7b`](https://github.com/Eabusham2/router-vpn/commit/d2bc4f7b70bcbcf2f3dfc564d30212a059bcf124) | Bring the Android import boundary into agreement with ordinary entries and test their displayed identities across Local/Server/Compare. | 66 actual shipping callback/store/policy checks and five rejected mutations pass. The complete Android runtime contract later passes with this repair. |
| [`49932886`](https://github.com/Eabusham2/router-vpn/commit/49932886bc0269ea89fd76d37ba43bd14da571d7) | Accept the pinned native parser's equivalent nil/empty bridge vector for plain Tor padding. | The actual-parser regression fails before the fix and passes after it. Full source/hash remains unchanged; a nonempty unselected bridge and eight option-corruption cases still reject. Complete Local padding protocol race suite passes in 6.933s. |
| [`576385d7`](https://github.com/Eabusham2/router-vpn/commit/576385d73a2a13d2bc253f1753ff1cd972c470e9) | Expire already-open authenticated Server Tor data streams independently of a pending control reply. | Native Server race suites pass in 5.832s/1.042s, including actual child tests without skips. Off, healthy renewal on the same stream, blocked STATUS expiry, late dial, disabled child, entered I/O and delayed/failed Close are covered. Missing-expiry and premature-join mutations fail the intended assertions. Native PQ and physical/public-network acceptance remain separate. |
| [`e234aa0a`](https://github.com/Eabusham2/router-vpn/commit/e234aa0abe0832a0e380ddc5ddf86f121d57ae1f) | Require the exact captured-source, status and lifecycle APIs in every cached Apple Libbox header. | All 15 cache/build contract tests pass against the pinned gomobile declaration spelling, including wrong NSError shape, wrong request owner, missing method and absent-header rejection. Actual Xcode builds remain separate. |
| [`a0b54f49`](https://github.com/Eabusham2/router-vpn/commit/a0b54f496b1f763dd8096bf84f3cb0bfed6a902e) | Enable owned Local outgoing Tor padding on Android and Apple, including native source/receipt validation, transactional settings, complete profiles and immediate exact-request cancellation. | Complete Android runtime contract passes. Final Android lifecycle passes 1,205 checks/21 mutations; hop 150/5 and DNS 261/7. Apple host delivery passes 1,062/1,063 checks across four variants, with ten defect controls; settings 711/eight, startup 274/twelve and connection profiles 15,220/five. Expanded exact-source native matrices below pass. Platform packages and physical traffic remain separate. |

### Retained measurement lifetimes and fixed Direct bridge protection

| Published commit | Concrete change | Focused evidence and limits |
|---|---|---|
| [`9c8b92fe`](https://github.com/Eabusham2/router-vpn/commit/9c8b92fec36c6bdc0c0b2e01740161d01440c29c) | Expose a memory-only `Joined()` acknowledgment for the exact embedded Tor invocation. | All 14 Cgo loader lifecycle cases and seven executable defect controls pass. A timed-out or failed join, an exited but unjoined process and a replacement owner cannot acknowledge this invocation's cleanup. The fixture executes the actual Go/C ABI wrapper with a controlled native C implementation; it does not establish a public Tor path. |
| [`f327b0b6`](https://github.com/Eabusham2/router-vpn/commit/f327b0b6db811541f99c79cde42626496f135856) | Check a Tor or ordinary-external native monitor's exact command ownership and claim its connection transaction atomically. | The Windows Startup Last failure in run `40618331049`, job `122586077216`, led first to a fixture Stop transaction correction. Repeated local race testing then exposed the production stale-monitor transaction race. Three repeated startup/profile/Stop/monitor suites pass in 50.332s; two executable old-owner/unsynchronized-capture mutations reject. A retired monitor can no longer briefly block the replacement's immediate connection action. New hosted Windows execution remains a separate gate. |
| [`000b205b`](https://github.com/Eabusham2/router-vpn/commit/000b205b690fba2c84c1770a0f91118e7fb82b04) | Measure a fresh external HTTP response on one retained, certificate-verified TLS stream. | Real local TLS and HTTP peers cover valid responses, untrusted roots, wrong hostnames, changed targets, redirects, closed/empty/truncated/oversized responses, cancellation during entered I/O and retryable failed close. Go 1.24.13 repeated race tests, the shipping Go 1.26.3 package and generated source closure pass; all five executable protection mutations reject on the published source. Timing starts with the HTTP request and ends after the complete validated response, excluding TLS preparation and cleanup. The helper cannot dial, resolve, redirect or reconnect. Its fixed external measurement targets are not a DNS policy override. Native circuit binding and public Compare activation are still separate unfinished work. |
| [`1ff69540`](https://github.com/Eabusham2/router-vpn/commit/1ff695407a72bfc5d427d1b58bb1e023c664a666) | Preserve desktop Direct strict protection for complete sets of one to eight literal obfs4 bridges, including all-obfs4 Custom selections. | The compiler reconstructs every TCP tuple from complete normalized source, retains all credentials and deduplicates only identical sockets. Both launch wrappers independently check the same hashed source and exact physical projection. Shared/controller race suites pass; 32 Unix wrapper tests, 2,837 Windows wrapper checks and actual nft/PF/Windows rule builders retain exact ports and cleanup. Shipping form callbacks pass 4,126 Swift, 3,518 PowerShell and 28,048 GTK checks; each rejects seven executable mutations and replays accepted payloads through the Go importer. GTK exercises actual dialogs under Xvfb; Swift uses value-only AppKit boundaries, and local PowerShell 5.1 array behavior is simulated rather than claimed as an actual Windows run. Plain Tor and dynamic PT Direct strict protection remain unfinished. |

### Tor comparison and restoration continuation through `07d89bfd`

This continuation resolves the earlier Tor Compare source gap across the
desktop controller and both mobile hosts. The selected private Router entry,
exit source, DNS and protection policy remain captured throughout the round.
Local and Server use the same randomly selected external target. Each valid
candidate scores `(last_node_response_time + external_response_time) / 2`, and
the selected path repeats both operands before retention. A failed initial or
final trial has no score. The Tor last-node operand is the captured final
relay's HTTP response; it is distinct from external HTTP, circuit setup time,
SENDME timing and ICMP RTT.

These are shipping implementation and executable-test findings. Controlled
native C/Go/Java/Swift fixtures do not establish a public Tor circuit, an actual
system VPN on every device, or a completed release.

| Published commits | Concrete change | Focused evidence and limits |
|---|---|---|
| [`23f13fcc`](https://github.com/Eabusham2/router-vpn/commit/23f13fccf8c2ec7199aa05ce58459b8fa7853e57), [`7c24fdb3`](https://github.com/Eabusham2/router-vpn/commit/7c24fdb36cb45fe17ea1acf9e456fc28d9701c8e), [`b85a3b9c`](https://github.com/Eabusham2/router-vpn/commit/b85a3b9c0372bbd9956fb08758751be1ce365f27) | Capture the one comparison target before candidate startup and implement the owned native final-relay HTTP probe. | Shared route-choice, pinned C helper and Go control/probe tests exercise actual framing, captured ownership and cancellation/drain. HTTP transfer timing excludes path construction. Stale or invalid observations never become successful measurements. |
| [`19554e69`](https://github.com/Eabusham2/router-vpn/commit/19554e69edb7ac2df92e4bfd16b672be5df0e0f9), [`0ee271ac`](https://github.com/Eabusham2/router-vpn/commit/0ee271ac7682554ff592fe69beb5725f921aeab3) | Route Server comparison probes through the authenticated private command and retained Tor circuit. | Actual native Box, authenticated command, verified TLS and HTTP fixtures cover captured circuit/source, selected path and teardown. This does not authorize a global entry-node route change or claim a live private-server test. |
| [`1039d3d6`](https://github.com/Eabusham2/router-vpn/commit/1039d3d6b6cbac8a986dc3f685261240587c9c2a), [`aabb9191`](https://github.com/Eabusham2/router-vpn/commit/aabb91910eb3a90465a46b37a226b3edfc9788ea), [`284a8c06`](https://github.com/Eabusham2/router-vpn/commit/284a8c066e1338aeeaada41b7170b73446e23eab) | Join desktop candidate, native Box and private command owners before replacement, and retain only the selected final owner. | Actual controller wire decoding and native composition are exercised together. Pending terminal flags and drained state cannot manufacture completed cleanup. Source/network/cancellation failures remain disqualifying. |
| [`db9d2648`](https://github.com/Eabusham2/router-vpn/commit/db9d2648a42c24733d6cdf2f7f2fd7e0a4928052), [`4c85fb04`](https://github.com/Eabusham2/router-vpn/commit/4c85fb047664f872663a5964e3c18b9e0be335d9) | Retain embedded probe workers and add the shared gomobile comparison coordinator with atomic Keep/Close ownership transfer. | Actual pinned native Box tests, generated bindings and controller integration pass. The final transfer race fixture runs 256 interleavings and rejects seven intentional defects. Mobile OS adapters follow in the platform commits below. |
| [`4be76a68`](https://github.com/Eabusham2/router-vpn/commit/4be76a68bb8221a0471ff68f196c0e27ba546a9a), [`a339087c`](https://github.com/Eabusham2/router-vpn/commit/a339087c62fd8365411b2fadb9fdf5e471d71dd7) | Keep desktop-only test inputs outside the mobile source copy and bind repeated admission assertions to each actual launch. | Source-copy and executable native fixture corrections preserve the shipping checks and rejection cases. They do not reduce the graph inventory. |
| [`057485d1`](https://github.com/Eabusham2/router-vpn/commit/057485d1f119e1f7ec0fcd451be4f69a5acc4543), [`d426ea74`](https://github.com/Eabusham2/router-vpn/commit/d426ea74cb123d80c4746750cbd8d95ef3f8b5b7) | Connect desktop Tor Compare through real candidates while preserving saved `auto`, and restore the proved execution through Startup Last. | Proof precedes save/adoption. HTTP cancellation and stale source checks retain exact owners. The revised admission audit rejects ten deliberate regressions instead of looking for an obsolete source pattern. |
| [`d0a2c253`](https://github.com/Eabusham2/router-vpn/commit/d0a2c253c28f1930c6ef961e943a10a00c69396a), [`55f46aff`](https://github.com/Eabusham2/router-vpn/commit/55f46aff68fa6f71585df683a8d599b657152690) | Expose captured private-Router Tor Compare in Windows, AppKit and GTK controls and in Speed Lab's typed capability selection. | Actual form callbacks, complete profile captures and Go consumers pass. Speed Lab includes 457 Windows, 1,935 Swift and 2,190 GTK checks at this checkpoint, with six rejected capability/source defects; later platform stages add progress coverage. These counts are local fixture cases, not devices or requirement totals. |
| [`33aaab36`](https://github.com/Eabusham2/router-vpn/commit/33aaab368db9667c81967c3bf54b4252055d10a9) | Execute temporary desktop Tor Compare and restore the previous complete connection and already-proved execution. | Actual controller subprocess and race tests pass under Go 1.26.3 and production Go 1.24.13. Three removed-capture/restoration defects fail their intended assertions. Both unavailable candidates preserve the old VPN; failed or cancelled trials do not save a temporary preference or rerun Compare during restoration. Fixed/Jumbo automatic-MTU no-op checks occur before the background operation lock. |
| [`59b93df0`](https://github.com/Eabusham2/router-vpn/commit/59b93df0d1cfd24b066ac56c4f2dda3d60fa9f41), [`e01a4284`](https://github.com/Eabusham2/router-vpn/commit/e01a428431ac25e388503e561d2c08617c57ccd4) | Correlate progress with a 32-character request nonce and the exact Windows action/observer generation. | Backend race tests pass on both Go toolchains. Strict request parsing rejects malformed, duplicate and case-aliased fields; a progress nonce grants no tunnel authority. Actual PowerShell callback suites cover 13 async groups, cancellation, replacement and closed-dialog completion, plus four new defect controls. Public Tor Compare uses 540 seconds and temporary Speed Lab uses 960 seconds. |
| [`68134183`](https://github.com/Eabusham2/router-vpn/commit/68134183267d516241a80d59353fa61de08fe0e8) | Update the reviewed GTK source digest after the prior Tor controls changed the immutable input. | All insertion guards and the older source identity remain intact. The actual GTK build, nine shutdown cases, ownership/DNS/protection tests and 12 source/anchor negatives pass. The three previously failing hosted UI/release-blocker gates later pass at `cfe6dcd6` and `d08cf0f1`. |
| [`cfe6dcd6`](https://github.com/Eabusham2/router-vpn/commit/cfe6dcd60e26b2b911243a50d7887eddc585f205) | Remove an obsolete initial score when final activation or either repeated operand fails, and publish that disqualification to each observer. | Seven original failures were reproduced. Shared race tests pass under Go 1.24.13 and 1.26.3, actual controller tests pass, and the pinned native Box JSON regression passes. Apple keeps its strict lowest-eligible-score validation; a legitimate fallback no longer conflicts with a failed candidate's stale score. |
| [`df06dcac`](https://github.com/Eabusham2/router-vpn/commit/df06dcac504bab022e0b423551b375f38f781431), [`d08cf0f1`](https://github.com/Eabusham2/router-vpn/commit/d08cf0f1be958c1915ceefaabb7c0482323a6dc1), [`78ca1410`](https://github.com/Eabusham2/router-vpn/commit/78ca14106c9966bf3485e5e1b52f6d29e022f402) | Keep AppKit progress tied to its request, bound response bytes during arrival, and give the actual public comparison session its 540-second resource deadline. | Actual Foundation loopback HTTP tests reject held oversized headers and unknown-length streams before EOF or timeout, accept exactly 32 KiB, preserve newer task owners, and reject six progress defects. The public transport test observes the actual session that creates the task, preserves the ordinary 300-second ceiling, verifies explicit session invalidation, and rejects three deadline/cleanup/redirect defects. Existing Speed Lab integration and eight source-pipeline controls pass; AppKit/Xcode/device execution is separate. |
| [`bbbc0895`](https://github.com/Eabusham2/router-vpn/commit/bbbc089590d1d34c4d5b9e8e52a284be4f71c1cb) | Run Apple Local/Server comparison sequentially inside one PacketTunnel, retain the final native engine, and preserve that concrete execution through temporary-test and Startup Last restoration. | Final shipping Swift host/provider fixtures pass 150 lifecycle assertions and 12 compiled defect controls. Whole-provider Stop during held Start/proof retains admission through final native cleanup; a failed activation releases admission only after acknowledged engine drain. Generated Objective-C selectors and cached headers are checked against the actual pinned bindings. Swift/Go profile, native engine, permission/settings and restoration suites retain their previous negative cases. Xcode and real devices remain separate. |
| [`f4b37272`](https://github.com/Eabusham2/router-vpn/commit/f4b372724bf28979ed7d9c4a1e8de57f21284c14) | Run Android comparison within the one pending Home owner and owned VPN service, preserve saved `auto`, and transfer only the proved final service. | Final Java host/service suites pass 139/287 checks and 11 deliberate defects. Actual generated gomobile API compilation and packaged signature checks pass. Successful transfer/drain releases the reverse Java-to-Go proxy reference; failed close retains it for retry. Existing runtime-contract children passed across the preserved prefix and corrected/resumed suffix, not one uninterrupted full-wrapper run. APK and physical permission/networking acceptance are not claimed. |
| [`02f4fe82`](https://github.com/Eabusham2/router-vpn/commit/02f4fe822e09581b8077790e599f58741ed92b95) | Restore Android Tor Startup Last from a secret-free record bound to complete source and the proved Local/Server choice. | Shipping policy/controller tests pass 1,505 checks and ten deliberate defects; runtime origin/late-completion tests reject three more. Permission passes 3,361 checks/seven controls; Speed Lab restoration passes 1,941/fourteen. Missing or changed history stays disconnected. Temporary/restored connections never overwrite Last, and startup still requires fresh native proof. Ordinary external and two-private-Router Last receipts remain separate work. |
| [`07d89bfd`](https://github.com/Eabusham2/router-vpn/commit/07d89bfd114b0099c49a102bd46d257d798fb75f) | Bind GTK public and temporary comparison progress to the captured request/action, with a dedicated 540-second Connect path and bounded two-second status reads. | Actual HTTP worker tests pass 15 cases; live GTK owner tests pass 113 checks and six runtime defects. Forms pass 2,342 Speed Lab, 7,701 profile, 412 external and 31,128 Tor editor checks, retaining seven editor defects. The complete transformed application builds and passes delayed SMART AUTO/Disconnect/Emergency Stop/MTU, seven Speed Lab heartbeat/Cancel/Close cases and nine CUSTOM dialog scenarios. The older async fixture now performs real profile-load/map-refresh initialization and first verifies rejection of an empty selection. Raw guarded GTK source is unchanged; physical visual/network acceptance remains separate. |

## Requirement ledger refinement

The earlier ledger's broader rows remain in force. These refinements close
specific stale source assessments, not whole requirement families.

| Original identifiers / later request | Shipping paths and evidence | Actual remaining gate |
|---|---|---|
| 111–119, complete profiles/startup; later full connection-profile correction | Android schema-5 and Apple complete profile stores retain ordinary-entry Local Tor, source kind, exact protocol, policy and node references. Desktop/Apple Tor restoration retains the proved leaf while saved `auto` remains unchanged; Android Tor Startup Last adds the source-bound historical leaf in `02f4fe82`. Temporary tests retain complete prior state and cannot publish stale history. The Android pending-permission supersession/replay repair in `a1c91d7b` remains covered. | Android ordinary external and two-private-Router saved-Compare Startup Last receipts; new exact-SHA packages and real permission/restart/restoration acceptance. |
| 149–169, modes/DNS; later explicit resolver policy | Shared external compiler and Tor native owners preserve each imported transport, selected DNS/bootstrap and private-vs-public proof authority. | Full requested graph parity, live selected-resolver traffic and provider checks. Ordinary providers still cannot impersonate a private Home resolver path. |
| 200–213 and 337, kill switch/lifecycle | Existing native physical-egress and cancellation owners are preserved; ordinary mobile source changes carry their own protection request. Desktop Direct sets of 1–8 fixed obfs4 bridges now use complete source-derived TCP exceptions in `1ff69540`. `f327b0b6` keeps retired monitors out of replacement connection transactions. | Actual platform leak/transition tests; direct dynamic Tor transport strict protection remains a source boundary. |
| 214–224 and 336; August 13–14 external node/hop/exit additions | Desktop and both mobile hosts admit the eight implemented ordinary import families before Local Tor. Per-hop measurements identify public entry and Tor exit independently. Private-Router Tor Compare now has distinct final-relay/external HTTP operands, the same captured target, final winner recheck, no-score failure/fallback, and native host retention/restoration. Windows, AppKit and GTK progress belongs to the exact captured action. | Exact-SHA native matrices/packages; real paths and broader requested graph compositions. These implemented Tor families do not close the full arbitrary external-graph scope. |
| 225–241, compatible Jumbo/MTU/measurements; August 16 retest correction | Shared ordinary proxy Jumbo compilation now preserves virtual TUN capacity and immutable policy while retaining packet endpoint MTUs. Native owner reconstruction and MTU authority agree. | Physical MTU/throughput, Retest/Cancel/network-transition acceptance. Raw-packet admission is not weakened to manufacture Jumbo support. |
| 321–326, wider packaging/Portable targets | Current `deploy/build-client.sh` retains qualified ARMv7, FreeBSD, OpenBSD, NetBSD, DragonFly and illumos controller/helper builds in addition to the ten core native packages. | Current CI/package validation where feasible. Controller/helper artifacts are not relabeled as additional full native applications or substituted for the core ten. |
| 342 and later bounded-padding settings | Desktop Local outgoing Tor padding and its companion native proof dependency are published in `5e6aa4a7`/`057957b7`; Android and Apple host adoption, settings and public Local admission are enabled in `a0b54f49`. Actual selected DoT/DoH pool renewal is covered in `15b67f3e`. Server retained-stream expiry is repaired in `576385d7`. Native leases bind full source, session and isolation, require real DNS/path proofs, expire data independently of control replies, and retain cleanup until entered I/O joins. | Current platform packages and physical/public-network cover acceptance. The explicit added matrices below do not represent every transport/rate/layer cross-product. |
| C5–C7, 348, 352–354 | Generic secret-free application delivery, separate private node linking, packaged licensing, image-only production and authenticated mutations remain required. | Exact-SHA package/image/compose publication plus private deployment/administration acceptance. No production server build fallback or Docker socket access is authorized. |

## Native gates, release and live evidence

The initial `dbff30e8` Actions read found 20 push runs: 11 failed and nine
successful. That is a historical diagnosis, not the current release status.
The subsequent changes address observed failures while preserving their
negative tests. Native Windows Tor cross compilation succeeded in diagnostic
run [40608694158](https://github.com/Eabusham2/router-vpn/actions/runs/40608694158);
its Windows AMD64 job then exposed the separate DNS fixture failure fixed above.
Its Darwin AMD64 job exposed the empty-array Bash failure fixed in `15b988c6`,
and Windows ARM64 exposed the file-metadata API mismatch fixed in `a5876568`.
These observed failures are not reported as current native successes.

The mobile host graph inventory is 348 existing Local/direct + 342 Server +
48 new ordinary-entry graphs per platform. Both complete 738-graph native gates
passed before publication in `e5b2d191`, with all 738 missing-engine controls
per host. Their first actual runs exposed a missing OpenVPN build tag and an
incomplete local Xray preparation; both were corrected without removing graphs
or weakening constructors. The full pinned composition was exercised with the
verified C Tor DSO and required Go/LLVM/Swift toolchains. The previous ledger's
missing-tool limitation no longer describes this workspace. The native gate
does not start a VPN or public Tor circuit and is not an Apple SDK/device test.

The final mobile activation retains those 738 cases per host and adds **224
Android** and **528 Apple** enabled Local configurations. The added matrix
covers plain Tor and obfs4 at default/32/64/192 rates, direct/private/ordinary
entries, and the explicitly enumerated Apple entry-layer combinations. The
original matrix retains all six Tor/PT kinds; these counts are not a claim to
have exercised every possible transport/rate/layer combination. Android rejects
738 original missing-engine cases plus 448 enabled missing-engine/changed-source
cases. Apple rejects all 1,266 missing-engine cases and 528 changed-source cases.
Both final runs match their before/after source, prepared copy, module and
native package identities; Apple checks 866 source inputs. No failed source
snapshot was relabeled as a new run.

After the measurement and fixed-bridge changes, the exact `1ff69540` Actions
query returned 26 runs. The source publication/secret, repository, weighted,
Setup Center status/admin and profile traversal gates had passed; native and
authoritative release jobs were still queued, pending or running. Earlier
`f327b0b6` jobs include superseded cancellations. These observations do not
establish a completed release for either commit.

The later exact `d08cf0f1` read shows successful map-first, native UI,
release-blocker, kill-switch, source-publication/secret, repository and weighted
gates. Its native build and authoritative release jobs were still queued,
pending or running at that read. After the public macOS deadline repair,
[`78ca1410`](https://github.com/Eabusham2/router-vpn/commit/78ca14106c9966bf3485e5e1b52f6d29e022f402)
was verified as the remote branch head. Its Actions query returned 25 runs,
including six completed successes and unfinished native/authoritative jobs.
The authoritative run is
[40634757771](https://github.com/Eabusham2/router-vpn/actions/runs/40634757771).
These are point-in-time observations; later main commits require their own
build, asset, checksum, image and compose verification.

The complete local Go package run passed the controller (251.815s) and shared
packages. Its isolated relay container-context fixture encountered a local
ancestor VCS discovery error; that one fixture passed separately in 5.337s with
`GOFLAGS=-buildvcs=false`, matching the Docker COPY context's absence of VCS
metadata. No production build or source protection was changed for that local
fixture condition. The complete Android runtime contract passed; the final
receipt-cancellation revision was also independently rerun through its lifecycle,
hop and DNS suites before the refreshed native identity gates.

The last release collection read still returned the
[`745b3e41` prerelease](https://github.com/Eabusham2/router-vpn/releases/tag/router-vpn-sha-745b3e41e5a78d734391976af9b7cd0637660a0b)
with 12 assets. No newer all-platform package/image/compose/publication success
is certified by this checkpoint. Superseded or queued workflows are not green
release evidence. Continue with the exact current SHA after source changes
stabilize, and verify the authoritative chain, checksums and published assets.

No private AI Board/Portainer deployment, live ASUS/AdGuard/forwarding change,
physical-device acceptance or signing operation occurred in this continuation.
Physical leaks/reconnect/network transitions, off-LAN Methods, visual/DPI and
accessibility acceptance, private benchmarks/admin/update/rollback/provider
checks and distribution remain separate obligations. Use
[the live evidence contract](LIVE-RELEASE-EVIDENCE.md) for actual accessible
targets after the correct exact-SHA release exists. A source audit or published
release cannot fill those evidence fields.
