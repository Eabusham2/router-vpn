# Router VPN continuation evidence — October 26, 2026

This ledger records the evidence recovered and changes delivered during the
October 26 continuation. It supplements the original requirements and
[reconciled contract](REQUIREMENTS-RECONCILED.md); it does not replace either.
Overlapping historical lists are not added into a completion percentage.

## Requirement authority and recovery limits

The user supplied the October 22 continuation handoff, the historical green
`745b3e41e5a78d734391976af9b7cd0637660a0b` release report, and a new instruction
to finish the requirements and immediately commit/push coherent finished work
to `main`. Live GitHub and the preserved workspace were instead at
`4d85fac8a207d04cd66565190ba52c118bbb99a9` when this continuation started.
The newer source was preserved; older recovery patches were not replayed over it.

Personal-context retrieval recovered indexed user passages, including the
August 11 product request and September 4 Tor bridge request. Searches for the
named original private documents did not return their full contents. In
particular, this continuation did **not** independently read all 356 original
numbered user passages, C1–C7 source messages, or the entire later 32-item
request. The repository audits provide a derived index, not a verbatim original.
An unavailable source is not evidence that its requirement was cancelled.

A later targeted retrieval also returned a user-indexed October 19 passage for
desktop packet exits, proxy entries, OpenVPN, Tor, MAX/ALL and external-node
additions. It supplied continuity evidence, not the complete original numbered
messages. A further private-file search returned no matching original files.

A targeted Tor Server/Compare request later returned "Personal context is
unavailable for this conversation"; one narrower private-file content search
also returned no original passage. The required meaning and source of a Tor
"last node response" therefore remain unresolved. The existing Tor-project
HTTP check proves a dynamic exit; it must not be counted twice or relabeled as
a response from the final relay to manufacture a comparison score.
A further self-contained context query returned "Unable to search relevant
sources". Exact and simplified private-file searches for the Router VPN,
Tor comparison, original transcript and addendum passages returned no matching
files. Those bounded access failures do not close or remove the requirement.

The supplied handoff's explicit corrections remain binding: Home AdGuard;
SMART AUTO and IPv6 On defaults; AUTO encryption/obfuscation requirements Off;
Off/AES-256-GCM/AES-256-GCM plus XOR Start Layers; comparison arithmetic mean
with the same external endpoint, invalid candidates unscored and repeat proof;
30-minute retention from READY; blank AdGuard allow-list unrestricted;
image-only exact-SHA production without Docker socket access; generic apps
separate from private linking; Windows Portable ZIP, with PAF cancelled;
client kill-switch fail-closed and household ASUS forwarding fail-open.
None of this continuation's changes alters those contracts.

## Delivered changes and their evidence

Every numbered commit below was advanced onto `main` with normal ancestry,
followed by a remote branch read. The self-reference row describes the commit
containing this ledger and is replaced with its exact identity in a subsequent
update. A pushed commit is not evidence of its completed release.

| Commit | Changed behavior | Executable evidence in this continuation | Remaining evidence boundary |
|---|---|---|---|
| `ea78be0460cecf7b81d58f1d69c7cd8a47ef2021` | Windows Tor wrapper protects the captured physical Router entry independently of the Tor policy exit. | PowerShell lifecycle/ownership cases and deliberate broken-owner/firewall mutations. | Native Windows kernel firewall and device path acceptance. |
| `0c3dad595a638a1af030212efa01202941176ee7` | Desktop Tor DNS editor/Retest/runtime retain the captured Router entry and exact private Home resolver transport; explicit public Tor DNS stays TCP/DoT/DoH. | Race-tested controller/native DNS selection, ownership, stale-selection, MTU and predecessor cases. | Real selected resolver and public Tor circuit behavior. |
| `2ed1ff2d56ba0d97c5caff542db151eb57a0919e` | Native ownership fixtures handle Windows held directory handles; dependency fixture follows the actual captured environment. | Actual generated Go ownership tests, a forced Windows branch, identity-guard removal rejection, and 13 Python dependency cases. | Hosted Windows compilation/execution for the current SHA. |
| `6aceae56c23ab6076a0dc0bbfa4db6dbdaa39b79` | Platform/build docs stop claiming already implemented native Tor/OpenVPN/AWG paths are absent; retain their real limits. | Repository validation and update audit. | Documentation is an index, not dataplane acceptance. |
| `90ff8885996164c279f01f30e6af982068239afc` | SS2022 handshake cancellation remains bounded when the verified WebSocket transport reports unsupported socket deadlines. | Actual pinned TLS/WebSocket encrypted TCP and Hysteria UDP, normal/low-memory race builds, wrong credentials/certificate rejection and bounded cancellation. | Physical transport/network transitions. |
| `c6673250160f76e88c958319e8bb3d9b632255ef` | Start Layer native test relay survives WireGuard's real handshake retry; the test deliberately drops the first initiation. | Actual WG/AWG AES and AES+XOR TCP/UDP in normal/low-memory race builds; production timeouts unchanged. | Device loss/recovery and live network behavior. |
| `a7f567a374c8a0a963b674e3748c238570b7a67e` | Apple schema-5 complete Tor connection profiles and default/empty LAN-range restoration. | Shipping callbacks/store/native validation: 1,801 Tor checks plus five rejected defect mutations; ordinary external, Codable and transaction suites. | Current Xcode package, signing and device acceptance. |
| `9b9484a6431bb9dd81d0e74d0e81d9180887e437` | DNS release audit follows the captured helper call path instead of a retired helper name. | Product audit; ten audit regression tests including sixteen broken call/ownership variants; actual Go DNS tests. | Source audit success is not DNS network proof. |
| `fa56a3548eba94008ccd4e6d1d6d322c373fa9a0` | Existing Apple release guards recognize schema 5 and retain Start Layer requirements. | Profile/release-gap audits and the actual Go Start Layer contract. | Does not independently prove migration or device installation. |
| `93f3106b0407f1828dfaf086c4882d54cf4b0e6b` | Desktop WG/AWG entry supports seven native proxy exits; profile/UI/Speed Lab retain exact transport and execution. Naive bootstrap follows the captured entry and owned Server lease. Missing mode cannot become Shadowsocks. | 189 graph/layer combinations; 126 native Local/Server parser cases; retained MTU/ownership tests; real WG→Naive H2/H3 TCP/UDP, wrong-key rejection and restoration; WPF490/AppKit727/GTK1074 profile checks; three native Speed Lab form→Go consumers; full GTK shipping/lifecycle gate. | Entry remains WG/AWG; broader packet/composite exits and entry parity remain open. Current all-platform packages and physical paths require separate proof. |
| `0e56a990870591194f751a46362112f9e7c33912` | Tor MTU subprocess fixture waits for a complete bounded mailbox record, matching the real native reader. | A forced 12-byte prefix reproduced exit 93 before the fix; complete transition race suite and four repeated partial-write/publication cases pass. Wrong-owner, expiry and stale-proof rejection remain. | This corrects a fixture race; production ownership, heartbeat and MTU limits are unchanged. |
| `cba811aa8efdb1561063d04d44d0a014ec4d7c75` | DoH3 fixture allocates its TCP downgrade witness first, then reserves the same UDP endpoint with bounded retry. | Complete pinned DNS proxy module passes race tests, including real IPv4/IPv6 HTTP/3, TLS failures, cancellation, listener cleanup and zero TCP fallback. The authoritative Windows ARM64 native DNS HTTP/3 and kernel-proof step subsequently passed at `79192471`. | This establishes the hosted Windows step at that SHA, not every later package or physical DNS path. |
| `bafd28b9a8eab4e43db129b03e2a4baef2c9e916` | Complete-profile Load returns an atomic selected/hop token map; AppKit catalog replies retain generation, request and source ownership. Windows/macOS Speed Lab checks the detached selection again at Run and sends exact source preconditions, including an explicit empty first-use selection. | 873 AppKit profile checks and nine rejected mutations; 156 candidate checks; 126 WPF and 503 Swift Speed Lab checks; both actual form payload sets pass the Go race consumer. Backend tests cover credential/policy changes, privacy, rollback, temporary preflight and current-path ownership without blocking Disconnect. | Exact native packages and physical OS behavior remain independent. Windows uses modal window ownership and value/token checks; it does not claim AppKit's generation mechanism. |
| `64c6521751bcb5464e312dcd212b52c2ab4e91ff` | Native Tor DNS fixture peers add real response latency so an instantaneous local reply cannot be mistaken for a valid zero-duration measurement. | A coarse-clock control reproduces both old CI failures; the delayed real peers pass three times under that same clock. All 25 native Tor cases pass three times with the original sampler; zero/backward/submillisecond clock tests pass under race instrumentation. | Native loopback suite ran without race and without the unrelated Rosenpass C-library tag unavailable in this workspace. Production timing validation is unchanged; hosted Windows verification remains necessary. |
| `7919247145493fd5547e9a6877d2217ec207a6c2` | Linux Speed Lab retains the opened main selection and hop preferences, freezes opaque catalog tokens, and sends the same Run preconditions as Windows/macOS. | 582 actual GTK callback checks; 1,074 complete-profile checks; real form payloads pass the Go race consumer. Full shipping GTK build, controller shutdown and all seven built-app Speed Lab cancellation/close scenarios pass; related map/MTU/CUSTOM UI checks report no errors. | This establishes the tested native Linux composition and loopback ownership, not physical VPN traffic or all-platform release publication. |
| `355fc9b4b6dfabe7e1545190994852381de53e45` | The macOS native import gate follows both real callers into the owned catalog helper and all five popups after the profile-ownership change. | 200 executable Swift form cases and their Go race consumer; 873 profile checks and nine rejected defect mutations. The corrected native import/Go compiler step also passed in the hosted macOS AWG job for this SHA. | A passed import step does not establish the complete AppKit package, iOS build or device behavior. |
| `fa79dbfe9e3f26cbaae3dfa6b9f87a3cfe7d3c76` | The authoritative build can use a configured persistent PKCS12 key, verifies the actual APK certificate/source/version, retains stable increasing ancestry-based version codes, and publishes digest-bound signing metadata. The updater compares the actual installed signer/version; changed keys cannot be labeled compatible upgrades. | Seven local executable signing/capture cases with a disposable private key; 182 updater checks and installed-source/expiry negative mutations; six release-provenance cases, materialization and focused workflow/parity checks. The exact-SHA authoritative Android job subsequently passed its mandatory real Gradle/signing fixture and runtime contract steps. | The real Gradle/APK fixture was explicitly skipped locally because no Gradle/Android SDK was available. No owner's key was created or installed. Production-key availability, the full package's signing state and actual device upgrades remain unverified until artifact/device evidence is inspected. |
| `6e994351f7017d4aa3061e1c8f84a295f34b56c4` | Desktop WG/AWG entries can use a captured WireGuard exit in Local, Server or Compare. The server's independently paired public identity is pinned across discovery, lease acquisition/renewal and restoration; private-key aliases cannot evade duplicate-peer checks. Native selectors, profiles and Speed Lab retain the eighth exit. | 216 captured graph/layer combinations; 144 complete-engine Local/Server parser cases; full shared graph/relay/scoring race suites; live-MTU/restoration/DNS and peer-pin negative tests. Actual encrypted Local/Server TCP/UDP passed with 64/1200/2000-byte payloads, wrong keys, restored keys and wrong Server password: 24 successful payload round trips and six required failures. The exact shipping native race selector passed in 113.310 seconds within its unchanged 180-second bound. WPF568/AppKit972/GTK1225 profile checks and WPF132/Swift524/GTK608 Speed Lab checks passed, including the actual Go race consumers. | Native parser and encrypted packet tests used the verified complete Linux AMD64 engine from `355fc9b4`, not a newly packaged current release. The traffic fixture replaces physical/TUN sockets and translates only the Server SOCKS association's bind address/port; native authentication, opaque UDP payloads and both encrypted endpoints remain active. Current packages, updated private agent pairing and physical-device acceptance remain separate. AWG packet exits and broader graph parity remained open at this commit. |
| `47ef728e3c0a9f05860da0a83bc29105342753b8` | The complete-profile fixture no longer lists canonical `wg` as unsupported. WireGuard aliases, malformed packet names and the other unsupported transports remain negative cases. | Focused Add/Update/Load, exact-hop/private-credential, missing-mode and execution-default tests passed against an exact `6e994351` source overlay, isolated from ongoing AWG work. The expanded working catalog subsequently passed the same focused suite. | This corrects the one stale fixture reported by several exact-`6e994351` CI gates; it changes no production validation and does not establish later CI or publication success. |
| `37c1a4439a50e502ec8489ed58e2f378f8adb411` | The pinned WireGuard adapter publishes dependency readiness only after its owned device starts, allowing an AWG exit to open UDP through the captured entry during native startup. Failed, cancelled and closed devices remain unavailable under the existing lock. | The old implementation failed the real literal-entry readiness assertion. Actual pinned phase tests passed ten times with race instrumentation, including domain deferral, native initialization failure, cancellation and concurrent Close. Exact-source preparation/idempotence/drift guards passed. Corrected native WG-to-AWG Fast Local/Server encrypted TCP/UDP passed. | The locally rebuilt CLI omitted the unavailable Rosenpass C-library tag. Complete shipping preparation reaches this patch, but all current native packages require their own exact-SHA build evidence. |
| `1f9a175525abac9f982a09784c285d35bad94d95` | Tor fixtures use captured-root file replacement for retained readers and explicit admission/cancel/join synchronization with a real transition expiry. Production immutable stop publication, heartbeat and transition limits are unchanged. | Six actual generated native fixture groups passed three times with race instrumentation in 40.316 seconds on an exact `47ef728e` source overlay containing only these two template corrections. Retained foreign readers, wrong ownership, expiry and premature stop acknowledgement remain negative controls. | Linux execution used the seven relevant tags without the unavailable Rosenpass C ABI. The reported Windows filesystem failures still require exact-SHA Windows CI confirmation. |
| `d3c196185c49da268b6c0788ad283ef8afc1f45c` | Desktop WG/AWG entries retain AWG Fast/Strong exits across Local/Server/Compare, complete profiles, native controls and Speed Lab. Exact AWG parameters, private keys, canonical paired Server identity, selected DNS, Start Layers and S4-aware packet overhead remain captured. A separately pinned test-only AWG server exercises the production client boundary without widening it. | 270 graph/layer combinations; full shared graph race suite 149.266 seconds and relay suite 8.454 seconds; focused desktop ownership/DNS/pin/restore tests 22.135 seconds. Existing native traffic selector passed in 109.232 seconds and the separate AWG group in 63.333 seconds, each within its unchanged 180-second bound. Actual WG-to-Fast, Fast-to-Strong and Strong-to-Fast Local/Server TCP/UDP delivered 72 payload round trips at 64/1200/2000 bytes, rejected six wrong-key/S4/lease cases and restored the captured graphs. WPF700/AppKit1170/GTK1527 profile checks and WPF144/Swift566/GTK660 Speed Lab checks passed with actual Go race consumers. | The locally rebuilt native CLI included WG/AWG, QUIC, uTLS, OpenVPN, Naive and gVisor but omitted the unavailable Rosenpass C-library factory/tag. This is bounded native traffic evidence, not a complete current package. Fresh pinned reference compilation and actual AWG traffic are mandatory in the complete-bundle gate. Current native builds, private agent pairing, path MTU and physical-device acceptance remain separate. Broader desktop entries and composite exits remain open. |
| `ad50a9b5b52f7e521057f78e66d84c1ab82fcc37` | The mandatory AWG reference helper selects Go 1.26.3 explicitly instead of allowing the runner's older launcher to force local compilation. Exact compiler and dependency checks remain required. | Six positive compiler-selection cases used a real Go 1.26.0 launcher and Go 1.26.3 compiler across two launcher forms and three inherited toolchain settings. The old-source mutation failed all six cases as intended. | This fixes the observed Linux ARM64 reference preflight failure after its complete engine and native traffic had passed; all newer complete native jobs remain independently required. |
| `f57ba86c62ce3ba5a3934e0019d6b5b887ba3273` | Native Xray traffic fixtures reserve the selected port through setup and require startup evidence from their owned child. Bounded retry handles only an observed joined bind collision. Production tunnel behavior is unchanged. | The exact prior head plus this template passed normal and low-memory race matrices in 8.109 and 7.918 seconds, each with 108 real encrypted TCP/UDP payload round trips. Foreign listeners, invalid configuration, UDP-only child/foreign TCP substitution and deliberately broken nested/native ownership remain negative controls. | Real Windows and complete Android/native package gates must execute the corrected fixture at the current SHA. |
| `e27a4e0e20dc26877c604530159094a63fc924ca` | Windows runtime privacy uses the actual opened file's ACL and establishes private directories before staging secrets. DNS proof parses the same validated bytes and retains file, command/native owner, session and profile identity through completion. Active proof never repairs permissions or adopts replacements. | An isolated exact-parent source overlay passed focused Linux race tests in 4.376 seconds; actual Windows AMD64 and ARM64 test packages compiled. Snapshot replacement, stale ownership, public runtime and selected-policy negatives remain covered; native Windows ACL cases are included in the shipping selector. | Windows ACL behavior itself requires actual Windows execution. Cross-compilation and Linux success do not establish it, physical DNS behavior or release completion. |
| `06eb91c1e03717a9d76ba8bf57499d12f211f2f7` | The authenticated router-agent HTTP decoder accepts the existing captured packet-public-key field and passes it into the real lease manager. Strict malformed-field and mode validation remains in place. | The old HTTP decoder rejected all six WG/AWG canonical-key and clamped-alias positive cases with 400. The fixed actual route/manager suite passes six complete discovery/create/renew/wrong-pin/delete lifecycles and 13 malformed/unowned cases; focused agent and relay race suites passed in 1.309 and 1.090 seconds. | Native process startup is doubled in this HTTP fixture; it establishes decoder/manager ownership, not encrypted packet delivery or private deployment. |
| `15a232ae8bb3b4b99145f843f25aee28a94719d4` | Desktop WG/AWG entries retain three complete TCP/UDP composite exits across Local/Server/Compare, profiles, native selectors and Speed Lab. The compiler preserves both authenticated lanes, their one optional Start Layer, selected DNS/bootstrap and captured physical endpoint; Server execution removes the entire local exit closure before adopting its owned lease. | Shared graph race tests passed 351 graph/layer combinations and 117 new malformed-owner negatives in 21.703 seconds. The unchanged native selector passed in 139.186 seconds, including 234 real parser cases. A separate native encrypted matrix passed 30 trial cases in 38.561 seconds with real TCP/UDP 64/1200/2000-byte payloads, wrong independent lane secrets, wrong lease credentials and restored sessions. Nine reference-helper escape cases are rejected. WPF898/AppKit1467/GTK1980 profile checks and WPF162/Swift629/GTK738 Speed Lab checks pass, including their actual Go race consumers. | The local native engine includes the exercised WG/AWG/composite/Xray/HY2 paths but lacks the Rosenpass C-library factory. Layer combinations have parser/ownership evidence; the new traffic matrix uses Start Layer Off. Complete current-SHA builds, physical/off-LAN acceptance, broader entries and the distinct complete MAX packet/helper graph remain open. |
| `968ca6da92f54d9d8beefbe8f8d8333130343e4e` | Tor DNS cancellation fixtures exercise both legitimate owned orderings without waiting for a stage that explicit cancellation has already replaced. Both retain completion-without-drain, DNS lock, MTU hold, original connection and joined teardown checks. Production cancellation and time limits are unchanged. | An exact-parent isolated fixture deterministically reproduced the old failure in 5.357 seconds. The corrected case passed ten race-instrumented repetitions in 8.134 seconds, and the complete Tor DNS group passed in 6.593 seconds. | This repairs the actual closure-CI fixture failure at `15a232ae`; it does not establish later CI or physical DNS behavior. |
| `7ceea27a81cfb50e86bb655a1f218c27a4c6571d` | Shared mobile Server execution captures canonical packet and paired PQ public identities across discovery, leases, renewals and native restoration receipts. The actual authenticated HTTP route and lease manager enforce the same strict mode/field rules. Start Layer rewriting cannot erase invalid original metadata. | An isolated exact-parent overlay passed 333 race-instrumented test/subtest records: mobile 190 in 8.936 seconds, relay 99 in 3.823 seconds and HTTP 44 in 1.214 seconds. All nine packet/PQ/MAX modes failed the original retained-pin baseline. An engine-replacement negative reproduced the need for final owner revalidation. Six source-copy/preparation/idempotence cases passed. | Native engines are doubled in these ownership fixtures; real PQ negotiation and traffic require separate native-factory evidence. The broader uncommitted graph matrix exceeded its local timeout and is not counted as a pass. |
| This commit — Apple Server identity restoration | Apple Speed Lab and startup Last retain public Server packet/PQ pins with the original source and proved execution. Provider preparation applies them before native startup, preserving them across MAX hostname resolution. Old unpinned packet Server receipts cannot authorize a new peer; legacy Local/proxy receipts remain compatible. | Shipping Swift receipt/store checks: 1,015; native-wrapper callbacks: 593 plus MTU-close 594; Speed Lab: 185 plus two guard-removal negatives; startup: 274; external-owner: 131. The provider MAX preparation suite passed 24 real Go launch graphs and 273 source/DNS/lifetime checks. Independent review found no blocking issue in the five shipping files and six harnesses. | Native handles, private-store and OS boundaries are explicit test doubles. The Go launch compiler is real; current Xcode-generated binding/build, signing and physical restoration remain independent requirements. |

The native Xray REALITY Vision, PQ REALITY Vision and XHTTP engine additionally
passed its real encrypted loopback TCP/UDP interoperability suite using the
pinned separately built Xray server. This tests the native transport; it is
not a claim that every composed graph ran against a private Router VPN server.

## Requirement index and actual remaining work

Number ranges below are taken from the repository's recovered audit comments.
They identify the historical groups; wording in this table is a paraphrase.
The later corrections and external-node additions overlap these groups.

| Requirement group | Current source/evidence index | Remaining requirement or evidence |
|---|---|---|
| 1–15: owned sessions, progress, proof, rollback | Controller/native ownership tests; retained DNS, MTU, comparison and Speed Lab owners. | Physical reconnect, cancellation, leak and network-transition acceptance for each platform and requested graph. |
| 16–44: usable third-party Methods | Setup Center Methods generators and protocol import/URI suites. | Real off-LAN compatible-client imports and traffic, including historical SOCKS5/OverTLS/Shadowsocks cases. |
| 45–92: setup, administration, management | Authenticated agent/admin routes, Setup Center onboarding and connected-client controls. | Private-target Stop/Emergency Stop/Resume, kick/revoke/ban and forwarding acceptance. |
| 93–110: generic packages and private linking | Exact-SHA delivery, portable ownership, pairing/private-store tests. | Current published assets plus real installation, relocation and multi-router linking. |
| 111–119: complete profiles and startup | Desktop setup metadata and native mobile profile stores; Apple Tor schema 5; desktop thirteen-exit round trips; delayed AppKit catalog restoration; all three desktop Speed Lab form-to-controller source captures. | Full original source wording still needs recovery; startup and complete-profile behavior retain OS permission/restart and physical-device acceptance obligations. |
| 120–148: native map-first UI and telemetry | WPF/AppKit/GTK/Android/SwiftUI shipping composition, native controls and truthful telemetry tests. | Real visual/DPI/orientation/accessibility and location permission checks; a source marker does not establish visual acceptance. |
| 149–169: modes, AUTO/SMART/CUSTOM, DNS | Shared native mode compilers, saved CUSTOM and DNS proof paths. | Complete requested platform/graph parity and actual provider/network proof. Fixed-transport Local/Server/Compare preserves the user formula; the older API-only transport-AUTO path remains separately bounded. |
| 170–199: all requested platforms/architectures | Current authoritative build workflow, native packages and provenance gates; configured Android production signing/version/receipt path. | Same-SHA published release, Apple distribution/signing, the owner's Android production key/full signed package/upgrade acceptance and physical devices. Broader qualified Unix/BSD packaging remains in scope. |
| 200–213: kill switch | Native firewall/route ownership, fail-closed mutation and negative controls. | Physical leak/transition checks; desktop dynamic Tor PT strict egress remains a source boundary. |
| 214–224: real multihop | Native entry/exit identity, seven desktop proxy exits plus WG, AWG Fast/Strong and three TCP/UDP composite exits, mobile wider graph families, authenticated per-session server leases and canonical packet peer identity pins. | Broader desktop entry/PQ/complete-MAX graph parity; Tor Server/Compare and ordinary external predecessors for Tor remain unimplemented boundaries, pending full original scope reconciliation and implementation. |
| 225–241: MTU, measurements, Jumbo, padding | Path-owned Auto/Fixed/Retest/Cancel, native interface readback, 50-sample node statistics, real byte/time throughput. | Physical path MTU and per-hop performance; Tor exit padding semantics must not be invented from an assistant's unsupported-feature list. |
| 242–251: asynchronous downloads | Broker ownership/cancellation/retention and archive safety tests. | Actual private-host download/retry/cancel and bounded-storage acceptance at the released SHA. |
| 252–262: AI Help/providers | Server-side provider configuration and truthful unavailable states. | Real provider credentials, requests and private-target behavior. |
| 263–274: release and live evidence | Exact-SHA authoritative native/images/compose/publication and live evidence tooling. | A green historical release does not certify current main; all applicable live gates remain independent. |
| 275–291: production/privacy/ASUS safety | Image-only compose, no socket boundary, private exposure and tagged forwarding invariants. | Deliberate exact-SHA AI Board/Portainer deployment, live ASUS/JFFS fail-open checks and rollback. |
| 292–311: current docs and retired designs | Reconciled scope and source/build docs. | Keep new source boundaries and exact release observations current; no claimed completion from old source-marker totals. |
| 312–319: two onboarding surfaces | Separate native and Setup Center guides/onboarding. | Fresh-user teaching, permissions and first-connection acceptance on actual targets. |
| 320–329: native/Portable/broad packaging | Current build/provenance and Windows Portable lifecycle tests. | Published current packages and native installed/Portable relocation/device checks. |
| 330–339: forwarding/LAN/pairing/multihop | Authenticated controls, private bundles, captured LAN and path choices. | Off-LAN and real-router acceptance, including household Internet preservation. |
| 340–347: MAX/ALL/padding/update | Native composite/MAX owners, bounded private DAITA, endpoint/source pins and update recovery tests. | Full platform/graph coverage and real private performance/update/rollback acceptance. |
| 348–356: licenses/management/branding/guides | Packaged-license, management-UI and guide gates. | Same-SHA package content and actual native visual/use acceptance. |
| C1–C7 | `deploy/recovered-corrections-audit.py` and `configs/current-requirements.json`. | AWG off-LAN, onboarding lifecycle, authenticated management, AdGuard policy, bounded Windows fallback, image-only production and generic/private separation retain their distinct source/live obligations. |
| Later 32-item/map-first/external additions | Current user handoff, reconciled contract and shipping host paths. | Original full user passages were not recovered in this continuation. Do not erase or re-count these requirements based on this table. |

## Release and live acceptance

Use the exact current main SHA and latest attempts of the authoritative
`Build all Router VPN release gates` workflow. Enumerate its child jobs even
when the wrapper says queued. Workflow counts vary with changed paths; an old
25-workflow count is not a permanent release denominator.

Verify all required native assets, checksums, manifest entries, ARM64 custom
images and generated exact-SHA compose before calling publication complete.
Unsigned re-signable IPA, debug-signed versus production-signed APK, image-only
compose and a published prerelease keep those exact meanings. The Android
compatibility filename alone does not identify its signing state. None is
private deployment evidence. The available GitHub connector rejected signing
secret/variable inventory as unsupported; this does not prove configuration
is absent. See [Android signing](../android/PRODUCTION-SIGNING.md) for the exact
configuration and evidence contract.

An earlier observation of `47ef728e`'s authoritative run
[40277443741](https://github.com/Eabusham2/router-vpn/actions/runs/40277443741)
had passed the source/security audit and Linux AMD64/ARM64 complete native
engine jobs. The current requirement, release-gap, multihop, custom-exit,
OpenVPN and standalone AWG gates passed. The real Android signing fixture
also passed, while its full authoritative APK was still building. The client
Android build exposed a native composite fixture listener collision after its
normal-memory matrix had passed. Windows native tests exposed a real DNS
runtime privacy check using POSIX mode bits on Windows, in addition to the Tor
fixture failures corrected above. The Windows privacy and Android fixture
repairs were subsequently published as `e27a4e0e` and `f57ba86c`, respectively.
Their focused tests passed; that does not establish a completed newer release.

At `d3c19618`, the authoritative run
[40333384733](https://github.com/Eabusham2/router-vpn/actions/runs/40333384733)
built the complete Linux ARM64 native engine, passed 29 receipt checks and ran
the existing native traffic selector successfully in 111.061 seconds. The
following AWG reference build rejected the runner's older Go launcher because
it inherited `GOTOOLCHAIN=local`. Commit `ad50a9b5` selects the required exact
Go toolchain; an actual Go 1.26.0 launcher regression demonstrated both the old
failure and the fixed selection. Current-SHA complete builds and all-platform
publication remain pending evidence. Superseded attempts cancelled by a later
push are not successful releases. At the last publication read, the published
prerelease still targeted
`745b3e41`.
The actual requirement-closure job at `15a232ae`
[40337813998](https://github.com/Eabusham2/router-vpn/actions/runs/40337813998)
exposed the Tor DNS cancellation-order fixture described above. The old failure
was reproduced in isolation and corrected in `968ca6da`; production cancellation
was unchanged. This is not a claim that the newer full release has passed.

Re-read live GitHub for the commit containing this ledger; these observations
deliberately do not claim a completed current release.

No live router, AdGuard, forwarding, Portainer deployment or private test device
was changed in this continuation. The record must remain incomplete until the
original applicable requirements and actual device/deployment evidence support
closure. See [LIVE-RELEASE-EVIDENCE.md](LIVE-RELEASE-EVIDENCE.md).
