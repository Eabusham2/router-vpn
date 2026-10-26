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

Every commit below was advanced onto `main` with normal ancestry, followed by
a remote branch read. A pushed commit is not evidence of its completed release.

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
| WireGuard packet-exit change accompanying this ledger | Desktop WG/AWG entries can use a captured WireGuard exit in Local, Server or Compare. The server's independently paired public identity is pinned across discovery, lease acquisition/renewal and restoration; private-key aliases cannot evade duplicate-peer checks. Native selectors, profiles and Speed Lab retain the eighth exit. | 216 captured graph/layer combinations; 144 complete-engine Local/Server parser cases; full shared graph/relay/scoring race suites; live-MTU/restoration/DNS and peer-pin negative tests. Actual encrypted Local/Server TCP/UDP passed with 64/1200/2000-byte payloads, wrong keys, restored keys and wrong Server password: 24 successful payload round trips and six required failures. WPF568/AppKit972/GTK1225 profile checks and WPF132/Swift524/GTK608 Speed Lab checks passed, including the actual Go race consumers. | Native parser and encrypted packet tests used the verified complete Linux AMD64 engine from `355fc9b4`, not a newly packaged current release. The traffic fixture replaces physical/TUN sockets and translates only the Server SOCKS association's bind address/port; native authentication, opaque UDP payloads and both encrypted endpoints remain active. Current packages, updated private agent pairing and physical-device acceptance remain separate. AWG packet exits and broader graph parity remain open. |

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
| 111–119: complete profiles and startup | Desktop setup metadata and native mobile profile stores; Apple Tor schema 5; desktop eight-exit round trips; delayed AppKit catalog restoration; all three desktop Speed Lab form-to-controller source captures. | Full original source wording still needs recovery; startup and complete-profile behavior retain OS permission/restart and physical-device acceptance obligations. |
| 120–148: native map-first UI and telemetry | WPF/AppKit/GTK/Android/SwiftUI shipping composition, native controls and truthful telemetry tests. | Real visual/DPI/orientation/accessibility and location permission checks; a source marker does not establish visual acceptance. |
| 149–169: modes, AUTO/SMART/CUSTOM, DNS | Shared native mode compilers, saved CUSTOM and DNS proof paths. | Complete requested platform/graph parity and actual provider/network proof. Fixed-transport Local/Server/Compare preserves the user formula; the older API-only transport-AUTO path remains separately bounded. |
| 170–199: all requested platforms/architectures | Current authoritative build workflow, native packages and provenance gates; configured Android production signing/version/receipt path. | Same-SHA published release, Apple distribution/signing, the owner's Android production key/full signed package/upgrade acceptance and physical devices. Broader qualified Unix/BSD packaging remains in scope. |
| 200–213: kill switch | Native firewall/route ownership, fail-closed mutation and negative controls. | Physical leak/transition checks; desktop dynamic Tor PT strict egress remains a source boundary. |
| 214–224: real multihop | Native entry/exit identity, seven desktop proxy exits plus WireGuard, mobile wider graph families, authenticated per-session server leases and packet peer identity pins. | AWG packet exits and broader desktop entry/packet/composite graph parity; Tor Server/Compare and ordinary external predecessors remain unimplemented boundaries, pending full original scope reconciliation and implementation. |
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

At the latest recorded observation, `fa79dbfe`'s authoritative run
[40274519770](https://github.com/Eabusham2/router-vpn/actions/runs/40274519770)
had passed delivery contracts, exact-source snapshot verification and the
Linux AMD64/ARM64 and Windows ARM64 complete native engine jobs. Its mandatory
real Android signing fixture and runtime contract steps also passed; the full
APK was still building. The separate Windows native contract and Android
runtime-truth jobs passed. Other native builds were running or queued.
Superseded attempts cancelled by a later push are not successful
releases. The latest published prerelease still targeted `745b3e41`.
Re-read live GitHub for the commit containing this ledger; these observations
deliberately do not claim a completed current release.

No live router, AdGuard, forwarding, Portainer deployment or private test device
was changed in this continuation. The record must remain incomplete until the
original applicable requirements and actual device/deployment evidence support
closure. See [LIVE-RELEASE-EVIDENCE.md](LIVE-RELEASE-EVIDENCE.md).
