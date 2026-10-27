# Router VPN continuation evidence — October 27, 2026

This record supplements the original user requirements, the
[reconciled contract](REQUIREMENTS-RECONCILED.md) and the
[October 26 evidence ledger](CONTINUATION-EVIDENCE-2026-10-26.md).
It does not replace the original 356 items, C1–C7, later 32-item product request,
map-first design, external-node additions or subsequent user corrections.
Overlapping lists are not converted into a completion percentage.

## Authority and recovered state

The current instruction is to finish the requirements and commit/push each
coherent finished change directly to `main` after reconciliation. The supplied
handoff's `5967e9c3` and green-release report's `745b3e41` are historical.
Live GitHub and the preserved workspace instead started at
`936516e5fb4fd0027dd1583fb2ff11b6072e593e`, 186 commits ahead of `745b3e41`.
Newer work and its normal ancestry were preserved. The prior workspace was
left intact, and recovery patches already present upstream were not replayed.

Personal-context retrieval recovered indexed user wording for Local/Server
comparison: measure the last node and the same random external endpoint through
each candidate, average the two valid response times, retain the lower result,
and disqualify timeouts. Searches of the named original private files did not
recover their complete contents. This continuation therefore does **not** claim
to have reread every original numbered request, C1–C7 source message, or later
32-item passage. Repository audits are a derived index; missing retrieval does
not cancel a requirement. A Tor exit-check response is not an independently
defined last-node measurement and cannot be counted twice for Compare.

The ordinary-external desktop Tor host changes and server Tor work found in
the previous workspace were inspected against current source. Only coherent,
tested changes listed below were published. Server prerequisites alone are not evidence of usable host integration.

## Verified source changes and pushes

Each linked commit was created on the current `main` parent without force,
and a fresh remote branch read confirmed the intended commit. Local source was
then reconciled with that exact Git tree while preserving unrelated work.

| Commit | Concrete change | Focused evidence and limits |
|---|---|---|
| [`c81d0930`](https://github.com/Eabusham2/router-vpn/commit/c81d0930a381633c83fcb267328612e5286d7be7) | Split the native capture/parser and retained-graph/MTU parser matrices into separate processes, each retaining the existing 180-second deadline. | The dependency suite passed 15 tests. Partition checks retain every original target exactly once, including platform ACL negatives. Ownership and real-traffic phases remain unchanged. This does not fix the separate native startup race. |
| [`f3eb9ffc`](https://github.com/Eabusham2/router-vpn/commit/f3eb9ffc1406ee2f89ec72b2b92c61a2905f671b) | Select Go 1.26.3 for source jobs using stable `testing/synctest`; preserve the module's Go 1.24.13 minimum and record its toolchain. | Focused relay/admin race tests and workflow checks pass. Explicit job versions are necessary because the pinned setup-go action reads the module's `go` directive rather than its `toolchain` directive. |
| [`2bdd2c66`](https://github.com/Eabusham2/router-vpn/commit/2bdd2c66508222c20145e0cd40266b13aa4ef5ee) | Verify GTK device dependencies in the actual source manifest and copy loop without requiring obsolete adjacency. | Real GTK device checks passed 600 cases and 49 saves; 14 deliberately broken variants were rejected. |
| [`548f9d24`](https://github.com/Eabusham2/router-vpn/commit/548f9d24f81ab460e298b3a92605da3d8041a08b) | Resolve the test-owned macOS temporary-directory alias, and clone a containing Windows profile store so PowerShell array enumeration cannot evade the relink fixture. | Old failures reproduced in isolation. Private-store, relink and payload tests pass without relaxing production symlink/source checks. Hosted macOS and Windows PowerShell 5.1 builds remain separate evidence. |
| [`3c125deb`](https://github.com/Eabusham2/router-vpn/commit/3c125debc9221efc111ab89a5d0dda851e6094de) | Adopt captured ordinary external predecessors across the desktop Local Tor connection lifecycle. | Focused isolated race tests, product and Tor audits, and rejected admission/source-token mutations cover Connect, profiles, startup, updates and Speed Lab restore. All eight supported import families retain complete transport validation and their distinct public-address proof. Physical networking and Server execution are not established by these tests. |
| [`02ddd025`](https://github.com/Eabusham2/router-vpn/commit/02ddd025568d5c8a7273e5be684bb8ceb6c95084) | Reopen saved ordinary Tor predecessors in Windows, macOS and Linux path dialogs without treating their protocol as a Router mode. | Windows 267, Swift 266 and GTK 259 cases passed; each generated payload set passed the Go race consumer. The published old Windows initialization reproduced the valid-path failure. Missing/duplicate entries, changed imported protocols and Router-only mode substitution remain rejected. Swift helpers run with value-only native-control doubles; GTK widgets run under Xvfb. Full AppKit/WPF packages and physical visual acceptance remain separate. |
| [`078d4ef3`](https://github.com/Eabusham2/router-vpn/commit/078d4ef3ccd2d1ac701c4b57c193799963857d2d) | Join initial native network/power callbacks before publishing Tor ownership. | Actual pinned native race and reset controls pass; real network changes still retire the owner. Physical transitions remain separate. |
| [`285a8093`](https://github.com/Eabusham2/router-vpn/commit/285a8093e47b05274b386d92f6f153f348cd8294) | Authenticate Tor source discovery and bind the detached catalog to entry identity, acquisition challenge, source hash and DNS-policy hash. | Discovery never starts a worker or grants traffic proof. Changed/replayed identities remain rejected. |
| [`d76977a8`](https://github.com/Eabusham2/router-vpn/commit/d76977a80b8e08277a395c7872af98f38710dca0) | Refresh the exact GTK source pin for the already published saved-path correction. | Actual GTK preparation, map and release orchestration checks pass; removing the source guard remains rejected. |
| [`a77a90a4`](https://github.com/Eabusham2/router-vpn/commit/a77a90a451e50b07b8573aa66525abfd40470fa8) | Run isolated native Tor workers and package the pinned standalone Tor/control runtime in the server image. | The private per-client front stays closed until selected-DNS/Tor proof; nonce and expiry generation bind every receipt. Actual built package, SAFECOOKIE/offline control, production-tag native tests and proof-gate/expiry mutations pass. ARM64 installed-image execution and public circuits need current CI/live evidence. |
| [`ae2195a6`](https://github.com/Eabusham2/router-vpn/commit/ae2195a6d2b79a7a9037b2bd79b699a77229910d) | Provision canonical private Tor sources before atomically updating the paired registry. | Isolated baseline plus ten files: 38 operator/regression tests and focused Go race tests pass using the actual package/native parser. Replacement owners, unrelated sources and ordinary exits are preserved. Installed ARM64 no-network validation is wired into preflight. |
| [`adf24e9a`](https://github.com/Eabusham2/router-vpn/commit/adf24e9aa3b0e6261fdffb9aef8f60b61ee11c72) | Adopt authenticated Tor Server leases inside the captured desktop native graph. | Shared and actual native Local/Server race suites pass. Native tests exercise SS2022 entry traffic, exact HTTP/SOCKS lease ownership, selected DNS and client public-exit proof; removing source matching, client DNS proof or retained cleanup ownership fails. No local Tor child is constructed for Server. These are Linux AMD64 native tests, not mobile host or physical-network acceptance. |
| [`9d87c110`](https://github.com/Eabusham2/router-vpn/commit/9d87c110458fc5d84f5c5366e748fa3982d24f57) | Connect, save and restore desktop Tor Server selections through public Connect, Startup Last, complete profiles, DNS/device edits and Speed Lab. | Exact isolated 28-file source: 796 cases/subtests pass with race detection, plus 1,920 Windows wrapper checks, 26 POSIX tests and 36 source-audit regressions. Two form-only entry points are run separately with their payloads below. Retained execution mismatch, null Server binary and stale graph/source captures reject before runtime/firewall admission. |
| [`943d7462`](https://github.com/Eabusham2/router-vpn/commit/943d74621667ac13e6a84f5a3d28dfefc3769c47) | Preserve private Router Server paths in all desktop bridge editors. | Windows 286 and Swift 312 callback checks, rendered GTK 2,176 checks across 82 dialogs, and three mutations per platform pass. Every generated Local/Server payload set passes the actual Go importer with race detection; changed execution rejects stale editor captures. Full AppKit/WPF builds remain CI evidence. |
| [`01ae5aef`](https://github.com/Eabusham2/router-vpn/commit/01ae5aef62f08ec23c930bf85d61e6031afa6b0e) | Make the verified lease client, canonical server policy and immutable proof/DNS values available to mobile preparation, preserving desktop aliases. | Focused shared race, actual generated mobile copy-set compilation, a rejected desktop-dependency mutation and server preparation tests pass. This prerequisite does not yet enroll mobile Server execution or its host cleanup. |


| [`1ee61b03`](https://github.com/Eabusham2/router-vpn/commit/1ee61b030422181612a4e0be9b7db257fc317aa0) | Reject enabled or malformed Tor padding before compiling a runnable graph. | Thirty rejection and ten dormant-policy cases, shared race tests and the actual generated mobile copy pass; removing the guard recreates silent omission. This is admission protection, not completion of padding. |
| [`c88a2f0c`](https://github.com/Eabusham2/router-vpn/commit/c88a2f0c1408dc9e493debfc80bbe20ac3dd5f1a) | Keep strict protection through all eight captured ordinary desktop Tor entry families. | Independently recomputed physical egress, typed ordinary proof, native/controller race tests and Windows/PF/nft consumers pass. Actual editor checks: Windows 1,409, Swift 1,533, GTK 11,483 across 451 dialogs; five broken variants per platform reject. Snowflake UDP remains invalid through TCP-only SOCKS/HTTP entries. These entries gain no private Router, Home DNS or Server authority. |
| [`c504b642`](https://github.com/Eabusham2/router-vpn/commit/c504b642b8ba8d4a92bdff70d8c4a6dd7cdfa86b) | Give the relay preparation tests valid pinned-core fixtures and preserve invalid-source rejection. | Two relay-build and six native-scope tests, plus the failing Go wrappers under race detection, pass. Production source validation remains unchanged. |
| [`a24845ef`](https://github.com/Eabusham2/router-vpn/commit/a24845ef32cad4c5271941b6f771450fc176fa41) | Own mobile Tor Server lease, selected DNS, complete native source and retained cleanup inside the existing Box. | Fifteen actual pinned native cases pass under race detection through SS2022, authenticated leased SOCKS, TLS Tor proof and DNS. Cancelled-data cleanup, changed-TUN-source and skipped-DNS mutations reject. Failed or late SOCKS construction retains its socket until acknowledged close. Android/Apple host adoption is separate from this foundation. |
| [`a9ee6fd5`](https://github.com/Eabusham2/router-vpn/commit/a9ee6fd5f60b4e428b021418f9e72ba466d079ac) | Run Windows lifecycle matrices in five bounded processes. | All 164 compiler-discovered tests from the original selection occur exactly once. Both actual workflow PowerShell bodies issue the exact commands and stop after an injected failed phase. Eleven release-gate tests pass; each process retains its original 180-second deadline. |
| [`9fcbd80f`](https://github.com/Eabusham2/router-vpn/commit/9fcbd80fa04dd6a9d4018772af06b159658cd525) | Capture canonical PQ fixture ownership through macOS temporary aliases. | Ten tests and four production mutations pass. Alias retargeting cannot redirect owned cleanup, and linked cores, changed sources and escaping directories still reject. Actual macOS packaging remains CI evidence. |
| [`8cce57a3`](https://github.com/Eabusham2/router-vpn/commit/8cce57a378d16eb356115d7f6831b512d915b1b2) | Carry Android Tor Server through the existing VPN service, exact proof receipt, saved choices and retained lease cleanup. | The host and boundary evidence is recorded below; physical networking and the complete native parser/package gates remain separate. |
| [`27ec75bb`](https://github.com/Eabusham2/router-vpn/commit/27ec75bbcde1e06995184e8cd06fe4583f48ebba) | Carry Apple Tor Server through the existing PacketTunnel Box, retryable cleanup, profiles, Startup Last and Speed Lab. | Swift 6 host lifecycle and actual shared-compiler tests pass. The exact graph inventories are retained for native CI. Current Xcode/IPA packaging, signing and device traffic are not established by host tests. |
| [`e5804875`](https://github.com/Eabusham2/router-vpn/commit/e5804875bb5e027242b5e0e3d00855ac9c253ba5) | Align the Android external-policy Tor boundary and declare the stable synctest files' Go language requirement. | The shipping Java/Go external-policy gate passes 1,311 checks. All 21 selected Tor lease/HTTP tests pass with race detection and the native Xray `go vet` package set passes. Production module minimum, validation and cancellation protections remain unchanged. |

### Android Tor Server host adoption in this change

The real Tor form, StandardExit dispatcher and existing VpnService now carry
explicit Local or Server execution for a captured private Router entry. Plain
Tor and all five bridge choices retain the exact entry mode, Start Layer,
credentials, selected DNS, IPv6, LAN and MTU policy. The staged metadata binds
the complete native graph, both profiles, session and predecessor graph hash.
A real native execution receipt must match the captured request before the app
reports Connected. Complete profiles, Startup Last and Speed Lab restoration
preserve Server instead of replacing it with Local or rerunning Compare.

Disconnect and asynchronous cancellation revoke data immediately. The service
joins retryable hop, DNS and MTU measurement owners before retaining its Box, TUN
and entry until the exact Server lease acknowledges DELETE.
During that bounded native close only, the already-cancelled Server owner may
bind new cleanup sockets to its captured unchanged physical network. A retained
MAX entry requires exact source and physical readback; changed Home selection
cannot reopen data. The eight-second admission is cleared on both success and
failure. Pending cleanup stays retryable and cannot release replacement owners.

Focused evidence: 342 actual Java/Go Server graphs and 6,541 assertions, alongside
348 Local graphs and 20,613 assertions; 4,363 real-form assertions and 162 compiler
roundtrips; 983 proof/service lifecycle assertions and thirteen rejected mutations;
561 real MAX preparation assertions and 55 full-service assertions; full service
compilation and four broken-signature guards; 1,729 profile assertions across
130 cases; 935 startup assertions; 941 Speed Lab restore assertions and twelve
mutations; 2,014 permission assertions; and the actual runtime teardown suite.
The unchanged MTU suite passes 118 assertions and six negative controls.

Java platform/native handles are boundary doubles in these host tests. The
actual native parser gate is wired to all 690 Local/Server graphs, with eight
pinned-gate contract tests passing. That 690-graph native run was **not** performed
locally: this workspace lacks the required verified Tor DSO and LLVM 21. It
remains exact-SHA CI evidence, as do APK packaging and physical Android tests.

### Apple Tor Server host adoption

The existing PacketTunnel engine dispatches Server profiles to the shared
Server compiler and one `routervpn-server-tor` owner in the same native Box.
Its immutable metadata captures execution, both profiles, predecessor graph,
session and complete native configuration. Server creates no local Tor process
or local Tor state directory. Selected-DNS and actual client-path public Tor
proof precede a usable receipt; a server-ready lease alone cannot connect.

Cancellation revokes data before draining captured hop, DNS and MTU operations.
The MTU owner keeps its physical network monitor while the entry carries exact
DELETE cleanup. Failed close retains the native proof, Box, platform and staged
source, and rejects a replacement start until cleanup is acknowledged. Retry
uses the captured owner and never a replacement connection. Local/Server choice
survives full profile CRUD, Startup Last and temporary Speed Lab restoration.
Startup Last now fingerprints the validated Tor entry slot instead of the
ordinary-external slot. Compare remains rejected pending real scoring inputs.

Focused evidence: 342 actual Swift/Go Server graphs and 6,479 assertions;
348 Local graphs, 285 Home-DNS variants, 2,025 ordinary-entry/execution/layer/
OpenVPN graphs and 320 device-policy combinations in the 39,888-assertion Local
gate; four Swift 6 engine variants with 670/670/671/670 checks and five Server
defect mutations; MTU cleanup with six rejected mutations; complete profile
CRUD across 288 cases and 6,676 checks with five original mutations; 1,443
execution/Startup Last checks; and 131 ordinary-external ownership checks.
The exported Server inventory contains 342 directories and 793 hashed files.
The native gate requires all 690 Local/Server graphs and both outbound
registrations, with nine gate contract tests passing. The actual 690-graph
native run and Xcode build were not performed in this workspace; they remain
exact-SHA CI requirements alongside real-device networking and distribution.

## Requirements still requiring source or runtime work

This is the concrete continuation queue, not a complete replacement inventory.
The older ledgers retain the original identifiers and broader requirements.

| Requirement family | Established source boundary in this continuation | Remaining evidence or implementation |
|---|---|---|
| Desktop ordinary entry → Tor | Public Local Connect and restoration retain WG, AWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and supported OpenVPN imports. | Strict protection now retains the captured physical egress (`c88a2f0c`); physical leak, reconnect and path acceptance remain. Ordinary public-IP proof must not acquire private Router authority. |
| Desktop private Router entry → Tor bridge Server | Real no-TUN worker, source provisioning, native leased outbound, desktop Connect/restoration and three editors are connected and locally tested. | Exact-SHA Windows/macOS/Linux packages and ARM64 image validation, public Tor circuits, private pairing/deployment and device acceptance. Plain-Tor desktop controls remain separate source work. |
| Mobile private Router entry → Tor Server | Shared actual native lease/proof/cleanup and Android/Apple forms, Connect, profiles, Startup Last and Speed Lab are integrated. | Each platform's complete 690-graph native gate, exact-SHA APK/IPA packages and device networking remain separate. |
| Tor Compare both | The required arithmetic and invalid-candidate rules are preserved. | Distinct, correctly owned last-node and external measurements through each actual candidate; final winner recheck and restoration. Dynamic Tor exit proof is not either score input by itself. |
| Tor native startup | Initial network/power callbacks are joined before ownership publication, with actual native race/reset controls (`078d4ef3`). | Current packaged native builds and physical network/power transitions; no remaining source race is inferred from the superseded failure. |
| Tor padding and direct dynamic-bridge protection | Requested policies remain explicit; unsupported paths cannot silently disable them. | Actual bounded padding and OS protection owners for the applicable graphs, followed by native/device verification. |
| Router multihop MTU | The retained compiler now uses the actual 19-entry/19-exit catalog, not the obsolete WG/AWG-to-SS/HY2 subset. | Current packaged runtime and real path acceptance remain distinct from graph constructor/restore tests. |
| Original requirement completeness | Current contracts, derived numbered audits and recovered user passages guide implementation. | The complete original source messages and all applicable per-platform evidence remain necessary before a full-delivery claim. A fresh targeted Personal Context search still did not recover original Tor-padding wording or numerical bounds; current rate/size constants are implementation contracts, not attributed user quotations. |

## Release, deployment and device evidence

The recorded exact-`e5804875` push-run query returned 26 runs: 23 queued and
three pending. The [authoritative release run](https://github.com/Eabusham2/router-vpn/actions/runs/40464897422)
was queued. These statuses are a point-in-time read, not final conclusions.
The release API still returned the twelve-asset prerelease targeting the full
`745b3e41e5a78d734391976af9b7cd0637660a0b` commit. Earlier successes and
superseded cancellations cannot certify these Android/Apple source changes.

The latest completed Android runtime/combined failures at `8cce57a3` exposed
the stale test-boundary overload corrected in `e5804875`. The native Xray
`078d4ef3` run exposed the synctest language declaration corrected there.
The Android multihop five-minute package deadline expired while the named
cancellation test had run for less than one second; its four cases subsequently
passed twenty race-instrumented repeats. A complete monolithic diagnostic
passed in 336.789 seconds: 246 top-level tests passed and two conditional
export helpers required their separate native-gate environment. Android now
uses the same existing seven-phase runner as native Xray, with the unchanged
180-second bound per phase, exact discovered inventory and omitted/duplicate
selection checks. All 248 discovered entries were selected exactly once;
the seven phases and retained relay/AWG race suites passed. No test assertion,
conditional export policy or production timeout changed.
An older Linux ARM64 MAX QUIC/WG Local encrypted-traffic timeout is being
checked separately; neither fixture readiness nor a production defect is
inferred solely from that failure. Local reproduction must use the complete
checksum-verified native preparation, including the HY2 deadline modules.

Re-read the latest attempts for the exact current commit. Publication requires
matching native packages, checksums/manifest, nine ARM64 custom images and
generated production compose. A cancelled superseded run is not a successful
release. The last recovered published prerelease targeted `745b3e41`; no newer
complete release is certified by this ledger.

Private AI Board/Portainer deployment, ASUS forwarding/JFFS fail-open behavior,
physical device networking/leaks/transitions, off-LAN methods, native visual
and accessibility acceptance, private benchmarks, live AI providers and
signing/distribution still need their own accessible target evidence. No live
router, AdGuard setting, forwarding rule or production deployment was changed
in this continuation. See [live acceptance evidence](LIVE-RELEASE-EVIDENCE.md).
