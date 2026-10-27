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
tested changes listed below were published. Unfinished server prerequisites
are not evidence of a usable Server mode.

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

## Requirements still requiring source or runtime work

This is the concrete continuation queue, not a complete replacement inventory.
The older ledgers retain the original identifiers and broader requirements.

| Requirement family | Established source boundary at `943d7462` | Remaining evidence or implementation |
|---|---|---|
| Desktop ordinary entry → Tor | Public Local Connect and restoration retain WG, AWG, SOCKS5, HTTP(S) CONNECT, Shadowsocks, Hysteria2 and supported OpenVPN imports. | Strict protection for ordinary predecessors; physical leak, reconnect and path acceptance. Ordinary public-IP proof must not acquire private Router authority. |
| Desktop private Router entry → Tor bridge Server | Real no-TUN worker, source provisioning, native leased outbound, desktop Connect/restoration and three editors are connected and locally tested. | Exact-SHA Windows/macOS/Linux packages and ARM64 image validation, public Tor circuits, private pairing/deployment and device acceptance. Plain-Tor desktop controls and Android/iOS Server host adoption are separate source work. |
| Tor Compare both | The required arithmetic and invalid-candidate rules are preserved. | Distinct, correctly owned last-node and external measurements through each actual candidate; final winner recheck and restoration. Dynamic Tor exit proof is not either score input by itself. |
| Tor native startup | Initial network/power callbacks are joined before ownership publication, with actual native race/reset controls (`078d4ef3`). | Current packaged native builds and physical network/power transitions; no remaining source race is inferred from the superseded failure. |
| Tor padding and direct dynamic-bridge protection | Requested policies remain explicit; unsupported paths cannot silently disable them. | Actual bounded padding and OS protection owners for the applicable graphs, followed by native/device verification. |
| Router multihop MTU | The retained compiler now uses the actual 19-entry/19-exit catalog, not the obsolete WG/AWG-to-SS/HY2 subset. | Current packaged runtime and real path acceptance remain distinct from graph constructor/restore tests. |
| Original requirement completeness | Current contracts, derived numbered audits and recovered user passages guide implementation. | The complete original source messages and all applicable per-platform evidence remain necessary before a full-delivery claim. A fresh targeted Personal Context search still did not recover original Tor-padding wording or numerical bounds; current rate/size constants are implementation contracts, not attributed user quotations. |

## Release, deployment and device evidence

The exact-`943d7462` Actions read returned 26 workflows, all pending, queued or
running at that observation. Authoritative release run
[`40459394588`](https://github.com/Eabusham2/router-vpn/actions/runs/40459394588)
was pending. The earlier `adf24e9a` read had seven successful completed
workflows and thirteen unfinished workflows; those results do not certify
`943d7462` or a later commit.

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
