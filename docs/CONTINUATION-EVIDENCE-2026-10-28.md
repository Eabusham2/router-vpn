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

## Verified changes through `ab7bf7f7`

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

## Requirement ledger refinement

The earlier ledger's broader rows remain in force. These refinements close
specific stale source assessments, not whole requirement families.

| Original identifiers / later request | Shipping paths and evidence | Actual remaining gate |
|---|---|---|
| 111–119, complete profiles/startup; later full connection-profile correction | Android schema-5 store and Apple complete profile store now retain ordinary-entry Local Tor, source kind, exact protocol, policy and node references. Speed Lab uses the correct captured entry slot and execution. | New exact-SHA packages; real permission/restart/restoration acceptance. The separate manual Android pending-permission supersession issue is being repaired, not considered closed by these profile tests. |
| 149–169, modes/DNS; later explicit resolver policy | Shared external compiler and Tor native owners preserve each imported transport, selected DNS/bootstrap and private-vs-public proof authority. | Full requested graph parity, live selected-resolver traffic and provider checks. Ordinary providers still cannot impersonate a private Home resolver path. |
| 200–213 and 337, kill switch/lifecycle | Existing native physical-egress and cancellation owners are preserved; ordinary mobile source changes carry their own protection request. | Actual platform leak/transition tests; direct dynamic Tor transport strict protection remains a source boundary. |
| 214–224 and 336; August 13–14 external node/hop/exit additions | Desktop and both mobile hosts now admit the eight implemented ordinary import families before Local Tor. New mobile per-hop measurement identifies public entry and Tor exit independently. | Exact-SHA native matrices/packages; live paths and broader requested graph compositions. Tor Compare still needs distinct valid last-node/external inputs, winner recheck and restoration. |
| 225–241, compatible Jumbo/MTU/measurements; August 16 retest correction | Shared ordinary proxy Jumbo compilation now preserves virtual TUN capacity and immutable policy while retaining packet endpoint MTUs. Native owner reconstruction and MTU authority agree. | Physical MTU/throughput, Retest/Cancel/network-transition acceptance. Raw-packet admission is not weakened to manufacture Jumbo support. |
| 321–326, wider packaging/Portable targets | Current `deploy/build-client.sh` retains qualified ARMv7, FreeBSD, OpenBSD, NetBSD, DragonFly and illumos controller/helper builds in addition to the ten core native packages. | Current CI/package validation where feasible. Controller/helper artifacts are not relabeled as additional full native applications or substituted for the core ten. |
| 342 and later bounded-padding settings | Server Tor already has owned bounded native cover; shared native control and lease infrastructure exist. | Local desktop/mobile Tor padding still requires complete post-DNS/proof admission, periodic freshness, receipt/counter validation and drain integration. A rejected enabled request is unfinished. |
| C5–C7, 348, 352–354 | Generic secret-free application delivery, separate private node linking, packaged licensing, image-only production and authenticated mutations remain required. | Exact-SHA package/image/compose publication plus private deployment/administration acceptance. No production server build fallback or Docker socket access is authorized. |

## Native gates, release and live evidence

The initial `dbff30e8` Actions read found 20 push runs: 11 failed and nine
successful. That is a historical diagnosis, not the current release status.
The subsequent changes address observed failures while preserving their
negative tests. Native Windows Tor cross compilation succeeded in diagnostic
run [40608694158](https://github.com/Eabusham2/router-vpn/actions/runs/40608694158);
its Windows AMD64 job then exposed the separate DNS fixture failure fixed above.

The mobile host graph inventory is 348 existing Local/direct + 342 Server +
48 new ordinary-entry graphs per platform. The expanded 738-graph native gate
is under verification at this checkpoint. Its first actual run exposed a
missing OpenVPN build tag and an incomplete local Xray preparation, not a reason
to remove those graphs or weaken constructors. The full pinned composition is
being exercised before that gate revision is published. A verified native Tor
DSO and the required Go/LLVM/Swift toolchains are now available locally; the
previous ledger's missing-tool limitation no longer describes this workspace.

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
