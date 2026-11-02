# Router VPN Requirements Reconciliation

This document records the current requirement precedence used by the source and release gates.

1. Later explicit user corrections refine the original requirements; shorter assistant handoffs cannot remove uncancelled scope.
2. Verified current source and exact-SHA evidence determine what is implemented, tested, built and published. They do not redefine what the user requested.
3. Requirements remain binding when they were never explicitly cancelled or replaced.
4. The final repository workflow is direct commits to `main`; old branch/PR instructions are cancelled.
5. The native Router VPN app is the map-first daily product. Setup Center remains private deployment, administration, download, recovery, and update infrastructure.
6. Source presence, shipping composition, native compilation, packaged artifacts, physical runtime, selected-path proof, and production deployment are separate evidence gates.

The reconciled scope includes the original 356 requirements, corrections C1–C7, later product/breakage additions, the unified map-first UI request, external node/hop/exit support where real, session and durable-state transaction corrections, exact-SHA release/update/recovery requirements, and ASUS fail-open household-network safety.

Setup Center package delivery is exact-SHA GitHub Release first, same-SHA Actions artifact second, then only a bounded local desktop/Portable fallback that the server can genuinely build. Android and iOS remain exact-SHA artifact-only. A generated package and its owned temporary build workspace are retained for retry for exactly 30 minutes from READY, without extending the deadline after download, then deleted. Explicit cancel/delete and shutdown clean them immediately.

Unsupported platform capabilities are disabled with a truthful reason; no UI may fake a working dataplane, route, DNS policy, exit proof, forwarding operation, multihop graph, or encryption layer.
Those capabilities remain unfinished requirements. A passing source audit,
successful build or published release does not establish all-device or private
deployment acceptance.

## Implementation reconciliation through f103637f

The original sources below have already been recovered. Continue their actual
implementation and acceptance work without replacing their scope or repeating
recovery. Published source through
[`f103637f`](https://github.com/Eabusham2/router-vpn/commit/f103637f63235872ba2c144dd87135d6a1832615)
and exact local/native boundaries are recorded in
[the current continuation evidence](CONTINUATION-EVIDENCE-2026-11-02.md).

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and later Start Layers | Retained Linux SS, Hysteria2, WG, AWG2 Fast/Strong and SS-V2Ray support Off/AES/AES+XOR. Preserve eleven AWG parameters, separate original/relay/outer sources, final-protocol DNS/proof and concrete composite cover ownership. Actual encrypted peer and rejection controls pass. Saved Off, settled-empty and complete same-boot On-connect release-intent recovery remain published. The installed gate now requires 299 scenarios; invalid older fixture MTU inputs were repaired without changing validators. The newer generated six-case gate fails MTU rollback's current receipt on both architectures at ce557096. Broader graphs, retained Node → external succession, Always/torn/legacy recovery and physical acceptance remain open. |
| #141–148, #222–223, #335 and August 10/19 node requests | Mobile and all three desktop apps now expose captured external comparison with fifty routed HTTPS measurements, metric-specific history, exact original restoration and fresh proof of the already-measured execution winner. Desktop native network observers and owned route/TUN receipts are published; focused race/action/namespace tests pass, with real MTU rollback failure retained separately. Quick live Router Fastest is distinct from the required durable 50–200 TCP benchmark and never writes its fields; the earlier blanket sample-count gap conflated the two. Quick samples do not satisfy durable benchmarking. Exact native packages, physical paths and unsupported retained transitions remain separate requirements. |
| #19–21, #26–30, #33–35, #265–269, selected DNS and Methods | Complete Hysteria CA/profile delivery now joins unchanged-client Shadowsocks, OverTLS TCP, SSR/Mihomo and manual SOCKS evidence. Preserve exact trust/auth/policy and real download bytes. Stock OverTLS UDP, finalized ARM64, C1 simple AWG and original off-LAN/device requirements remain. |
| Tor native composition and fixture integrity | 60de6b39 fixes test receipt timestamp ordering without changing production validation. Actual mobile Server Tor 28 subcases and desktop eight groups/21 subcases pass under race. Desktop Tor selected-path fifty-sample measurement and joined cancellation are now published. The updated ownership audit passes 42 regressions and the full local orchestration gate. Exact-SHA packaged, public-network and device acceptance remain separate. |
| Mobile UI and restoration gates | The comparison actions, terminal Apple native capture and moved Android dialogs retain their published source/compiled negative controls. b38a53be repairs the actual Swift 6.1.2 Sendable error; the old failure is reproduced and the repaired 433-check composition passes. Newer Swift passes 353 comparison checks and six compiled controls. Xcode/IPA and APK results remain separate. |
| Native macOS and Windows | Windows bootstrap's earlier two-architecture evidence remains historical. New real-account CI starts the genuine Limited primary and normal runas Full workers, then exposes a fixture's incorrect primary requirement for a linked identity observation. f103637f uses the retained authenticated parent's actual primary token, exact object/incarnation and private lifetime for the access test; all original cases remain and real retained-parent lifecycle is mandatory. Six policy groups/88 subcases, seven compiled defects and both pointer-check builds pass. The actual f103637f job then passed the genuine Limited/Full lifecycle and all original native cases, preserving the real denied elevated-thread access result. It later failed the separate GLOBALROOT file-not-found/zero-callback probe. Full MAX/Portable/5.1, interactive consent, cross-account product use and current release acceptance remain unproved. macOS first/legacy inventory and Intel managed CodeDirectory still fail; ARM64 managed inventory passed its bounded negatives. Signing and actual devices remain open. |
| All other original and later requirements | Retain their existing source/native/live evidence. No percentage, reduced denominator, full-release claim or physical deployment follows from these units. The stopped unpublished PQ fixture work remains preserved and excluded. |

## Original-source recovery refreshed November 1, 2026

The continuation recovered all 356 unique historical audit identifiers and
read the complete addendum containing 312–356 and C1–C7. These are an
assistant's historical organization of requirements, not 356 verbatim user
messages, and their old Done/Partial/Missing labels are not current verdicts.
Original user passages were also retrieved; the shorter handoffs were not used
as their replacement. The source dates below are those recorded in the copied
documents, without inventing a missing message date or timezone.

| Source | Original material recovered |
|---|---|
| `mm.md` | Audit identifiers 1–311 and the August 11 native application/product request. |
| `router_vpn_chat_audit_addendum_v2` (retrieved duplicate filename) | Complete August 11 addendum, identifiers 312–356 and C1–C7, including multiline platform details. |
| `Continue Storage Diagnostics.md` | August 10 original onboarding, Setup Center controls, multiple nodes, DNS and at-least-50-sample measurement request. |
| `Router VPN Handoff Audit.md` | August 12 original native/all-device, breakage, methods and separate generic installation/node-linking request. The distinct shorter `(1)` document was not assumed newer because of its suffix. |
| `Router VPN Progress Update.md` | August 19 original map-first layout, settings, measured paths, complete Add/Load/Update/Delete profiles and external-node request. |
| `Pasted text(20261019-065229)` | Original Local/Server/Compare request and surrounding same-endpoint/reproof rules. The copied passage does not retain an original message date beside it. |

Project/personal context was actively queried as a continuity index and the
original files were retrieved separately. This does not claim access to every
historical conversation. Current source and exact-SHA native/release evidence
are recorded separately in [the November 1 continuation](CONTINUATION-EVIDENCE-2026-11-01.md).
Private transcripts and account/file identifiers are not reproduced here.

### Corrections retained during implementation

| Reference | Surviving contract |
|---|---|
| C1 / #17 | The simple AWG method still needs real off-LAN third-party interoperability evidence. |
| C2 / #91 | Onboarding continues until completion, stores progress/completion and offers a permanent rerun. Setup Center and the native app teach their own tasks. |
| C3 / #63 | Multiple administrator accounts are optional; authentication and authorization for sensitive changes remain required. |
| C4 / #169 | A blank AdGuard Allowed Clients list is unrestricted. Never create a restrictive list just to add VPN subnets; an existing restrictive list must be read before changing it. |
| C5 / #101; C7 | Generic installed/Portable applications remain separate from private node bundles/pairing and support multiple nodes without reinstalling. |
| C6 | Production is exact-SHA, image-only deployment without the Docker socket. A bounded desktop-package fallback does not authorize building the production stack on the AI Board. |
| #324–325 | Portable relocation and clean exit must join owned processes and release their files. |
| #337 | Manual Disconnect and failure/reconnect protection have distinct ownership and release semantics. |
| #340–342 | MAX may not downgrade silently; ALL uses validated candidates; cover/padding remains bounded, private and non-amplifying. |
| Later comparison correction | Compare uses `(last_node_response_time + external_server_response_time) / 2`, one shared randomly selected external endpoint, each candidate's actual route and repeat proof. Invalid or stale candidates receive no score. |
| Later Start Layer correction | Off / AES-256-GCM / AES-256-GCM + XOR whitening; whitening supplements authenticated encryption. Capture entry and exit independently. |
| Later download correction | Keep the completed package and its owned workspace for 30 minutes from READY; repeat downloads do not extend it, and Cancel/Delete/shutdown clean immediately. |

The checked configuration still preserves SMART AUTO, IPv6 On, Home AdGuard,
Auto MTU and AUTO encryption/obfuscation requirements Off. No earlier default
was restored merely because it appeared in an old transcript. Older qualified
Unix/BSD requests and all required desktop/mobile architectures remain in the
scope even where their acceptance differs from the core native products.
