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

## Implementation reconciliation through 2f62badb

The original sources below have already been recovered. Continue their actual
implementation and acceptance work without replacing their scope or repeating
recovery. Published source through
[`2f62badb`](https://github.com/Eabusham2/router-vpn/commit/2f62badb9d9a74c8f93a8232f914ef63eb4f2d7f)
and exact local/native boundaries are recorded in
[the current continuation evidence](CONTINUATION-EVIDENCE-2026-11-01.md#latest-source-and-native-evidence-through-2f62badb).

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and later Start Layers | Retained Linux SS Off/AES/AES+XOR, WG/Off, Hysteria2/Off, AWG2 Fast/Strong Off, saved Off and settled-empty checkpoint recovery are published. AWG2 preserves all eleven selected parameters and actual encrypted peer/DNS/ownership evidence. The generated six-case native TUN gate passed both architectures at 06a65417 and 26b294e9. All 93 expanded installed scenarios, broader graphs/layers, legacy succession, nonempty Always/torn recovery and physical acceptance remain required. Complete release-intent recovery is still unpublished pending isolated-source validation. |
| #141–148, #222–223, #335 and August 10/19 node requests | Most used, private proved usage and external map metadata remain published. Both mobile selected external50 and all-node comparison now capture source, network, execution and MTU ownership, restore the original and re-prove only the selected measured winner. Their compiled controller suites and negative controls pass. Desktop native fifty-sample and owned batch/UI parity remain source work; direct Router TCP, packaged behavior and physical acceptance are separate. |
| #19–21, #26–30, #33–35, #265–269, selected DNS and Methods | Complete Hysteria CA/profile delivery now joins unchanged-client Shadowsocks, OverTLS TCP, SSR/Mihomo and manual SOCKS evidence. Preserve exact trust/auth/policy and real download bytes. Stock OverTLS UDP, finalized ARM64, C1 simple AWG and original off-LAN/device requirements remain. |
| Tor native composition and fixture integrity | 60de6b39 fixes test receipt timestamp ordering without changing production validation. Actual mobile Server Tor 28 subcases and desktop eight groups/21 subcases pass under race. The original APK job remains failed, and its exact-SHA rerun, public-network and device acceptance remain separate. |
| Mobile UI and restoration gates | Three source audits now exercise the actual comparison actions, preserve Router selection-only guards and require terminal Apple native capture; all three GitHub workflows pass at bbc224e7. The dialog fixture executes the moved Router handler and all nine Performance actions, preserving seven hidden-list controls. These source/fixture results do not establish a packaged APK/IPA. |
| Native macOS and Windows | Windows bootstrap passed on both architectures at a88c9d61; cancelled WFP/startup work and complete release/5.1 recovery remain separate. Fresh c51c84fc macOS first/legacy inventory and Intel managed CodeDirectory still fail; ARM64 managed inventory passes with its copied/unlinked negative. The bounded ES diagnostic repair grants no installer authority. Ordinary UAC, signing and actual devices remain open. |
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
