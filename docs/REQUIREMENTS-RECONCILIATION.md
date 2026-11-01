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

## Implementation reconciliation through 6e7032f5

The original sources below have already been recovered. The next step is to
close their actual implementation and acceptance gaps; repeating recovery or
substituting a smaller green gate does not satisfy them. The current published
cutoff is [`6e7032f5`](https://github.com/Eabusham2/router-vpn/commit/6e7032f52acecb13128443e52fadd82ee567068a).
Detailed commits, tests and exact native outcomes are in
[the current continuation evidence](CONTINUATION-EVIDENCE-2026-11-01.md#latest-source-and-native-evidence-through-6e7032f5).

| Recovered scope | Current reconciliation |
|---|---|
| #112, #200–213, #337 and later Start Layers | Retained Linux SS Off/AES/AES+XOR, WG/Off, saved-policy Off and settled-empty checkpoint recovery are published with real encrypted peer/ownership tests. All 48 installed scenarios, broader graphs, legacy succession, nonempty Always/torn recovery and physical acceptance remain required. |
| #141–148, #222–223, #335 and the August 10/19 node request | Most used, private proved usage and Android external map metadata remain published. Android selected external50 captures actual source, execution and native drain; temporary restoration now validates the original adopted source before Stop. Routed history stays separate from direct TCP. Apple parity, external all-node/Fastest comparison and packaged/device acceptance remain open at this cutoff. |
| #19–21, #26–30, #33–35, #265–269, selected DNS and Methods | Final Shadowsocks, OverTLS TCP, SSR/Mihomo and manual SOCKS downloads have independent unchanged-client evidence. SOCKS preserves the actual finalized private endpoint/authentication. Stock OverTLS UDP, complete Hysteria CA/trust delivery, finalized ARM64 images and original off-LAN/device requirements remain. |
| Native macOS and Windows | macOS guardian success at 9201f036 remains distinct from strict installer failure at 29497c54. Windows source-copy and 5.1 module-path repairs need completed native reruns; the 9559799d controller run still fails linked-token/GLOBALROOT diagnostic acceptance. Signing, ordinary UAC and actual devices remain separate. |
| All other original and later requirements | Keep their existing source/native/live evidence boundaries. No percentage, reduced denominator, full-release claim or physical deployment follows from these units. |

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
