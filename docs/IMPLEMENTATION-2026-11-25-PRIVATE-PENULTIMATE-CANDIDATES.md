# Measuring a replacement final through a paired private hop

November 25, 2026

A user who selects Compare can measure a different paired final through the
original penultimate hop when Local wins. The editor can then save that measured
route under a new name. Choosing a candidate or completing the measurement
leaves the active connection and its saved Home profile in place.

## Qualified source and measurement

The new path uses an original schema-six route with a WireGuard entry, one or
more independently imported Shadowsocks 2022 hops with literal endpoints, one
paired Shadowsocks 2022 hop immediately before the final, and a paired
Shadowsocks 2022 final. Every Start Layer is Off. The three-member schema-two
route retains its existing candidate path through the imported middle hop.

Before Compare, the editor can identify the eligible stop from the original
source. After Compare, the shared runtime requires the actual Local winner,
its active trial and selection epoch, its captured configuration, and the same
imported-node registry used to prepare the route. The candidate plan borrows
that trial's prefix for the private response challenge. A result requires
50 authenticated responses. Selecting Server or receiving a Server winner
leaves the private-response operation unavailable. An existing route member,
including the outgoing final under another profile ID or private proof ID,
cannot become its own replacement.

Android and iOS/iPadOS carry the measured prefix position and identity from
the original capture through the candidate catalog, result and future profile.
On iOS, each page of candidate metadata must match that same position and ID.
The named proposal retains the original prefix, execution selection and the
measured final's own source. Draft cleanup finishes before the result can be
used for a separate profile. Explicit Load selects the saved route.

## Verified in the shared core and mobile clients

| Check | Evidence |
| --- | --- |
| Go selected-runtime plan | `TestCompareLocalPrivatePenultimateCandidate` exercised four, nine and sixteen nodes at zero-based positions 2, 7 and 14. Each size covered both Compare winners and an explicit Server request. The test rejected final-ID and private-proof aliases, a copied registry, and a changed selection epoch. `TestNodeChainCompareLocalImportedResponseCandidate` retained the three-node path. |
| Android editor, store and receipts | `android/test_android_node_candidates.py` passed 222 existing receipt and cleanup checks, 120 selected-response checks, and 22 catalog-capacity checks. Java exercised the original store, Go source compiler and selected callbacks at 3, 4, 9 and 16 nodes. The mutation controls covered source replacement, partial receipts, cancellation and cleanup ownership. |
| iOS/iPadOS catalog and proposal | `deploy/test_ios_node_candidates.py` passed 410 ordinary checks and 58 selected-response checks covering 3, 4, 9 and 16 nodes. The capacity, Local, Server and Compare phases also passed. All ten compiled mutations failed at their corresponding checks, including a metadata page carrying another prefix's ID. |
| iOS/iPadOS editor and trial | `deploy/test_ios_node_chain_imported_nodes_profiles.py` passed 696 shipping Swift checks and five source mutations. `deploy/test_ios_selected_draft_candidates.py` passed 164 checks of selected trial, private IPC, and state after shutdown. `deploy/test_ios_node_candidate_transaction.py` passed its source, epoch, cancellation, adoption, drain and foreign-owner controls with modeled operating-system and store boundaries. |

The source format accepts up to 96 nodes. This extension's shared and mobile
candidate checks establish the new operation at 4, 9 and 16. Existing 96-row
UI and request-capacity checks exercise representation and size limits. An
encrypted native run or installed-device acceptance at 96 nodes would require
separate evidence. Platform delivery and device acceptance are tracked in
[BUILDS.md](BUILDS.md).

## Desktop controller and editor verification

Windows, GTK and AppKit retain the complete original `response_source_nodes`
map alongside the candidate view, selected Local result and selection epoch.
The map contains only public node IDs, modes and roles. Each offered replacement
must compile as a complete future profile before the editor can offer Save.
The connected and draft catalogs omit candidates whose complete proposal is
not saveable. Results and Save acknowledgments retain the same view and source.

The actual Go HTTP handlers passed connected measurement, status, named Save,
duplicate-Save refusal and cold explicit Load at four, nine and sixteen nodes.
The controlled native-process boundary exercised the original private mailbox,
metadata-before-Start ordering, catalog pulses, uncommitted-file refusal and
joined MTU release. TCP handshake receipts failed the private-response
validator. The earlier packet-candidate and three-node response paths passed
their existing lifecycle controls. A sixteen-node temporary Server winner
refused the private catalog, joined its original cleanup, returned zero scores
with its actual winner and epoch, and refused named Save.

Connected Cancel now carries its original view token. Its bounded public
snapshot survives a competing catalog refresh and retirement of the completed
worker. Before admission, cancellation reserves the request nonce under the
same lock as its original view so a delayed POST cannot acquire another
candidate purpose. After admission, a completed cancellation requires the
original worker's joined cleanup. Both replies retain the original source and
contain no accepted scores. Draft cancellation before selection retains its
source without inventing a winner or selection epoch.

| Desktop checks | Evidence and boundary |
| --- | --- |
| Windows | 2,354 shipping editor checks; 388 candidate checks and 264 Advanced Performance checks with controlled WPF and controller boundaries. The final PowerShell run disabled telemetry and prohibited new sockets in the kernel. |
| GTK | 41,438 real-widget editor/persistence checks and all 41 editor mutation controls; 223 candidate checks using real widgets and controlled HTTP replies. |
| AppKit | 49,199 profile/editor checks; 365 candidate callbacks, 104 transport checks and 17 candidate mutation controls. |

The desktop source-map fixtures include 96-row representation. The encrypted
qualification below establishes the measured route at the explicitly listed
depths. Both composed recovered native-UI and map-first release audits passed
after integration.

## Encrypted worker qualification

The canonical Linux/amd64 race image passed all sixteen selected private
response cases, with 32 exact root/leaf Go PASS records. Positive cases at
three, four, nine and sixteen nodes required all 50 authenticated challenges
through every retained encrypted prefix. Each positive then independently
rebuilt the route with the measured final, proved that final's private identity,
DNS and application traffic, and joined every original owner. The nine- and
sixteen-node cases covered zero-based stops 7 and 14.

At both three and four nodes, wrong cipher credentials, forged responses,
wrong private identity, catalog revocation on response 50, cancellation on
response 50 and a Server winner produced zero accepted scores. The original
source/registry, private ownership and candidate-alias controls remain required.
All thirty native-runner control tests passed with the existing time limits.

The [canonical receipt](evidence/private-penultimate-candidates-linux-amd64-2026-11-25.json)
retains all sixteen case names, ten compiled worker-source digests, the pinned
sing-box and Xray commits, and the verified Rosenpass archive identity. Its
SHA-256 is `b661e90df86cd3a310458b1f8dde51146d19b2448ee4a4a7871b5cb4b9fdd418`;
the race image is
`797226a814573c53538506bfd8fef5e172b45db4b413c188c9f9cc5455fd8865`.

This component run exercised the shipping registered worker in one process.
The separate required 37-case worker gate, complete exact-commit release
matrix and installed-device/private-deployment acceptance retain their own
evidence requirements. The manual private-response diagnostic now runs from
`main` and checks the full sixteen-case inventory and new controller tests.

## Hosted regression repairs

The preceding integrated commit exposed source-projection and audit regressions
in the required hosted gates. The typed-candidate dependency mutation now
asserts that its source marker occurs exactly once before changing it. The
Hysteria2 identity fixture compiles the original identity-bounds helper. The
iOS profile audit checks the current sealed role predicate and retains causal
controls for foreign sources, sessions and selection epochs.

Shared Android store fixtures now compile the original private-position helper;
the service type boundary declares the captured private-role field while its
constructors still refuse to create a capture. The node-usage, telemetry,
history, DNS, SOCKS, CONNECT and real latency-receipt control suites passed.
The Mac ownership fixture compiles the shipping Load transaction and its models,
including durable-journal admission. Its local Unix-listener ownership case was
blocked by the managed Linux host; hosted Darwin remains the required native
authority. These fixes preserve the shipping predicates and their original
mutation controls.

The Windows external Connect fixture loads the real profile-admission module
and checks the same captured request with the durable journal present and
cleared. Its 370 callbacks and 18 source-selection controls passed; the current
Go controller consumed all five generated payload families. The complete
profile matrix now runs as six independent groups under the original 90-second
child limit. Exact receipts retain all 57 pair transactions, 78 Connect cases,
41 ordered transactions, recovery and setup checks, and all 21 mutation
witnesses. Tests reject omitted or duplicated group/case receipts.

The iOS imported-node matrix now checks the previously qualified later-hostname
path through its original literal predecessor and its own saved TCP resolver.
It also supplies the original validated session count for longer progress
captures. All 3,603 Swift/shared Go checks at three through nine and sixteen
nodes, and seven compiled mutation controls, passed. These changes correct
the fixtures' expectations without changing the shipping hostname policy.

The iOS runtime contract invokes the complete candidate fixture in six bounded
phases. It requires all six original positive operations and all ten compiled
mutation witnesses exactly once and in order. Native phase times ranged from
27.92 to 105.10 seconds under the unchanged 300-second caller limit, retaining
the original 90-second compile and 180-second runtime limits. The standalone
default still runs the full suite. Seventeen source/verdict controls reject
missing or duplicated phases, wrong scope, invented receipts, ignored failures
and deadline changes.

## Remaining hop-by-hop candidate coverage

The editor requirement calls for repeating measurement through each selected
prefix. A four-node schema-six route with a WireGuard entry, two literal
imported Shadowsocks 2022 hops and a paired final shows a remaining software
gap. The original source can compile a private-response candidate plan at
either imported hop. After Compare selects Local, the selected runtime refuses
the plan at both positions because this schema-six grant requires a **paired**
penultimate hop. A focused Go runtime check reproduced the same refusal at
positions 1 and 7 of a nine-node route and positions 1 and 14 of a sixteen-node
route. The requirement is recorded in [current requirements](CURRENT-REQUIREMENTS.md).

Measuring a distinct final through the last literal import is the smallest
remaining case. Measuring an earlier successor would also require preserving
the original suffix when the user saves the named proposal. Private responses
through a Server winner require their own authenticated measurement path.
