# Original packet prefixes and imported stream routes

This continuation closes source gaps found while reviewing the
[recursive measurements and longer Local routes](IMPLEMENTATION-2026-11-23-ROUTE-MEASUREMENTS.md)
against the [surviving requirements](CURRENT-REQUIREMENTS.md). A compatible
ordinary route must not lose candidate measurement merely because its first
packet transport is AWG or because it contains more than one packet prefix.

## Measuring candidates after ordinary packet prefixes

An ordinary Local route can measure a candidate through one or more
independently paired WireGuard, AWG2 Fast or AWG2 Strong members followed by
literal SS2022 streams. The selected stream can be an imported provider or
a paired Router node. All original members of a mixed-private route and its
paired SS2022 final have Start Layer Off. The complete original source, private
proofs, catalog generation, MTU ownership and cleanup remain bound to the
operation.

One ordinary hostname case also qualifies: a single imported SS2022
penultimate after one or more paired packet members, with its original
saved Custom TCP resolver. The native parser binds that resolver to the
immediately preceding packet outbound. The closed preparation preserves the
same resolver and outbound bytes. A failed routed resolution cannot fall back
to a different resolver or produce a candidate score.

The score remains fifty fresh authenticated private-agent responses through
the actual imported cipher and the candidate's own original SS2022 cipher.
It is not a TCP handshake metric. These additions do not grant response
authority to an imported candidate without a private proof endpoint or to
the selected Server/Compare candidate operation.

Native peer tests exercise fifty replies through one AWG2 Fast packet peer,
two WireGuard peers, six AWG2 Strong peers, and one WireGuard or two AWG2 Strong
peers followed by the original routed hostname import. Every original packet counter advances
and both stream peers receive all fifty connections. Negative tests cover
wrong packet or candidate keys, forged authentication, a source change after
the fiftieth reply, cancellation during socket cleanup, and NXDOMAIN before
the candidate is dialed. The suite runs with the Go race detector. These are
controlled native peers; installed-device and off-LAN acceptance remain
separate.

## Longer mixed Local sources

Schema six retains a contiguous physical packet prefix, a segment of literal
SS2022 streams containing at least one independent import, and the original
paired SS2022 final. A paired stream may appear before, between or after
imports. Consecutive paired streams are valid. Every stream must have its own
endpoint tuple and cipher key. The native compiler checks each paired member's
WireGuard identity companion and private agent, and keeps the exact imported
source and public proof for each independent provider.

For an original route with `P` packet members and `N` total nodes, positions
start at zero.

| Position | Original member | Evidence used for that position |
| --- | --- | --- |
| `0` through `P - 1` | Paired WireGuard or AWG packet member | Authenticated private-node result |
| `P` through `N - 2` | Independently imported literal SS2022 | Public HTTPS benchmark reached through that specific imported path |
| `P` through `N - 2` | Paired literal SS2022 | The node's own authenticated private-agent result |
| `N - 1` | Paired SS2022 final | Authenticated private-node result and the selected application DNS proof |

Earlier extended routes with an all-imported stream segment keep their public
integer `paired_prefix_nodes` marker where that marker was already used. An
original deep Local plan exposes the exact ordered array of `private-node`
and `public-path` roles through `ExtendedLocalRolesJSON()`. A valid packet
count alone cannot identify the proof owner of a mixed-private stream.
Selected Server and Compare retain separate admission rules.

Native encrypted tests at nine and sixteen nodes exercise two WireGuard
prefixes, one AWG2 Fast prefix, and two AWG2 Strong prefixes. Each positive
transfers 8 MiB in both directions and proves the original private and public
hops, final and DNS. The corresponding late imported-key corruption is
rejected before final readiness. The twelve peer cases pass under the race
detector and join their original peers on cleanup.

The final canonical fixture also passes all twelve cases with one and with two
Go scheduler threads. A single-thread replay exposed a three-second deadline
intended for tiny proof responses cutting off an authenticated 8 MiB upload.
The controlled peer now changes its deadline only after validating the exact
benchmark request, using the existing private/public transfer budgets. The
mixed transfer caller additionally enforces a hard twenty-second deadline per
direction. The byte counts, original proof deadlines, wrong-key refusals and
joined cleanup remain required.

The physical traversal bound remains 96 and the existing input, encapsulation,
MTU, byte and deadline limits still apply. Source preservation at larger
counts does not establish encrypted traffic at every count or an adequate
MTU on a particular WAN. A source-family marker alone does not grant late
candidate-measurement authority; that operation requires its own original
native plan and qualification.

## Candidate measurements and named future profiles

The mixed family now has that separate qualification. Seven additional native
peer cases execute the original connected manager and the independently
compiled closed-prefix Box. A nine-node route with two WireGuard packet
members measures fifty authenticated replies after imported position seven;
a sixteen-node route with two AWG2 Strong packet members measures after
imported position fourteen. A sixteen-node route with nine WireGuard packet
members measures fifty real destination TCP handshakes at packet position
eight through both connected and closed managers. These packet and private
response results keep their separate metric names and scoring rules.

The tests also change the source after reply fifty, cancel during native
cleanup, and corrupt a late imported cipher. Each produces no score and joins
the original owner. The closed preparation preserves the original application
and DNS deny gate, selected position, tags, and original prefix. The source
seal tests reject a later source mutation, a foreign tag, and a different
selected position. A displayed packet-count marker cannot substitute for this
native authority.

At an original imported penultimate, the measured paired candidate can be
saved as the final of a distinct, explicitly named future profile. The real
HTTP/store tests additionally cover AWG2 Fast, two WireGuard packet members,
and the original routed hostname after one WireGuard or two AWG2 Strong
members. Save retains every preceding original reference and leaves Home's
selected path unchanged. Repeated Save, lost replies and late cancellation
retain the single committed profile identity. An ordinary packet choice
continues to use its separate insertion transaction and validates the complete
resulting graph.

At an earlier SS2022 stream, a measured paired candidate can also be saved
as an intermediate. The separately named Local profile preserves every
original packet member, imported or paired stream, and final. Reopening that
profile permits another measurement and named insertion. Consecutive paired
streams are supported. The packet transports must form a contiguous physical
prefix, followed by literal SS2022 sources with independent credentials and
endpoint tuples. Start Layer is Off throughout. Each original paired stream
keeps its own WG identity companion and private proof. Each imported stream
retains its public proof. The existing physical traversal and total source
size bounds apply.

The following original-source checks were executed for the generalized Local
family in the implementation linked below.

| Original members | Executed evidence |
| --- | --- |
| 5 and 8 | Connected and closed candidate runs reached the selected private SS intermediate or a following import. Each positive collected 50 authenticated responses. A wrong paired key, substituted private identity, late catalog change and cancellation during Close each suppressed publication. |
| 7 | A path containing consecutive private SS intermediates proved its original hops, DNS and final, then carried 8 MiB in each direction. |
| 9 | The route `WG → import → private SS → private SS → import → private SS → import → import → final` retained each proof owner. The race-enabled native run collected 50 samples per node, 450 total, and transferred 8 MiB in each direction through the final. |
| 10 and 12 | A ten-member closed prefix measured after position 8. A twelve-member connected path measured after position 9. Both returned 50 private-agent replies, with at least 50 fresh decryptions at every traversed stream. |
| 16 | A deliberately wrong private key at position 12 stopped after the original private proof at position 11. Position 13 and final DNS stayed untouched. The earlier independent-import family separately passed 16-member bidirectional traffic. |
| 96 | A source compiled at the existing physical traversal limit and returned every original role. Replacing a late private source invalidated the role and measurement authority. This case exercised the compiler and retained owners. |

The native fixtures use encrypted WG/AWG and SS2022 peers, native Box
managers, controlled interface routing and independent proof servers.
[Encrypted peer cases](../mobile/chain_component/mixed_local_traffic_test.go.tmpl) · [Recursive candidate cases](../mobile/chain_component/mixed_local_candidates_test.go.tmpl) · [Physical-depth source test](../internal/mobilemultihop/node_chain_extended_mixed_test.go)

The desktop HTTP and private store tests save a separately named
profile, reopen it, measure a fresh candidate and save another named
insertion. The eight-member source grew to nine and then ten members. The
tests check each complete ordered path, Home selection, source tokens, saved
and connected proposal logic, repeat Save, cancellation, reloading and the
startup Last capture. GTK, Swift and Windows callback tests check complete
proposals and reject forged suffixes or attempts to exceed the physical
depth. The malformed source-kind regression rejects a foreign kind even
if the record still contains a valid-looking private proof ID.
[Desktop transaction](../cmd/client/ordered_candidate_draft_final_test.go) · [Desktop source classification](../cmd/client/multihop_node_chain_imported_nodes.go) · [Desktop candidate controls](../deploy/test_desktop_ordered_candidates.py)

These mixed-private data paths require Local execution and Start Layer Off.
The subsequent [hostname and Fast continuation](IMPLEMENTATION-2026-11-24-HOSTNAME-FAST.md)
qualifies the first original hostname followed by additional Off streams and
the longer literal Fast selected family. Layered hostname paths, selected
Server/Compare private candidate timing, and an unpaired provider without its
own private agent each require separate source and execution qualifications.
Local peer and structural results do not establish WAN MTU, Android/iOS device
behavior or installed desktop firewall behavior.

The eight-to-nine-node transition is checked against that complete native
compiler. The macOS editor now inserts the measured packet at its actual
chosen position before validating the full graph; its former append-then-move
sequence wrongly tested the packet after the imported suffix. Original source
tokens and every suffix member must still match. The GTK adoption callback
already inserts at the chosen position and passes the same transition with
stale-token, reordered-suffix, foreign-candidate, generation and busy-owner
refusals.

## Verification and delivery

The GTK source, saved-profile and receipt checks execute the shipping C
helpers. The throughput guards bind the complete private/public row boundary,
ordered token and original 8 MiB budget. Full GTK widget, WPF, AppKit, mobile
SDK and native interface behavior remain part of the hosted platform gates.
The updated GTK source checks execute 9,978 assertions, including late mixed
packet and stream positions, original layers, and saved source round trips;
the 36 existing causal controls still reject their intended defects. These
headless checks do not claim GTK widget interaction.

Source audits now describe the explicitly qualified longer source branches
and retain causal tests for removing their Local-only, role, identity and
Start Layer checks. The Android durable-state gate retains the new original
paired capture phase alongside every older phase. These changes repair audit
expectations; they do not stand in for native traffic or durable-store tests.

The complete native shipping audit passed all 79 tests after the mixed source
and original packet boundary were added. The physical component inventory
retains its original 117 cases and additionally requires the paired nine- and
sixteen-node captured-Box cases. Replaying the hosted CONNECT job's original
119-case physical transcript passes the unchanged verdict parser; removing
either new case fails it. The SS physical negative control still changes only
the old trio restriction and pins the complete current helper, including its
independent extended source checks. Hosted whole-image execution remains
required after these verifier repairs.

The [release workflow](../.github/workflows/build-all.yml) must publish packages,
the manifest, ARM64 images and generated production Compose for one complete
source SHA. [Live release evidence](LIVE-RELEASE-EVIDENCE.md) still governs
physical routing, leak protection, off-LAN interoperability, private providers,
applicable provisioning and deployment acceptance. This record does not claim
that those live checks or a release run have finished.
