# Original route measurements and longer paired Local paths

This work continues the [native repair and map changes](IMPLEMENTATION-2026-11-23-NATIVE-REPAIR.md).
It addresses two recovered requirements: measure the next candidate through
the previously chosen nodes, and preserve longer compatible routes through
the native editor, saved profiles, connection, measurements and history.

Source qualification, controlled encrypted-peer tests, hosted native gates,
release artifacts and installed-device acceptance are separate evidence.
The [current requirements](CURRENT-REQUIREMENTS.md) remain binding.

## Candidate measurements through the original prefix

Packet prefixes continue to measure fifty fresh routed TCP connection
handshakes. A qualified Local Shadowsocks prefix can instead measure fifty
authenticated replies from an independently paired candidate's private agent.
These are separate metrics, with separate result kinds and labels:

| Captured metric | What one sample measures | Candidate requirement |
| --- | --- | --- |
| `routed-tcp-connect` | TCP connection establishment through the captured packet prefix | An original supported saved endpoint |
| `routed-candidate-response` | Connection and cipher establishment plus the candidate's authenticated private response through the captured stream prefix | Original paired SS2022 credentials, Start Layer Off, node identity and private agent key |

The stream response uses a fresh 128-bit nonce. Request and response HMACs use
separate domains and bind the nonce to the original node identity. The bearer
secret is never sent as the request credential. The server checks the actual
tunnel peer; forwarded-address headers do not acquire access. A reply from a
different node, key or nonce cannot complete the sample. The nonce's freshness
belongs to the original client request; the endpoint does not claim a global
server-side replay cache.

The source, configuration, node catalog, selected prefix, native owner and MTU
ownership remain captured for the entire operation. A lazy stream dial alone
does not produce a response score. All fifty samples, the correct measurement
kind and joined socket cleanup are required. The existing expiry and trimmed
mean rules remain in place. TCP and private-response scores are never pooled.
An imported candidate without an attributable private proof endpoint remains
unmeasured rather than receiving a fabricated node RTT.

Stream qualification is Local, with an original unlayered paired WireGuard
entry, contiguous independently imported literal SS2022 members through the
chosen prefix, and an original unlayered paired SS2022 final. Positions one
through six retain the ordinary source authority. Later positions require the
complete original extended schema-six family: every interior must be an
independently imported literal SS2022 member, every Start Layer must be Off,
and the entire route must remain within the physical traversal bound. A late
measurement cannot borrow authority from a valid shallow prefix when another
member of its captured route has changed.

This qualification does not confer response authority on Server/Compare,
hostname imports, a mixed packet/stream prefix or other Start Layers. The
native capability determines which prefixes the applications offer.

### Choosing a measured final

For desktop drafts, an imported stream at the original penultimate position
can offer **Save profile with this final**. This is an explicit named profile
write. Its complete proposed path preserves every earlier node and replaces
only the original final with the measured paired SS2022 candidate. Home and
the current draft remain unchanged. The user loads the saved profile for a
future connection through the existing profile flow.

The catalog and committed receipt carry `proposal_action: save-final-profile`.
The original request, view token, candidate, path and source inventory remain
bound to the save. A delayed successful write is retained even when Close or
Cancel is waiting for native cleanup. The saved profile ID remains visible
until that original cleanup finishes. Ordinary packet-prefix insertion keeps
its existing separate editor action and ownership checks.

iOS retains its existing complete future-path proposal and recompiles it from
the original sources. Single-import and multiple-import preparation must reopen
with their own exact native source family; one family cannot borrow another's
sealed launch record.

## Longer paired WireGuard Local paths

The additional extended family uses an original schema-one paired source at
every position, standard WireGuard at every prefix, and a paired SS2022 final.
Every Start Layer is Off and execution is Local. Original node identities,
private keys, endpoint targets, profile tokens, source digests and the complete
order remain independent and captured. This does not broaden the existing
ordinary protocol combinations or the separate imported Server/Compare family.

The original physical traversal bound remains 96. It is a resource and input
bound, not a promise that an arbitrary route can carry packets at a given MTU.
The native compiler must prove the complete nested packet envelope. Captured
MTU, native readback, rollback and final DNS/identity proof remain required.

Controlled encrypted-peer tests exercised nine total nodes at MTU 2000 and
sixteen total nodes at MTU 3000, including 64 KiB upload and download, final TLS
and DNS, all prefix identities, authenticated MTU, wrong late-prefix credentials
and wrong final credentials. The sixteen-node route at MTU 2000 was correctly
refused. These tests do not establish a suitable MTU on an ordinary WAN, an
installed TUN session or physical-device acceptance. Larger source/editor
fixtures establish preservation and bounds, not encrypted traffic at every
possible depth.

Late packet-candidate measurement requires the sealed original extended Local
plan. A sixteen-node source exercises closed-prefix preparation at position
eight and fifty routed samples. Ordinary unsealed callers retain their
existing position bounds.

### Complete profiles, results and history

Editors and Save/Load retain every node and source token through the entire
qualified path. A changed late member, wrong family, unsupported layer,
Server/Compare substitution or over-bound source cannot reuse that capture.

Extended Local latency inventories distinguish two complete families: all
private paired nodes, or private endpoints with every interior imported.
Mixed inventories cannot borrow either family's receipt. Private-node results
keep their private endpoint, measurement label and latency budget. History
remains bound to its source/configuration and current results also require the
original generation and native session.

Desktop throughput identifies the new family with the strict optional boolean
`paired_wireguard: true` inside `ordered_local_source`. Its absence preserves
the existing imported family. It is unavailable in `ordered_original_source`.
GET and POST must preserve the exact source object, ordered capture and every
node. Paired rows use private cumulative labels; imported interiors use their
public benchmark labels. A changed source flag or mixed labels cannot be shown
as a valid result.

## Verification and release boundary

The shared response fixture uses the pinned native SS2022 cipher on every
traversed imported prefix and the paired candidate. Positive runs use fifty
fresh nonces, including a nine-node connected source and a sixteen-node closed
source. Every traversed imported peer independently decrypts all fifty
connections before the candidate returns its authenticated reply. The suite
also passes with the Go race detector. Negative cases cover wrong late-prefix
or candidate cipher, agent key, node identity, replay, catalog/route changes,
a changed original member beyond the measured prefix, and blocked close or
cancel. The fixture's WireGuard physical transport is controlled; it does not
substitute for the separate native packet/TUN gates.

The named-final transaction also runs through the actual desktop HTTP handler
and profile store at three, nine and sixteen nodes. It preserves every earlier
node, writes the reviewed candidate as the final in a distinct named profile,
keeps Home unchanged, and preserves the committed result across a repeated
Save or late Cancel. These transaction tests are separate from the native
cipher qualification.

Shipping Windows, macOS, Linux, Android and iOS source/callback suites check
their actual capture, proposal, receipt and persistence logic. Linux's headless
source and receipt checks do not claim widget execution. Full GTK/WPF/AppKit,
generated mobile SDKs and native platform networking still belong to the
authoritative hosted release matrix.

Two hosted failures found during this continuation have concrete fixes. The
Windows physical runner now retires its original verified executable by file
identity and digest after its owned process joins, including bounded handling
of Windows sharing violations. Failure to prove retirement still fails the
gate. The iOS OpenVPN profile fixture generator now emits a complete Swift
statement and uses the actual original capture accessor; its source checks
continue to execute.

The [build-all workflow](../.github/workflows/build-all.yml) owns publication
of matching packages, manifest, ARM64 images and production Compose for one
complete SHA. [Live release evidence](LIVE-RELEASE-EVIDENCE.md) remains required
for installed-device routing, leak protection, off-LAN interoperability,
applicable signing and deployment acceptance. This document is not a claim
that a release run or those live acceptance checks have completed.
