# Ordered external exits, selected Server responses, and native ownership

This continuation follows the [recursive selected-hop record](IMPLEMENTATION-2026-11-25-RECURSIVE-SELECTED-CONTINUATION.md)
and the [reconciled requirements](REQUIREMENTS-RECONCILED.md). It implements a
distinct ordered external-final family, extends selected candidate responses to
the original Server winner, and carries AWG2 Fast and Strong entries through
recursive Compare-selected Local measurements. The original source, native
owner, credentials, selected execution, and cleanup boundary remain separate
from public presentation metadata.

## Ordered paths with an independently imported final

The new source schema supports Local paths with 3–96 members. The first member
is an original paired WireGuard entry. Each following member, including the
final, is an independently imported literal-address Shadowsocks 2022 node.
Every Start Layer is Off. The compiler retains each complete source and rejects
duplicate identities, dependent keys, changed captures, incompatible DNS, or
another source family presented as this one.

The first paired entry remains the selected control. The actual last import is
the public exit. That distinction now survives desktop and mobile editors,
saved whole-connection profiles, source replay, startup, Last restoration,
map identity, live response, durable latency history, and throughput.
Saved profiles contain node references and settings; credentials remain in the
original private node records.

Desktop Connect requires the canonical `external_final: true` intent together
with the complete node order and original revision tokens. Missing, false,
aliased, detached, or incompatible intent is rejected. The public capability
field describes an eligible source shape; native ownership still comes from
the complete compiled source and original retained process.

Home DNS keeps its captured route through the paired entry. An explicit custom
resolver retains the final import's policy and route. An intermediate IPv6-Off
choice also constrains DNS lookup strategy without changing the captured
resolver or its detour. iOS named-profile validation distinguishes this complete
ordered Home path from a standalone external node without a Home route.

Only the original first transport receives physical bootstrap permissions.
An imported intermediate or final cannot acquire a direct physical route by
appearing in the public graph. The Darwin protection capture records the
distinct control and runtime identities and retains its Off, on-connect, and
always cleanup rules.

The final's measurements describe a public path. Its latency is an HTTPS
response after TLS, and its label identifies the cumulative path through the
custom node to the Cloudflare edge. It cannot claim a paired private-agent
identity. The 50-response capture and saved history carry the actual external
final ID alongside their original source, configuration, generation, position,
and request. Live response and the 8 MiB throughput result retain the same
actual exit. The desktop Performance capture binds every original node ID,
including short three-node paths.

This source family does not establish arbitrary protocol combinations. AWG
entries, private interior nodes, hostname exits, non-Shadowsocks imports,
additional Start Layers, and Server/Compare execution remain outside this
external-final constructor. Its closed candidate preparation can measure the
original WireGuard entry; later stream-prefix candidate measurements still
require the separately qualified paired-final source. These are explicit
functional boundaries, not evidence of universal ordered-path support.

## DNS status uses the original ordered route

The generic imported-entry observer previously intercepted ordered routes
because their DNS registration shares the imported-runtime marker. The new
ordered observer runs before that generic observer and retains the actual
ordinary or selected execution owner.

A passing observation requires the complete original source, current profile
and control, actual process, selected winner, positive selection epoch where
applicable, and the native DNS proof and reader. Missing graph/native owners,
replaced profiles, a different runtime, cancellation, or an unproved selected
route cannot fall back to an ambient OS lookup.

The status reports the captured final resolver's verified policy. It does not
invent the duration of a new DNS query: its observation has zero newly measured
latency. A DNS benchmark or Retest remains a separate operation. Selected graph
observation also rejects incomplete, unready, DNS-unproved, public-unproved, or
failed native progress.

## Candidate responses through the selected Server

The new version-two candidate operation retains the original selected Server
trial, authenticated descriptor, complete source inventory, operation owner,
selection epoch, and finite grant. It is available to explicit Server and to
Compare whose actual winner is Server. Compare selecting Local continues to
use the original Local response owner.

The candidate's private source must already be independently provisioned in
the server's NodeChains registry. Its identity, source digest, transport tuple,
private API address, and credentials must match the requested candidate. A
client-local pairing, or an ordinary external-exit record without that full
identity source, does not satisfy the server's authority.

Clients send references and fixed challenge data. They do not send candidate
credentials or choose an arbitrary HTTP target. The server loads the original
private source, retains its inode and digest, and transfers it through the
owned private runtime file to the captured worker. A byte-equal replacement
file is a different owner and is rejected.

The worker accepts a bounded nonce/challenge frame, constructs the fixed
private-agent request, traverses the original Server prefix and candidate
transport, and returns the authenticated response MAC. Each completed score
requires 50 responses from that candidate and complete native drain. Wrong
MACs, replayed nonces, changed source, expired grants, stale epochs, and failed
cleanup cannot produce a score. The original 90-second grant and one-at-a-time
quota are preserved. Legacy version-one packet-prefix TCP establishment keeps
its original protocol and meaning.

Desktop catalogs opt in with `server_response=true`; subsequent operations
inherit that intent from the issued immutable view. The public
`response_executions` array describes eligible source geometry. It does not
certify server provisioning. An unstarted Compare draft has no invented winner
or selection epoch. Once selected, connected and terminal results bind the
actual winner and original epoch. Older unversioned clients retain their prior
Local-only behavior.

An absent candidate registration produces a distinct authenticated terminal
result only after the original native operation has joined and the live lease
has been checked again. Its MAC binds the complete request, original source,
candidate identity, endpoint, selected trial, epoch, and operation owner. The
result carries `candidate_disposition: "not-registered"`, no benchmark, and no
score. The next independently registered candidate can run on the same trial.
Desktop, Android, and iOS keep that row out of rankings and refuse Save or Use.
An ordinary error, forged receipt, substituted candidate, stale lease, failed
cleanup, or unknown disposition remains a fatal batch failure. It cannot be
reclassified as a missing registration to continue measurement.

The desktop native child now checks the measurement kind of the actual issued
operation. Private-response Local and Server operations no longer fail an
unrelated TCP-establishment-only mailbox check. Cancellation retains the
original operation kind and native join boundary.

## AWG2 recursive continuation

Compare-selected Local private-response measurements now retain original
WireGuard, AWG2 Fast, or AWG2 Strong entries through repeated independent
private/imported Shadowsocks streams. Use preserves the remaining suffix and
original paired final, and the next operation recaptures the changed draft.
The ordinary three-node start and the original 96-position source capacity
remain distinct from a claim of physical traffic at every depth.

The required encrypted selected-response inventory now contains 76 cases:
the previous 48 WireGuard cases plus 14 Fast and 14 Strong cases. The AWG cases
require actual client and peer parameter readback, authenticated responses,
and wrong-key and wrong-header refusal. The six external-final encrypted
cases form a separate required inventory. Each requires its original root,
leaf, and native witness; a root-plus-leaf pair is not two executions.
The Server imported-worker inventory separately requires the new
`stream-response` case. A prior receipt cannot qualify one of these additions.

The earlier 48-case hosted run exposed a server-side test-fixture identity
collision after a recursive insertion. It completed 50 authenticated
responses, but the reloaded six-node operator suffix reused one private key for
two private nodes. The production independence check correctly refused that
suffix. The repaired fixture derives each companion key from the original
node identity and position. All nine five-, six-, and nine-node WireGuard,
Fast, and Strong policy cases passed with the real source and server compilers
under race detection. Restoring the old constant seed reproduces the six- and
nine-node failures while retaining the five-node controls. This repair does
not relax the production validator or establish a successful encrypted run.

## Verification and CI integration

The local checks exercise production source and explicitly identify modeled
native boundaries. They do not stand in for encrypted native qualification,
installed devices, signing, or release artifacts.

- The final integrated run passed 16 complete controller roots with race
  detection and their original 120-second per-root deadlines, producing 128
  root/leaf PASS verdicts. The complete, unmodified `cmd/client` package was
  compiled once; the source and executable hashes remained unchanged through
  every root. The [receipt](evidence/external-final-server-controller-linux-amd64-2026-11-25.json)
  and [transcript](evidence/external-final-server-controller-linux-amd64-2026-11-25.log)
  record the toolchain, commands, hashes, durations, and each verdict. Coverage
  includes source/projection, canonical requests, Save/Load/Last, 50-response
  history, owned ordinary and selected lifecycle, both Compare winners,
  throughput, live response, missing-registration Save refusal, and cancellation.
  Source/projection exercises lengths 3, 4, and 9; shared-source and protection
  checks separately include 96. This is not a claim that every possible length
  or every root in the full package was exercised.
- The ordinary ordered startup, both Compare winners, selected graph ownership,
  and external-final controller roots passed together under race detection in
  56.111 seconds after the DNS observer repair. Their Windows native process,
  controller, and kernel boundaries are explicit models.
- Six connected/draft HTTP Server-response scenarios passed in the complete
  controller package with race detection. The two original roots completed in
  48.11 and 46.89 seconds. They retain explicit Server, Compare/Server, and
  Compare/Local source and result ownership. Native transport is modeled in
  those HTTP tests.
- The shared Server response suite passed its six race-enabled roots in
  82.273 seconds with the production grant bound. Its real fixed-frame private
  HTTP challenge verifies 50 nonces and wrong-MAC refusal while modeling the
  native encrypted transport. Independent source-registration tests reject a
  missing tuple, changed tuple, and byte-equal inode replacement.
- The complete `hopmeasure` and `multihoprelay` race suites passed in 45.241 and
  89.620 seconds after adding authenticated registry absence. The actual shared
  response fixture continued from a missing candidate to 50 independent
  responses from a registered candidate on the original trial. Forged MAC,
  substituted candidate, stale epoch, and incomplete cleanup controls passed.
  The source-fingerprinted release grant gate passed all 43 relay, agent, and
  policy verdicts under its original 180-second phase bounds.
- Android, Swift, WPF, and GTK component checks exercise the actual changed
  capture, editor, saved-profile, receipt, or transport callbacks. WPF's portable
  host models platform controls; GTK uses real widgets under Xvfb. These
  results are not installed Windows/macOS/mobile acceptance or visual QA.
- The complete Darwin PF source and causal-mutation gate passed, including
  small and long external-final captures, distinct control/runtime IDs,
  complete Off-layer enforcement, and on-connect/always cleanup.
- All 83 native shipping source validation tests passed, including causal
  mutations of explicit external-final intent, original control/source, and
  ordered DNS ownership. The full run completed in 615.844 seconds. All 14
  requirements-closure source/security audit commands also passed after their
  exact shipping-source anchors and additive native inventories were updated.
  These are source-contract checks, not installed native acceptance.
- The final Android candidate suite passed 889 checks with its original
  deadlines and 18 logged causal mutations. The current iOS selected-draft
  suite passed 352 checks and eight causal mutations; saved-profile coverage
  passed 9,562 shipping checks. The old iOS held-draft fixture advertised only
  the last eligible interior, preventing the legitimate earlier-stop callback;
  its repaired inventory exercises all original eligible positions. Same-kind
  import permutation and substituted control/source remain rejection cases.

Hosted runs exposed complete-source and Android jobs reaching their existing
job deadlines. The requirements source job is now distributed across six
immutable matrix jobs; each compiles the complete package and runs its disjoint
original roots. The first job also executes every other package unfiltered.
Android's four existing shared-core groups are distributed across twelve jobs.
The demonstrably slow AWG original-graph roots have individual bounded phases.
Compiler-discovered inventories still require exact complete coverage. No test,
operation deadline, job deadline, native gate, or release dependency is removed.

The macOS Performance fixture now checks the exact expected URL/POST inventory
for each scenario, including the public final. Its former hardcoded count
rejected otherwise passing transport scenarios. The new external-final source
also reaches the separate Swift loopback allowlist used by saved 50-response
measurements; a substituted control position remains a refusal.

The encrypted Server transcript verifier now requires the actual successful
`stream-response` witness: ready and verified selected DNS, encrypted TCP and
UDP observations, and private sink replies. Its former positive-case list
omitted the new operation and consequently demanded false readiness/DNS flags.
The corrected real-success transcript passes; independently removing either
flag or any of five traffic observations fails. Reinstating the former
predicate rejects that same success transcript. The complete base verifier,
inherited CONNECT verifier, and selected/external-final diagnostic verifier
passed 33, 20, and 35 tests respectively. These verify transcript acceptance
and refusal; they do not manufacture an encrypted runtime receipt.

## Delivery and acceptance

[Build all Router VPN release gates](../.github/workflows/build-all.yml) remains
the sole release owner. Packages, provenance, checksums, ARM64 server images,
and generated production Compose must all identify the same complete commit.
The tracked Compose template is not a generated deployment.

The new 76-case selected-response, six-case external-final, and Server
`stream-response` inventories still require their own successful hosted native
execution. Source inventories or component fixtures do not certify those
encrypted cases. A complete exact-commit release, legitimate iOS provisioning,
installed routing/DNS/leak and network-transition checks, off-LAN operation,
visual/accessibility acceptance, private live integrations, and deliberate
production deployment remain separate evidence required by the product
contract. macOS Developer ID signing/notarization retains its existing optional
status.
