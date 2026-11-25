# Setup Center, forwarding and native release repairs

This record accompanies the [selected draft insertion implementation](IMPLEMENTATION-2026-11-25-SELECTED-DRAFT-INSERTION.md).
The changes below repair observed ownership and lifecycle problems without
changing the separate requirements for an exact-commit release or installed
acceptance.

## Retained Setup Center jobs

A generated package and its build workspace belong to the original job. A
successful or interrupted delivery keeps those same files available until the
original READY timestamp plus 30 minutes. Retrying a download does not renew
that deadline. Explicit Delete, deadline expiry and service shutdown now stop
and join an active writer before removing its input files.

Previously, a blocked socket could keep a job in `delivering`, bypass the expiry
scan and delay authenticated deletion. Delivery attempts now register an abort
callback and a completion event. Cleanup interrupts the original socket and
waits for that writer to finish. Late callbacks from an earlier attempt cannot
update a later attempt. Fallible metadata and file checks occur before the
writer is registered; all subsequent handler failures reach its final join.

The package builder now runs in an owned process group. Cancellation stops its
compiler descendants as well as its immediate Python process. The extracted
source and build tree are retained beneath the original job workspace, with
the original broker process and directory identity checked before use.
Unrelated processes and foreign replacement directories are not cleanup
targets. A failed directory cleanup remains visible as `cleanup-pending` and
is retried by the retained reaper. Shutdown refuses new jobs, joins existing
owners, and reports incomplete cleanup rather than silently discarding it.

## Interruptible GitHub sources

Exact-SHA GitHub Release retrieval remains first, followed by exact-SHA Actions
artifacts and the existing bounded local build fallback for supported desktop
packages. Mobile packages remain GitHub-built.

The original Release and Actions transfer implementations now run inside an
owned worker that can be stopped even during DNS lookup, connection setup,
response headers or a blocked body read. The parent retains cancellation
ownership, propagates progress, joins the worker and checks the identity of the
verified output before adoption. Cancellation is propagated through fallback
handlers instead of being converted into another retrieval attempt.

Missing `Content-Length` no longer suppresses cancellation probes. A network
open failure closes the already-created package descriptor. Partial-file
cleanup checks the original file identity and preserves a substituted file in
that failed-transfer cleanup handler. Later fallback or whole-job cleanup
still owns files inside the original retained workspace.
The existing SHA, digest, provenance, size, redirect and authorization checks
remain in the original transfer implementations.

Nineteen lifecycle tests passed, including independent reruns. They exercise real
blocked delivery sockets, Delete, original-deadline expiry, interrupted headers,
cleanup failure and retry, service SIGTERM, a compiler descendant that ignores
SIGTERM, and real loopback Release and Actions transfers stalled before or
after headers. The stalled upstream cancellation and shutdown cases completed
in less than two seconds, before the upstream source resumed. A separate live
process survived the compiler-group cleanup test.

The retained job also captures its original directory device, inode, broker
PID and nonce. READY pins the producer's file and requires its independently
verified whole-file SHA-256. A cancellable scan outside the job lock records
immutable 1 MiB chunk hashes before starting the retention period. Each
delivery opens and verifies that same file before headers, then checks every
read buffer before writing it to the socket. The final byte count and digest
must still match. Cleanup cannot borrow another job's directory or a copied
ownership marker.

In the actual HTTP/1.1 regression, the second chunk changed after headers while
the original file size and modification time were restored. The client
received only the unmodified first MiB, then an incomplete-download error;
no altered bytes were emitted. Replacement of the pathname after headers
still delivered the original opened file. Incorrect producer hashes prevent
READY, and cancellation remains available during package verification.

The package retention and private-bundle audits, production entrypoint tests,
exact-SHA Release tests, 23 broker source controls, 15 package-safety tests,
broker security and owned-temporary-directory tests also passed. These are
local production-code and loopback service checks; they do not establish a
deployed production Setup Center.

## Forwarding controls belong to the displayed router session

Desktop forwarding reads now return a path token derived from the original
proved router session, profile policy, active telemetry state and complete
immutable multihop route identity. AppKit, Windows and GTK retain the router
ID and token displayed by that read and submit both with an explicit Boolean
update.

The controller rejects an update after a foreign session, reconnect away and
back, or a changed graph before contacting the private router API. It checks
ownership again after the remote response. Remote readback must contain an
actual Boolean: missing, null or malformed `enabled` values cannot become a
successful false response.

The integrated controller suite passed the forwarding API, ordinary GET/PUT
and disconnected/external refusal roots, including stale requests that make
no upstream mutation. Shipping callback harnesses passed 163 GTK, 71 Windows
and 123 AppKit checks. Native session-mutation and map-first source gates are
kept separate from these controller and callback results.

## Windows firewall observation

The Windows ARM64 imported Naive H3 run at commit
`aa5a7610b1650d5385fad121c39de13f6a64bcb5` lost its original policy readback in
the whitening cells. Its first affected cell had already completed private
identity, DNS, authenticated TCP/UDP traffic and independent peer counters.
Two preceding ARM64 jobs passed the same cell with unchanged Windows sources.
The failing log alone does not identify which policy or identity check retired
the connection.

Review found that foreground Bind, Grant and tunnel/readback checks still
enumerated all host firewall filters twice while holding the same gate as the
watchdog. They now use the already-qualified single read-only BFE transaction,
with a fresh snapshot on each call. It still verifies both exact sublayer
records, ACLs and weights, the empty session lock, the full host filter
inventory, all expected baseline/tunnel/live rules, and successful transaction
commit. A failed proof remains a refusal. No native deadline or ownership
condition was relaxed.

All 21 host runner controls passed. The regression compiles the original
foreground and monitor methods, rejects the preceding double-enumeration
implementation and exercises transaction failures. The original Windows ARM64
test package and actual kernel observer cross-compiled successfully; the
resulting image SHA-256 is
`80291bbcc10fdb8e2458ba62bdca602b0af80dc9db52e82c238d81a686fedb0f`.
This is compilation and host-runner evidence. The genuine Windows ARM64
kernel job must pass on the final published source before the native repair
can be accepted for release.

## Mobile preview assertions and complete depth coverage

The earlier hosted Android and iOS suites contained assertions that treated a
now-qualified Compare source preview as evidence of a live Local owner. The
corrected assertions distinguish the bounded preview from original runtime
ownership. The Apple five-node case retains the permitted penultimate import,
and rejects Server, other positions, a missing paired source and a changed
final Start Layer. Its full original Swift/Go suite passed at depths
3, 4, 5, 6, 7, 8, 9 and 16, with all seven original negative controls.
The complete Android gate passed 3,742 checks across 29 phases and all nine
original mutation controls. Two additional causal mutations independently
confirmed that removing the qualified Compare preview or giving a Local
capture selected-execution ownership fails the corresponding assertion.

The shared-runtime job also exhausted a 180-second Go process budget after
combining 87 roots. It had reached depth 45 of the unchanged four-through-96
selected-source sweep. The complete 93-case sweep is now an explicit required
phase in a separate CI worker. Eight-depth batches keep the original
180-second Go and 240-second parent bounds. The job retains the existing
15-minute outer limit. Exact root, leaf, package-terminal and union checks
reject omitted, duplicated, foreign, skipped or failed cases. The other
original runtime phases keep their existing worker and bounds. The remaining
controller/proof phase also exceeded 180 seconds after growing to 88 roots.
It now runs in its own required 15-minute worker, in batches of up to eight
complete ordinary roots. The original Apple OpenVPN fixture emitter runs as a
separate root in six packet-count selections. Each executes its original body
and produces all 24 mode, network and layer combinations for that count. The
union must contain exactly the original 144 distinct keys. Leaving the test
selector unset still generates the full original matrix. Each invocation uses
a fresh private output directory and keeps the same 180/240-second bounds.
Skipped roots, missing or duplicate keys, foreign keys, arrays and symlink
outputs are refusals. Every original descendant remains subject to the strict
root and package verdict parser. No source assertion or shipping implementation
was removed. These emitter selections belong to `runtime_remaining`; the
separate Apple graph producer retains its original purpose and dependencies.

The [complete remaining-runtime receipt](evidence/shared-runtime-remaining-linux-amd64-2026-11-25.json)
records all 88 unique roots and 510 child cases passing with race detection.
The six generator invocations passed all 144 original fixture cases and account
for five intentional additional root PASS events. All 18 processes completed;
the longest took 98.391 seconds. Five actual malformed-selector runs also
failed at the original selector check before the missing-destination skip.
The receipt retains verdicts and byte hashes for all 520 package source and
test files. The initial discovery compile was killed by local memory pressure;
after lossless verification and compression of older task-owned cache objects,
the full unchanged package compiled and passed under its original bounds.

The [Linux/amd64 depth receipt](evidence/selected-source-depths-linux-amd64-2026-11-25.json)
records all 93 source depths passing with race detection in 12 bounded batches.
The longest batch took 128.75 seconds, within its original 180-second limit.
The full original package compiled without a test projection. This local run
does not establish the hosted worker's 15-minute completion requirement.

These depth tests qualify source construction, reopening, ownership and wire
capacity refusal. They are not live 96-hop network evidence. The final hosted
Build-all release must still use one commit for every client package, server
image, checksum and production Compose result.

## Required Xray shards and original Windows UI dependencies

The preceding Native Xray job spent almost its entire 45-minute limit in the
unfiltered shared-runtime dispatcher and stopped before its later source and
native-parser work. The workflow now runs four core shards and six other
shared groups independently. The original native parser and Docker build
require successful Apple fixtures and every shared matrix result first.
Failed, canceled, skipped or missing dependencies fail that requirement.

Workflow controls expand the actual Bash arguments through the shipping
dispatcher and account for 208 phases and 1,224 source-declared roots exactly
once. The ordinary Linux package discovers 1,223 roots: the additional original
Linux native-carrier test requires `routervpn_server_chain_acceptance` and
belongs to its separate genuine native gate.
The five Xray controls, 45 dispatcher controls, nine imported-prefix source
controls and fifteen imported-prefix workflow controls passed. Every original
native command and unrelated job remains unchanged apart from moving the
unfiltered shared dispatcher into the required parallel jobs. Each Xray job
keeps the existing 45-minute maximum, and the original per-process bounds
remain unchanged. Hosted shard completion is still separate evidence.

The Windows Stop Retry fixture also omitted the shipping profile-journal
helper newly called by ordinary Connect. It now imports the real UI state
module and exercises both an actual pending profile transaction and its
clearance before selection. The original failure was reproduced, the repaired
PowerShell harness and contract checks passed, and a bypass mutation was
rejected. This fixture repair does not remove the production journal guard or
substitute for the required Windows PowerShell 5.1/native execution.

The macOS Performance fixture now checks its two private-transfer label
refusals independently. Its original broad mutation correctly failed at the
earlier selected sixteen-node check, while the harness expected the later
Local nine-node diagnostic. The repaired fixture checks that earlier refusal
and separately mutates only the Local branch to reach the later refusal.
The original shipping Swift/loopback scenario and all five negative mutations
passed. Production label validation is unchanged; genuine hosted Darwin
execution remains required.
