# OpenVPN Local restore ownership evidence — November 16, 2026

## Corrected behavior

An opaque ordered OpenVPN restore now retains the proved Local winner while
accepting the replacement native endpoint's own connected generation and time.
The shared preparation keeps its original connected observation and exact
engine pointer. A fresh private receipt belongs to the replacement engine;
the old preparation anchor is never reset or overwritten.

The original implementation stored the connected observation only on the
preparation. Opaque restore reuses that preparation, so a new Local endpoint
could fail against the old endpoint's generation or connection time. The older
restore fixture selected Server and returned constant endpoint values, which
did not exercise this Local-owner boundary.

## Authority and lifecycle

The separate `NodeChainOpenVPNExecutionRetiredObserver` contract exposes
`OpenVPNExecutionRetiredContext(context.Context, *NodeChain)` on the original
native engine. During `Run`'s existing bounded context, fresh same-preparation
restoration requires all of the following:

- Positive original shared cleanup, the original opaque capsule, projection,
  identity and retired owner.
- A successful joined retirement observation from the exact old native engine
  and source, repeated around the replacement-owner observation.
- A different engine pointer, EngineID and SessionID, with the replacement's
  exact identity and construction owner rechecked after the second retirement
  callback. A network or owner change during admission refuses the grant.
- An immutable private connection receipt bound to that preparation, native
  engine and captured identity. Later generation, connection time or capacity
  changes fail the selected Local path.

Ordinary runtime construction cannot borrow the original receipt from another
engine, even when the reported values match. An independent Server candidate
continues to use its own proof without requiring a connected Local provider.
Same-Box MTU resume inherits the exact existing receipt; it cannot authorize a
new endpoint generation. The existing mobile restore path still proves its
captured reader/native retirement and creates its separate preparation.

The shared scoring formula, common randomly selected endpoint, caller clocks,
original source/profile ownership and already-proved winner/target restoration
are unchanged. Restore repeats the selected path's proof and probes without
rerunning Compare.

## Executed validation

The unit was tested from source base
`0f07335da94b015fbc73d2581f29cbe16dbc9047` with the pinned Go toolchain,
race instrumentation, `GOMAXPROCS=1`, `-p=1`, `GOMEMLIMIT=900MiB` and `GOGC=50`.
Each run retained source hashes before and after execution. All 73 distinct
records below passed with no skipped tests, race reports or source drift.

| Scope | Passing records |
| --- | ---: |
| Fresh Local restore for 3/4/8 nodes over TCP and UDP | 7 |
| Unjoined/failed native retirement, missing observer, wrong owner/pointer/IDs, late network/owner change, cancellation and deadline refusals | 12 |
| Retained generation/time/capacity and cancelled/held receipt observations | 6 |
| Ordinary construction with equal or different endpoint values on another engine | 3 |
| Same-Box MTU resume with retained or changed generation | 3 |
| Twelve existing scoring, candidate, receipt, mobile/Last, generic/CONNECT/SOCKS/OpenVPN restore and MTU roots | 42 |

The existing two-valid-candidate regression executes the actual shared formula
`(last_node_response_time + external_server_response_time) / 2`, common target,
fresh winner trial and final repeated measurements. All five new roots are
mandatory alongside the original twenty OpenVPN execution roots. The existing
180-second phase and 240-second caller limits remain. The 25 Python inventory,
parser and dispatch controls also passed.

Three separately compiled production omission controls produced their exact
expected test failures: omitting the fresh restore grant reproduced rejection
of a new Local generation; omitting old native retirement admitted an unjoined
owner; omitting the original engine pin allowed another engine to borrow equal
values. Their complete run/failure witnesses and original source hashes are
retained outside the shipping source. The omitted code was never published.

## Preserved initial fixture result

The initial six-case run compiled and passed five leaves. Its four-node TCP
case failed before restoration because the 1 ms/200 ms response-delay setup
actually measured a lower Server average. That complete failed result and its
exact fixture bytes were preserved. Production code was unchanged by the
fixture correction.

The new Local-owner fixture deterministically acquires the real authenticated
Server lease, receives the existing TLS test endpoint's private-address answer,
and requires Compare to reject that response with no score. It requires the
original PUT/DELETE and stopped Manager worker before retaining Local. The
corrected four-node focus passed, followed by the complete six-case matrix.
Existing tests with two eligible candidates remain unchanged.

## Evidence boundary

The tests execute the shared Go implementation, authenticated Manager leases,
HTTP/TLS proof transport, actual Compare, opaque Restore, Last and shared MTU
resume. Native OpenVPN endpoint, routing, Box retirement and reader observations
are explicit boundary models. The new two-owner fixture uses the existing
35-second Last/mobile lifecycle budget; original single-owner fixture clocks
and production deadlines are unchanged.

Native Box/provider integration must implement and verify the retirement
callback against its retained construction and successful original Box.Close
receipt. Native packaged execution, real encrypted provider traffic, device
network behavior and full release acceptance remain separate required evidence.
This unit adds no platform/UI admission and does not close those requirements.
