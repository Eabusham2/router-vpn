# Server transport retirement — 2026-11-16

## Failure and change

The hosted ordered Server acceptance run `43799624677` at
`a1a1bbeaf100c9fc2b1dcc38890ca1a657ccec82` failed on both AMD64 and ARM64 at
`http-connect/prefix-wg-one`. The worker could not join its original connections
on Stop and reported the sanitized `close-connections` deadline stage. The
preceding direct-proxy cases had passed. This was a later shutdown stage than
the earlier front/packet retirement repairs.

The worker previously cancelled the context shared by admission, proofs and
native packet transport before attempting graceful connection retirement.
WireGuard's actual ClientBind then rejected sends needed for CONNECT's original
TCP FIN/peer-EOF exchange. The repair separates logical work cancellation from
the transport owned by that same worker. Stop, parent cancellation and proof
expiry still stop admission immediately. The worker joins front and proof work,
drains its original sockets, and retires the typed protocol owner before
cancelling and joining the transport watcher and closing Box/carrier resources.

Transport retention remains bounded by the original eight-second command drain
budget. A single watcher starts at the first logical cancellation; another
cancellation or failed retry cannot renew it. Failure retains the exact original
close object and error. Cancellation of the transport does not acknowledge an
unjoined protocol owner. Partial construction also retires the captured context
and watchers. The new `close-transport` diagnostic uses the existing fixed safe
vocabulary and never formats underlying private native errors.

## Focused evidence

The seven implementation/test outputs were frozen on base
`56d5f95a57773912035b12f773ffaee93572aa0f`. Their preimages were verified unchanged
on integration parent `66f73ea50da59a5c397cf8bf0ff0b7b79b6fe9d8`.

- All 17 affected Python runner tests passed in 26.116 seconds. They include
  actual extracted shutdown/ledger bodies, the real service registry and stage
  error wrapper, loopback/UoT objects, the original compiled controls, and seven
  new lifecycle cases with four compiled causal omissions.
- The lifecycle cases cover explicit Stop, parent cancellation, the original
  expiry cancellation handle, zero-socket partial construction, failed-close
  retry, cancellation while an original close is held, and the unchanged
  eight-second force bound. The expiry callback's generation/proof guards were
  not replaced or relaxed.
- A separate race-instrumented protocol diagnostic used actual gonet TCP,
  shipping ClientBind over real loopback UDP, and the actual CONNECT connection
  close implementation. It incorporated the exact repaired lifetime bodies.
  Explicit Stop and parent cancellation both joined FIN/EOF before retiring
  the original transport. The counterfactual early-cancel arm reproduced the
  original 1.02-second protocol timeout and four refused ClientBind sends.
  All four exact test records passed; compilation took 6.275 seconds and
  execution 2.257 seconds.
- The mandatory full native runner preserves all 94 original records and adds
  eight records, for 102 across 22 roots. Its original native bounds remain
  unchanged. Two additional causal arms exercise the real native command
  package in the hosted gate.

The local protocol diagnostic explicitly models the unencrypted packet-link
adapter. The extracted worker tests explicitly model absent Box/carrier
boundaries. They do not establish a full native worker build, encrypted network
namespace acceptance, installed-host behavior, deployment, or device acceptance.
The exact-SHA AMD64 and ARM64 hosted encrypted Server runs still have to pass.

## Frozen evidence identities

- Source manifest SHA-256:
  `ef8646fcecd20cff4ba9a3258032d61ec0dd5b0e68ceb31fb5eb04bdf4936ce9`.
- Change patch SHA-256:
  `885392a8aeec674d149ab05355df86b0decf56b83bb7e0d6b8ec504fb74524fb`.
- Validation receipt SHA-256:
  `fa198c9bae54dacf47349f07edadee691ce015d5c2624b006d0a176c7f4e7198`.
- Repaired actual packet diagnostic JSON log SHA-256:
  `0fe2d7ddb10257cc36be3dc4d8b73d97c881562b928356f9bfb0a69ef9d6353e`.
