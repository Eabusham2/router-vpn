# Shared mobile MTU controller

## Implementation status

The shared controller is connected to the process-owned Libbox TUN path on
Android and iOS/iPadOS. Android source integration is committed in `71be1466`;
Apple tunnel ownership, Retest UI, IPC and comparison-lease integration are
committed in `2dc2630f`. Native Go core preparation is pinned and exercised on
both Linux and macOS. These are source and test facts, not a declaration that
all Router VPN requirements or device acceptance gates are complete.

`AndroidMTUSession` and `RouterVPNMTUSession` provide captured session, physical
path and reader identities, actual MTU readback, a TUN-reader-only transaction,
and sockets explicitly bound to that OS VPN. The native bridge replaces only
the captured inbound. It does not restart the Box, rekey the encrypted tunnel,
change DNS, or use an ambient/default-network probe fallback.

Auto-MTU activation follows selected-node path proof. Manual/Jumbo settings do
not silently enter the optimizer. Retest and Cancel are session/request bound.
Speed Lab, hop measurements and SMART AUTO comparisons hold/drain adaptive MTU
work, including temporary replacement sessions. UI completion requires fresh
packet and transfer evidence rather than a stored number or a cache hit.

Apple WG and both native AWG variants select their Libbox endpoint owner for
Auto-MTU, preserving the exact transport and imported peer bytes. The raw
WireGuardKit path remains available for nonadaptive fixed/manual/default MTU;
a stale raw Auto-MTU handoff is rejected rather than silently ignored. Supported native graphs, actual
packaged-app compilation and physical-device acceptance remain separate gates.

## Controller behavior

Before mutation, the controller proves the selected private node through the
supplied interface. It considers at most five sizes inside the captured native
packet envelope. Each candidate is applied and read back, then tested using six
authenticated bidirectional datagrams and actual 256 KiB private transfers in
both directions. Failed, truncated, wrong-node, blind-echo and stale-path results
cannot win. Cached sizes are only suggestions and must be measured again.

Selection requires more than a five-percent combined upload/download rate gain
and no more than 0.2 ms additional median packet RTT relative to the original
baseline. The RTT allowance does not accumulate across successive candidates.
These bounds are selection rules for observed samples, not guarantees about
future network latency or throughput.

The winner is applied and proved again before a compare-and-swap cache write.
Failed application, readback or persistence restores the pre-test MTU only while
the same owner and path remain active. Explicit cancellation restores that
snapshot; Stop, a replaced connection or a changed physical path must not be
undone by rollback. Fixed MTU and Jumbo do not silently enter the optimizer.

The cache contains only a path/configuration hash, MTU and measurement timestamp,
with a 64-entry bound and 24-hour suggestion lifetime. It never stores private
credentials or reuses old rates as fresh measurements.

## Test scope

`go test -race ./internal/mobilemtu ./internal/hopmeasure ./internal/mtuprobe`
executes the production controller, validators, cache, authentication and
transfer measurement code. Tests exchange real local HTTP payloads and
authenticated datagrams but double OS ownership/application boundaries.

`native-mtu-integration.yml` prepares the exact native core and executes its
manager, bridge and shared controller with race detection on Linux and macOS.
`mtu-contract.yml` executes the shipping Java and Swift ownership, IPC, lease,
readback and evidence-validation implementations against platform boundary
doubles; negative controls must still fail. Build-all and the Apple compile
smoke separately compile actual SDK applications and embedded native engines.

None of those substitute for real-phone routing, leak, cancellation,
Wi-Fi/cellular transition, reconnect, signed installation or off-LAN tests.
No new device-validation claim is made by this source integration.
