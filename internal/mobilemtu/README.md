# Shared mobile MTU controller

## Implementation status

The shared controller and its behavioral tests are implemented. **This package
is not yet connected to Android's VpnService or Apple's PacketTunnel.** It does
not make the mobile Auto-MTU/Retest requirement complete, and it does not replace
that requirement with a capability exclusion. Existing mobile runtime selection
and production network behavior are unchanged by adding this package.

The `Owner` adapter must supply a live session, physical-path and virtual-interface
identity, actual interface MTU readback, a guarded TUN-only MTU change, and sockets
explicitly bound to that OS VPN. It must never provide an ambient/default-network
socket or restart an invalidated connection. No production adapter is claimed
here. The native adapter, UI/IPC, complete packaged-app tests and physical-device
acceptance remain separate work.

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

`go test -race ./internal/mobilemtu ./internal/hopmeasure` executes the production
controller, validators, cache, authentication and transfer measurement code.
The tests exchange real local HTTP payloads and authenticated datagrams, but
double the OS interface ownership/application boundary. They are not real-phone
routing, leak, reconnect or radio-transition tests. The full repository Go suite
continues to include this package automatically.
