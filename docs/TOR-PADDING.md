# Bounded outgoing Tor circuit cover

Router VPN's native extension sends standard `RELAY_DROP` cells through the
captured Tor circuit's existing relay encoder, hop encryption and scheduler.
It adds no socket, UDP sink, listener, relay command, circuit or stream. It does
not request a different guard or exit, extend a circuit's lifetime, or change
Tor's ordinary adaptive padding settings.

This is outgoing cover. A relay discards a recognized DROP; the extension does
not require or claim a padded reply. It is not Mullvad DAITA or Maybenot, and a
configured rate is not a measurement of privacy effectiveness.

The protocol basis is Tor's [relay-cell specification](https://spec.torproject.org/tor-spec/relay-cells.html)
and [padding overview](https://spec.torproject.org/padding-spec/overview.html).
The former identifies DROP as a circuit control message; the latter explains
that its relay command is protected by the circuit's encryption layers.

## Delivery and admission

The extension is source pinned in `mobile/tor/padding-source-lock.json` and
applied by `deploy/apply-tor-padding.py` to Tor commit
`4a522a3ca491c6c04d4a44cb006b92101c42efc1`. Every upstream file must match its
exact original hash before applying the patch; every resulting source and
copied implementation must match its resulting hash. The mobile embedded and
standalone package builders use this same extension. Tor's six-function mobile
C ABI and upstream version remain unchanged; the owned control capability has
its own protocol version.

The native extension and package evidence are prerequisites. A native host must
also capture the selected policy, bind it to its exact session and source,
require this capability from its real owned Tor runtime, and start and renew it
only after the required selected-path and DNS proofs. Local runtime compilation
continues rejecting enabled padding until its host adoption is complete. The
extension alone does not close the all-platform padding requirement.

The standalone server worker now has an owned activation path. Its optional
private source `padding` object captures `enabled` and `rate_kbps`; the source
hash changes when that selection changes. It keeps its private application
front closed until the exact child has passed selected-DNS and routed Tor exit
proof, and the native padding controller reports a positive channel-cell count.
Renewals use the recorded proof deadline; an unchanged old proof or stalled
counter cannot renew cover indefinitely. Configuration changes, source
replacement, cancellation and expired proof retire the captured owner.

The authenticated server receipt carries the outgoing link-cell count, bytes,
rate, generation, original observation time and conservative expiry. Clients
require the selected rate, reject missing or regressed counters, and stop their
existing data sockets when the last receipt expires even if no new status
response arrives. They reject unrequested cover when the saved selection is Off.
These server primitives do not enable a client UI path by themselves; the
corresponding client compiler and host must preserve and prove that policy.

### Mobile Server capture

The Android and Apple Server compilers retain the exact saved `daita_enabled`
and `daita_rate_kbps` fields in the final native owner and canonical private
server source. These existing profile field names select outgoing Tor cover;
they do not change its direction or accounting. Enabled with an omitted or zero
rate selects 192 kbit/s. Off preserves a dormant zero or 32–192 kbit/s choice.
The operator must provision a source with the matching selection and source
hash before the client can acquire a lease.

Idle validation permits saving a typed, bounded cover request before choosing
an entry. It produces no runnable graph. Connection compilation admits it only
for explicit Server execution with the complete captured private Router entry.
The single mobile VPN owns that entry, the authenticated lease, selected DNS,
client exit proof and cover receipt. Local, direct Server, ordinary external
predecessors and Compare do not acquire cover authority through this path.

The shared device-policy builder uses a separate Off template while preparing
the graph; its Local Tor owner is replaced before the graph reaches a runtime.
The final Server owner retains the original enabled source, and MTU authority
rejects another saved rate. Android node/profile stores and Apple node import,
runtime handoff and Add/Load/Update/Delete preserve the selected rate without
copying private Router sink credentials. Legacy Apple connection profiles that
omitted a rate retain the linked node's value; new profiles explicitly capture
zero when the saved rate was unset.

## Budget and path ownership

| Property | Enforced contract |
| --- | --- |
| Rate | Integer 32–192 kbit/s; the captured application's default is 192. |
| Accounting | Actual Tor link-cell bytes, 512 or 514 per queued cell. TLS, TCP and pluggable-transport framing are additional overhead. |
| Timing | One cell at a time; the minimum delay rounds up for a 514-byte cell. Random additional delay reduces the instantaneous scheduled rate to 75–100% of its ceiling. |
| Aggregate bound | One budget across every eligible circuit, with at most one owned cell waiting in the circuit queues. More circuits do not multiply the budget. |
| Congestion | Existing circuit queue, circuit backpressure or unavailable channel capacity prevents an additional cover cell. No accumulated credit or catch-up burst. |
| Circuit selection | Existing open general-purpose origin circuits with at least three open hops, the exact captured SOCKS username/password, unmixed SOCKS isolation, and a previously attached stream. |
| Exclusions | Directory, internal, one-hop, unfinished, closed, unrelated and retired idle circuits. Onion-service circuit purposes are not covered by this version. |
| Lifetime | One authenticated owning control connection, canonical session/source hashes, a strictly increasing generation, and a monotonic 100–10,000 ms proof lifetime. |

The rate bounds preserve the existing Router VPN implementation contract. The
original private messages containing any more specific Tor padding wording or
numeric requirements were not recovered; these numbers must not be attributed
to an unavailable original request. A fixed-size Tor cell cannot use the
variable-size UDP payload mechanism of the separate paired-Router cover service.

## Owned control protocol, version 1

`ROUTERVPN_PADDING INFO` returns the actual extension version, direction, bounds,
accounting unit and generation high-water mark. Even discovery requires an
authenticated owning controller. Stock Tor rejects the command; a host must not
convert that rejection into a successful unpadded connection.

The remaining commands use an exact 64-character lowercase hexadecimal session
identifier and source SHA-256, followed by a canonical positive decimal
generation. `START` additionally accepts the rate, proof lifetime in
milliseconds and the captured SOCKS username/password.
The username is exactly 32 or 64 hexadecimal characters, preserving the
shipping desktop and mobile/server credential encodings; the password is exactly
64. Circuit selection compares both the captured length and all captured bytes.
These are generated private runtime credentials, not user-supplied Tor commands.

```text
ROUTERVPN_PADDING START <session> <source> <generation> <rate> <ttl-ms> <username> <password>
ROUTERVPN_PADDING RENEW <session> <source> <generation> <ttl-ms>
ROUTERVPN_PADDING STATUS <session> <source> <generation>
ROUTERVPN_PADDING STOP <session> <source> <generation>
```

Only the captured controller may renew, inspect or stop that owner. A second
owning controller cannot take over a retained owner. An expired/stopped owner
cannot be revived by renewal, and a reused or older generation cannot start.
Changing configuration or issuing a lifecycle signal invalidates active cover;
the host must prove and start a new captured generation. Losing ownership,
closing control, disabled/dormant networking or proof expiry stops its timer.
Arguments containing credentials are wiped by the control dispatcher and never
included in the reply.

`running` means the bounded scheduler is active. It does not establish that a
circuit is eligible, that a cover cell was sent, or that selected-path proof
succeeded. Hosts must use actual counters and their independent path proofs.

## Counters and Stop

The reply retains separate `queued_cells`, `channel_cells`, `dropped_cells`,
their corresponding link-cell byte counts, `pending_cells`, and the last
selected circuit identifier. A receipt follows only the exact cell produced by
this extension; ordinary traffic and Tor's own padding cannot inflate it.

`queued_cells` increments after the production relay path encrypted and queued
that cell. `channel_cells` increments only after the actual channel write method
accepts it. It does not claim that the remote relay received it or that bytes in
a TLS/TCP buffer already reached the physical network. Failed writes and queued
cells removed by Tor's normal teardown increment `dropped_cells` instead.

`STOP` disables generation immediately. If a cell remains in a circuit queue,
the reply is `stopping`, with `pending_cells=1`. Tor has already advanced that
circuit's encryption state; deleting that cell while keeping the circuit alive
would desynchronize its ciphers. The reply becomes `stopped` only after that
owned queued cell is accepted by the channel or discarded by circuit teardown.
No replacement generation may start while it remains pending. A host must wait
within its cancellation bound and retire its Tor owner if draining cannot
finish; it must never announce completed cancellation from a `stopping` reply.
Bytes already handed to the transport cannot be recalled by this protocol.

Server shutdown first revokes front admission and joins the controller's
in-flight bounded operation. Quiescing the exact child lets normal native
circuit teardown account for any queued ciphertext before `STOP` readback.
If control cannot acknowledge the drain, shutdown must join that same child
process. A failed control read is never replaced with a fabricated stopped
receipt or a different process's state.

## Executable evidence

The source includes tests compiled inside the exact patched Tor tree. They run
the production control parser, timer, relay encoder, three layers of circuit
encryption, circuit queue and channel accounting. A controlled transport reads
the actual encrypted cells and decrypts them using three distinct Tor relay
crypto contexts, requiring that only the final hop recognize a stream-zero,
zero-length DROP. This is an offline execution test, not public-network or
physical-device acceptance.

The mobile Server regression runs the shipping compiler, actual native Box,
encrypted SS2022 entry, authenticated lease/SOCKS client, selected DNS and TLS
exit verifier. Its remote server and OS TUN are explicit fixture boundaries.
Missing, wrong-rate, empty-counter and expired cover receipts cannot admit a
stream, and a changed generation during renewal closes an existing stream while
retaining its exact private cleanup path. Separate shipping Swift/Java graph
and saved-profile fixtures exercise the platform capture and restoration paths.
These checks do not establish public Tor or physical-device acceptance.

The tests exercise both link-cell sizes, aggregate budgets across multiple
circuits, delayed timers, renewals without extra credit, stale owners and
generations, queued-cell conservation, honest Stop acknowledgements, proof
expiry, network/configuration invalidation, and ineligible or unrelated
circuits. Package control checks keep `DisableNetwork=1` and must reject padding
activation while checking the installed capability. Native platform builds and
the host's live selected-path, reconnect and leak checks remain separate evidence.
