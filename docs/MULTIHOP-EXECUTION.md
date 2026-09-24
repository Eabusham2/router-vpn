# Local and server-side multihop execution

The execution setting is separate from the entry/exit transport. **Local** runs
the exit tunnel on the client. **Server** runs an isolated exit engine on the
entry server. **Compare both** measures both and retains the lower eligible
average. Server execution entrusts the entry with the exit-tunnel credentials
and its decrypted inner traffic; it is not the same trust boundary as nested
client-side encryption. Existing saved profiles default to Local.

## Scoring and failure handling

For a fixed entry, exit and selected exit transport, the score is:

```
(last-node routed response time + external-server routed response time) / 2
```

One external HTTPS test endpoint is randomly selected from the approved literal
IP endpoints at the beginning of the round and reused for both candidates and
the final recheck. These are bounded routed HTTP response-time probes, not a
claim to be ICMP measurements. The last-node probe verifies the exact private
agent identity; the external request carries no node token. Requests use the
candidate's actual exit path with no ordinary-interface/proxy fallback.

Either timeout, failed identity proof, nonpositive result, changed network or
changed session excludes the candidate; an excluded candidate has no numeric
score. Both probes are repeated on the selected candidate before it is retained.
If it fails activation, the next previously eligible candidate may be tried.
If neither passes, no new path is declared connected. Cleanup that cannot be
confirmed is not treated as permission to overlap runtimes.

The desktop controller uses its existing owned process lifecycle and strict
route protection. Android and iOS/iPadOS use the same tested scoring package
inside their already-owned Libbox runtime. A native outbound selector changes
between the local exit and the entry-hosted relay; it does not create a second
system VPN. Mobile Disconnect and network changes cancel the comparison and
invalidate its results. Progress carries measurements and rejection reasons,
never relay passwords or node tokens.

## Provisioning a server-owned exit

Server execution requires an operator-paired exit registry on the entry node.
The current registry supports WireGuard, Shadowsocks and Hysteria2. A client
cannot submit arbitrary executable paths, shell commands or entire server engine
configurations through the lease API.

On the entry server, using the updated agent image and an operator-owned,
private exit bundle mounted read-only into that environment:

```sh
router-vpn-relay-pair \
  --bundle /private/exit/router-vpn-bundle.json \
  --exit-id EXIT_ID_AS_STORED_IN_THE_CLIENT \
  --agent-config /etc/router-vpn/router-agent.json \
  --registry /etc/router-vpn/multihop-relays.json \
  --listen-ip ENTRY_PRIVATE_TUNNEL_IP
```

Use paths actually present and writable in the operator's maintenance container
or staging environment. The normal production config mount is read-only; this
command does not remount it or modify a running deployment. It locks the registry,
checks ownership and symlinks, preserves other exits, validates the generated
configurations using the bundled native core, then atomically publishes the
private registry. It does not start tunnels, modify host routes or restart the
agent. Apply the resulting private config and restart only the agent deliberately
through the normal deployment procedure after successful validation.

The exit ID must match the selected exit ID in each client's node list. The
registry node proof must match the selected exit's actual identity. For mobile
WireGuard local/server comparison, provision a **separate authorized client key
on the exit** for the server engine. Reusing the mobile's own WireGuard key would
make the exit peer roam between two endpoints. The mobile controller rejects that
unsafe pairing rather than falsely reporting two independent paths.

Leases bind the authenticated tunnel source, entry identity, exit and random
session. Listener ports 26240–26271 stay private and reserved from broad port
forwarding. Listener proposals require fresh independent credentials and cannot
take another session's port. Lease renewals preserve identity; Disconnect requests
exact readback of deletion; expiry removes abandoned sessions. A Linux agent
crash terminates its owned child engines. Exit credentials remain in private
operator files; they are not returned in capability or progress responses.

## Native controls and saved setups

Windows, macOS and Linux expose Local / Server / Compare both in their multihop
controls, show the two measurements and mean, and save the execution preference
with connection profiles. Android exposes it with the multihop node/transport
selection and captures it through the VPN permission flow. iPhone/iPad exposes
it in the multihop sheet and saved connection profiles and obtains live progress
from its owned PacketTunnel through bounded IPC.

This execution choice does not add support for every possible transport graph.
It operates on graph families the existing native engine can actually compose.
An unprovisioned server candidate is rejected; in Compare mode a genuinely proved
local candidate remains eligible. No unsupported protocol is relabeled as working.

## Verification boundaries

Source and offline tests exercise the actual route-choice policy, graph builders,
lease lifecycle, private registry operations, Android connection ownership,
saved preferences and IPC bounds. The mobile build also compiles the bridge
against the pinned Libbox source and checks the generated selector graph with
that native core. The authoritative exact-SHA release run must pass separately.
Physical-device networking, private-server deployment, reconnect/leak-negative
acceptance and Apple signing are not established by offline tests or a green build.
