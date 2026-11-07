# Explicit REALITY UDP/443 client capability

REALITY/Vision can carry UDP payloads, including selected DoH3, through its owned
encrypted TCP connection. The pinned Xray engine deliberately refuses UDP
destination port 443 for the ordinary `xtls-rprx-vision` client flow. The explicit
`xtls-rprx-vision-udp443` client flow permits that destination. Both use the same
existing mode identity, server credentials and ordinary Vision server inbound.
This adds no raw mode or logical picker entry.

## Obtain a capable original private bundle

For an intended installation or update, choose **on** at the installer's
**REALITY DoH3/QUIC on UDP 443 (keep/on/off)** question. With the image-only
Portainer stack, set:

```text
REALITY_CLIENT_FLOW=xtls-rprx-vision-udp443
```

The value reaches both initialization and finalization. An existing readiness
marker cannot suppress an explicit capability change: the finalizer compares
the requested flow with both actual generated client assets and their saved
generation state before deciding that the profiles are ready.

After finalization succeeds, obtain a new private `router-vpn-bundle.json` from
the authenticated Setup Center, then explicitly update or relink the intended
node in the app. Its original `reality-vision/xray.json` and
`reality-pq-vision/xray.json` contain the chosen flow before client capture.
Selecting DoH3 uses those captured assets and the selected resolver's address,
port, path, TLS name, trust and bootstrap. It never changes the original client
flow, substitutes another resolver, or grants SS UoT authority.

The installer defaults to **keep**, represented by an empty stack value:

| Choice | Generation behavior |
|---|---|
| `keep` / empty | Preserve each existing standard/PQ client flow independently. A fresh generation keeps ordinary Vision. |
| `on` / `xtls-rprx-vision-udp443` | Explicitly enable UDP/443 in both generated Vision client families. |
| `off` / `xtls-rprx-vision` | Explicitly return both generated client families to ordinary Vision. |

Removing an explicit stack setting later preserves the saved choice. To disable
the capability, select **off**, regenerate and explicitly update the device's
private node assets. A saved/imported device profile remains unchanged until
that update; regenerating server-side download assets does not rewrite a device.
The UDP payload travels inside the configured REALITY TCP transport.

## Source and lifecycle contract

`generate-xray-pq.sh` captures the exact requested flow in each original client
and persists `standard_client_flow` and `pq_client_flow` independently. Older
state without these fields is recovered from each existing original client.
An absent older client falls back to the ordinary historical flow; a saved
capability can regenerate a missing client without losing its choice.

Malformed or foreign flows, duplicate client fields, a different client UUID,
non-private or redirected files, and disagreement between an existing client
and saved state are refused before authoritative generation. Explicit enable
or disable does not override a malformed source. Engine validation precedes
the existing private atomic batch, and a partial adoption failure restores the
previous client assets and state.

The shared native compiler and actual Swift host accept exactly the two Vision
flow strings and retain their source bytes. Saved wrappers cannot be restored
using a different original flow. Both independently owned Start Layers retain
the captured capability. XHTTP still requires its original empty flow; its
transport is not converted to Vision. Dual-transport modes keep their existing
packet route and mode identity.

The native flow option changes only client-side permission to carry UDP/443.
The server inbound continues to use `xtls-rprx-vision`; the pinned engine
normalizes the explicit client suffix for the wire protocol. Private/public
node proof, DNS proof, connection ownership, cancellation and teardown remain
required before reporting a usable connection.

## Verification boundaries

The generation suite executes the actual generator, preservation reader,
private bundle writer and atomic transaction. It uses explicit engine-command
test doubles, then sends the generated bundle through the real shared Go
compiler. It covers ordinary fresh defaults, explicit enable/disable, mixed
saved choices, older state, missing-client recovery, rejected malformed/private
sources, candidate validation failure and observed partial-adoption rollback.
These checks establish the provisioning/capture path, not encrypted traffic.

The actual Swift fixture exercises original source preservation, selected DNS,
cold Codable restoration, saved-wrapper mismatch rejection and unchanged mode
identities. The separate native gate runs the pinned Xray and actual sing-box
DNS transports through the captured native owner, including HTTP/3, ordinary
Home UDP DNS, DoT and DoH. It must retain plain Vision's UDP/443 refusal and
reject incorrect TLS trust/name, resolver route/port/path, Xray key and stale
owners. Cancellation, close and replacement ownership remain mandatory.

The final source-bound native result, exact-SHA native packages, release
publication, private deployment and physical-device acceptance are separate
evidence. No live target is modified by implementing or testing this capability.
