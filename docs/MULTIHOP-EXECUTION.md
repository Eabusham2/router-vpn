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
claim to be ICMP measurements. For Router VPN exits, the last-node probe verifies
the exact private agent identity. The external proxy extension below uses
its explicitly configured HTTPS endpoint on the captured exit server. The
external request carries no node token. Requests use the
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
The registry source includes WireGuard, AmneziaWG Fast/Strong, Shadowsocks and Hysteria2. A client
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
WireGuard/AmneziaWG and desktop WG/AWG Local/Server comparison, provision a
**separate authorized client key on the exit** for the server engine. Reusing the
device's own packet client key would make the exit peer roam between two endpoints.
Controllers compare the canonical public identity, including private-key encodings
that X25519 clamps to the same peer, before acquiring an independent Server lease.

Desktop WG/AWG requests also carry `expected_packet_public_key`, captured from
the authenticated entry's paired-exit catalog. The updated agent checks it against
its private registry under the lease lock before acquisition or renewal. This
binds discovery to the actual paired key even if the entry restarts between GET
and PUT. An older agent that rejects the field or does not return the exact bound
request cannot satisfy this desktop Server contract. No fallback drops the pin.
Every renewal rechecks fresh capabilities against the original identity. Temporary
Speed Lab restoration retains the proved Local/Server choice and, for Server,
the captured peer pin; changed pairing requires a new user connection.

Leases bind the authenticated tunnel source, entry identity, exit and random
session. Listener ports 26240–26271 stay private and reserved from broad port
forwarding. Listener proposals require fresh independent credentials and cannot
take another session's port. Lease renewals preserve identity; Disconnect requests
exact readback of deletion; expiry removes abandoned sessions. A Linux agent
crash terminates its owned child engines. Exit credentials remain in private
operator files; they are not returned in capability or progress responses.

## Router entry to a paired external proxy exit

The shared native execution path supports privately paired third-party
Shadowsocks, Hysteria2, authenticated SOCKS5, HTTP CONNECT and HTTPS CONNECT
exits behind an existing captured Router VPN predecessor graph. Its
supported native entry mode, entry Start Layer, helpers and bootstrap policy
stay in that same graph. Android captures this path in its existing VpnService;
Apple captures it in the ordinary external PacketTunnel owner. The client
keeps the external server identity separate from Router VPN node identities:
an external provider does not need, and is never assumed to expose, a Router
administration API.

An eligible Server or Compare profile needs its exact external proxy
configuration, expected public exit address, and a node-response endpoint
configured in the external node editor or imported profile. This endpoint is
optional for an ordinary Local connection:

```json
"response_probe": {
  "url": "https://203.0.113.20/node-response",
  "server_name": "node.example"
}
```

Place this member inside the node's `external` object. The example address and
name are placeholders. The URL must use the same public literal IP as the
captured protocol server, with HTTPS and a successful bounded response.
`server_name` is optional when the certificate already verifies the literal IP;
otherwise it selects and verifies the server's HTTPS virtual host. The socket
still dials only the captured literal address. Query strings, credentials in
URLs, redirects, private targets and ambient hostname resolution are refused.
The optional endpoint does not change ordinary Local connection eligibility.

Pair this exact external node bundle on the Router entry with the same
`router-vpn-relay-pair` command above and its actual client exit ID. The private
registry retains the protocol credentials and response-endpoint parameters.
The native offline check validates the resulting relay graph before atomic
publication. Its public capability catalog contains the public endpoint/proof
fingerprint and expected egress IP; it contains no password digest or private
credential. A per-session keyed proof binds the client's captured credentials
to the particular entry, exit and random listener proposal before a server
engine can start. SOCKS5 and CONNECT Server/Compare require a nonempty paired
username/password. Ordinary Local use may retain a deliberately anonymous
provider; an absent credential is never invented for server authentication.

Every external protocol acquisition also signs a fresh challenge from the
authenticated entry: its current boot epoch, observed tunnel peer, 60-second
acquisition deadline and random attempt. A DELETE received before a delayed PUT
retires the same attempt; restarting the entry changes the epoch. Active owned
leases can renew after the initial acquisition deadline, but a retired attempt
cannot recreate a process. Existing proxy bundle fingerprints and credential
derivation remain compatible. Old clients or entries without this challenge
return an explicit upgrade requirement; an unchallenged acquisition is not an
accepted fallback. The historical capability member is still named
`external_packet_challenge`, including for proxy and OpenVPN acquisitions.

Each trial measures a complete **HTTPS response time** from that configured
last node and the same randomly selected external HTTPS endpoint. Merely opening
the proxy stream is insufficient: native early connection establishment
does not prove that the requested final destination answered. The trial also
proves the selected DNS policy and the expected public exit independently. The
lower valid average wins only after both measurement probes pass again. A
failed response, certificate, DNS policy, exit proof or session has no score.

The Local candidate and authenticated server SOCKS candidate remain within one
captured native selector and TUN. The relay accepts only the owning tunnel
client and literal destinations; it cannot introduce a provider DNS fallback
for hostnames. Saved DNS, IPv6, LAN and MTU policy remains bound to the complete
compiled graph. The proof owner retains the private lease, renewal and selected
candidate; cancellation invalidates publication immediately, and checked close
waits for late proof callbacks and confirmed lease cleanup before native
teardown. Restoring a proved winner for a saved Compare profile directly
reopens that local/server choice without changing the saved preference or
starting another comparison.

### Imported entry and exit Start Layers

An external proxy can retain an independently provisioned Start Layer. The
profile's `start_layer` selects `aes-256-gcm` or
`aes-256-gcm+xor-whitening`; its private `external.start_layer` contains exactly
`mode`, `api` and `transport`. The mode must match the selection. `api` names the
private inner target with an explicit port. `transport` is the complete
Shadowsocks 2022 AES-256-GCM outer transport on the same captured public server,
with its actual private key. The native compiler owns the inner rewrite and
outer detour; the XOR variant uses the provisioned whitening port 8389.

Entry and exit layers have distinct owners. An ordinary external entry's outer
transport owns the physical path; the exit's outer transport traverses the
captured entry. Neither layer substitutes credentials, TLS identities, DNS or
LAN/IPv6 policy. Saved connection profiles store the selected layer mode and
refer to the current private node provision; they do not copy the key. Changing
that provision incompatibly requires updating the saved setup.

The desktop ordinary-path builders also apply these imported layers, including
the controlled upstream proxy for a native OpenVPN final exit. Layered desktop
paths require the verified complete native runtime, which includes the XOR
adapter. The shared generated native graph tests remain separate from physical
device acceptance.

### External WireGuard and AmneziaWG peers

An external WG/AWG Server or Compare path uses **two independently provisioned
client peers on the same provider**. The normal `external.wireguard` or
`external.amneziawg` block retains the Local client's private key and PSK. The
entry server receives a separate private peer profile. It must use the same
remote protocol, endpoint, provider public key, routes and AWG parameters,
with a different canonical client public key and different assigned addresses.
The remote provider must authorize both peers. Different spellings of one
clamped X25519 private key do not count as independent peers.

Only this public descriptor of the server-side client goes into the client
node's `external.server_peer` member:

```json
{
  "public_key": "BASE64_SERVER_SIDE_CLIENT_PUBLIC_KEY",
  "addresses": ["10.93.0.3/32", "fd93::3/128"],
  "mtu": 1360,
  "persistent_keepalive_interval": 25
}
```

This is the relay-side **client** public key, not the remote provider's key.
The assigned addresses must be real addresses provisioned by that provider,
one per family, matching the Local peer's address families and differing from
its assigned IPs. MTU is explicit, 1280–9000. Keepalive is optional, 0–65535;
omitted and zero both disable it. Private keys, PSKs, unknown fields, duplicate
fields, noncanonical public encodings and low-order X25519 identities are
rejected. The same-host HTTPS `response_probe` and expected public exit IP
remain required for Server/Compare. A Local-only node may omit both its server
descriptor and comparison response endpoint.

Prepare a separate private `server-peer.json` with exactly `protocol` and the
complete matching `wireguard` or `amneziawg` block. That block contains the
**server-side client's** private key, assigned addresses, remote provider key,
endpoint, allowed routes, MTU, optional PSK/keepalive and the exact AWG
parameters where applicable. It is not a second copy of the Local bundle.
The offline agent can derive the public descriptor without exporting the
private key or PSK:

```sh
router-vpn-agent describe-external-packet-peer \
  < /private/server-peer.json > /private/server-peer.public.json
```

Import that public result as the node's `external.server_peer`. Then pair the
complete client bundle and the independent private server profile on the
intended Router entry:

```sh
router-vpn-relay-pair \
  --bundle /private/exit/router-vpn-bundle.json \
  --server-peer-profile /private/server-peer.json \
  --exit-id EXIT_ID_AS_STORED_IN_THE_CLIENT \
  --agent-config /etc/router-vpn/router-agent.json \
  --registry /etc/router-vpn/multihop-relays.json \
  --listen-ip ENTRY_PRIVATE_TUNNEL_IP
```

The offline Go compiler checks both identities and exact public parameters.
Only the Server private key/PSK and both **public** descriptions survive in
the resulting server registry; the Local private key/PSK is not copied into
it. No server private key/PSK goes into the client profile. The existing native
checker validates the generated engine graph before atomic registry
publication. This command does not start a tunnel or modify the live router.

For packet leases, X25519 agreement between these two client keys derives a
domain-separated HKDF-SHA256 authentication key. Public fingerprints bind the
two public configurations, expected egress, response endpoint and optional
outer layer, without publishing a digest of either PSK. Runtime packet and
exit/DNS proofs still have to succeed; possession of a lease is insufficient.
Each acquisition signs the entry's fresh boot epoch, observed tunnel peer,
60-second acquisition expiry and a random attempt ID. Renewals keep the same
already-owned process. Cancellation or teardown retires that attempt, including
a DELETE that reaches the entry before its delayed PUT. Failed cleanup keeps
the process, port and canonical key reserved but cannot renew a retired path.
A Compare winner's repeat proof gets a fresh attempt while keeping the
captured session, listener and graph. Restart changes the epoch and rejects
old signed acquisitions.

The Local and Server transports retain their own interface MTUs and keepalive
settings. A shared client TUN cannot exceed the captured Server interface in
Server/Compare; incompatible fixed values fail validation. Packet exits with
an imported AES or AES+XOR layer account for the SS2022 request/response headers,
per-key identity headers and inner destination address before fitting into a
packet entry. These are configured bounds; current-path MTU evidence still
comes from the owned measurement and proof lifecycle. Canonical packet/PQ
ownership also includes the packet base inside complete MAX chains.

### External OpenVPN provider sessions

An external OpenVPN Server or Compare path keeps two independently provisioned
provider sessions. The client retains the complete original
`external.openvpn` inline profile. The Router entry receives its own original
inline profile with a different client certificate public key and canonical
common name, a different provider username, or both, according to the provider's
authentication method. Reissuing a certificate with the same public key,
changing only name case or whitespace, or supplying another password for the
same provider username does not create a distinct owner.

Each owner also holds a separate random 32-byte X25519 pairing key, stored in
standard base64. These dedicated authentication keys are independent of the
provider's TLS and password credentials. The server's private input has this
shape:

```json
{
  "protocol": "openvpn",
  "openvpn": {
    "config": "the server owner's original inline OpenVPN profile",
    "username": "the server owner's provider username when required",
    "password": "the server owner's provider password when required"
  },
  "pairing_private_key": "the server owner's dedicated base64 X25519 key"
}
```

Export its public counterpart descriptor offline:

```sh
router-vpn-agent describe-external-openvpn-peer \
  < /private/server-openvpn-peer.json > /private/server-openvpn-peer.public.json
```

The descriptor contains the pairing public key, canonical public transport
policy and provider identity. It excludes the original profile, TLS client
certificate/key, provider password, TLS control key and pairing private key.
Keep this descriptor inside the private node bundle; it is not a discovery or
public status record. The client's `external.openvpn_pairing` contains exactly
`private_key` for its dedicated Local pairing key and `server` for that public
descriptor. The native editor validates the raw profile and pairing objects
before JSON conversion can discard unknown or duplicate private fields.

Pair the complete client bundle with `router-vpn-relay-pair` using the same
arguments shown for packet peers and
`--server-peer-profile /private/server-openvpn-peer.json`. The real Go compiler
verifies the original sources and both descriptors. The private registry retains
only the Server profile and pairing private key, plus both public descriptions.
The client retains no Server private material. Public capabilities contain only
the external fingerprint and expected exit address; public profile views expose
pairing eligibility as a boolean.

X25519 agreement and a separate HKDF domain authenticate the lease. The public
fingerprint includes both public descriptors, response endpoint, expected exit
and selected Start Layer. It does not publish a provider password digest.
The common challenge, cancellation, expiry and confirmed-close rules above
apply. Concurrent relay leases cannot alias a canonical provider public key,
common name or username, and a process whose cleanup failed keeps that identity
reserved.

Existing single-host pairings retain their v4 identity and `response_probe`.
For different-host lists, the private import instead supplies
`external.openvpn_response_probes`, with one verified HTTPS response endpoint
for every distinct original public literal host:

```json
"openvpn_response_probes": {
  "203.0.113.20": {
    "url": "https://203.0.113.20/response",
    "server_name": "provider.example"
  },
  "203.0.113.21": {
    "url": "https://203.0.113.21:9443/response",
    "server_name": "provider.example"
  }
}
```

The map contains two to sixteen exact hosts. Missing, extra, duplicate,
noncanonical or unrelated hosts are rejected before private JSON decoding can
discard them. It cannot coexist with the legacy `response_probe` or singular
`start_layer`, including explicit null fields. The map remains private through native import,
saved profiles, pairing and capture; public profile views expose eligibility
only. Both owners retain their original remote order, ports, transport fallback,
TLS, cipher, control wrapping, keepalive, fragment and MTU options.

This v5 pairing requires the entry's `fresh-connected-transport-v1` capability.
The actual native OpenVPN endpoint supplies the connected physical remote and
an immutable generation for that transport. A queued configuration callback
from an older dial cannot mark a new connection ready. The private relay
answers each status request using a new request nonce and the exact owned
process, source digest, lease epoch and attempt; an existing recent receipt
file is insufficient. A changed remote, reconnect to the same remote, stopped
process, expired owner or delayed replacement response invalidates that proof.

Each candidate measures its last-node response through its own connected remote's
map entry. Both candidates use the same randomly selected external endpoint,
and their scores remain `(last_node_ms + external_ms) / 2`. The controller
checks the exact native generation around DNS, both timed probes and the
winner's repeated proof. Failures receive no score. Restoration keeps the
already-proved Local/Server choice. Retained MTU, DNS Retest and Speed Lab
operations perform fresh checks at capture and result-adoption boundaries;
the background health watch alone cannot certify a new measurement.

Single-host Off, AES-256-GCM and AES-256-GCM plus XOR exit Start Layers use the
same owned native graph. Different-host mapped profiles retain v5 for Off and
use v6 when `external.openvpn_start_layers` supplies a complete private layer
map. This map has two to sixteen canonical original public hosts, with exactly
the same coverage as `openvpn_response_probes`, and at most 128 KiB of raw JSON.
Each value has the existing `mode`, private `api` and authenticated `transport`
fields. Every value must match the selected exit mode, either AES-256-GCM or
AES-256-GCM plus XOR; the Router entry's separately captured layer is independent.
A singular layer, explicit null, duplicate key or incomplete map is invalid.

The native `routervpn-openvpn-layer-map` owns one authenticated outer child for
each original host. It routes only exact captured original host/port/network
tuples, preserving the complete ordered OpenVPN server list. Only the chosen
child's dial target changes to that host's private service address and original
OpenVPN port. Two providers with identical private addresses remain distinct.
The native configured event and fresh remote receipt retain the original tuple
and immutable transport generation, including UDP/TCP fallback and reconnects.
No user-provided per-remote detour tag can substitute another runtime owner.

V6 requires the entry's `captured-per-remote-v1` capability in addition to the
fresh connected-transport capability. The fingerprint binds both provider public
identities, every response endpoint and all public layer policy; the private
lease authentication additionally binds every host's outer key. No public
password digest is exposed. Outer keys cannot reuse either dedicated Local or
Server pairing private identity, including canonical X25519 aliases. Existing
v4 single-host and v5 mapped-Off fingerprints remain byte compatible.

The mapper bounds pending/adopted sockets, cancels late dials and closes only
its owned children. Failed closure retains the owner and prevents a replacement
provider session. Physical desktop exceptions use the compiled outer
host/port/network tuples, including the whitening listener's actual port. The
MTU envelope uses the largest allowed per-host wrapper and private address
family; it never treats that conservative bound as a fresh path measurement.

The private relay runs a userspace `openvpn-client` endpoint with
`system: false`; it does not create another system VPN or change the entry's
global default route. The client proves its selected DNS and exit through the
chosen path. Configured interface/fragment bounds account for the enclosing
packet and Start Layer overhead without representing them as a fresh path MTU
measurement.

`deploy/test_external_openvpn_native.py --core PINNED_CORE_CHECKOUT` executes
real encrypted traffic with independent Local and Server client certificates
over TCP and UDP, in all three layer choices. It uses the actual native provider,
relay builder, lease manager and shipping whitening binary. The same race gate
checks wrong CA, peer name, control key and listener password, repeated traffic
from both owners, replay after deletion and closed listeners. Only the test's
physical sockets are mapped to owned loopback endpoints; production endpoint
validation stays active.

External-entry Server execution still requires its own administrative/runtime
owner. Operator pairing and device/off-LAN acceptance remain distinct evidence;
no private deployment occurs when sources or tests are updated.

## Mobile LAN-Off enforcement

The shared native compiler applies both frozen nodes' `home_lan_access` policy
before engine startup. When a node disables LAN access, its configured private
`home_lan_cidrs` are denied to ordinary TUN traffic. An absent/empty list uses
RFC1918 IPv4 ranges and IPv6 ULA. Public, default, malformed or ambiguous network
ranges are rejected, never silently substituted. More-specific TUN included
routes keep physical LAN routes from bypassing this filter.

Only the selected exit's exact TCP Router API host/port remains reachable for
normal private control. Entry/exit proof listeners and native DNS dialers keep
their existing separately owned paths; the policy does not create an admin,
SSH, SOCKS or subnet-wide bypass. IPv6-Off stays ahead of the control exception.
Apple's `excludeLocalNetworks` routes local traffic **outside** the VPN, so it is
never enabled by LAN-Off; both hop policies must permit that exclusion. Android
and Apple compile the same policy, and native build tests parse the protected
graph with the pinned core. Real-device network and leak-negative tests remain
separate evidence, not implied by this source implementation.

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

## Android WireGuard exit and frozen graph policy — September 27, 2026

Android now compiles standard WireGuard entry to a different Router VPN
WireGuard exit inside the existing Libbox VpnService, alongside its
Shadowsocks/Hysteria2 exits. Local, server and automatic comparison keep the same
session-owned selector, independent node proofs and private lease lifecycle.
The native parser binds each WireGuard public key to the paired node identity,
preserves preshared keys and persistent keepalive, and rejects duplicate peers,
ambiguous fields, shell directives and hostname bootstrap. This is not an
additional OS VPN, external shell helper or AWG-as-WireGuard substitution.

The frozen exit DNS policy is applied to the encrypted exit endpoint before
session files exist. A missing selected profile or absent encrypted DNS outbound
is an error, never an implicit first-node or direct-DNS fallback. Both hops
retain separate fixed MTU settings. Nested WireGuard reserves IP/UDP, WireGuard
authentication and padding overhead; an explicit fixed exit MTU that does not fit
is rejected rather than silently clamped. Default sizing is a configured
conservative bound, not a claim of measured Auto-MTU completion. IPv6-Off retains
OS IPv6 capture and rejects ordinary TUN IPv6 traffic. LAN-Off continues to
compile both frozen nodes' private-network policy.

Executable coverage includes the shipping Java controllers linked to the actual
shared Go compiler and policy package, malformed-input and ownership negatives,
and native graph schema tests in both pinned Android/Apple builds. JVM tests
double Android OS handles and the node store, not the graph/compiler/DNS policy.
They do not replace physical-device routing, leak or network-transition tests.
That September 27 addition did not yet cover helper/PQ/MAX/ALL, AWG-entry or
mobile Tor dataplanes. Later shared native composition supersedes those source
exclusions; the current entry matrix and platform evidence above describe the
implemented paths. This historical checkpoint is not a current missing-feature
list or proof of physical-device acceptance.

## Native AWG exit source integration

Android and iOS/iPadOS can compose supported WG/AWG entry endpoints with an
AWG Fast or Strong exit in one native graph. The exact exit mode, peer key,
preshared key, all eleven obfuscation parameters, and DNS detour are retained.
Saved-profile validation includes both AWG variants. This extends the exit side;
it does not claim support for arbitrary mixed helper/PQ/MAX graphs.

The shared execution controller exposes the paired AWG exit to Local, Server and
Auto comparison. Server comparison requires distinct paired client credentials.
The entry relay's custom CLI is built with the identical pinned AWG endpoint
implementation used by mobile; stock sing-box cannot parse that endpoint. The
image checks production-generated configurations for all five relay transports.
Keep the old image until the new exact-SHA image gates pass; copying a registry
does not upgrade a running server engine.

Nested packet sizing subtracts IPv4/IPv6 UDP/WG framing plus the AWG exit's S4
transport padding, then aligns down to sixteen bytes. A fixed MTU exceeding that
envelope, or an envelope below the dual-stack minimum, is rejected. Live Auto-MTU
retains its existing captured-owner validation.

Regression coverage includes shared controller/key ownership, server lease
validation, provisioning, saved-profile round trips and Swift/Java graph
composition. A native two-hop AWG TCP/UDP IPv4/IPv6 traffic test is included in
the pinned engine's existing test suite. Only executed tests are proof: this
continuation still requires actual Android/native build execution and a new
exact-SHA release run, followed by physical-device/off-LAN acceptance.


## Desktop AWG Fast/Strong packet exits — October 26, 2026

The desktop Router-node graph accepts `wg`, `awg2-fast` and `awg2-strong`
entries with an exact AWG Fast or Strong exit in Local, Server or Compare both
execution. This extends the existing seven proxy choices and WireGuard exit;
the separate transport-AUTO candidate search keeps its existing contract.
Windows, macOS and Linux controls, complete connection profiles and Speed Lab
retain the selected runtime ID and execution choice. The pinned native lifecycle
publishes a literal WireGuard entry only after its device has initialized under
its lifecycle lock, so the dependent AWG bind can open during the same startup
phase. Deferred hostname peers, failed or cancelled starts and closed owners
remain unavailable; initialization does not replace node/DNS path proof. Broader Router entry
families, other packet/helper/composite exits and physical acceptance remain
separate unfinished requirements.

Local retains both native packet endpoints. Server removes only the captured
local exit endpoint and replaces it with the authenticated owned relay. Its
registry must contain the exact AWG variant, all eleven obfuscation parameters,
preshared key where selected, address/route data and an independent client
identity. The updated agent must support `expected_packet_public_key` on AWG
requests. An older agent's broader AWG transport catalog alone does not satisfy
this new desktop pin contract. Capability renewal and temporary-test restoration
keep the original public identity and already-proved execution; changed or
missing pairing, a reused canonical peer, a stale owner or an expired lease
cannot reach a new PUT or silently restore a different path.

MTU accounting retains AWG S4 alongside the whole Start Layer datagram envelope,
then aligns the remaining nested capacity down to sixteen bytes. For example,
a captured 1420-byte entry with IPv4 peers, S4=32 and the selected AES/XOR Start
Layer has a 1264-byte aligned nested bound, below the supported 1280 minimum,
and is rejected. The same explicit 1500-byte entry capacity permits 1344 bytes;
a requested fixed 1408 value is rejected for that layered path. A fixed 1280
choice can be used within the demonstrated configuration bound. These are
configuration limits, not fresh path-MTU measurements, and the compiler does not
raise the entry MTU or substitute historical effective-MTU values to make a
graph fit. Off, AES and AES+XOR retain their separate captured policies.

The native bundle gate executes current compiler/lease/restore regressions and
a separate bounded encrypted AWG graph group. Its reference peer is test-only:
it binds loopback and allows only exact declared echo/forward sockets. The
client graph uses the actual packaged native engine, real WG/AWG cryptography,
separate Local/Server client identities and native relay authentication. Tests
preserve documentation-address peers through explicit physical-socket adapters;
they do not relax production peer validation, open a host TUN or edit routes.
Wrong exit keys, mismatched S4 and a wrong relay password must fail, and valid
captured bytes must work again afterward. Those loopback tests do not establish
private deployment, end-user path proof, leak behavior or physical-device
network-transition acceptance.
