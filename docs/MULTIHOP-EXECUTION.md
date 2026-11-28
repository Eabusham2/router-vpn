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

## Measuring the next node in an unfinished route

An unsaved ordered draft can retain its original selected prefix while measuring
eligible next nodes. Local, Server and Compare keep distinct execution owners.
A successful measurement can be adopted only after its original operation has
finished cleanup and the draft, device, inventory and registration are freshly
captured. The next measurement uses that enlarged prefix; saving a complete
profile is not a prerequisite for this interaction.

The private prefix plan has six root fields: `schema`, `purpose`, `entry_node_id`,
`entry`, `members`, and `candidates`. Its current forms are:

| Schema | Retained prefix | Next candidates |
| --- | --- | --- |
| 1 | Paired WG/AWG packet nodes | Literal Shadowsocks 2022 |
| 2 | Paired packet nodes followed by literal Shadowsocks 2022 nodes | Literal Shadowsocks 2022 |
| 3 | Paired WG/AWG packet nodes | WG, AWG2 Fast, or AWG2 Strong in one captured raw mode |

These Server/Compare forms require Start Layer Off and the original literal
transport addresses. Each schema 3 candidate is a `paired` Local capture plus a
`server_peer` object containing its private `bundle` and `profile_id`. Local and
Server use independently captured client keys and a common peer; the transport,
MTU, mode and full source identities remain bound together. An AWG candidate uses
its actual AWG keys, not the separate WG companion profile's keys.

Compile an operator plan with the existing private command:

```sh
router-vpn-agent compile-server-node-chain-prefix-plan < private-plan.json > private-prefix.json
```

The output contains private `source_json` and its public `reference`. Store the
source in the existing privileged prefix registry under its source digest; only
the reference belongs in client discovery. A stale or changed registration
invalidates the measurement.

Each candidate retains the existing fifty fresh authenticated private responses.
Compare also uses fresh private and approved HTTPS observations through the same
original candidate endpoint. Missing proof cannot become a score. Packet keys,
streams and UDP work remain owned until actual cleanup finishes, including late
factory results and cancellation.

Packet NEXT after a retained Shadowsocks hop, HY2 NEXT, proxy-first prefixes and
independent candidate layers remain further implementation work. The current
source forms do not cancel those requirements. Application and native runtime
acceptance must be established for the exact release source; source eligibility
alone is not runtime evidence.

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

## Desktop Tor bridge Server execution

Desktop Windows, macOS and Linux now support an explicit Server selection for
a Tor bridge exit behind a captured private Router entry. The client authenticates
that entry and matches the exact paired bridge/source and selected-DNS hashes
before acquiring a per-client lease. The final native outbound uses its private
authenticated SOCKS front through that same encrypted entry. A Server capture
contains no local Tor executable or PT listener. The same native graph owns the
TUN, IPv6/LAN policy, selected DNS and MTU.

Server readiness is separate from client proof: the client verifies its selected
DNS and Tor public-exit response through its own final path. Cancel immediately
retires application traffic, then retains the exact entry for authenticated lease
deletion. Failed deletion stays pending and can retry without borrowing a
replacement connection. Startup Last, whole-connection profiles and Speed Lab
restore the saved Server selection directly with fresh proof; they do not rerun
Compare. Bridge edits preserve execution and invalidate stale editor captures.

This implementation boundary is the desktop `tor-bridge` path. Mobile Server
host adoption and plain-Tor desktop controls are separate work. Tor Compare still
requires a distinct owned last-node measurement under the formula above; the
dynamic exit-check response cannot be counted twice. Current native packages,
private pairing/deployment and public-circuit/device acceptance require separate
exact-SHA evidence.

## Provisioning a private server Tor source

The same operator command can pair a **Tor** or **Tor bridge** source with the
entry node. This is a separate source reference in `tor_exits`; it does not turn
a Tor circuit into an ordinary exit with a fixed public address or Router node
proof. The native worker owns its child process and private listeners inside
the agent image. Pairing does not bootstrap Tor, create a lease, or change the
server's default route.

Prepare a mode-0600 JSON file in an operator-owned private directory. Its fields
come from the selected client path: the exact exit ID, entry node identity,
bridge selection, DNS policy, and saved Home AdGuard addresses. The authenticated
discovery reference must match the client's source and DNS hashes before it can
acquire that source. A different ID, resolver selection, entry, or bridge list
must be paired deliberately; the client cannot upload a replacement source.

The input shape for a bridge source is:

```json
{
  "schema": 1,
  "id": "saved-tor",
  "entry_node_id": "REPLACE_WITH_THE_EXACT_64_LOWERCASE_HEX_ENTRY_NODE_ID",
  "mode": "tor-bridge",
  "dns": {"mode": "home"},
  "adguard_ipv4": "192.168.50.133",
  "tor_bridge": {
    "transport": "obfs4",
    "bridges": ["REPLACE_WITH_THE_COMPLETE_AUTHORIZED_BRIDGE_LINE"]
  }
}
```

Replace the example addresses and placeholders with the captured selection.
For plain Tor, use `"mode": "tor"` and omit `tor_bridge`. Home DNS requires the
entry's captured private AdGuard address or addresses; it does not substitute a
public resolver. Add `adguard_ipv6` only when it belongs to that same capture.
Explicit Custom DNS uses `mode`, `transport`, `address`, `port`, `server_name`,
and `path` as required by the selected transport. `rescue` is an explicit
selection. Resolve an application Fastest selection to its actual measured
resolver before pairing. The operator command delegates all bridge and DNS
validation and normalization to `mobiletor.NewServerTorPolicy`, the same
compiler used by the running worker; it has no separate Python resolver rules.

If the captured client selection requests outgoing Tor cell cover, include
`"padding": {"enabled": true, "rate_kbps": 192}`. The rate must be an integer
from 32 through 192 kbit/s. An omitted or zero enabled rate canonicalizes to
192; Off preserves a valid saved rate, including zero. Omitting `padding`
preserves the previous source identity, while an explicit Off/dormant choice
remains part of the source hash. The server source and client selection must
compile to the same hash; neither can silently enable, disable or change the
other's cover policy. This covers outgoing Tor link cells, with transport
overhead additional; it is not a promise of bidirectional padding. The worker
requires actual owned native channel counters before opening its application
front. See [the native Tor cover contract](TOR-PADDING.md) for accounting,
proof expiry and shutdown behavior.

First produce an explicit private review plan:

```sh
router-vpn-relay-pair \
  --tor-source /private/selected-tor-source.json \
  --exit-id saved-tor \
  --agent-config /private/stage/router-agent.json \
  --registry /private/stage/multihop-relays.json \
  --tor-sources /private/stage/tor-sources \
  --listen-ip ENTRY_PRIVATE_TUNNEL_IP \
  --dry-run /private/review/tor-pairing-plan.json
```

The dry run reads and snapshots the current private files, stages the complete
candidate registry and its referenced sources, verifies the installed Tor
package, and runs the actual bundled native configuration parser. It writes
only the explicitly named mode-0600 review plan, which contains private source
and registry material. It does not create a lock or publish a source in the
input configuration tree. The plan is for private review; it is not a runtime
registry file. The terminal reports validation status and counts, without
bridge lines, resolver credentials, or registry secrets.

After reviewing it, repeat the command without `--dry-run` to publish into the
chosen staging tree. The command recompiles and validates the current captured
inputs before publication; a stale review does not authorize replacing newer
files. The default source directory is `tor-sources` beside `--registry`.
Production uses `/etc/router-vpn/tor-sources`.

Each source is written as `<canonical source_sha256>.json` with mode 0600 in an
owned mode-0700 directory. A complete immutable source is published before
the registry starts referencing it. Existing ordinary exits, other Tor sources,
and unrelated source files are preserved. Repeating an identical pairing
reuses its exact source file. Updating a selection changes its source reference;
old source files are retained for deliberate operator review and recovery.
If publication fails before the registry changes, cleanup removes only a new
source still owned by that operation. A replacement owner or a registry that
already references it is preserved.

An existing private staging tree can also be checked directly:

```sh
router-vpn-agent check-multihop-registry \
  /private/stage/multihop-relays.json \
  /private/stage/router-agent.json \
  /private/stage/tor-sources
```

This checker includes ordinary, Tor and ordered entries in its validated count. It
rejects missing or changed sources, wrong entry/source/DNS identities, unsafe
private files, an unavailable installed Tor package, or native parser failures.
It does not launch the Tor worker or prove public connectivity. Apply the
reviewed registry and source tree only through the normal exact-SHA image
deployment process, then deliberately restart the agent. Live bootstrap,
selected-path DNS, cancellation, reconnection, and client acceptance remain
separate runtime checks.

## Provisioning an ordered Server path from private bundles

Ordered paths use a separate `node_chains` registry reference. The operator
command accepts a private plan naming the exact entry and suffix members in
traffic order. It resolves complete node bundles through the same typed
compiler as the running native worker. The entry identity comes from
`--agent-config`; neither a client lease nor a file's default selected profile
can replace it.

The supported paired plan has two through eight total nodes: a WG or AWG
Fast/Strong entry, zero through six WG/AWG intermediates, and a paired
Shadowsocks final node. Each paired suffix needs its own independently
provisioned server bundle. That includes the final Shadowsocks node's standard
WG identity asset. Packet peers must have independent canonical public keys
and assigned addresses; copying the device bundle into the server slot is
rejected. The server bundles must retain the same remote node, endpoint,
protocol parameters and selected transport. The original client selections
govern DNS, Start Layers, LAN and IPv6 policy.

For example, this mode-0600 plan selects three paired nodes. Replace the paths
and explicit profile IDs with those in the actual private bundles:

```json
{
  "schema": 1,
  "entry": {
    "bundle_file": "entry-client.json",
    "profile_id": "home-entry",
    "mode": "wg"
  },
  "members": [
    {
      "paired": {
        "bundle_file": "middle-client.json",
        "profile_id": "middle",
        "mode": "awg2-strong"
      },
      "server_peer": {
        "bundle_file": "middle-server.json",
        "profile_id": "middle-server"
      }
    },
    {
      "paired": {
        "bundle_file": "exit-client.json",
        "profile_id": "exit",
        "mode": "shadowsocks"
      },
      "server_peer": {
        "bundle_file": "exit-server.json",
        "profile_id": "exit-server"
      }
    }
  ]
}
```

Paths may be absolute or relative to the plan's directory. Every referenced
file must be an owned mode-0600 regular file without symlinks or hard links.
When a selected node has an explicit DNS bootstrap capture, add
`dns_bootstrap_file` beside its `bundle_file`, `profile_id` and `mode`. That file
contains the original bootstrap JSON; the operator command does not choose a
public resolver. Bundle contents and private capture data are sent to the
agent compiler through stdin, never command-line arguments or terminal output.

Create a private review result before applying the staged configuration:

```sh
router-vpn-relay-pair \
  --node-chain-plan /private/ordered-path.json \
  --agent-config /private/stage/router-agent.json \
  --registry /private/stage/multihop-relays.json \
  --tor-sources /private/stage/tor-sources \
  --node-chain-sources /private/stage/node-chain-sources \
  --listen-ip ENTRY_PRIVATE_TUNNEL_IP \
  --dry-run /private/review/ordered-pairing-plan.json
```

Ordered pairing uses its complete descriptor and source digest, so it does
not accept `--exit-id`, `--bundle-profile` or `--server-peer-profile`. After
review, repeat the same command without `--dry-run` to publish into the chosen
staging tree. This repeats validation against the current inputs. It retains
existing ordinary, Tor and ordered references, with a combined limit of 64.
Distinct selected DNS, Start Layer or source variants keep distinct records;
an identical source reuses its existing immutable file.

The plan metadata is bounded to 64 KiB, each bundle to 32 MiB, an explicit
DNS bootstrap to 16 KiB, and the resolved private compiler input to 40 MiB.
The command snapshots the plan and every referenced file, checks the complete
candidate registry with the actual installed native parser, then rechecks
all captured identities before publishing. A changed input, an equal-byte
replacement inode, a conflicting source digest or a failed check prevents
registry publication. Rollback removes only a newly created source still owned
by that operation; it preserves replacement owners and sources already adopted
by a registry.

For the supported three-node imported variant, the entry is WG/AWG, the
middle is one unlayered Shadowsocks 2022 import with a literal endpoint, and
the final node is paired Shadowsocks. Replace the middle member with:

```json
{"imported": {"capture_file": "original-imported-capture.json"}}
```

The private capture file must contain exactly two strings, `config` and
`capture`, from the original imported-node capture compiler. Keep their exact
contents; an ordinary provider configuration alone lacks the captured policy
and proof identity. A guided client export for that private capture remains
separate unfinished work. Hostname imports and SOCKS middle nodes do not gain
Server execution through this bounded plan format. Existing complete
server sources can alternatively be paired with `--node-chain-source FILE`;
they use the same descriptor validation and publication transaction.

An HTTP CONNECT or HTTPS CONNECT middle uses a **distinct schema-4 plan**.
Set the outer `schema` to `4`, select the original paired WG/AWG entry, and
provide exactly two members: the imported capture above and an independent
paired Shadowsocks final with its separately provisioned server bundle. The
middle must retain its original literal endpoint, authentication, TLS policy
where applicable, public proof and device policy. It has no fabricated Router
node ID or packet key. The final must retain its declared SS2022 UoT-v2 service
and Start Layer Off. The same private-file, byte-bound, identity, staging and
rollback rules apply to this plan.

The agent dispatches schema 4 to the typed CONNECT plan/source compiler.
Rejected CONNECT input cannot fall back to the paired or imported-Shadowsocks
compiler. The installed registry reader and offline native checker use that
same typed policy. The original entry packet identity authenticates the
client lease; the remote CONNECT suffix opens only its captured TCP transport
and does not create an artificial WireGuard lower. Existing schema-1 plans
and schema-1/2 sources retain their own constructors and semantics.

This operator format installs a private suffix policy. Client Server/Compare
support requires the corresponding typed native client owner, authenticated
discovery, original selected-path proofs and platform admission. Pairing
success alone does not enable an unfinished client integration or establish
network acceptance.

To check an existing staging tree containing ordered sources, provide both
source-directory positions, including a private empty Tor directory when no
Tor source is present:

```sh
router-vpn-agent check-multihop-registry \
  /private/stage/multihop-relays.json \
  /private/stage/router-agent.json \
  /private/stage/tor-sources \
  /private/stage/node-chain-sources
```

The registry check parses the original native graph without starting a lease,
listener or tunnel. Successful pairing does not deploy the configuration or
prove device traffic. Apply the reviewed tree through the exact-SHA image
deployment procedure; client Server/Compare admission still requires matching
authenticated discovery, an owned lease and fresh selected-path proofs.

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
families, additional packet/helper graphs and physical acceptance remain
separate unfinished requirements. The next section describes the separately
implemented SS-V2Ray/Split/MAX composite exits.

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


## Desktop SS-V2Ray, Split and MAX composite exits — October 26, 2026

The desktop Router-node graph composes `wg`, `awg2-fast` or `awg2-strong`
entries with captured `ss-v2ray`, `split` and `max` TCP/UDP composite exits.
These three choices follow the prior ten in the Windows, macOS and Linux
catalogs; existing defaults and the separate transport-AUTO candidate search
are unchanged. Complete profiles and Speed Lab preserve each exact exit and
Local / Server / Compare both preference. The comparison still uses the two
required routed response times through each candidate and the same external
endpoint. It does not give a failed candidate a zero score.

The shared compiler extracts the validated transport from the complete node
graph, including its selected DNS, LAN/IPv6 policy, cover and MTU settings.
The six-field composite dispatcher never gains a generic `detour`. Its
independent authenticated TCP and HY2 UDP children both route through the
captured entry. With AES or AES+XOR selected, both instead route through the
one captured exit Start Layer, whose outer route is the entry. TCP credentials,
HY2 credentials and certificate, REALITY/PQ settings and per-node identities
remain separate. Hostname capture freezes both physical lanes from the same
lookup while retaining TLS names, SS-V2Ray plugin host/path and authentication.

Server execution requires the exact composite mode and exit Start Layer in
the entry's paired private registry. It validates the captured local closure,
removes its dispatcher children and exit-layer owner, and installs the
authenticated private lease as the exit. The entry endpoint and its own layer,
selected DNS and bootstrap paths, interface policy and separate entry/exit
proofs remain owned. Temporary Speed Lab restoration retains the already-proved
Local or Server execution and exact captured source rather than starting a new
Compare operation. Missing or changed owners, malformed/extra child routes,
a bypassed lane or a stale source are rejected.

The native package gate has a separate mandatory bounded composite traffic
group. A test-only peer process supplies fresh complete node assets to the
actual desktop capture and Local/Server compilers. The packaged native engine
then transfers TCP and UDP payloads through WG/AWG entries and independently
authenticated SS-V2Ray, Split and MAX lanes. The Server cases execute the real
relay compiler and listener authentication. Exact loopback adapters translate
only the test's captured physical sockets and SOCKS UDP association endpoint;
protocol framing and encryption remain native. Wrong TCP credentials, wrong
UDP credentials and wrong lease passwords must fail. A wrong single-lane
credential must leave the other independent lane working; a wrong lease
password must block both. Restoring the captured credentials must restore
traffic. Peer shutdown joins its owned listeners and asserts traffic
through both real encrypted lanes. The helper is excluded from release assets.

Shared graph tests cover all supported entry and exit Start Layer combinations,
selected policy and MTU retention, full Server closure removal, canonical
child ownership and malformed-graph negatives. The dedicated traffic matrix
uses one WG/AWG entry representative per composite mode with Start Layer Off;
it does not claim every layered live path was exercised. Existing shared
native composite suites separately exercise nested encrypted lane behavior.
Current-SHA native/package results and physical device, off-LAN, leak and
network-transition acceptance remain separate requirements. The `max`
composite addition does not close the distinct complete MAX packet/helper
graph, all Router entry families, ALL, Tor Server/Compare or unrestricted
platform graph parity.


---

<a id="section-android-proxy-entries"></a>

# Android native proxy multihop entries

The paired-node Android builder composes Shadowsocks and Hysteria2 entries with
WireGuard, AmneziaWG Fast/Strong, Shadowsocks and Hysteria2 exits inside the existing
Libbox/VpnService owner. Local, Server and Auto retain the exact captured modes,
independent node proofs and entry/exit private credentials. Unsupported helper,
Tor, PQ and MAX compositions are not claimed by this change.

The selected entry profile is validated by `CompileProxyEntry`. Only an owned
TCP+UDP authenticated native outbound is accepted. Entry TLS trust is inlined
from its own asset before exit files are staged, so identical certificate
filenames across nodes cannot replace either node's trust. Existing proof lanes
1098/1099 remain distinct and follow the selected entry/exit graph.

Proxy entries have no invented packet interface MTU. Fixed entry policy owns the
real shared TUN, and `MultihopMTUProfile` captures that policy for later optimizer
work. Conflicting fixed settings fail before any private session is staged.

Both Android entry pickers, pending permission restoration, active runtime
restoration, and saved/live entry identities recognize the added transports.
No source node bundle is rewritten by graph preparation.

## Reproducible source checks

Run `python3 android/test_android_multihop_graph.py` with Go, JDK 17 and the real
Android JSON implementation (`ANDROID_JSON_JAR`). It executes shipping Java and
shared Go compilers and tests all ten proxy-entry/exit pairs under three execution
choices, credential/trust separation, fixed MTU capture, source immutability and
failure-before-staging. `ROUTERVPN_ANDROID_GRAPH_FIXTURES` optionally exports the
actual prepared and execution graphs with generated test certificates, not live
node credentials, for native parser checks.

Also run saved mode, Java syntax, multihop source and session identity contracts.
These host tests do not prove APK type checking or physical Android network,
permission, lockdown, transition, public-exit or reconnect acceptance. Those gates
remain separately required on the exact release commit.

## Native parser release gate

`deploy/test_android_multihop_pinned.py` consumes the actual Android-generated
session and execution graphs on the immutable prepared Libbox core. It requires
all 30 entry/exit/execution directories, both configurations per directory, and
only the matching exit trust assets. The native test calls `CheckConfig` for
all 60 configurations and also requires rejection after corrupting each native
entry transport type. No VPN is started by this configuration gate.

The Android AAR build runs this gate before binding and validates both proxy
compiler API symbols. Its cache digest includes the shipping Java graph/policy
sources and harness, and Gradle declares those inputs; a cached AAR from an older
host graph cannot substitute for the new configuration evidence. This is native
configuration acceptance, not encrypted-traffic or physical-device acceptance.

The native parser gate accepts an explicit `ANDROID_JSON_JAR` or the installed
Android JSON host package. When neither exists, it fetches only the SHA-256-pinned
Maven artifact into its temporary test directory, validates the archive, and
passes the absolute path to the shipping Java harness. Invalid explicit paths,
checksum failures, oversized downloads and changed origins fail the build. This
test dependency is not packaged into Android and does not change VPN DNS.


---

<a id="section-desktop-imported-router-path"></a>

# Desktop imported entry to paired Router final

Source admission added November 7, 2026. Installed Windows, macOS and Linux
acceptance remains distinct from the compiler, controller and parser evidence
below. The broader original requirement still covers imported nodes in either
hop role; this implementation does not close every imported graph or execution
mode. The shared compiler's wider scope is recorded in
[MOBILE-IMPORTED-ROUTER-PATH.md](MULTIHOP-EXECUTION.md#section-mobile-imported-router-path).

## Daily connection

Select the independently paired Router VPN final as the main node. In the
multihop controls, choose the original imported entry, that same paired final,
Local execution and an admitted final transport. Entry mode can name the
original import protocol, or use the saved selection when it agrees with that
original profile. Windows, macOS and Linux include original imported WireGuard,
AmneziaWG, bounded OpenVPN TCP/UDP, SOCKS5 and HTTP/HTTPS CONNECT in their native entry selectors alongside
the existing Shadowsocks and Hysteria2 choices. Imported packet selections use
the original `wireguard` or `amneziawg` protocol identity, independently of the
paired-node `wg`, `awg2-fast` and `awg2-strong` choices.

The main/profile catalog contains 25 explicit entry choices: the 19 paired
Router transports plus the distinct `wireguard`, `amneziawg`, `socks5`,
`http-connect`, `https-connect` and `openvpn` imports. Full-profile Add/Load/Update and
Connect serialization preserve those original IDs. Saving a choice does not
grant a new execution mode; imported connection admission still requires Local
and the original independent profiles.

Speed Lab's **temporary Router multihop** captures an original imported entry
and independently paired final before suspending the current VPN. Its per-node
choices distinguish the 19 paired transports from the imported node's exact
canonical protocol; imported entries offer Local execution and the bounded
final catalog below. Windows, macOS and Linux preserve a captured main-profile
selection and use the same per-node rules when the entry changes. An unavailable
saved mode stays visible and invalid instead of silently becoming WireGuard.

The temporary graph keeps the complete original entry credentials and applies
requested DNS, packet and protection overrides to the paired final. The actual
compiler and native preflight run before suspension. Startup consumes those
same checked bytes once, validates the original caller, profile revisions,
selected source, network and owned operation, then proves the original public
entry, paired final and selected final DNS. An unstarted launch retires only its
own private workspace and DNS registration. Restoration retains the already
proved original Local/Server choice instead of rerunning Compare.

The existing protection transition guard remains: a previous connection whose
retained native protection owner cannot yet transfer into this multihop runtime
is rejected before suspension. Completing that protected runtime handoff remains
a separate requirement. These source changes do not establish installed-device
networking, physical visual acceptance or every imported graph combination.
Native callback tests consume the real daily and temporary controller catalogs
separately; a generic union catalog cannot grant imported execution authority.

The desktop host admits original WireGuard, AmneziaWG, SOCKS5, Shadowsocks 2022,
Hysteria2, HTTP CONNECT, HTTPS CONNECT and bounded OpenVPN entries. Its final transport catalog is Shadowsocks,
Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong and REALITY/Vision. A
catalog entry alone does not promise that every cross-product can be compiled.
The existing imported-entry compiler validates each original transport,
independent Start Layer, selected final resolver and physical socket graph.

| Captured entry | Baseline desktop graph admission |
|---|---|
| WireGuard, AmneziaWG | All six listed paired final transports, with independently captured entry/final layers and sufficient original packet capacity |
| OpenVPN TCP or UDP | The same six finals, with one original literal remote in a supported inline profile, fresh native connected-state observation, and sufficient actual packet capacity |
| Shadowsocks 2022, Hysteria2 | All six listed paired final transports |
| SOCKS5 | REALITY/Vision; other compiler-supported graphs require an exactly bounded outer socket graph |
| HTTP CONNECT, HTTPS CONNECT | Shadowsocks or REALITY/Vision with the original carrier and selected-DNS capability |

An ordinary SOCKS5 UDP association negotiates a relay address. Desktop physical
ownership cannot grant that changing destination from the original control
socket, so such graphs fail before the current connection is stopped. An
independently provisioned Start Layer can make a graph's outer sockets static;
the same exact physical projection decides admission. No endpoint-wide or
all-port permission is substituted.

For CONNECT to Shadowsocks, the baseline carrier is TCP-only and requires a
compatible selected TCP, DoT or DoH policy. Home AdGuard UDP and other datagram
traffic require the independently paired final's original validated SS UoT-v2
service declaration. A raw imported option cannot grant that capability.
REALITY/Vision uses the paired final's own validated transport. Unsupported DNS
or transport combinations fail without changing the saved resolver. Home
AdGuard remains the default wherever the original graph can carry it.

## Source, proof and ownership

The imported profile and the paired final bundle stay separate. The final's
saved WireGuard identity must match its authenticated NodeProofID before its
selected transport can be captured. Entry protocol credentials, expected public
exit, TLS settings and Start Layer are taken only from the original external
profile. No private Router API token or synthetic Router address is invented for
that entry.

Each node retains its own Off, AES-256-GCM or AES-256-GCM + XOR choice. An entry
layer retains the original same-node public address, its separately provisioned
outer port and credentials, and its validated private inner service. The final
layer retains the final's own asset map. The complete original profiles,
credentials, policies and asset digests are sealed into the captured path.

The compiled graph uses one protected full-device TUN and two reserved loopback
proof lanes. The entry lane proves the original expected public address through
the imported transport. The final lane proves the paired node's private identity
through the complete chain. The selected final DNS configuration and resolver
query must then pass before public Connected state is published. A fresh private
mailbox nonce and monotonically increasing request generation bind that query
to the original session, complete configuration, network path, TUN reader, MTU
and caller deadline. Request and cancellation files become visible atomically
only after their private contents are complete and synced. The retained native Box uses
its selected DNS router with both caches disabled, preserving the original
upstream transport, TLS and bootstrap policy. Its matching result is admitted
only after the request is consumed and the same live TUN reader is observed.
An already cancelled request never enters DNS. Cancellation joins an entered
query and cannot adopt a late successful reply. A long query waits for a fresh
heartbeat from the same reader; a replacement reader or MTU transaction fails.
No OS resolver lookup can substitute for this proof, including when the live
launch disappears but its captured imported identity remains. The temporary
standalone transport seed never supplies DNS to the executable chain.

Preflight runs before draining the previous connection. The existing retained
native-node transaction stages the private graph, applies protection, owns the
child process and keeps its cleanup identity until Stop joins. The launch's
exact outer address, port and protocol tuples reach all three desktop hosts.
Unix helpers require the captured node session and configuration digest plus
the imported-path marker; a missing tuple list cannot fall back to broad
endpoint permissions. Persisted protection retains the same exact tuples.

WireGuard and AmneziaWG remain userspace endpoints inside the same native Box.
The original private key, peer key, preshared key, addresses, AllowedIPs,
keepalive, endpoint MTU and AWG parameters remain attached to the imported
profile. Their physical permission is one original UDP peer tuple, or the
independently provisioned original entry layer's UDP tuple. Neither the final
peer, public proof destination nor DNS server gains a physical bypass.

The original entry's configured packet capacity must contain the complete
selected nested data and control envelopes, including AWG junk and both Start
Layers. A saved 1280-byte entry can therefore reject a nested packet final.
Admission never enlarges that original endpoint MTU. The restored TUN value is
validated with the shared `mobilemtu.NewPlan` contract against the captured
graph; it cannot expand the original packet envelope. This distinguishes the
virtual interface size from captured packet capacity without imposing a new
blanket Jumbo policy.

A cancelled proof, changed original profile, changed paired source or replaced
runtime cannot admit the old result. Failed startup uses the existing owned
teardown. Temporary restoration captures the original graph, independent
profiles, settings and actual owned MTU readback before retiring the old owner;
the restored process receives a fresh runtime directory and session.

Saved connection profiles support Add, Load, Update and Delete for this direction.
Their independently captured imported hop policy must exist on Load. Deleting
the connection profile keeps the original nodes. An explicit Local request can
run a candidate when the saved final has Server or Compare selected, without
rewriting that saved choice; omission of the override is rejected. Server and
Compare requests for ordinary imported entries are rejected before acquiring
network authority.

## Speed Lab entry measurements

An ordinary imported entry has no Router VPN private benchmark API or node
credential. Its independent entry measurement uses the reserved original entry
lane and the existing public HTTPS Speed Lab endpoint. Four response samples
are labeled **Entry-routed HTTP response**; separate 8 MiB download and upload
transfers are labeled **Entry-routed HTTPS transfer**. Mbps comes from consumed
bytes and elapsed time. It is not an ICMP sample, a measurement to the entry
server itself, or an authenticated private-node benchmark.

The original expected public exit is proved before sampling, before transfer
and after load. Caller, live graph and profile ownership are checked around each
phase. Redirects, incorrect byte counts, unread uploads, cancellation, a wrong
public identity or a replacement graph cannot produce a successful transfer.
The paired final still uses its own authenticated private-node lane and
benchmark. Neither side borrows the other's credentials or measurement.

## Evidence and required release checks

The new tests exercise original-source capture, exact physical permissions,
final-owned DNS, private final identity mismatch, credential replacement,
cancellation, complete saved profiles and explicit Local restoration semantics.
The shared physical projection test verifies immutable repeated capture and
rejects the controller after Close. The Unix adapter tests execute its actual
tuple parser and nft rule generator and reject missing, malformed, mixed-owner
or unbounded permissions.

`ROUTERVPN_IMPORTED_DESKTOP_FIXTURES` must identify an existing private output
directory. Failure to emit a requested file is fatal. The fixed inventory is
26 JSON files:

- 12 Shadowsocks/Hysteria2 entry graphs across the six admitted final modes.
- One SOCKS5 to REALITY/Vision graph. SOCKS5 to unwrapped Shadowsocks is a
  required negative verdict and emits no file.
- Four HTTP/HTTPS CONNECT graphs across Shadowsocks and REALITY/Vision.
- Nine independent entry/final layer pairs for Shadowsocks to REALITY/Vision.

The release-selected roots are
`TestDesktopImportedNativeCaptureExactGraphAndPhysicalSockets`,
`TestDesktopImportedExplicitLocalPreservesSavedExecutionAndLayers`, and
`TestDesktopImportedDailyConnectRestoreAndOwnedTeardown`. Their exact verdict
set on Linux contains three root passes, 18 graph leaves, 27 saved-execution/layer
leaves and three lifecycle leaves. Windows and macOS run the 47 graph/layer
verdicts; the retained-process fixture is currently Linux-specific. The lifecycle leaves are `success`, `public-proof`
and `source-replaced`. The saved executions are `local`, `server` and `auto`;
each has all nine independent layer pairs. Missing, skipped, duplicate or foreign
verdicts cannot count as release evidence.

The DNS parent group adds ten exact verdicts: the six
`TestDesktopImportedDNSReceiptAdmission` cases (`success`, `dns-failed`,
`reader`, `source`, `owner`, `old-receipt`) and its root, plus
`TestDesktopImportedDNSCancellationWaitsForNativeJoin` and
`TestDesktopImportedDNSCannotUseSuccessfulOSLookup`, and
`TestDesktopImportedDNSAtomicPublicationAndFreshHeartbeat`. The prepared native
`cmd/sing-box` group adds thirteen: `TestRouterVPNImportedDNSMailbox` and its
ten cases (`success`, `dns-failed`, `session`, `config`, `path`, `reader`,
`deadline`, `replay`, `source-replaced`, `owner-replaced`),
`TestRouterVPNImportedDNSCancellationJoins`, and
`TestRouterVPNImportedDNSNativeRouterIsUncached`. The last test executes the
real Box and DNS router against a real captured TCP resolver, alternating
success, NXDOMAIN and success and counting all three wire queries. Its TUN
readback is an explicit fixture; it does not claim an installed OS tunnel.

The production builder therefore requires exactly 61 host verdicts on Linux
and 57 on Windows/macOS. It checks all 26 emitted graphs with the completed
bundle's actual CLI, comparing the source-owned bundle receipt before and after
the checks. Fresh builds and reused bundles both execute that gate. A separate
matching-host native run executes all 13 DNS verdicts immediately after the
existing native command tests, with the full production tags and the original
verified PQ linker environment. Only Windows ARM64 uses the established
non-race exception. A missing, skipped, failed, duplicate, foreign, reordered or
timed-out verdict prevents successful completion; a root pass cannot replace
its leaf results. Runner regressions exercise these failures, source template
registration and failure propagation before build/reuse success.

### Additional WireGuard and AmneziaWG gate

The packet extension preserves the 26 graph, 57/61 host and 13 native DNS
inventories above. `ROUTERVPN_IMPORTED_DESKTOP_PACKET_FIXTURES` names another
existing private directory for exactly 108 complete desktop graph files:
two original entry protocols, all six paired final transports, and all nine
independent entry/final layer pairs. Missing output or an unwritable requested
destination is fatal. Every graph retains one protected TUN, both original
proof lanes, final-owned Home AdGuard DNS and one bounded outer UDP tuple.

The additional exact host verdict inventory is:

| Test root | Required verdicts, including its root |
|---|---:|
| `TestDesktopImportedPacketGraphs` | 109 |
| `TestDesktopImportedPacketSourceOwnership` | 29 |
| `TestDesktopImportedPacketLimits` | 17 |
| `TestDesktopImportedPacketSelectedDNS` | 7 |
| `TestDesktopImportedPacketProfiles` | 3 |
| `TestDesktopImportedPacketProof` | 11 |
| `TestDesktopImportedPacketDailyConnectRestoreAndOwnedTeardown` (Linux) | 9 |

The source controls replace original keys, addresses, AllowedIPs, keepalive,
endpoint, packet MTU, AWG parameters, expected public exit, paired token, final
DNS and each independent layer. The limits reject cancellation, insufficient
entry capacity, an overflowing fixed MTU, missing layer provisioning,
Server/Compare, a paired entry-mode alias and an OpenVPN label substituted onto
a WireGuard/AWG profile without its original OpenVPN credentials. Home AdGuard, custom DoT
and custom DoH retain the final's original transport, port, TLS name and path.
The profile tests execute Add, Load, Update and Delete for both packet families.
Public entry proof rejects the wrong address, cancellation and owner replacement.

The production builder requires all 176 additional host verdicts on
Windows/macOS or 185 on Linux, with the same mandatory physical-inventory flag
for Linux lifecycle cases. It then executes the completed full-production
CLI against all 108 original graphs. The exact bundle receipt and graph bytes
must remain unchanged. Both new-build and reuse paths run this gate after the
existing 26-graph gate and before successful completion. Runner regressions
reject missing/duplicate/foreign/early verdicts, skips, failures, timeouts,
changed or linked graph files and replaced bundle receipts. Existing shared
native packet peer gates remain independently required; neither a parser pass
nor a fixture-based controller proof substitutes for installed-device traffic.

`ROUTERVPN_REQUIRE_IMPORTED_DESKTOP_LIFECYCLE=1` makes unavailable physical
network inventory fatal. Without that release flag, the lifecycle test explicitly
skips on hosts that deny the required interface inventory. This test retains
the shipping compiler, staging, process/Stop join, private directory, graph
registry and restoration transaction; installed-image and remote-proof
boundaries use the existing retained-runtime fixture seams.

### Additional bounded OpenVPN gate

OpenVPN uses the original inline profile inside the same retained native Box.
This admission requires exactly one literal TCP or UDP remote; scripts,
multiple remotes, hostname remotes, a system OpenVPN interface and incomplete
credentials are rejected. The original user/password bytes, certificate or
fingerprint policy, remote, transport, entry packet capacity, expected public
exit and independent Start Layer stay attached to that entry. No second VPN
service or invented connected receipt is used.

Before authentication, the native owner pins the exact Box endpoint pointer,
configuration digest and application TUN reader. Its first successful native
observation additionally pins the connected remote, native connection generation,
connection timestamp and actual packet capacity. The observation reads the
endpoint's existing authentication/ready state and live packet device; saved
MTU is only the required lower bound. Reconnection, a replaced endpoint or TUN
reader, changed remote/capacity, pending authentication after connection, or an
active/failed MTU transaction invalidates that owner. A later successful read
cannot replace the original tuple. A replacement child receives a fresh owner.

The host uses the existing atomic private mailbox with the explicit
`openvpn-observe` operation. It binds the response to the original process,
source, session, physical network generation, request generation, nonce,
caller deadline and TUN readback. Observation responses cannot substitute for
DNS responses. Cancellation joins an entered operation and does not adopt a
late success or retire a healthy connection solely because the caller stopped
measuring. Entry/final proof, selected DNS, response measurements, Current-path
Speed Lab, asynchronous measurement adoption and restore capture revalidate
the original connected observation. The native loop also checks it around
readiness, at heartbeat boundaries and around the actual selected-DNS query.
The observation cost is excluded from response sample timing.

Periodic native observation uses at most 250 ms and is capped by the last
successful original-tuple observation plus the existing two-second heartbeat
freshness bound. A brief timeout skips heartbeat, mailbox and MTU work and
retries; it does not close a still-fresh healthy child. Only a real successful
read advances freshness. Exceeding that bound or losing the original tuple
fails closed. A completed query must reobserve before another heartbeat can
publish. The portable actual-loop runner passes 15 race verdicts and rejects
five causal mutations, including the old terminal-timeout behavior and stale
publication. This extracted-loop evidence keeps its explicit native/OS fixture
boundaries; the 44 native and 13 DNS production verdicts remain independent.

`ROUTERVPN_IMPORTED_DESKTOP_OPENVPN_FIXTURES` is a separate required output
directory. Exactly 108 files cover TCP/UDP, all six paired final transports and
all nine independent entry/final Start Layer pairs. These graphs retain the
original physical TCP or UDP tuple, one protected application TUN, both proof
lanes and the paired final's selected DNS. The existing 26 proxy graphs and
108 WireGuard/AWG graphs are unchanged.

The separate host inventory has 192 verdicts on Windows/macOS and 196 on Linux:
108 graph children, full-profile round trips, public-proof negatives, exact
selected resolver tests, original-source replacement controls, bounded-admission
negatives, private observation receipt negatives, no-relatch controls, joined
cancellation, context-owned locks and the DNS/observation separation. The Linux
increment retains the actual controller staging, child/Stop join and restoration
fixture with the same mandatory physical-inventory flag. A native IPC fixture
is explicit evidence for the host protocol, not for OpenVPN TLS traffic.

The prepared native command has an additional exact 44-verdict inventory:
constructor (10), original tuple (18), caller context (4), mailbox (8), joined
cancellation (1) and actual TCP/UDP connected observations (3). It runs with
all production tags plus `routervpn_openvpn_remote_test`, requires
`ROUTERVPN_REQUIRE_IMPORTED_OPENVPN_OBSERVATION=1`, and rejects every missing,
skipped, duplicate, foreign, failed or prematurely completed verdict. The
actual connected fixture uses a real mutual-TLS/data peer and selected DNS;
its platform TUN readback and mapped physical tuple remain explicit fixtures.
The unchanged 13 native DNS verdicts run independently first.

Fresh builds and reused complete bundles must then pass the exact host
inventory and the full production CLI's `check -c` for all 108 OpenVPN graphs.
Original bundle receipts and graph bytes must remain unchanged before and
after parsing. Windows ARM64 preserves the existing race-toolchain exception;
every other matching host runs race detection. Gate regressions prove that
missing files/verdicts, symlinks, replacements, skips, errors and timeouts
prevent build/reuse success. Source registration checks bind the observation
implementation and both test templates to the actual native preparer. The
release-candidate source job invokes all three imported runner suites and the
complete heartbeat runner, including its new OpenVPN loop cases.

The November 7 development workspace passed the focused Go race suites, exact
26 graph checks with a freshly prepared pinned native CLI, and the Unix policy
regressions. That supplementary CLI omitted the optional PQ tag because the
workspace lacked the required Rust archive; none of these 26 graphs selects a
PQ mode. The full production native CLI parser remains mandatory in the release
gate. The packet extension also passed all 176 additional non-lifecycle host
verdicts under race detection and all 108 graph checks with that supplementary
CLI, alongside the unchanged 57 baseline non-lifecycle verdicts. Those executions
were on Linux; they do not establish Windows or macOS runtime acceptance.
The lifecycle tests could not run here because netlink interface inventory
was denied. The prepared native DNS mailbox and cancellation race cases passed;
the real Box uncached-query case failed during network-manager startup because
the workspace denied netlink sockets. That native query case remains mandatory
in the production gate. Verified Linux Swift 6.4.2 is available and has executed
the mobile source producers. The extracted desktop Swift profile callbacks also
passed 3,098 behavioral checks including the OpenVPN entry, and all 14 mutation
controls were rejected; their widgets and scheduling remain explicit fixtures.
The macOS SDK/AppKit build and PowerShell remain unavailable locally. Verified
Debian GTK headers, runtime and Xvfb have been extracted, but the executor
refuses Xvfb Unix sockets, so actual GTK execution remains unproved. These are explicit
remaining validation obligations, not successful installed-desktop acceptance.

The OpenVPN host extension also passed the exact combined 425 non-lifecycle
race verdicts (57 original, 176 WireGuard/AWG, 192 OpenVPN), and the supplementary
pinned CLI accepted all 108 newly emitted OpenVPN configurations. This parser
still omits the optional PQ tag and does not establish full-production bundle
acceptance. The native connected TCP/UDP and uncached-DNS cases compile but
remain blocked here by native Box network-manager netlink startup. The exact
native observation and DNS inventories remain mandatory in release builds.

## Remaining product scope

The wider shared OpenVPN compiler supports additional remote arrangements.
Desktop multiple-remote/failover and hostname-remote admission remain outside
this bounded single-remote unit. The later `81626bce` change implements the
captured imported native Auto/Retest/Cancel adapter, authenticated measurements
and rollback; the earlier blanket statement that these public dispatch paths
always reject imported owners is superseded. The
[MTU evidence guide](testing/imported-native-mtu.md) records its bounded host
result and the separate protected Windows integration still requiring repair
and verification. A fixed/captured TUN value, parser pass or that host result
does not prove a live private path measurement.

The `e5875af0` [PQ REALITY extension](testing/imported-pq-reality.md) adds the
seventh paired final to the imported host producers and actual native registry/
protocol gates. Protected public-child startup, source replay and negotiated
SOCKS UDP ownership still need their own complete integration evidence. Other
paired final families, Server/Compare for this direction, and complete graph
parity remain open. Selected-path live proof, retained native lifecycle,
completed-package verification and real installed-device acceptance are required
independently of source or configuration-parser success.


---

<a id="section-mobile-imported-router-path"></a>

# Mobile imported entry to paired Router final

Source scope reconciled November 7, 2026. Current admission,
required executable inventories, earlier observed results, and pending native/device
acceptance are distinguished below. The complete continuation evidence is in
[CONTINUATION-EVIDENCE-2026-11-06.md](https://github.com/Eabusham2/router-vpn/blob/13b7624cda832920ce0b4f647d7552e07f0bf083/docs/AI-DEVELOPMENT-HISTORY.md#note-continuation-evidence-2026-11-06).

## Requirement and implemented direction

The original August 19 map-first request allows Router and imported/custom nodes
in either hop role. The original requirements and later corrections also require
independent Start Layers, complete saved connection profiles, selected-path DNS,
owned temporary tests, and native tunnel integration. Android and iOS/iPadOS
implement the Local compiler and host admission for the following captured
sources. These rows do not by themselves establish native-package or device acceptance:

| Imported entry | Independently paired final transports | Captured graph cases |
|---|---|---:|
| Shadowsocks 2022 or Hysteria2 | Shadowsocks, Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong | 100 |
| WireGuard or AmneziaWG | Shadowsocks or Hysteria2 | 36 |
| WireGuard or AmneziaWG | WireGuard, AmneziaWG Fast or AmneziaWG Strong | 54 |
| SOCKS5 | Shadowsocks, Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong | 45 |
| SOCKS5 | REALITY/Vision, nine independent entry/final Start Layer pairs | 9 |
| Shadowsocks 2022 or Hysteria2 | REALITY/Vision, nine independent entry/final Start Layer pairs per protocol | 18, separate inventory |
| OpenVPN, TCP or UDP outer transport | Shadowsocks, Hysteria2, WireGuard, AmneziaWG Fast, AmneziaWG Strong | 90 |
| HTTP CONNECT or HTTPS CONNECT | Shadowsocks 2022, both Start Layers Off, captured Home/custom literal TCP DNS | 12 |
| HTTP CONNECT or HTTPS CONNECT | REALITY/Vision, nine independent entry/final Start Layer pairs per protocol | 18, separate inventory |
| WireGuard, AmneziaWG, OpenVPN TCP or OpenVPN UDP | REALITY/Vision, nine independent entry/final Start Layer pairs per original transport | 36, separate inventory |

The original-source inventory now contains 346 captured cases: the earlier
247 proxy/packet/SOCKS5/CONNECT cases, 90 OpenVPN cases, and nine separately
bounded SOCKS5 to REALITY/Vision cases. All 338 earlier filenames, including
the REALITY/Vision Off/Off source, are preserved; eight layer pairs are added. The OpenVPN cases retain two original
outer networks, five paired finals and nine independent entry/final layer pairs.
The twelve retained baseline CONNECT cases use two entry protocols, three SS2022
final ciphers and two selected literal TCP DNS policies. Each of the five
non-Xray SOCKS5 finals supports all nine independent entry/final Start Layer
pairs, as does the SOCKS5 REALITY/Vision final. The earlier five pairs with both layers Off, four
SOCKS5-to-SS/Hysteria pairs with only a final layer, six SOCKS5-to-WG/AWG
pairs with only a final layer, and ten pairs with only an entry layer remain
in the matrix. Twenty pairs with both layers enabled extended the published
215-case matrix to 235 before the CONNECT addition. These counts describe
executable configurations, not completed user requirements. The separately
captured configured-CONNECT inventory adds 24 required cases, and the selected
encrypted-DNS inventory adds 44 accepted captures plus four plain-carrier H3
refusals. Those inventories remain separate from the 346 original-source files;
they are not added into a product-completion denominator. Another separate
32-capture CONNECT entry-layer inventory covers two entry protocols, two
enabled entry layers, four final-service/layer states and two DNS policies.
A separate 18-capture SS2022/Hysteria2 to REALITY/Vision inventory retains the
346-file primary matrix and the independent CONNECT inventories unchanged.
It covers two original encrypted entry protocols and nine entry/final Start Layer
pairs for each. Its source and host evidence is recorded at the end of this file.
Another separate 18-capture inventory covers HTTP/HTTPS CONNECT to the paired
REALITY/Vision final. It preserves the original 346 files, the 32 CONNECT-to-SS
entry-layer files and the 18 SS2022/Hysteria2-to-REALITY files without renaming,
replacing or merging their evidence sets.
The CONNECT inventory retains the twelve original CONNECT cases and both existing configured-service
and selected-DNS inventories.

The later Android host correction `95f36b95` is required for the daily Connect,
Home transition, startup and cold reattachment paths to use this capability
consistently. Earlier duplicated protocol lists still rejected SOCKS5 after
the producer and native-peer matrix passed. Those callers and usage now consult
the same captured entry/final capability. The recorded runtime composed with the
Home store passed 35 cases and rejected three old-guard mutations at that
historical checkpoint; later host inventories and results are recorded in the
continuation evidence. Native proof and OS boundaries remain explicit doubles
in that host test. Producer/native
configuration evidence alone did not establish this daily-app admission.

Packet composition validates the complete data, handshake, cookie and enabled
junk envelope, including the final's separately captured Start Layer, before
constructing a native owner.

Execution is Local, inside the application's existing Android VpnService or Apple
PacketTunnel. A Shadowsocks entry supports `2022-blake3-aes-128-gcm`,
`2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`. Hysteria2 preserves
its original server, port, password and verified TLS server name. For the five
non-Xray paired final families reached through non-CONNECT entries, entry and
final retain their separate Off, AES-256-GCM, or AES-256-GCM + XOR whitening
choices. All nine layer combinations for each admitted pair are constructed
from the original sources. Two alternate SS2022 ciphers are retained for each final family.
For SS2022/Hysteria2 entries, each of the five final families has twenty cases:
nine independent layer pairs for SS2022 AES-256 and Hysteria2, plus the two alternate SS2022 entry
ciphers with both layers Off. Thirty-six additional packet-entry cases cover both
packet protocols, both proxy finals and all nine independent layer pairs.
WireGuard and AmneziaWG retain the original endpoint, private key, peer key, PSK,
addresses, AllowedIPs, keepalive and packet MTU. AmneziaWG also retains its exact
obfuscation parameters. The packet endpoint belongs to the same native graph;
this does not start a second system VPN. The Hysteria2 final retains its original TLS
server name, password, certificate trust and Salamander parameters. Its optional
outer AES transport comes from the same final node's original SS asset map,
separate from the inner QUIC transport and the imported entry's own layer.
WireGuard and AmneziaWG finals likewise use their own raw same-node SS assets
when a final Start Layer is selected. Their complete endpoint object retains its
captured keys and all AWG fields. The original requested packet MTU remains in
the captured source; a nested Auto graph may derive a smaller final endpoint
cap before startup, as described below. The paired WG public identity and
the selected AWG transport's independent peer key are not substituted for one
another.

A SOCKS5 entry retains its original server, port, version, username and password.
It uses the paired final's authenticated encrypted transport; SOCKS5 alone is
not presented as an encrypted VPN. An entry Start Layer requires that imported
node's separately provisioned AES transport and exact whitening choice. A final
Start Layer requires the paired final's own original assets. A missing layer
provision, a provision belonging to the other node, or a changed credential
prevents construction. No second system VPN is started.

The additional WireGuard, AmneziaWG, OpenVPN, SOCKS5, Shadowsocks 2022, Hysteria2 and HTTP/HTTPS CONNECT to paired REALITY/Vision
paths are Local and retain all nine independent Off/AES/AES+XOR entry/final
layer choices for each imported protocol. The original
paired-node compiler retains the final's complete VLESS/REALITY source and
validates either its exact unwrapped native transport or its exact owned
`start-layer-aes` detour. It attaches only the final's outermost edge to the
captured imported entry. Each layer retains that node's original transport,
private inner host, key and whitening choice; the imported layer's renamed
closure cannot become the paired final's layer. Entry public-address proof, final authenticated
private-node proof and selected final DNS remain independent. Android and Apple
selection, preparation and restoration retain these same captured sources.
The SS2022 inner transport requires exact 16-byte AES-128 or 32-byte AES-256/
ChaCha20 keys as decoded by the shipping `sing-shadowsocks2` constructor. AES
identity chains retain their original order; ChaCha20 accepts one key. The outer
Start Layer keeps its separate established constructor and source rules.
PQ REALITY, XHTTP, Split, MAX and Server/Compare for this direction remain
outside its implemented admission. Their safe rejection does not close those
requirements.

An OpenVPN entry retains its exact inline profile, ordered public remotes,
original TCP/UDP network, TLS trust, username/password and bounded supported
profile directives. It uses the existing userspace native packet endpoint in the
same graph. System-device mode, scripts and unsupported profile directives remain
refused. An enabled entry layer uses the existing source-validated per-remote
layer map even for one remote; the authenticated receipt continues to name the
original public remote, while only the owned physical transport reaches the
captured private service. The final's independent source and credentials remain
separate. No Router API, response-probe authority or second system VPN is
invented for the imported entry.

A CONNECT entry retains its original proxy address, port and credentials;
HTTPS also retains the original TLS name and trust. The paired SS2022 final
keeps its separate credentials and all three supported ciphers. The imported
entry supports Off or its own separately captured AES-256-GCM or AES-256-GCM +
XOR whitening transport. The original proxy moves only to that entry
provision’s validated private endpoint; the outer layer keeps its original
public endpoint, independent key and codec. The final’s provision and
credentials cannot grant or substitute entry-layer authority.

For a Shadowsocks final without its separately captured service declaration, the composition
remains TCP-only with the final Start Layer Off. It supports compatible selected
TCP, DNS-over-TLS and DNS-over-HTTPS policies, including a hostname only when
its complete captured bootstrap policy can use the same carrier. Default Home
UDP, DoH3 and a UDP-only bootstrap cannot use this plain carrier. Rejection
preserves the saved resolver instead of substituting another transport or service.

With the final's original service declaration validated against its node and
source assets, the compiler derives explicit SS UoT-v2 transport. That bounded
path supports the selected UDP/Home DNS policy and final Off, AES-256-GCM or
AES-256-GCM + XOR whitening, as well as compatible encrypted DNS and captured
bootstrap. A raw inline udp_over_tcp option never grants this authority.
The declaration is configured source evidence, not proof that a live receiver
works. Actual selected-path proof remains required.

Both forms retain the final-owned resolver's transport, address, port, TLS name,
HTTP path and query/bootstrap options. No DNS fallback or public resolver is
invented. Android and Apple host admission, captured preparation and saved state
follow the same capability; unrelated imported directions keep their own bounds.

### CONNECT to REALITY/Vision

HTTP and HTTPS CONNECT can instead carry the paired final's original
REALITY/Vision transport under Local execution. The shared compiler first
validates that final through `NewNodeProfile`, including the exact native Xray
assets, captured flow and optional independent final Start Layer. It then
attaches the final's outermost stream edge to the captured CONNECT entry. The
new `vless-stream` transport capability is derived from that actual final;
neither a CONNECT connection nor an SS UoT service declaration grants it.
An SS service file attached to the REALITY asset map is refused. An independently
validated SS companion for the final's AES layer retains only its existing
layer authority.

All nine entry/final Off, AES-256-GCM and AES-256-GCM + XOR whitening pairs are
captured separately for each CONNECT protocol. Original CONNECT address,
authentication, HTTPS TLS name and trust remain bound to the entry; final
VLESS credentials, REALITY keys, source flow and private-node proof remain
bound to the paired Router. The final VLESS stream carries UDP as well as TCP.
Ordinary `xtls-rprx-vision` retains the pinned engine's UDP-443 refusal. QUIC or
DoH3 on port 443 requires an original final asset provisioned with
`xtls-rprx-vision-udp443`, using the explicit generation option documented in
[REALITY-UDP443.md](NETWORKING-REFERENCE.md#section-reality-udp443). No imported or saved asset is rewritten
to acquire that capability, and neither flow adds a raw or logical mode.

Selected Home/custom DNS, its transport, address, port, TLS name, HTTP path and
literal bootstrap/query options stay on that final path. The constructor
retains LAN/IPv6, MTU and padding policies. Public-address proof for the imported
entry, authenticated private-node proof for the final and selected DNS proof
remain separate prerequisites; cancellation and replacement retain the
captured source owner. Android selection, prepared restoration and the Apple
picker, saved capture, cold restoration and PacketTunnel final-source builder
use this same bounded Local direction.

The additional source captures and mobile-host tests are independent of the
mandatory encrypted CONNECT/REALITY peer and native parser gates. Source
admission does not establish an exact-SHA native release or physical-device
acceptance.

Other imported entry protocols, other paired final transport families, and
Server/Compare for this new direction remain requirements to implement and
verify. Existing supported directions retain their own admission and proof
rules. This document does not mark the complete external-node requirement or
the complete product delivered.

## Open graph requirements

The original Router/imported choice for each hop is still broader than this
implemented Local matrix. These are current source
limitations, not merely missing credentials, live access or physical tests.

| Direction or capability | Current source boundary | Work still required |
|---|---|---|
| Imported HTTP/HTTPS CONNECT → paired Shadowsocks with an entry Start Layer | Local independent entry Off/AES/XOR is admitted from that imported node’s original provision. Final AES/XOR and datagrams still require the final’s validated configured SS UoT-v2 service. Plain TCP/DoT/DoH retains final Off without that declaration. | Complete exact-SHA native release and device acceptance for the captured compositions; extend other graph directions separately. |
| Imported HTTP/HTTPS CONNECT → paired REALITY/Vision | Local capture admits all nine independent layer pairs per protocol and derives VLESS stream authority from the exact paired final. Original plain Vision and explicit UDP-443 flows remain distinct. | Complete the separate exact-source parser and encrypted CONNECT/REALITY peer gates, then exact-SHA packaging and device acceptance. Source admission and the existing CONNECT-to-SS peer do not prove this final. |
| Imported HTTP/HTTPS CONNECT → paired Hysteria2/WG/AWG | Admission still excludes these final modes. The existing configured SS UoT-v2 composition is specific to the paired SS final and does not automatically authorize other finals. | Implement the particular compatible carrier, source ownership and native graph for each final. A successful CONNECT stream or a service declaration for another final is insufficient. |
| Other imported entry protocols and paired final families | The constructor and mobile hosts retain eight entry labels and five general paired final modes, with the additional SOCKS5, SS2022, Hysteria2, HTTP/HTTPS CONNECT, WG/AWG and OpenVPN REALITY/Vision nine-layer matrices. Other Xray families and pairings remain excluded. Bounded OpenVPN Local is implemented; Trojan/VLESS are not ordinary imported catalogue entries. | Implement and validate each particular protocol/source capture, encrypted graph, credential/reference ownership, restoration and native path. Standalone support or these bounded Local REALITY paths do not prove another pairing. |
| Imported entry → paired final with Server or Compare | The constructor requires captured Local execution; both host adapters enforce Local and restoration deliberately does not invent a Compare winner. | Design actual execution and proof authority, measurement/comparison and restore semantics for this direction. An ordinary imported entry has no paired Router API/token; a public-address proof cannot grant server-side authority. |

Any extension of CONNECT→SS must retain the final-selected Home/custom DNS
transport, address, port, TLS name and HTTP path. UDP or DoH3 selection
cannot silently become TCP/DoH or a public resolver just to make the graph work.
The existing `externalUDP`, `externalExitRequiresUDP` and selected-DNS validator
express the carrier's actual transport limits. `importedCONNECTCapture` and
`importedCONNECTDNS` preserve those limits and the complete final-owned DNS
closure through mobile preparation; they do not choose another resolver.

The baseline `node_imported_connect_entry_test.go.tmpl` covers CONNECT to
encrypted SS traffic, final-owned TCP DNS, auth/target/HTTPS trust rejection,
public-entry/private-final proof, UDP refusal without service authority,
unsupported finals, cancellation and restoration. Later configured-service and
encrypted-DNS captures have their own mandatory source and parser inventories.
The new independent-entry groups additionally drive real entry AES/whitening,
HTTP/HTTPS CONNECT and final SS/AES/whitening peers. The configured final uses
the pinned native UoT-v2 receiver for selected UDP DNS while every physical
entry and final carrier remains TCP. The 32 success leaves and 62 rejection or
retirement leaves run in two separately bounded native processes. They retain
wrong-key, wrong-whitening, wrong-private-route, selected-DNS, both proof,
HTTPS trust/name, cancellation and closed-entry-owner witnesses. These are
reference protocol peers; they do not claim mobile TUN, Box DNS-router or device
acceptance.
The existing `node_external_ss_connect_test.go.tmpl` exercises **SS→CONNECT**,
the reverse direction, and cannot certify CONNECT→SS. Actual Android/Swift
capture, pinned native parsing, protocol-peer execution and physical acceptance
remain separate evidence stages.

## Selection and saved state

Android's multihop editor lists eligible imported entries alongside Router
entries. Choosing an imported SS2022, Hysteria2, WireGuard, AmneziaWG, SOCKS5,
HTTP CONNECT, HTTPS CONNECT or OpenVPN entry allows
selection of its paired Router final and an eligible complete transport from
the table above. The picker
compiles each offered choice from captured sources and retains the final-file
digest through selection. A changed entry or final cannot adopt the old choice.
Saving selects that final and the complete Local graph; Connect still
requests permission, starts the native graph, and proves the path.

Apple's multihop editor admits the same imported entry when a paired Router
final is selected. Its final-transport picker requires the selected pair and
that linked final's complete raw transport/Start Layer assets, with Local
execution for this direction. A different saved mode remains visible
as an explicit unsupported placeholder until deliberately changed. Saving
retains both original node references; only one paired final is required for an
imported entry.

Android connection profiles use schema 6 at the existing private store location.
Add, Load, Update, and Delete retain the imported entry's external policy and
the final node's independent Router policy. Credentials remain in their original
node stores. Older schema-five imported-entry/Tor profiles retain their typed
read path. Validation precedes node or preference writes, and selection rollback
does not overwrite a newer selection. Preference publication and rollback
compare the original and intended maps under the actual shared preference
monitor. The same owner covers node selection and the profile mutation interval.
A newer owner prevents an older failure from reverting either source files or
selection; incomplete rollback is reported. Automatic selection during refresh
reads and checks the current selection under that monitor.

Permission, Activity rotation, startup, restore, and node-usage accounting retain
the original typed entry and final references. A matching text ID does not turn
an imported node into a paired node. A changed source, protocol, execution
choice, pending permission owner, or Home generation prevents the old request
from starting or being adopted. Activity recreation compares the exact captured
entry protocol; node usage also checks that original protocol against the proved
Home owner. Startup does not invent a historical Compare
winner for this Local-only direction.

## Compiler and proof ownership

`internal/mobilemultihop/imported_entry.go` composes the actual imported
transport with the paired final transport. The typed constructor accepts the
seven original source inputs, captures their digest, and produces the config,
metadata, and MTU profile together. Metadata or a prebuilt config alone cannot
create an imported-entry proof owner through the legacy constructor.

The imported entry has public-path proof. It never receives a fabricated private
Router API, token, node proof, or entry proof listener. The final retains its
paired private identity and proof lane. Connected requires the imported entry's
expected public address, the final's private identity, the selected DNS policy,
and the original live engine owner. Native peer tests separately check actual
encrypted traffic through proxy and packet entries and SS/Hysteria2 finals,
including a Hysteria2 final behind its actual AES outer transport. They reject wrong
entry credentials, wrong final keys, bypassed final routing, wrong DNS routing,
and wrong final identity. Hysteria2 additionally rejects incorrect SNI and
untrusted certificates using the actual native TLS/QUIC certificate error.
Packet tests add actual WG-to-SS and AWG-to-Hysteria2 encrypted traffic, entry
AES wrapping, and wrong private/public keys, PSK, AWG parameters, entry route,
outer-layer key and public-entry identity. An invalid entry route must fail at
its actual startup boundary with no authority over the original peer or final.
New actual encrypted peers also exercise SS-to-WireGuard, SS-to-AWG Fast,
Hysteria2-to-AWG Strong and a packet final behind its AES outer transport. Their
controls reject incorrect final private/public keys, PSK, AWG parameters, entry
keys and TLS trust, outer-layer keys, routes, selected DNS and private/public
identities. A transport that must authenticate during Start may reject there;
the fixture requires a live original context and no acquired final authority.
Timeouts and cancellation cannot satisfy certificate-refusal assertions.

SOCKS5 peer tests send actual encrypted TCP and UDP traffic through all 45
independent layer combinations. The entry wrapper carries the original SOCKS
control connection and its UDP association. The tests reject wrong entry/final
layer keys, changed whitening, SOCKS authentication downgrade, a foreign relay,
retired control connections, and bypassed final or DNS routing. The previously
published SS/Hysteria and WG/AWG final-layer fault matrices are retained
separately, including their authentication refusals and MTU-sized DNS checks.
Dynamic UDP test peers retain the original
control owner until their workers join; deterministic controls exercise a
retiring worker, concurrent root cleanup, a replacement owner and foreign or
closed associations. This peer evidence is separate from physical VpnService
or PacketTunnel routing.

Nested packet tests add seven successful encrypted paths, including WG-to-WG,
AWG Fast-to-WG, AWG Strong-to-AWG, independent entry/final layers, both layers,
and an IPv6 carrier. Fourteen negative cases reject changed private/public keys,
PSKs, AWG parameters, layer keys, final/DNS routes and proof identities. The
independent decrypted peers observe full-size IPv4/IPv6 payloads and reject
fragmentation; a UDP socket being bound is not sufficient evidence. Closing the
captured graph joins its workers and prevents a late dial from reusing them.

Application DNS comes from the final's captured policy, including Home AdGuard.
The imported source's standalone DNS configuration remains part of its original
source digest, but it does not replace the final's DNS in this two-hop graph.
An internal transport-validation projection is discarded; it is not the running
DNS config. LAN and IPv6 choices are reconciled from both original policies.
The stronger required protection applies to the one native tunnel.

Legacy paired profiles may omit `node_kind` or contain an empty string. Only
that discriminator is normalized for compilation. The original bytes remain in
the source digest, and the final still needs its paired proof and API authority.
Explicit null, nonstring, or external final kinds are rejected.

Android captures the explicitly selected Local execution in a copied final
profile. A stored Server/Compare preference from an imported node bundle cannot
override that new graph choice. The complete original bundle and its source
digest still govern preparation and restoration; selecting Local does not
rewrite that bundle or grant Server execution to this direction.

## Measurements, MTU, cancellation, and restoration

Typed hop and MTU factories require the same successful native controller and
core instance. The public entry and private final retain different measurement
kinds. The hop adapter maps its public entry role only to the captured native
entry outbound; it does not relax general hop validation. Network changes,
owner replacement, or retirement revoke those factories and their retained
operations.

OpenVPN path authority captures the exact authenticated public remote,
generation, connection timestamp and negotiated native PortMTU. The initial
capacity must satisfy the complete compiled entry envelope. Any subsequent
receipt or MTU change, including an increase, revokes the old proof and its
measurement factories; revalidation captures a new owner. A cancelled measurement
cannot publish a result and does not by itself retire an otherwise unchanged
path. Native receipt/capacity, public/private proof and selected DNS observations,
plus the imported hop engine's `IdentityContext` and `Dial` methods, retain the
actual caller context through instance, selector and outbound readback.
Contextless native identity queries use the existing 1,500 ms observation bound.
A connection returned after cancellation or original owner replacement is closed
before the operation returns; it cannot be handed to a replacement owner. Startup
publishes its cancellation owner before observing native identity and joins that
read on Close. The shared `hopmeasure.Service` now uses an available
`IdentityContext` capability throughout its original operation and never queries
native identity while holding its admission/status lock. It registers cancellation
before identity or activity acquisition; a rejected start preserves the previous
completed result and drains any returned activity release before returning. Late
status observations cannot invalidate a replacement request or cancellation, and
an expired final observation cannot publish a 50-sample result. The existing
90-second complete request budget includes admission; the five-second drain
allowance is unchanged. Context-capable activity owners can retain that same
caller through `BeginMeasurementContext`; legacy engines and activity callbacks
keep their compatibility behavior and are not claimed to be interruptible.
The paired and imported native hop factories now carry their original 1,500 ms
constructor context through native instance/selector capture, controller health
and the shared `NewContext` constructor. The imported constructor rechecks its
proved original controller after the final identity callback and closes an
unpublished service if that owner changed. Canceling the completed constructor
does not cancel the returned service's independently owned later measurements.
The exported mobile binding signatures and the shared contextless compatibility
wrapper are unchanged. Exact caller and replacement controls run against the
shared source and the pinned native instance/selector mutexes; successful network
proof is an explicit fixture model, not physical tunnel acceptance.
The ordinary MTU adapter retains its separate context-bound readback and rollback
contract. The ordinary external hop factory now carries its own captured proof,
native-instance and operation contexts through the separate authority path
described in [SPEED-LAB.md](SPEED-LAB.md). Ordinary proof construction now retains
its own bounded native capture and independent returned request lifetime.
The ordinary external mobile DNS constructor now retains its original caller
through proof/source/selected-resolver capture and final native publication,
without tying later DNS operations to the constructor's timeout. Ordinary mobile
DNS admission, watcher/status reads, activity and query/dial callbacks now retain
their own operation contexts and joined socket/scope ownership. Ordinary
external proof execution now retains its original operation through native
admission, original-graph comparison capture, connected OpenVPN observation,
entry/DNS/exit proof and final native delivery. Proof and comparison admission
mutexes obey cancellation, and a completed proof retains the VPN lifetime
after its operation ends. Trial and final selection now pass that same caller
to the captured native selector, including the paired mobile adapter. External
engines without this mutation capability are refused. Native selector and
interruption admission waits are cancellable, and history admission is checked
before mutation. The original cache write, exact connection interruption filter
and history notification remain in one synchronously joined commit, shared with
the legacy selector API. Cancellation cannot publish a score for a cancelled
trial or a successful retained path after final activation expires.

An already-entered native cache write, connection `Close`, or later history
notification is not interruptible. It must finish before selection returns,
including cancellation while a real bbolt writer is held. This is a cancellable
admission and joined-commit contract, not a hard deadline for native side effects.
No detached selection worker can mutate a replacement after return. History is
not locked across `Close`, because a close callback can itself update history.
The mandatory gate adds 12 shared selection verdicts, two native paired-adapter
held-read verdicts and 27 actual Box/selector verdicts, retaining the existing
context suites and rejection of missing, duplicate, foreign or skipped tests.
These fixtures use real managers, selectors, cache persistence and interruption;
their modeled connections do not establish physical VPN acceptance.

Desktop legacy boolean measurement callbacks, plus Tor resident/padding/Server
proof and lease observations remain separate context-propagation requirements.

The complete compiled graph supplies the MTU plan. For a nested packet final,
`internal/awgpolicy` accounts for the actual IPv4/IPv6 carrier, 16-byte transport
padding, AWG data/control parameters and the selected authenticated outer layer.
The entry endpoint keeps its original MTU. Auto derives a fitting final endpoint
cap; Fixed must fit unchanged. Oversized control packets are rejected even when
data would fit. Metadata records the original request, effective endpoint cap,
data overhead and largest control envelope as **configured-unmeasured**.
Those values are configuration bounds, not a measured physical path MTU.

Fixed-value conflicts are
validated, and compatible Jumbo is virtual TUN capacity, not a claim of a
9,000-byte physical path. The existing Auto/Retest/Cancel transaction retains
its original native interface and proof owner. No cached measurement becomes
fresh proof merely because a source compiles. The already-compiled packet
endpoint and its cap remain unchanged when the application TUN is retuned. Packet-entry
and packet-final graph tests verify that application TUN retuning preserves each
complete captured packet endpoint; the new final tests use a 1392 target. This is configuration/lifecycle evidence;
it is not proof that a particular physical path carries 1400-byte or Jumbo
payloads. Effective/interface readback and authenticated path measurements keep
their separate ownership and validation requirements.

Android stages original sources in its private session directory and recreates
the typed native owner from those sources before launch. Config, metadata, and
source digest must match the recreated owner. Its session label must also match
the recreated final transport; a different final label cannot adopt the plan. A cancelled preparation retains
ownership of its exact directory until cleanup is proved. Failed cleanup remains
reachable through Disconnect and blocks replacement startup. The service closes
an unadopted typed preparation and retains its usual native teardown rules after
adoption.

Both hosts restore the same captured Local direction and source identities.
Neither substitutes a paired entry for an import nor reruns an unrelated
Compare selection during restoration. Ordinary `wireguard` and `amneziawg` entry
labels remain distinct from the paired raw-mode catalogue. Home state, startup,
permission recreation and live usage retain those original protocol identities.
Android's stored `http`/`https` labels are canonicalized through its existing
external-policy mapping into the captured `http-connect`/`https-connect`
identities. Saved profiles, startup and Home retain the same canonical identity;
changing it cannot adopt an older proof. The CONNECT Retest witnesses use the
actual MTU controller and retained native outbound for refusal, cancellation
and successor retention, with the OS TUN capture/apply boundary modeled. They
do not establish measured PMTU through a TCP-only entry.

The pinned native WG/AWG stack drains an admitted packet delivery before entering
gVisor teardown. Late writes and attaches cannot revive the retired dispatcher.
A deterministic native race test covers the actual stack and rejects both lost
delivery retention and draining under the stack lock. This correction is shared
by Android and Apple runtime preparation.

The original AmneziaWG bind also checks its captured generation, connection and
context before and after receiving. A retired native UDP error becomes
`net.ErrClosed`, so the upstream receive worker exits promptly. A late successful
read cannot publish a packet into a successor. The lifecycle regression covers
both native close errors and late success, using the actual bind implementation.

OpenVPN native peer fixtures execute all 90 TCP/UDP, final and independent-layer
combinations with actual TLS/authenticated entry traffic, paired private proof
and final-owned UDP DNS. Three additional real TCP failovers retain ordered
first-remote refusal and successful original-public-remote receipt through Off,
AES and XOR entry layers. Fourteen negative cases require observed native
password, independent layer authentication/whitening or private-route refusal,
with no authenticated receipt or decrypted final traffic; a timeout is failure.
Foreign public host/port, private identity substitution and network changes are
also rejected by the actual layer mapper before physical dialing. These are
userspace encrypted-protocol and ownership results, not operating-system
interface or physical-policy acceptance.

## Executable gates and evidence limits

The shared compiler/runtime race tests cover the independent
layer matrix, all three SS2022 entry ciphers, Hysteria2 TLS/password capture,
WG/AWG endpoint capture, policy and source ownership,
strict paired-final admission,
public-entry/private-final/DNS proof, full Run-to-Healthy measurement ownership,
retirement, and malformed or forged source rejection.

`deploy/test_mobile_imported_entry.py` now requires exactly 346 shared original
source fixtures and 346 from the actual Android helper. Configured CONNECT and
selected encrypted DNS are retained in their separate required directories.
Independent CONNECT entry layers add 32 original source receipts and 32 actual
Android receipts in their own mandatory directories, each with its own
33-verdict native parser group. The pinned
libbox constructor must reproduce their original config and source digest.
Its actual native parser, MTU profile reader, and MTU planner must accept them.
The required fixture gate rejects missing, skipped, duplicated, foreign, or
malformed cases. The Linux native peer gate executes actual encrypted pairs
across the implemented entry and final families, including the complete SOCKS5
layer matrix and Hysteria2 finals behind their actual AES transport. Every
group and negative case in the runner's explicit inventory must execute and
pass once. The expanded groups run separately under the unchanged finite
native-test deadlines. All 346 original-source graphs retain the primary native-parser and typed-MTU
requirements. The new SOCKS5/REALITY file additionally requires its focused
native-parser root in the existing non-peer invocation. With the configured
CONNECT, selected-DNS and independent-entry-layer groups, the default non-peer
inventory retains every prior verdict and adds the 33 new CONNECT layer
verdicts; the Android source groups remain additional. These are required
inventories, not a statement that the new current-SHA invocations have passed. This does not claim physical mobile
TUN traffic for every layer combination. Removing the final outer-edge ownership or bypassing actual
native TLS verification is rejected by the corresponding causal controls.
Dropping the captured packet endpoint or bypassing the final detour also fails
at its intended native witness. Additional compiler controls reject lost endpoint
discovery, overwriting an inner final detour, and an outer Start Layer from a
foreign node. Prepared native source retains the complete mobilemtu/mtuprobe
import closure; copied test imports must compile in the actual pinned module.

`deploy/test_mobile_imported_proxy_xray.py --native-parsers --android` adds
separate SS2022/Hysteria2-to-REALITY source inventories. It requires all 161
shared race-test verdicts, exactly 18 original shared source receipts and
exactly 18 actual Android receipts. Each origin has its own 19-verdict pinned
Libbox parser group, including the parent. The Android transports run in two
separate owned export directories under their existing 240-second process
bounds; a strict duplicate-free merge must retain the complete 18-file union.
The original 346-file and CONNECT inventories cannot satisfy these groups.
Before and after execution, the gate verifies captured bytes, the prepared
mobile source and the production Xray module version and prepared source.

Android gates exercise the actual helper, saved-profile store, permission
controller, startup policy, multihop runtime, MTU session, node-usage recorder,
and service composition with explicit OS/native boundaries. Deliberate source
mutations must fail the intended assertions. The mandatory imported-profile
dispatcher includes the three added nested final families as well as the six
existing families. Original preference, forward-apply and rollback ownership
retain their 57 focused checks and seven causal controls. The Java syntax gate
covers every shipping Java source; the actual SDK/AAR APK build remains separately
required.

`deploy/test_ios_imported_router_pinned.py` is mandatory in Apple smoke and
release preparation. It now requires the actual Swift-produced 346-graph matrix
and all 347 exact native verdicts, including the parent. A separate Swift
producer invocation exports exactly 32 independent CONNECT entry-layer graphs
and a separate pinned parser invocation requires all 33 corresponding
verdicts. A third producer invocation exports the 18 SS2022/Hysteria2 REALITY
graphs, with a separate 19-verdict pinned parser group. None of these groups
can satisfy or replace another. The new full pinned
invocation remains required even when a Swift-only producer or host fixture passes. Swift harnesses cover
selection, profiles, restoration, typed MTU, and PacketTunnel composition.
The local Swift 6.4.2 harness executes actual selection, save and graph-building
source. This is separate from the required Xcode app/PacketTunnel build, native
Apple networking and physical-device acceptance.

The new `deploy/test_mobile_imported_socks_xray.py --reference-only` stage
retains twelve real SOCKS5/REALITY Off/Off reference leaves plus their parent.
It additionally requires all eight new layer-pair parents and 42 real
independent-layer success, wrong-key/whitening and cancellation/close leaves.
Those 51 new verdicts execute in a separately bounded invocation of the same
source-verified native test binary; the original thirteen verdicts remain
mandatory. It drives
actual authenticated SOCKS5 and Xray REALITY/Vision outbounds, selected UDP Home
DNS, distinct entry/final proofs, credential/route/identity rejection and owned
cancellation/teardown. Its desktop source closure is separate from the mandatory
mobile parser, and its receipt explicitly records `native_parser: false`.
The earlier Off/Off runner regressions, pinned parser and reference were
source-reviewed but unexecuted when published in fc261fd0. Current execution
evidence must name the tested source identity. Passing this reference still does
not prove Box DNS-router integration, the shipping host proof adapter, OS TUN
behavior, a mobile Connected result or device acceptance.

The separate `deploy/test_mobile_imported_proxy_xray.py --reference-only`
stage retains all 18 SS2022/Hysteria2 REALITY layer pairs. Its exact encrypted
peer inventory contains 114 leaves, or 139 named verdicts including the
transport/method parents and the physical UDP ownership regression. The
reference uses actual SS2022 or Hysteria2 entry peers and the captured paired
REALITY/Vision final, selected Home DNS, separate public-entry/private-final
proofs and TCP/UDP traffic. It rejects incorrect entry credentials, Hysteria2
SNI/trust, final credentials/routes/identity, and independent layer keys or
whitening. Cancellation and close must retire the original graph without
closing a replacement owner. The Hysteria2 retirement witness counts decrypted
entry streams as well as physical dials, since a live QUIC association can
otherwise carry another stream without a new physical socket. This stage runs
in the Linux native build and the independent hosted reference workflow; it
retains the existing native interface guard and finite test deadlines. Its
required inventory is separate from evidence that an invocation passed.

The independent CONNECT entry-layer increment was exercised locally with 184
exact shared CONNECT race verdicts, including all 32 new captures and ten new
source-authority refusals. The actual Android producer passed 3,072 checks for
those 32 captures and 1,162 checks for the twelve retained CONNECT captures;
its five existing causal controls still rejected the intended regressions.
The complete Android producer exceeded its old aggregate 240-second wrapper
before reaching the new layer cases. The repaired gate runs six disjoint phase
groups, each retaining that 240-second process bound and every original
180-second phase bound. Each group still runs all five causal recompilations.
Fresh group exports must match their exact expected subsets before a
non-overlapping union can reach the native parser. The actual six-group run
completed in 586.005 seconds at the isolated `9b94d010` continuation base,
retaining all 338 original source files and the separate 32 new files, with
all 30 causal recompilations rejected at their intended assertions. The existing
1200-second aggregate imported gate remains unchanged. The separately published
eight REALITY layer captures must remain in the 346-file primary inventory
when this increment is integrated; this historical local run does not replace
that newer inventory.
The actual Swift producer passed 769 checks for the 32 new captures. Whole
Swift graphs and Android receipt configurations agreed for all 32 cases.
A fresh exact-pinned mobile composition then passed all 99 required Libbox
verdicts for the shared, Android and Swift 32-file groups and their parents.
The shared and Android constructors reproduced the original seven-source
SHA/config and retained native parser, typed-MTU and unproved-owner checks.
Both mobile and peer prepared sources passed the exact shipping-source audit.
The pinned native encrypted peer binary then passed all 51 original CONNECT
verdicts, 62 HTTP-layer verdicts and 66 HTTPS-layer verdicts under the race
detector. The two new groups include 32 success leaves and 62 rejection or
retirement leaves. These observed peer results do not substitute for exact-SHA
native application builds, publication, private deployment or physical-device
acceptance.

The following CONNECT results are historical evidence with explicit source
cutoffs. They do not certify later configured UoT, selected encrypted DNS or
SOCKS5/REALITY additions. The complete encrypted
peer run passed 976 mandatory verdicts (the previous 925 plus 51 new ones) on
the `bc6cffef`-based snapshot, before the additional explicit UoT-field refusal
and later Compare-progress merge. The Swift producer passed 5,568 checks and
the pinned Apple parser passed 248 verdicts before those two changes. The
Android/shared 496-verdict parser run used the `d847152e`-based source, including
the UoT refusal and corrected runtime capability. After the progress merge,
the focused shared race run passed 457 imported-entry verdicts and 12 Compare
progress verdicts. All twelve complete CONNECT source/capture/config arrays
remained byte-identical to the full encrypted run. Existing HY fixtures
regenerate certificates, so the complete 247-source arrays are not claimed
byte-identical. Final actual host fixtures additionally passed 2,481 Swift
selection checks, 110 CONNECT profile checks, and the Android runtime/Home
checks with the original and canonical-admission causal controls retained.
After preserving the concurrent `9e0341f0` baseline, the actual Android startup
deadline fixture passed 3,785 checks across 1,089 cases and all three premature
deadline/dependency mutations, including delayed native readiness and ordinary
timeout teardown.
These results do not claim that the entire encrypted suite was rerun on the
final published commit; exact-SHA integrated CI remains a separate gate.

Exact-SHA Android/iOS builds, release publication, physical-device routing,
permission and network transitions, leaks, off-LAN interoperability, visual
acceptance, and Apple signing/distribution are distinct evidence stages. No
private deployment or physical-device acceptance is established by these local
tests.

### November 7 independent SOCKS5/REALITY layers

This increment adds the eight missing Local layer pairs while retaining the
original 338 graph names and the original REALITY Off/Off source bytes. The
shared compiler and Android/Apple hosts require each selected layer's own
original provision. They keep other Xray finals, other imported protocols to
REALITY, and Server/Compare outside this increment's admission.

Local verification completed on the feature source:

- All 88 exact SOCKS5/REALITY shared test verdicts passed under Go 1.26.3 race
  instrumentation. The wider imported-entry and Xray Start Layer race tests
  passed. Three source mutations were rejected at their intended witnesses:
  removal of the original admission, bypass of the final's authenticated layer,
  and omission of the independent imported-entry proof.
- The actual Android helper and shared compiler passed 948 checks for the nine
  REALITY layer captures; all five retained source/cleanup causal controls were
  rejected. This used actual Java compilation with release 17 API symbols and
  the Android JSON implementation; OS/VPN service boundaries remain doubles.
- The actual Swift/shared compiler producer exported 346 graphs with 7,200
  checks. The shipping selection/save/capture fixture passed its original
  3,231 checks plus 112 REALITY checks. Existing configured CONNECT and selected
  DNS checks passed. The exact file comparison retained all 338 old names and
  added exactly eight; no device or native traffic proof is inferred from it.
- The pinned native Xray executable and race-instrumented native reference test
  image compiled, and their complete prepared source identity checks passed.
  Local peer execution stopped before traffic: all twelve original Off/Off
  cases failed in the existing interface inventory with
  `route ip+net: netlinkrib: operation not permitted`. The interface guard is
  unchanged. The original thirteen and new 51 native verdicts remain mandatory
  in CI; neither the new layer traffic nor physical mobile acceptance is claimed
  from this locally blocked execution.


### November 7 SS2022/Hysteria2 to REALITY source and host checkpoint

This increment adds Local imported Shadowsocks 2022 and Hysteria2 entries to a
separately paired REALITY/Vision final. Both original imported protocols execute
inside the existing single VPN owner. The shared compiler retains their original
credentials, physical transport, TLS identity where applicable, and independently
provisioned entry Start Layer. It attaches the final's outermost validated edge
without replacing its original Xray assets or its separate final Start Layer.

The 18 source receipts are exported through
`ROUTERVPN_IMPORTED_PROXY_XRAY_FIXTURES`. The actual Android and Apple producers
use `ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES` and
`ROUTERVPN_APPLE_IMPORTED_PROXY_XRAY_FIXTURES`. Names are
`<shadowsocks|hysteria2>--reality-vision--<entry-layer>--<final-layer>.json`, using
`off`, `aes-256-gcm` and `aes-256-gcm+xor-whitening`. They are separate from the
346 primary captures and the 32 CONNECT entry-layer captures.

Local verification on the source/host checkpoint:

- Go 1.26.3 race execution passed 161 exact new verdicts and all 88 existing
  SOCKS5/REALITY verdicts. The tests cover all 18 graphs, all three SS2022
  methods, exact short/long/malformed-key refusals, AES identity-chain retention,
  ChaCha chain refusal, original source bytes, selected plain/encrypted DNS and
  captured hostname bootstrap, independent entry/final proofs, cancellation,
  replacement ownership and teardown. These controller proof tests model native
  handles; they are not encrypted native peer evidence.
- The actual Android producer passed 2,022 new checks for all 18 sources,
  alongside the retained 948 checks for all nine SOCKS5/REALITY sources. All
  five existing source/cleanup causal recompilations failed at their required
  witnesses. The combined invocation completed in 59.905 seconds under its
  unchanged 240-second process bound, with unchanged 180-second phase bounds.
- Swift 6.4.2 with the actual shared Go compiler passed 606 checks and exported
  all 18 new graphs in 41.294 seconds. All 18 complete graph objects match the
  corresponding actual Android graphs. The original Swift producer still
  exported exactly 346 graphs and passed 7,218 checks in 49.056 seconds.
- The actual Swift selection/save/capture fixture retained its 3,231 baseline
  checks and 112 SOCKS5/REALITY checks, and passed 112 additional checks for each
  SS2022 and Hysteria2 entry. All nine independent layer pairs pass through the
  real picker, saved selection, cold source capture and original asset/key
  fingerprints. Existing configured CONNECT checks and selected DNS cases also
  pass. The portable cryptographic helper performs real SHA-256; OS storage and
  native-readiness boundaries remain explicit doubles.

Android daily selection, saved-profile loading, Connect, Startup Last and
restoration return through the same original-source checks and shared compiler.
Apple's captured `IOSMultihopExecution.Source` and PacketTunnel imported-entry
startup validate the separate imported entry, paired final, requested/restored
Local choice and both original asset maps before starting the shared native plan.
The SS/Hysteria raw mode names also represent paired profiles, so their global
selector is not incorrectly restricted; the captured imported source enforces
this direction's Local-only boundary.

The coordinated native fixture and build-gate integration was then checked on
fresh pinned sources:

- The actual Swift producer and pinned Libbox parser passed all three separate
  inventories: 346 primary graphs with 347 exact verdicts, 32 CONNECT layer
  graphs with 33 verdicts, and 18 SS2022/Hysteria2 REALITY graphs with 19 verdicts.
  The native parser accepted the actual Swift graph bytes, rather than a
  reconstructed copy of their expected configuration.
- The new shared/Android gate passed all 161 shared race verdicts. Each of its
  two separately owned Android phases passed 1,011 checks, exported exactly
  nine captures, and rejected all five existing causal source mutations. Its
  first Libbox attempt unnecessarily added race instrumentation to the pure
  parser command and reached the unchanged 600-second subprocess bound before
  emitting verdicts. Matching the established native parser flags then passed
  all 38 exact shared/Android verdicts in 0.447 seconds of package execution.
  The complete 18+18 captured files and repository/prepared source receipts
  remained unchanged before and after that run. Shared lifecycle and encrypted
  reference tests retain race instrumentation; no execution bound was raised.
- The final 11 runner contracts passed. They include the two owned Android
  export phases, exact parser flags/verdicts and the lifetime of the caller's
  checksum-pinned fallback JSON JAR. Both imported producer gates now finish
  inside that JAR's original temporary workspace. Restoring the old placement
  is rejected after success, first-child failure and second-child failure;
  normal cleanup is required in all three paths.
- The complete desktop native peer package compiled. Its actual connected-UDP
  ownership and replacement-owner regression passed with race instrumentation
  in 1.099 seconds. A positive SS2022 case and a positive Hysteria2 case each
  stopped before encrypted traffic at the retained Netlink interface inventory
  with `operation not permitted`. The original guard remains
  unchanged. These local results do not establish the new 114 encrypted peer
  leaves; the complete hosted inventory remains mandatory.

The parser compilation limit and native interface guard were not relaxed.
Those local results were followed by the successful hosted reference
[run 42329514042](https://github.com/Eabusham2/router-vpn/actions/runs/42329514042)
at `46d28632e2352fbc43997442470ba194a5c5ce4f`: all 139 named SS2022/Hysteria2
verdicts, including the 114 encrypted leaves, passed, and the original 64 named
SOCKS verdicts were retained. That exact-source hosted result closes the
encrypted-reference gap for that increment. It does not establish the new
CONNECT-to-REALITY composition or a later changed Xray runtime. Source/host,
native parsers, actual encrypted references and physical socket ownership
remain distinct evidence. None establishes exact-SHA packages, a release,
private deployment, OS tunnel behavior or physical mobile acceptance.

### CONNECT to REALITY source and mobile-host evidence

The November 7 source increment was checked with Go 1.26.3, JDK 21.0.13
compiling the existing Java 17 target, and the portable Swift 6.4.2 toolchain.
It retains the existing 20 raw profiles and 16 logical mode choices.

- The focused shared race suite passed all 172 new named verdicts and all 433
  retained CONNECT, SOCKS/REALITY and SS2022/Hysteria2/REALITY verdicts. There
  were no duplicate, skipped or failed verdicts. The new roots cover the 18
  source captures, selected policies, original Vision flows, hostname bootstrap,
  independent service/layer authority, malformed source refusals, independent
  entry/final/DNS proof and cancellation/replacement ownership. The original
  scope test retains its named cases: HTTP/HTTPS CONNECT now requires the
  captured `vless-stream` capability; unrelated entry and final families remain
  refused.
- Each actual Android CONNECT-to-REALITY phase exported its nine original
  source receipts and passed 1,184 checks. Both invocations rejected all five
  existing causal source mutations. The same final source also retained the
  twelve original CONNECT-to-SS exports and their 1,162 checks. All invocations
  stayed within the unchanged 240-second aggregate bound; no child limit or
  case was removed. The new host checks include 36 selected DNS/flow cases
  across both protocols, exact hostname bootstrap/query capture, prepared
  restoration, explicit UDP-443 assets and rejection of forged SS transport
  capability.
- The actual Swift producer exported the 18 separate CONNECT-to-REALITY graphs
  and passed 943 checks through the shipping builders, public runtime selector
  and real shared Go compiler. Its 36 selected DNS/flow cases retain explicit
  `dot`, `doh` and `doh3` choices, exact original flow assets and complete
  bootstrap/query policy. Changing the captured bootstrap cannot restore the
  previous Local startup choice.
- The separate Swift picker/save/cold-capture fixture retained its 3,231-check
  baseline and the original SOCKS, Shadowsocks and Hysteria REALITY groups. Both
  new CONNECT protocol groups passed 112 checks each, including all nine
  independent layer selections, source replacement and transactional refusal.
  The prior 24 configured CONNECT combinations/336 checks and 44 accepted
  selected-DNS captures/four plain-carrier H3 refusals also passed. Its storage
  and native-readiness boundaries remain explicit fixture doubles.
- All 28 existing imported-source runner contracts passed after the new
  separate Android phase and export names were added. Original primary,
  CONNECT-to-SS layer and SS2022/Hysteria2-to-REALITY inventories remain
  separate; none can satisfy a missing CONNECT-to-REALITY graph.

These are source, ownership and mobile-host results. The added exact-source
native parser and actual encrypted CONNECT/REALITY reference stages remain
required before claiming that native increment verified. They do not establish
OS tunnel behavior, an exact-SHA all-platform release, private deployment or
physical-device acceptance.

### November 7 resumed CONNECT native parser gate

The resumed continuation reconstructs the missing parser gate from current
published sources. It does not claim recovery of the unavailable fourteen-file
native/reference worktree. The new
`deploy/test_mobile_imported_connect_xray.py` keeps the eighteen CONNECT/REALITY
captures separate from the primary 346, CONNECT-layer 32 and SS/HY2-REALITY 18
inventories. Its eight shared roots require all 172 named verdicts; the pinned
native reader separately requires nineteen verdicts for each of shared,
actual Android and actual Swift captures. Both Android producers keep their
separate empty directories, original 240-second bounds and owned JSON
implementation. The Apple stage runs the actual Swift producer and checks the
same captured bytes again after native parsing.

The native parser checks the captured HTTP/HTTPS protocol, authentication,
TLS validation, both independent Start Layers, selected Home DNS through the
final, the sole Local selector and the real paired VLESS transport. It rejects
an injected SS UoT capability. Source receipts bind the actual prepared native
HTTP package and Xray source, and failures retain their original diagnostics.
Missing, duplicated, foreign, skipped or changed-source verdicts cannot satisfy
the gate. The established parser flags and deadlines remain unchanged.

Local verification in this continuation passed the full 172 shared race
verdicts and all nineteen shared native parser verdicts, using Go 1.26.3,
core `1ac1a339cb1223e9c70eae14c44411c75033c02d` and prepared Xray
`50231eaff98c`. Ten new runner tests and the eleven retained SS/HY2-REALITY
runner tests passed. At that initial checkpoint, the Android producer could not
compile its Java 17 target because the executor lacked the JDK release-symbol
archive, and Swift was unavailable. Complete verified JDK and Swift toolchains
were subsequently acquired. A separate CONNECT execution against source
`2ff74fd3` now passes both actual Android producer phases: 1,220 checks and nine
independent exports each, with all five existing causal controls per phase.
The actual Swift producer passes 943 checks and emits its own eighteen graphs.
The current native reader then passes all 38 shared/Android and nineteen Swift
verdicts without skips. These are the 57 required parser verdicts, not encrypted
traffic or OS-device verdicts. The 172 shared race verdicts also pass.

The separate CONNECT execution used verified Temurin 21.0.13 with the unchanged
Java 17 release target and official Swift 6.4.2 on Linux, Go 1.26.3 and the same
pinned native core/Xray source. Its source receipt covers 2,200 inputs with
SHA-256 `54418836ef4c28a4f43214770ddb1277671b202d0bb6bfb38830d477e3ee8f7b`.
Actual captured files and prepared-source identities match before and after
parsing. This host composition does not substitute for an Apple SDK build,
signing or device acceptance.

This parser increment does not close the separate encrypted CONNECT/REALITY
peer, selected encrypted DNS, physical-interface, system-tunnel, package,
signing, release or device requirements. Those retain their own original
positive and negative controls.

### November 7 resumed packet entry to REALITY source and parser gate

WireGuard, AmneziaWG and the bounded OpenVPN TCP/UDP entry profiles now reach
an independently paired ordinary REALITY/Vision final under explicit Local
execution. This is a new source increment validated against the current pinned
runtime, not a claim that the historical incomplete recovery patch passed.
The existing userspace packet endpoint and Xray outbound live inside the same
owned native graph. Android and Apple selection, preparation and restoration
use the new admission without starting a second system VPN.

The constructor retains the complete packet source: WG/AWG private and peer
keys, PSK, addresses, AllowedIPs, keepalive, MTU and AWG parameters; or OpenVPN
inline profile, original TCP/UDP remotes, credentials, trust and connected-state
readback. Each role owns its independent Off, AES-256-GCM or AES-256-GCM + XOR
Start Layer. The final retains its original VLESS credentials, REALITY keys,
Vision flow and paired identity. Selected Home AdGuard and explicit DNS policies
continue through that final; ordinary Vision's UDP-443 refusal remains distinct
from an original asset explicitly provisioned for UDP 443. No SS UoT capability,
paired entry token, invented final endpoint MTU or ordinary-network DNS proof
is added.

`deploy/test_mobile_imported_packet_xray.py` requires a separate inventory of
36 private source captures, eight shared roots with 298 exact named verdicts,
and 37 exact native parser verdicts for each source producer. Original primary
346, CONNECT-layer 32, proxy-REALITY 18 and CONNECT-REALITY 18 inventories remain
unchanged. Four actual Android phases each own nine exports and retain the
Java 17 target, pinned JSON implementation and existing 240-second child bound.
The Apple stage runs its actual Swift producer, requires all 36 original
exports, checks the native reader against its shipping template before and
after execution, and rejects changed files, skipped cases and incomplete
verdicts. The real native parser checks the original userspace endpoint,
independent layers, selected final resolver and Xray graph.

Local Go 1.26.3 verification passed all 298 shared verdicts under `-race` and
all 37 shared parser verdicts in pinned core
`1ac1a339cb1223e9c70eae14c44411c75033c02d`, with prepared Xray `50231eaff98c`.
Restoring the old packet rejection and bypassing the final's independently
captured layer both failed at their intended causal witnesses. The retained
SOCKS/REALITY scope cases now require the supported original packet entries
and still reject fabricated paired authority; unrelated final-family refusals
remain intact. The shared runtime cases retain actual HTTP identity proofs,
explicit modeled native packet ownership, cancellation/replacement controls,
and OpenVPN connected-remote, reader and MTU replacement checks. They do not
claim real encrypted packet traffic.

The complete official Temurin 21.0.13+9 JDK was checksum-verified and used with
the unchanged Java 17 target. All four actual Android phases passed: WireGuard
1,089 checks, AmneziaWG 1,206, OpenVPN TCP 1,044 and OpenVPN UDP 1,044. Every
phase retained the five source/ownership causal controls. All 74 shared and
actual-Android native parser verdicts passed, with no skips or failures.

The official Swift 6.4.2 Debian distribution passed its detached release-key
signature check. Its actual producer passed 931 shipping Swift/Go checks and
exported all 36 original graphs. The pinned native reader then passed all 37
Apple verdicts with exact before/after source, reader and export checks. The
shipping picker/save/cold-capture fixture passed 186 checks for each of four
packet groups, retaining the 3,231-check baseline, five existing REALITY groups
at 115 checks each, 336 configured-CONNECT checks, and the original selected-DNS
cases. Cross-host comparison normalizes only the WG/AWG omitted-versus-false
`system` default in private fixture copies; true, malformed values, keys, MTUs,
routes, remote fields and OpenVPN remain exact. No production graph bytes were
changed for that comparison.

The full shared package passed after retaining the original SOCKS/REALITY scope
case names and adding explicit forged-pairing refusals to the newly admitted
packet cases. Ten new runner controls and 66 retained imported-source,
CONNECT, proxy and Apple inventory controls passed. Source/host and native
parser evidence is now established for this increment. The separate actual
encrypted packet/REALITY and selected-DNS reference stage, system-tunnel
behavior, exact-SHA packages and physical-device acceptance remain required.
Packet desktop admission and Server/Compare for this direction are separate
unfinished requirements.


---

<a id="section-ios-owned-strategies"></a>

# iOS mode selection inside one VPN session

The iPhone/iPad app now runs single Router VPN node AUTO, SMART, CUSTOM,
logical-mode fallback and ALL trials inside one owned PacketTunnel session.
ALL tries complete MAX TLS branches before complete MAX QUIC branches, using
the saved WG/AWG base and fallback policy. It never substitutes a partial chain.
External-node and multihop connections retain their separate captured graphs.

## Captured configuration

The app validates candidate assets and prepares native Xray endpoint addresses
before starting the VPN. It stores the bounded candidate catalog with the exact
node credentials, selected DNS policy, Start Layer assets and interface policy
in the provider configuration. Later strategy IPC contains only references to
that catalog, request identifiers and the owning provider session. It cannot
inject another node, replace credentials or mutate active policy.

Changing saved policy requires the previous connection to finish Disconnect.
SMART may prefer a remembered exact raw mode, but the provider proves that mode
again. A remembered label is never evidence that the current route works.

## Connection and teardown ownership

The provider installs nonempty full-device hold settings before reporting the
system tunnel started. Each trial closes the previous native runtime, preserves
the system VPN interface, creates a fresh runtime and verifies both the private
node identity and the selected DNS route. DNS verification uses the owned native
DNS router without its response cache. The app shows Connected only after both
proofs and final activation have succeeded.

A failed SMART reduction can restore the last proven candidate. Restoration is
reported distinctly from success of the requested reduction. Every replacement
and restoration creates a new runtime epoch, so measurements from the previous
runtime cannot remain current even when its displayed node and mode match.

The native settings queue rejects stale generations before and after asynchronous
NetworkExtension callbacks. Failed runtime teardown remains owned and blocks
another trial. The protected session remains cancellable; explicit Disconnect
revokes pending app startup, disables on-demand reconnect with readback, stops
the owned system VPN and verifies its terminal state. Unknown status does not
unlock profile mutation or become Disconnected.

## Verification boundaries

The required Apple runtime contract executes the shipping wire parser, provider
coordinator, native runtime driver and app orchestration. App/provider fixtures
substitute operating-system handles and controlled node/DNS results. Their
negative controls detect premature Connected state, reused runtime identities,
lost cancellation ownership and changed source accepted during startup.

Separate tests execute the real Swift selectors and Go graph compilers. The
pinned native-core gate exercises actual DNS routing, fresh startup, interrupted
startup and checked close errors. The complete Xcode/IPA release build checks
the real generated native bindings and Apple SDK. These checks do not establish
physical-device routing, leak behavior, network transitions or Apple signing;
those acceptance results require their own device runs.


---

<a id="section-native-execution-tun-readback"></a>

# Native ordered execution TUN readback

The shared ordered execution runtime requires an effective native TUN observation
when attaching MTU control or capturing mobile restoration. The native engine
implements that capability in `mobile/chain/execution_readback.go.tmpl`.

## Retained identity and retirement

Capture observes the original active reader through the real TUN's bounded
readback method. It retains the original Box, execution identity, gate control,
reader generation, interface name, interface index, and effective MTU. An unchanged
reader retains its random nonce. An authorized reader replacement receives a new
nonce and generation; an earlier capture cannot describe the replacement.

The application gate and original execution must remain current before and after
the native observation. A changed interface or non-cancellation read failure
invalidates an existing capture permanently and revokes application admission.
Restoring old OS values cannot restore that capture. Ordinary caller cancellation
does not itself invalidate a current reader.

Retirement is recorded only after the exact engine has joined its owned stops,
closed its gate, and retired its ingress. A successful restore receipt additionally
requires the actual original `Box.Close` result. The early `Box.done` signal and a
caller-created readback value cannot substitute for it. The receipt remains
queryable after host teardown without querying destroyed managers or the OS;
an original native close error remains an error.

## Verification boundary

The native component tests exercise the real pinned managers, selector, gate,
discovery, reader transaction, and `Box.Close`. Privileged TUN readback and encrypted
transport remain explicit test boundaries. The public readback method rejects the
fixture TUN. These tests do not establish physical-device MTU, network-transition,
or leak acceptance.

## Recorded execution

- The complete native owner inventory passed with the race detector: 31 roots
  and 98 root/child verdicts across the Box, TUN, and outbound-manager packages.
  Their package execution times were 38.593, 1.105, and 1.017 seconds.
- Removing the actual close join failed at the original-close assertion.
  Removing exact issued-value equality failed at the forged-observation
  assertion. Both controls executed the real compiled native adapter.
- All seven verdict-parser checks and nine preparation checks passed.
- The prepared core was pinned to
  `1ac1a339cb1223e9c70eae14c44411c75033c02d`. This local run used explicit
  current-owner overlays on the officially prepared `01cc839` desktop core;
  the owner sources included the `0765d62` Last-adoption changes and this unit,
  based on `a683e62`. All 5,146 original core files remained byte-identical
  before and after execution. No manifest was changed to bless an overlay.
- The hosted native runner retains its full inventory and all 21 causal
  controls, including the two new controls above. Only those two newly added
  controls are claimed as executed in this focused local run.


---

<a id="section-native-pq-dial-observations"></a>

# Native PQ dial observations

The protected PQ transport failures below are **not causally resolved** by the
admission diagnostic. The diagnostic preserves their original native error and
records bounded evidence for the next executed failure. It neither retries the
connection nor changes a transport, peer, permit, timeout, or acceptance gate.

## Observed CI boundary

| Exact source and job | Observation |
| --- | --- |
| `100c1e5abbf7e9f7ebaedb459a41e961425283ab`, [Aux ARM64 job 128336558558](https://github.com/Eabusham2/router-vpn/actions/runs/42340818031/job/128336558558) | `TestRouterVPNDesktopNodePQTraffic/awg2-pq/off` failed during native PQ startup with `protected PQ peer transport could not open`. The entire leaf took 1.47 seconds. The other five mode/layer leaves passed. |
| Same source, [Windows ARM64 job 128321441483](https://github.com/Eabusham2/router-vpn/actions/runs/42340816527/job/128321441483) | `TestRouterVPNDesktopNodeCompleteMAXQUIC/max-quic-wg/aes-256-gcm+xor-whitening` failed with the same admission error. Its reported construction took 1.743363 seconds and the entire leaf took 1.76 seconds. The other five QUIC leaves passed. |
| `6fa3efa1e315a032018c1e88bd00f51bda3c6dd2`, [later native Windows MAX run 42398899779](https://github.com/Eabusham2/router-vpn/actions/runs/42398899779) | The ARM64 QUIC job passed. AMD64 job `128482204527` failed the separate actual-WFP credential case `max-quic-wg/off/kem-peer`: the negative did not reach its retained encrypted peer. That different fixture/failure does not establish a cause or repair for the earlier composed-peer admission failures. |

Both initial failed leaves completed before the existing five-second dial
admission limit. Their generic errors discard the underlying native result, so
they do not identify a timeout, socket syscall, protected permit rejection, or
caller cancellation. Extending the limit would not follow from this evidence.
At the initial review of published selector source
`35e72a44c1df446b57d71d94d3725c23f51757ab`, its auxiliary ARM64 and relevant
Windows runs were still pending or queued; no successful rerun was claimed.

## Retained diagnostic

`internal/mobilepq/controller.go` captures the rejected dial result before
closing any returned socket. The private `dialAdmissionFailure` retains the
original error through `Unwrap`, so `errors.Is` and `errors.As` can inspect the
native syscall and wrapper identity. A separately captured caller error and
five-second budget expiry remain distinguishable.

Its formatted startup message contains only:

- Elapsed admission milliseconds and whether the admission budget expired.
- A fixed caller-error class and whether the native dial returned a socket.
- A fixed native-error class, numeric syscall error, and allowlisted operation
  and network names.

Unknown error types produce `other`; arbitrary error text, addresses, keys,
paths, and operation names are not formatted. Classification visits at most
16 nodes, reads concrete standard-library wrapper fields, and unwraps only
the exact standard-library `fmt`/`errors` wrapper types. It never invokes a
custom `Error`, `Is`, `As`, `Timeout`, or `Unwrap` callback. Deep or opaque error
trees remain inspectable by an explicit caller but cannot delay the diagnostic.

## Ownership and execution boundary

The original admission predicate remains: stop the five-second timer, require
the monotonic return time to precede its deadline, require a live retained dial
context, require no dial error, and require a returned socket. A late or failed
socket is still closed synchronously before protocol cleanup. Failed admission
cannot process a cryptographic event, install a key, or publish readiness.

The existing virtual-clock tests still prove the exact before/at/after
five-second boundary, post-admission transport lifetime and rekey I/O, and
cancellation joining the original late socket. New tests execute the actual
controller against native error shapes, cancelled and expired admission,
late sockets, cleanup failure, opaque callback errors, and bounded redaction.
They retain original cause identity and prove exactly one peer revocation and
protocol cleanup. These tests do not execute a real Rust KEM or establish the
cause of the recorded Windows failures. Existing native Rosenpass, NodePQ,
complete MAX, real peer traffic, credential rejection and physical-owner gates
remain required without timeout or verdict changes.

## Local validation of this diagnostic

- `go test -p=2 -race -json ./internal/mobilepq -count=20 -timeout=90s`
  passed: 66 distinct root/subtest verdicts, repeated 20 times (1,320 verdicts).
- `go vet ./internal/mobilepq` and the Windows ARM64 test-binary
  cross-compilation passed. Cross-compilation is not Windows execution.
- `deploy/test_native_pq_bridge.py` passed all six existing bridge tests with
  their declared modeled native handles and protocol events.
- An overlay restoring the original generic admission error fails the new
  actual-controller `native-syscall` case because the original admission
  evidence is missing. The overlay does not modify the tested source tree.
- `deploy/test_native_pq_factory.py` could not launch its C compilation because
  `clang` was unavailable locally. No local real Rosenpass archive was available;
  a real native KEM exchange was not executed for this diagnostic.

At the final CI review of source `35e72a44c1df446b57d71d94d3725c23f51757ab`,
[Native Rosenpass protocol and ownership run 42402763402](https://github.com/Eabusham2/router-vpn/actions/runs/42402763402)
had succeeded, while the relevant auxiliary ARM64 and Windows PQ/MAX runs
remained pending. That published source predates this diagnostic.
