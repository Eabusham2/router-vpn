# Native mobile OpenVPN

## Implemented path

Android and iOS/iPadOS compile a private inline `.ovpn` profile through
`internal/nativeopenvpn.CompileEndpoint`, exposed by the existing
`mobile/routervpn_openvpn.go` binding, into a native `openvpn-client` endpoint. The
endpoint runs inside the application's existing Libbox runtime with
`system: false`; it does not launch a command-line VPN or install a second OS
TUN. Both mobile builders pin sing-box 1.14.1 at
`1ac1a339cb1223e9c70eae14c44411c75033c02d` and include the OpenVPN build tag.
Generated Swift/Java bindings are checked, rather than assuming matching names
mean matching signatures.

The shared compiler preserves bounded inline CA/client certificate/key material,
credentials, remote ordering and supported transport/TLS options. Inputs are
limited to 256 KiB of UTF-8 text. Remote addresses must be literal unicast IPs;
no pre-tunnel hostname lookup is introduced. Private credentials are neither
trimmed nor copied into connection-profile summaries. TLS requires server
verification and at least TLS 1.2. Unsupported directives are rejected, not
silently discarded. Scripts, plugins, management listeners, local file references,
active compression and interactive authentication challenges are not accepted.
This is not a promise to support every provider's OpenVPN profile.

On Android, Add custom exit includes a private OpenVPN form. Direct connections
and connections through a captured Router VPN entry use the shared external
policy compiler. The predecessor is the complete selected entry graph, including
its WG/AWG/PQ/Xray/MAX/helper transports, Start Layer and owned padding service.
It retains the process-owned VpnService, socket protection and lockdown policy.
The combined Libbox/Xray AAR remains one Go runtime.

On iOS/iPadOS, Add External Node and Linked Nodes expose OpenVPN. The private
linked-node store retains the original profile. PacketTunnel recompiles its
frozen profile and uses the same shared external policy and captured predecessor
graph. Ordinary imported OpenVPN profiles can be entry or exit transports. Only
the unique Router VPN-owned manager may be selected for startup.

The policy compiler recompiles the exact original inline OpenVPN configuration
and compares the entire endpoint before applying the captured path. Remote order,
fallback transports, credentials and TLS material must agree. It retains the
selected DNS transport, IPv6 and LAN conjunction, entry identity proof where
applicable, and routed DNS and public-exit proofs. A TCP OpenVPN carrier can carry
UDP application packets inside its encrypted stream; an OpenVPN profile with any
UDP remote cannot use a TCP-only outer proxy.

Endpoint MTU and the shared OS TUN remain separate owners. An imported explicit
fragment size is preserved and checked against the enclosing packet tunnel;
fragmentation is never added implicitly. Without explicit fragmentation, nested
UDP OpenVPN reserves a conservative 160 bytes for supported encryption/framing
and IPv6/UDP overhead. An oversized fixed inner MTU is rejected. These are
configuration bounds, not an Auto-MTU measurement of an external provider.

## Executable evidence

`go test -race ./mobile` executes parser acceptance, rejection and fuzz seed
cases without a VPN server. `deploy/test_mobile_openvpn_pinned.sh` additionally
runs the actual pinned core with ephemeral certificates and local sockets. It
checks direct and WireGuard-detoured configuration shapes, an encrypted payload,
untrusted CA and wrong peer-name rejection, malformed CA rejection, and listener
shutdown. The traffic fixture maps one documentation-only destination to its
local echo service and rejects other server egress. It does not contact the
user's router or an external test server.

`deploy/test_mobile_openvpn_contract.py` checks the shipping compiler, forms,
private store, runtime builders, proof call sites and generated binding adapters.
The iPhone/iPad Xcode app/extension build and Android APK build are separate
native gates. Marker checks are not substitutes for either native compilation
or real traffic tests.

`go test -race ./internal/mobilemultihop -run '^TestExternalOpenVPN'` also checks
114 complete Router VPN predecessor graphs (19 modes, three Start Layers, and
TCP/UDP OpenVPN exits), imported entry combinations, TLS/credential mutations,
fallback transport rejection and nested MTU ownership.

`deploy/test_external_openvpn_pairing.py` invokes the actual offline Go compiler
and Python private-registry pairer. It verifies separate provider and pairing
credentials, all three exit Start Layer selections, secret-free counterpart
descriptors, strict raw JSON, source preservation and rejection of duplicate
provider identities. The copied mobile binding tests exercise
`RouterValidateExternalOpenVPNPairing` before Java or Swift private-store
decoding can drop invalid fields.

`deploy/test_external_openvpn_remote_native.py --core PINNED_CORE_CHECKOUT`
executes the actual pinned OpenVPN endpoint and the private relay command with
ephemeral certificates and owned local sockets. It verifies TCP/UDP fallback
to a different captured remote, encrypted relay traffic, reconnect generation,
deliberately delayed old configuration callbacks, failed TLS ownership and
strict request/source/receipt file ownership. Its dependency patch is applied
only to a private module copy whose entire unmodified source is checked against
the pinned Go checksum; module-cache source is unchanged. Repeated preparation
in either order preserves the existing close policy and generation policy.
The mapped-layer cases use the actual authenticated outer engines and include
concurrent UDP-to-TCP failover/close, exact predecessor retention during native
manager replacement, and immediate cancellation of pending dials from a retired
network generation. A joined already-closed error cannot hide a separate cleanup
failure. The five-second owned-close deadline is unchanged; a timeout records
native goroutine diagnostics instead of reporting successful teardown.

Those diagnostics exposed a native OpenVPN/gVisor lock cycle: packet delivery
held the link-dispatcher read lock while entering the stack, and stack shutdown
held the stack lock while detaching that dispatcher. The exact-pinned
`mobile_openvpn_stack_policy.py` now detaches and drains the captured link before
stack shutdown. Its actual-stack regression pauses packet delivery and checks
that teardown leaves the stack lock available; restoring the original order
fails that control. The transport credentials, remote-generation proof and
individual teardown deadline are unchanged.

`deploy/test_external_openvpn_native.py --core PINNED_CORE_CHECKOUT` runs the
real OpenVPN provider and both independently authenticated owners under the race
detector. TCP and UDP each carry actual payloads with Off, AES and AES plus XOR
layers; TCP uses TLS-auth and UDP uses TLS-crypt. The test includes wrong CA,
name, control key and listener-secret rejection, simultaneous retained owners,
deleted-lease replay and confirmed listener shutdown. No external provider,
private router or system TUN is involved in this loopback fixture.

The release audits preserve their existing weights and manual evidence gates.
Their source score is not a percentage of all original features delivered.
No physical-device, reconnect/leak/permission, off-LAN, private AI Board/Portainer,
live ASUS forwarding, signing or notarization result is asserted here.

## Multihop architecture boundary

Local connections compose client-owned entry and exit transports. A captured
Router VPN entry can also run an isolated OpenVPN Server candidate, or compare
it with Local, when the imported node contains a complete
`external.openvpn_pairing`. This private pairing holds the Local owner's
dedicated X25519 key and the Server's public counterpart descriptor. The Server
independently owns its original provider profile, TLS client key/certificate
and/or username/password, plus its own dedicated pairing key. No Server private
credentials are copied to the phone, and no Local private credentials survive
in the server registry. Canonical certificate public keys, common names and
usernames prevent duplicate provider sessions from impersonating independent
paths. Pairing controls and commands are described in
[MULTIHOP-EXECUTION.md](MULTIHOP-EXECUTION.md#external-openvpn-provider-sessions).

The fresh authenticated entry challenge binds every acquisition to its boot
epoch, observed peer, deadline and random attempt. Cancellation, renewal and
confirmed teardown preserve the same owner. The Server engine uses a private
authenticated listener and userspace OpenVPN endpoint; the device keeps one
owned system VPN and its selected DNS, IPv6, LAN and MTU policy. Compare applies
the required average of the last-node and same external response timings and
repeats both probes for the chosen candidate. Restoring an already-proved
Local/Server choice does not rerun Compare.

Legacy single-host pairings preserve their `response_probe` and v4 identity.
Different-host paired profiles provide a private
`external.openvpn_response_probes` map covering every original host. Native
forms and imports strictly validate and preserve this map. Each native
candidate proves its actual connected remote and immutable transport
generation before using that host's response endpoint. The v5 relay contract
requires a fresh process-owned response to each request and retires a retained
proof when the provider reconnects, even to the same address. The same fresh
boundary protects MTU, DNS Retest and Speed Lab result adoption.

Different-host profiles can also capture `external.openvpn_start_layers` with
one separately provisioned AES-256-GCM or AES-256-GCM plus XOR layer for every
original host. All entries use the selected exit mode; the independently
selected Router entry layer is unchanged. The strict private map is limited to
128 KiB and two to sixteen canonical original hosts, exactly matching the
response map. Missing, extra, duplicate, null, mixed-mode and singular-layer
combinations are rejected before platform decoding can discard them.

The native mapper leaves the original ordered OpenVPN remotes intact. It chooses
an owned authenticated child from the original host, port and TCP/UDP network,
then translates only that child's inner destination to the captured private
service address. Providers may share the same private address without sharing
identity. The connected receipt still identifies the original remote and its
immutable generation. Every per-host key participates in v6 lease
authentication; the public fingerprint includes policy and counterpart public
identities without publishing password hashes. Outer keys cannot alias either
role's private pairing key, including alternate X25519 encodings of one identity.
Legacy single-host v4 and mapped-Off v5 identity formats are preserved.

Each mapper owns its pending dials and encrypted connections. Cancellation,
network changes and closure revoke stale generations; failed cleanup retains
ownership and rejects replacement dials. Desktop firewall exceptions capture the
actual outer host, port and network. MTU configuration bounds include the largest
permitted wrapper branch, private IPv4/IPv6 address and identity-header overhead.
They are not a measured path MTU. The real native gate exercises encrypted
TCP/UDP fallback, independent Local/Server provider credentials, AES and XOR,
colliding private addresses, reconnects and stale configured callbacks.
External-entry Server execution requires an authenticated administrative
runtime owner on that entry. An ordinary unmanaged provider import alone
cannot install or authorize that execution owner. These qualifications do not
change the bounded inline-profile compatibility rules above.
