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

Paired Server/Compare currently requires one public literal host across the
original remote list so its last-node response proof identifies the actual
provider. Multiple ports and transport fallbacks on that host remain supported;
ordinary Local profiles retain different-host lists. Different-host paired
comparison and external-entry Server execution remain open extensions with
additional remote-observation and runtime ownership requirements.
