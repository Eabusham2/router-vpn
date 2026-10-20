# Native mobile OpenVPN

## Implemented path

Android and iOS/iPadOS compile a private inline `.ovpn` profile through
`internal/nativeopenvpn.CompileEndpoint`, exposed by the unchanged
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

The release audits preserve their existing weights and manual evidence gates.
Their source score is not a percentage of all original features delivered.
No physical-device, reconnect/leak/permission, off-LAN, private AI Board/Portainer,
live ASUS forwarding, signing or notarization result is asserted here.

## Multihop architecture boundary

The current mobile paths compose client-owned entry and exit transports. A
server-managed entry-to-exit route is also a possible architecture, but is not
implemented by this OpenVPN change. Moving the second tunnel onto an entry
server changes where that tunnel terminates and where exit credentials reside;
it is not automatically equivalent to client-owned nested encryption. A future
server-managed path must define per-client authorization, isolation, failure
behavior, exit identity, DNS ownership and teardown explicitly. No existing
client multihop feature is removed by this continuation.
