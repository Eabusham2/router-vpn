# Native mobile OpenVPN

## Implemented path

Android and iOS/iPadOS compile a private inline `.ovpn` profile through
`mobile/routervpn_openvpn.go` into a native `openvpn-client` endpoint. The
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

On Android, Add custom exit includes a private OpenVPN form. It feeds both the
direct-exit builder and the existing WireGuard-entry/custom-exit builder. The
latter sets `detour: entry-wg`. The new code retains the process-owned VpnService,
socket protection, lockdown requirements and expected-public-exit verification.
The combined Libbox/Xray AAR remains one Go runtime.

On iOS/iPadOS, Add External Node and Linked Nodes expose OpenVPN. The private
linked-node store retains the original profile. PacketTunnel recompiles its
frozen profile and requires the existing exact public-exit proof before startup
completes. Only the unique Router VPN-owned manager may be selected for startup.
This change does not add OpenVPN to every arbitrary iOS multihop composition.

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
