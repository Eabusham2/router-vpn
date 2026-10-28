# Captured desktop Tor physical sockets

This prerequisite connects the desktop Tor native lower dialer and its selected
bootstrap DNS to an explicit owned-socket capability. It does **not** enable
Direct plain Tor, meek, WebTunnel or Snowflake under strict desktop protection.
Their public compiler and wrapper guards remain closed until each platform's
privileged policy/identity factory and launcher are implemented and verified.
The existing exact, fixed obfs4 endpoint path is unchanged.

## Actual native call path

The real `routervpn-desktop-tor-network` service captures the immutable session,
full source identity and a fresh network-generation nonce. A source may request
`physical_broker`, but that flag creates no authority. Before activation, the
native host must supply a `DesktopSocketBroker` backed by an independently
provisioned `DesktopSocketPolicy` and bind it to the actual concrete
`routervpn-tor-physical-egress` outbound in the same Box.

Activation emits a private context capability. Both the C Tor guard SOCKS proxy
and the in-process pluggable transports already call the captured desktop lower
dialer. When this capability is required, that lower dialer detours through the
physical outbound. Every selected bootstrap-DNS transport and dependency must
use the same detour; the existing native resolver dependency capture rejects a
DNS path that escapes it. The broker receives numeric destinations and never
resolves a hostname using the system resolver.

Missing capability, wrong full source, another network generation, duplicate
binding, an unrelated context, a replaced native outbound or a network reset
rejects the operation before any socket permit. Ordinary predecessor-routed
Tor continues to use its captured predecessor; the physical capability cannot
replace that owner.

## Kernel socket and policy lifetime

`DesktopSocketPolicy` is an OS boundary, not a receipt decoder. Its owner must
identify an independently provisioned kernel identity. A process path, shared
UID, printed PID or caller-supplied tuple is insufficient. `Current` is a bounded
memory-only witness. `Bind` captures and verifies the actual raw descriptor and
creator identity, then applies and reads back the captured physical interface.
`Grant` independently verifies the actual bound socket's kernel owner before
installing and reading back the exact owner, interface, transport, local
address/port and remote address/port. This permits native bound-socket identity
queries that are unavailable before bind; it does not permit any connect or
data write before the complete owner/tuple acknowledgment.
`Revoke` acknowledges both deletion and an independent absent readback.

The native broker exclusively binds the actual kernel socket before requesting
permission. It retains a duplicate handle until permission removal and all
entered I/O have joined. A failed or canceled connect cannot free an authorized
source port while a late/unknown control result remains outstanding.

There are at most 128 captured sockets and 32 actual peer tuples per UDP socket.
Binding UDP alone grants no traffic. Each new STUN/ICE/peer destination requires
its own acknowledged tuple before a datagram is written. Incoming datagrams
from ungranted peers are discarded without copying their bytes into the
application's buffer. A valid existing grant continues to carry data while its
renewal is pending; the renewal does not serialize healthy UDP traffic.

An accepted receipt must match every captured field and the actual request
sequence. Native observations are at most five seconds old, and a grant ends
within ten seconds of its observation. Data deadlines and an independent
memory-only monitor enforce the earlier bound even when a control operation is
blocked. Expiry cancels the exact socket's connect/renewal work and interrupts
entered reads/writes. Cleanup joins delayed control calls, confirms exact
permission absence, then releases the socket handles. A failure remains owned
and retryable; it does not acknowledge a successful close or touch a replacement.

### Platform socket implementation

Linux and macOS disable and read back address/port reuse, bind the actual local
address and retain a duplicate descriptor. The ordinary creator continues
through the native Go TCP dialer. Windows uses `SO_EXCLUSIVEADDRUSE` and retained
Winsock handles. Its TCP
connection directly owns nonblocking Winsock connect/read/write with bounded
`WSAPoll` waits, cancellation and actual I/O joins. The Go Windows dialer binds
again before `ConnectEx`, so handing an already bound/authorized socket back to
it would fail. No temporary unbind, guessed source port, unsafe netFD or
`CloseHandle` substitution is used. Other qualified Unix targets still reject
this new capability until their socket adapter exists.

### Imported Unix socket creator

A trusted policy may additionally implement `DesktopSocketSource`. This is a
typed factory capability; JSON cannot select a socket provider. Its request and
reply bind the entire source/session/network capture, kernel owner, physical
interface/address, fresh socket ID and TCP/UDP protocol. The broker takes
ownership of a returned file before inspecting any reply or error, including a
late result after cancellation. Missing or changed fields cannot reach Bind.

The Unix implementation independently checks the actual descriptor is the
expected kernel socket family/type, still unbound, not listening and not
connected. It then uses the same Bind and exact grant path as the ordinary
creator. `net.FileConn` and `net.FilePacketConn` duplicate the supplied kernel
socket; they do not create a new socket under the receiving process's UID. TCP
connect begins only after acknowledged permit readback and uses that same
descriptor with Go's network poller, bounded cancellation and an actual peer
readback. UDP import installs no peer grant until the captured peer is used.

The privileged policy must still read the actual kernel creator independently.
On macOS, XNU stores the creator credential in the socket's `so_cred`; both the
PF socket lookup and socket `fstat` UID derive from that credential. An SCM_RIGHTS
reply's claimed UID is not this proof. The production UID allocator, helper
invocation authentication and PF guardian are separate work; this import path
does not claim those components already exist.

Cancellation revokes pending source creation. Broker Close waits for the
creation/transfer operation, every exact permit's absent readback, all entered
I/O, and all original/imported/retained socket handles. It then requires the
source's retryable Close to join its creator processes and descriptor transfer.
An error or unknown creator close cannot release the isolated identity. The
privileged guardian must retain the identity until that complete acknowledgment
and must also cover native-process crashes independently.

## Privileged integration still required

No existing installer or launcher currently provisions the isolated identity
represented by this new capability. An eventual factory must establish it
before the first native physical socket, independently verify the actual
process/socket identity, and retain it through process and policy cleanup.
The current native callback cannot manufacture that factory from JSON.

Linux can pair an inaccessible retained cgroup with owner-filtered nftables
tuple sets and kernel timeouts. Windows needs a separately protected session
identity plus exact WFP permits and independently owned dynamic-session cleanup.
The existing macOS PF boundary needs an isolated socket UID and exact anchor
rules with verified state/removal behavior. These are implementation directions,
not evidence that those operating-system boundaries have been deployed.

The policy owner must also cover native-process and launcher crashes. Retaining
only an application-side duplicate is insufficient if that process dies. A
privileged guardian can retain a transferred duplicate before installing a
permit; identity reuse must remain quarantined until all grants are absent and
the native process/children have joined. A shared process path or recycled UID,
cgroup identity, interface index or local port must not inherit an old grant.
Kernel permit expiry, baseline fail-closed behavior and actual cleanup must be
verified separately from the broker's in-memory timers.

Private-address exceptions must come from the captured DNS, bridge and LAN
policy. Supporting Home AdGuard or custom DNS does not authorize arbitrary
dynamic physical access to the household LAN.

## Executable evidence and limits

The shared suite uses actual local TCP/UDP sockets, transferred bytes, bound-port
conflicts, expiry, cancellation and entered-I/O joins. The privileged identity
and firewall calls are explicit fixture doubles; the suite installs no policy
on the test host. The native suite constructs the actual lower dialer, physical
outbound and selected TCP DNS transport, and checks their real loopback traffic
and rejected capability/owner/DNS substitutions.

The selective desktop preparer copies the exact shared lifetime tests. The
mandatory native runtime build executes `TestDesktopSocket` on matching desktop
hosts, alongside the PT/network-owner tests, before building and packaging the
runtime. Windows ARM64 uses the existing no-race exception from the pinned Go
toolchain; other shipped desktop hosts retain race instrumentation. Successful
cross-compilation alone does not establish those Windows/macOS socket results,
kernel firewall enforcement, public Tor operation or physical-device acceptance.

The explicit `routervpn_privileged` UID fixture uses a real fork/exec under a
random unused test UID and SCM_RIGHTS transfer, then verifies the actual creator
UID after transfer, connection/packet import and retained duplication. Its
IPv4/IPv6 TCP/UDP cases exchange actual loopback bytes; a wrong kernel UID is
rejected before any grant. This fixture creates no accounts or firewall policy
and is not production UID allocation or PF acceptance. Tests selected by this
tag fail when their required root privilege is missing; they do not skip.

`deploy/test_desktop_socket_uid.py` verifies the exact copied socket sources,
compiles the fixture as the build user, and executes only the privileged UID
tests under available root or noninteractive system sudo. Matching Linux and
macOS native builds require this gate before packaging. The Windows build path
is unchanged. macOS socket execution must be established by its actual native
runner, separately from a Linux fixture or Darwin cross-compilation.

## Primary mechanism references

- Go Windows connect implementation: https://cs.opensource.google/go/go/+/refs/tags/go1.26.3:src/net/fd_windows.go
- Winsock exclusive binding: https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
- Winsock socket duplication: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw
- Winsock nonblocking mode: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-ioctlsocket
- Winsock polling: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll
- WFP condition identities: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers
- WFP dynamic-session object cleanup: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- nftables owner expressions, tuple sets and timeouts: https://netfilter.org/projects/nftables/manpage.html
- XNU socket creator credentials: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket.c
- XNU socket fstat UID readback: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_socket.c
- XNU PF socket lookup: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c
- XNU TCP/UDP PCB credential lookup: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c
