# Captured desktop Tor physical sockets

The desktop Tor native lower dialer and selected bootstrap DNS use an explicit
owned-socket capability for dynamic Direct paths. Linux now has an implemented
privileged UID/socket guardian, native factory and exact nftables boundary for
plain Tor, meek, WebTunnel and Snowflake. It requires the captured privileged
launch path; an ordinary user process cannot manufacture that authority from
JSON or a command argument. Windows and macOS still require their corresponding
privileged policy/identity factories and launcher integration before these
dynamic paths can be admitted under strict protection. The existing exact,
fixed obfs4 endpoint path remains available.

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

## Linux privileged guardian

`DesktopLinuxSocketPolicy` is constructed by the native network-owner factory
after the real default-interface monitor initializes and before the Box starts
its TUN. Captured interface name, index and addresses are independently checked
against the kernel. IPv6 Off omits the IPv6 physical binding. A real default
network change retires the generation; creation of the owned TUN does not replace
the captured physical interface.

The launcher first installs the existing `inet router_vpn_killswitch` output
chain with policy drop and an exact session/source comment. Dynamic Direct
launch adds no global public-endpoint exemption. The guardian requires the
complete expected baseline, including selected LAN allowances, before creating
any account. It then captures the table, chain and every baseline rule handle
and expression. A later broader accept, changed rule, inactive marker or
replacement chain cannot become a new grant. Permits live inside this same
output chain: acceptance in an unrelated nftables table would not override its
drop policy.

An independently running root guardian allocates a fresh high numeric UID with
a locked password, expired account, no home directory and a nologin shell. A
private root-owned record captures the source and UID before `useradd` can
mutate the account database. Kernel/socket ownership does not come from a
printed account name. Every socket is created by an otherwise empty fork/exec
child under the allocated UID with no supplementary groups. The child transfers
the unconnected descriptor over an inherited anonymous sequenced Unix socket
and joins before the guardian acknowledges creation. Actual SCM credentials,
socket inode, `SO_COOKIE`, socket UID, transport and address family are checked.
The guardian retains a duplicate independently of the native process.

Before a grant, the guardian verifies the retained descriptor's identity and
actual local tuple, reads back `SO_BINDTODEVICE`, checks the captured interface
address, and rejects either address or port reuse. The nftables rule combines
the dedicated originating socket UID with the exact interface, local address and
port, remote address and port, and TCP/UDP family. Each tuple has a nine-second
kernel timeout; the native receipt expires after seven seconds and is issued
only after independent rule, set, tuple and timeout readback. A stopped or
killed guardian cannot extend a permit. Every selected bootstrap DNS socket
uses this boundary, with exact private resolver/bridge exceptions. An enabled
Home LAN policy retains its explicitly captured private-prefix allowances;
choosing Home AdGuard alone grants no other LAN access.

Cancellation retains the source port until the exact permit is absent and all
native I/O and handles have joined. Per-socket `ReleaseSocket` then closes the
guardian's duplicate, so sequential connections do not consume the 128-socket
limit indefinitely. Final account retirement requires every source descriptor
to have completed that acknowledgment, all rules/sets to be absent, and the
creator processes to have joined. Native-process EOF makes the independent
guardian remove permits and close its retained handles. Exceptional or unknown
outcomes retain the locked account and its recovery record to quarantine the
UID; they never guess that identity reuse is safe. Old-owner cleanup removes
only its captured rule/set identities and preserves a replacement session.

The Linux source requires root, nftables, `useradd`, `userdel`, and `nologin` in
the trusted system locations checked by the installer and runtime. The native
installed GUI now uses a fixed polkit-authorized controller, anonymous
credentials/lifetime input, authenticated local API, and retained installation
locks; see [native installation and permissions](LINUX-NATIVE-INSTALL.md).
Its separate fixed-install namespace and real GTK callback tests supplement
the socket guardian tests. These results do not establish an interactive
authorization prompt, a public Tor circuit, or physical-device acceptance.

## Remaining platform boundaries

Windows still needs a separately protected session identity, exact WFP permits
and independently owned dynamic-session cleanup. The macOS PF boundary still
needs an isolated socket UID and exact anchor rules with verified state and
removal behavior. The imported Unix descriptor tests do not supply those missing
factories. Both platforms must also retain identity across native-process and
launcher crashes before public strict dynamic Direct admission can open.

## Executable evidence and limits

The shared suite uses actual local TCP/UDP sockets, transferred bytes, bound-port
conflicts, expiry, cancellation and entered-I/O joins. Its portable policy calls
use explicit fixture doubles. The separate Linux kernel suite below uses the
actual privileged implementation. The native suite constructs the actual lower dialer, physical
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

`deploy/test_desktop_linux_guardian.py` verifies and hashes the exact prepared
Linux sources, resolves the native build's actual selected Go compiler, and
builds the `routervpn_linux_guardian` tests with race instrumentation. It executes
them only in fresh user, PID, mount and network namespaces with private account
files and `/run`, a veth link and a separate peer namespace. The host account
database, routes and firewall are untouched. Every required case must run and
pass; missing privilege or kernel functionality fails the gate instead of
skipping it. Matching Linux native packages require this gate before compilation
and packaging.

The ten real-kernel cases cover actual TCP/UDP bytes over IPv4 and IPv6, kernel
rejection of a matching tuple from the wrong UID, uncaptured private peers,
independent expiry after guardian SIGKILL, 130 sequential socket retirements,
broader-baseline rejection, native-parent crash cleanup and guardian join,
blocked-control source-port retention, stale source/network generations,
replacement-safe cleanup, and refusal to retire an identity with an outstanding
native descriptor. The runner's `--mutations` mode uses temporary Go compiler
overlays to remove UID enforcement, extend kernel expiry, omit baseline checks,
skip per-socket release, and skip final descriptor acknowledgment. Each broken
production variant must fail its corresponding actual-kernel assertion. The
working tree and prepared source are not edited by those controls.

## Primary mechanism references

- Go Windows connect implementation: https://cs.opensource.google/go/go/+/refs/tags/go1.26.3:src/net/fd_windows.go
- Winsock exclusive binding: https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
- Winsock socket duplication: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw
- Winsock nonblocking mode: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-ioctlsocket
- Winsock polling: https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll
- WFP condition identities: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers
- WFP dynamic-session object cleanup: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- nftables owner expressions, tuple sets and timeouts: https://netfilter.org/projects/nftables/manpage.html
- nftables originating socket UID matching: https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
- Linux socket inode credential allocation and UID changes: https://github.com/torvalds/linux/blob/master/net/socket.c
- XNU socket creator credentials: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket.c
- XNU socket fstat UID readback: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_socket.c
- XNU PF socket lookup: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c
- XNU TCP/UDP PCB credential lookup: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c
