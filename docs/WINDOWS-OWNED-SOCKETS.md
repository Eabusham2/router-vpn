# Windows owned sockets and WFP protection

Windows strict Direct Tor needs a physical socket owner inside the existing
native runtime. An application path or a process ID alone does not distinguish
its permitted transport sockets from ordinary application traffic. The native
source therefore holds a fresh disabled account token, retains the original
Winsock endpoint, and verifies the actual ALE endpoint, token statistics,
application identity, address family and bound tuple before a permission can be
installed. The separate identity gate executes those checks on Windows.

## Managed baseline

The Go WFP adapter creates one persistent managed sublayer. Its bounded,
canonical provider data records the original session, source fingerprint,
network generation, selected protection policy, captured LAN prefixes and DHCP
renewal servers. A new session reads the entire old record and complete rule
set, then replaces the old baseline and installs its new baseline in one BFE
transaction. Unknown records, extra filters and altered rules are rejected.

A separate dynamic sublayer acts as the exclusive native-session lock. It has
no traffic filters. Its fixed object key prevents concurrent owners from
adopting the same baseline, and the same dynamic BFE session owns every socket
and tunnel permit. BFE removes dynamic objects when that process/session ends.
Only the persistent baseline survives. Management ACLs on these objects grant
access to Administrators and SYSTEM; the adapter changes no foreign sublayer,
filter, Firewall profile default, route or existing account.

The baseline covers both IPv4 and IPv6. Exceptions are loopback, bounded DHCP
and neighbor discovery, and the captured Home LAN policy. Public peers receive
no endpoint-wide or all-port rule. Each physical permit requires the isolated
user SID, interface LUID, protocol, exact local address/port and exact remote
address/port. Socket descriptors remain owned until the corresponding filters
are independently absent. Late native operations retain their resources for
retryable cleanup.

The seven-second grant receipt is an application admission deadline. WFP does
not attach that timer to a filter. A separate memory-only broker monitor and
socket I/O deadlines stop new data admission if a control call stalls; the
source retains its exclusive handles while exact filter removal is pending.
Bytes already accepted by Winsock before cancellation can remain in kernel
queues. Their filters still identify the same isolated user, interface and peer;
they do not authorize another process or a replacement socket. Process death
closes the handles and BFE's dynamic session. Actual connected/queued-I/O,
blocked-control and process-death tests are required separately before Windows
dynamic admission, including the distinction between interrupting new writes
and retracting bytes the kernel already accepted.

The native Box supplies its actual TUN readback to the tunnel policy. An MTU
replacement first retires the old tunnel permit, then binds the returned native
reader, including a rollback that has a different interface index. A stale
network callback cannot acknowledge another generation's tunnel grant.

On-connect cleanup removes the exact captured baseline after all dynamic
permissions, sockets and token ownership have drained. Always retains the
baseline. Explicit recovery acquires the same exclusive session lock and
removes only a completely validated managed baseline; it refuses a live owner.
A cancelled recovery that never reached the caller cannot make a late policy
change. Closing an old owner cannot delete a replacement owner's lock.

## Verification and remaining integration

`deploy/test_desktop_windows_identity.py` is the actual Windows account/token,
Winsock and ALE proof gate. `deploy/test_desktop_windows_wfp.py` exercises the
actual BFE baseline, exclusive ownership, Always replacement, record/rule
rejection and explicit recovery. Every filter in the WFP fixtures additionally
matches the exact test executable, with the production loopback exemption
omitted. Tests do not change the host's Firewall profiles or other applications'
network policy. Production negative controls must fail their intended assertion;
a compiler error, missing capability, timeout or skipped test is not accepted.

`deploy/test_desktop_windows_traffic.py` adds the actual TCP/UDP IPv4/IPv6
transfer and renewal cases. A copied executable with a different independently
read AppID hosts the local peers; the subject's scoped rules therefore cannot
accidentally exempt its own listener. The gate also rejects ordinary-token
traffic, holds a native control operation while a real Winsock send is already
backpressured, checks independent data expiry and retained source handle/port
ownership, and kills a separate process to inspect BFE dynamic-object rundown.
The crash case deliberately exercises BFE lifecycle without creating an orphan
test account; isolated-token cleanup has its own identity and traffic cases.
These are required tests. At commit
`d6337bea2ee3c5f6d52351b0971b0c95bbc98649`, the completed identity, baseline and
traffic steps in [Windows job 123224546154](https://github.com/Eabusham2/router-vpn/actions/runs/40805819408/job/123224546154)
passed: 17 identity cases with 12 rejected production mutants; 12 baseline and
status cases with eight rejected mutants; TCP/UDP IPv4/IPv6 transfer and renewal,
blocked-control backpressure, actual process death, selected-adapter DHCP
readback, and two rejected traffic mutants. That workflow was subsequently
cancelled. These completed step results establish their named native
boundaries, not a complete release or the still-pending full shipping path.

The same runner exercises read-only DHCP capture for an actual IPv4 adapter and
rejects missing, substituted or malformed lease records. The factory helper
selects by the captured interface index, never by adapter enumeration order.
Static IPv4 adds no renewal server, and IPv6-only execution does not call this
IPv4 API. No DNS lookup, adapter change, route change or DHCP request is made.

### Generated native factory

`mobile/desktop/tor_physical_windows.go.tmpl` is registered in the same pinned
native preparation as the Linux and Darwin factories. It installs the owned
source at native Initialize, after default-interface capture and before TUN
startup. The real network monitor's selected name, index, addresses and masks
must agree with kernel readback. IPv6 Off omits that family's physical binding;
Home LAN uses the selected adapter's actual private or link-local subnets. The
factory captures only that adapter's IPv4 DHCP server and separately projects
the compiler's exact literal private destinations. No profile supplies an
account SID, token, LUID, firewall object key or helper executable.

Changes to the captured interface identity, address list, mask or up state
invalidate the in-memory generation. The WFP owner independently rechecks its
kernel LUID and local address before socket grants. A partial or late native
constructor remains owned through cancellation and Close; it cannot be
discarded while its operation is still completing.

Matching Windows native packaging runs `TestRouterVPNWindowsPhysicalFactory`.
Those wiring tests read the actual adapter, mask and DHCP lease and exercise
Initialize, replacement, partial-owner retention and teardown. They explicitly
replace only the privileged constructor and therefore do not substitute for
the real WFP gate or the final compiler-to-native selected-DNS and wrapper
composition. Public Windows strict dynamic admission remains closed until that
composition is verified.

### Prospective bootstrap composition

`deploy/test_windows_physical_bootstrap.py` verifies the exact prepared source
closure and then compiles the real Box, generated Windows factory, native
interface monitor, isolated socket owner, WFP policy and PT resolver callback.
Its explicit fixture selects Cloudflare HTTPS DNS at `1.1.1.1:443`; that is a
test profile, not a product default or a fallback. The query must receive a real
answer through the captured resolver, while an ordinary process-token socket
to that same endpoint is rejected by WFP. Independent readback checks the live
kernel endpoint and its exact resolver, local tuple, interface and capture.
The fixture also rejects a different compiler source, uncaptured context,
replacement DNS object and retired network generation, then checks exact
baseline/session-lock absence after cleanup.

Every test filter additionally matches the running test executable. The TUN is
the existing harmless Box fixture, so this gate changes no host route and does
not establish an actual TUN, Tor circuit, Connected state, full wrapper launch
or physical-device acceptance. The separate Windows diagnostic prepares the
same pinned core/Xray sources with CGO disabled and makes no package, PQ-link
or race claim. Matching Windows package builds also run the gate using their
actual shipping tags, verified PQ link environment and supported race mode.

While public Windows admission remains closed, `--prospective` overlays only
the reviewed static OS predicate in the test compilation. Additional test-only
visibility and executable scope also exist only in the Go overlay; no ordinary
binary accepts an environment, profile or request switch for those controls.
Cross-compilation alone is not an executed Windows result. Before publishing
admission, remove `--prospective` from both gates and rerun against the
unmodified admitted compiler/native source. This bootstrap evidence and the
separate remaining connection/installation evidence must remain distinct.

### Real Wintun identity and retirement

`deploy/test_windows_physical_tunnel.py` adds a separate actual Windows gate
for the shipping Wintun reader and `BindTunnel` / `RetireTunnel`. It reconstructs
the checksum-pinned sing-tun preparation in a private directory and compares
every prepared source and embedded driver byte before compiling. Extra, missing
or changed dependency files fail the gate; the subject is never repaired.

The test creates uniquely named, held native adapters with external
configuration and `AutoRoute=false`. It configures no addresses or DNS and
adds no default route. It compares the retained adapter's LUID with independent
Windows index/LUID readback, then reads the real WFP permit conditions through
a separate BFE session. IPv4-only and IPv4/IPv6 policies must have exactly their
required directions and families. A captured physical interface, wrong network
generation, duplicate binding and stale reader retirement are rejected. A
replacement reader remains authorized when its predecessor sends a late
retirement callback. Exact filter absence precedes reader close; complete
interface enumeration then proves the created adapters' names and LUIDs absent.

Three compiled production mutations must fail their intended native assertions:
allowing the physical interface as a tunnel, replacing the retained LUID in a
permit, and accepting another reader's retirement. All filters additionally
match only that test executable. There is no public OS-admission overlay in this
gate. Both native architectures run the standalone diagnostic; matching package
builds repeat it with their shipping compiler/link settings and supported race
mode. Cross-compilation is not actual Wintun acceptance. The bounded identity
and retirement result does not establish tunnel packet forwarding, selected-path
DNS through the TUN, a Tor circuit, Connected state, or physical-device behavior.

The WFP baseline gate by itself does not prove connected socket traffic or the
shipping Windows wrapper/factory composition. Those gates and the complete
native integration remain required before Windows strict Direct dynamic Tor
admission can be enabled. Cross-compilation is recorded separately from actual
Windows execution. The existing PowerShell WFP fixture is also separate from
the legacy `windows-kill-switch.ps1` production path; its success cannot certify
that legacy path or authorize changing another application's Firewall defaults.

Microsoft primary references:

- [WFP object/session lifetimes and transactions](https://learn.microsoft.com/windows/win32/fwp/object-management)
- [WFP access control](https://learn.microsoft.com/windows/win32/fwp/access-control)
- [Application and user conditions](https://learn.microsoft.com/windows/win32/fwp/permitting-and-blocking-applications-and-users)
- [User-mode ALE endpoint inspection](https://learn.microsoft.com/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0)
- [Winsock socket duplication](https://learn.microsoft.com/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw)
- [IPv4 adapter and DHCP lease readback](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersinfo)
- [Wintun retained adapter, session and close API](https://git.zx2c4.com/wintun/about/)
