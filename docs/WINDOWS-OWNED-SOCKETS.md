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
These are required tests, not a claim that a particular Windows run has passed.

The same runner exercises read-only DHCP capture for an actual IPv4 adapter and
rejects missing, substituted or malformed lease records. The factory helper
selects by the captured interface index, never by adapter enumeration order.
Static IPv4 adds no renewal server, and IPv6-only execution does not call this
IPv4 API. No DNS lookup, adapter change, route change or DHCP request is made.

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
