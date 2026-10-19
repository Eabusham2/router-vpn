# Native Tor outbound in the existing VPN runtime

These templates compile into the exact pinned Libbox core, using its existing
Android VpnService or Apple PacketTunnel owner. `routervpn-tor` is a TCP final
outbound with the captured connection session ID and the native core's existing
protected dialer or multihop detour options. An omitted or empty `bridges` list
selects ordinary Tor guard relays; nonempty lists use the strict bridge grammar.
Ordinary Tor never inserts a bridge. Its authenticated process-local SOCKS5
proxy carries only literal public relay TCP through the captured lower owner.
It rejects unauthenticated clients, domain targets, UDP and private addresses.

The resident C Tor invocation has an owned socketpair control connection and a
stable private directory independent of Libbox's disposable working path. The
host binds a canonical unlinked app-owned directory once per process; its open
directory identity survives session stops and rejects replacement or changed
permissions. It starts with networking and all
listeners disabled. A session can acquire it only after the previous session
proved both Tor configuration quiescence and independent transport/socket drain.
The final native close is reserved for a quarantined or finished process; normal
session changes never invoke `tor_run_main` again.
Only Tor's dedicated native thread and its children block SIGPIPE. This keeps
a closed proxy peer from terminating the app while preserving the host's own
process-wide signal handlers and calling thread mask.

Bootstrap begins at `StartStateStarted`, after the pinned core has started its
DNS, protected network, and TUN owners. In-process bridge listeners are bound to
the exact bridge arguments in that session. Fresh random SOCKS authentication
isolates application streams, and readiness requires the fixed HTTPS Tor check
to return `IsTor: true` and a public exit address through that final authenticated
SOCKS outbound. Configuration acceptance and bootstrap percentage cannot report
a connected VPN by themselves.

The Go host entry points are:

```go
Libbox.RouterTorSetStateDirectory(directory string) error
Libbox.RouterTorCreateProof(server *CommandServer, outboundTag, sessionID string) (*RouterTorProofRequest, error)
Libbox.RouterTorCreateProofWithPredecessor(server *CommandServer, outboundTag, sessionID, profileJSON string) (*RouterTorProofRequest, error)
request.Run() (string, error)
request.Cancel()
request.Healthy() bool
```

The factory captures the actual native instance and adapter before any wait.
The host retains that handle through UP and invokes `Cancel` immediately on
STOP or network change, before waiting for its serialized native close. Cancel
never consults a mutable host service or cancels a replacement session. Run
returns JSON containing
`session_id`, `ip`, `is_tor`, and `checked_at`. The caller must pass its frozen
session ID and final outbound tag. WithPredecessor first verifies the immutable
private Router VPN entry through that same captured lower graph; entry tokens
are not copied into Tor profiles or proof JSON. The fixed HTTPS Tor exit check
uses verified synchronous TLS/HTTP and joins its physical read/write/close work.
`Healthy` checks the same native/session/state/transport owners without making a
new network probe; it does not claim renewed public reachability. The original
`RouterTorProof` convenience function remains a synchronous factory/Run wrapper.
`RouterTorSourceNotices() string` exposes
original transport licenses, module checksums, and source/adaptation manifests;
those bytes are embedded in the same final Android/Apple Go library.

Disconnect cancels traffic, waits for bounded local control commands to finish,
disables networking/SOCKS/bridge configuration and every upstream proxy field,
joins application, private proof, PT and ordinary TCP proxy workers,
and repeats the actual Tor quiescence check before releasing the resident lease.
A pending native acquisition or lower dial remains owned after a close timeout;
it quarantines the process instead of becoming a connection in another session.

## Reproducible gate

Build the pinned host C package with `deploy/build-mobile-tor-package.py`, then
use a disposable checkout of the pinned Libbox core and a new evidence directory:

```sh
python3 deploy/test-mobile-tor-outbound.py \
  --go /path/to/go1.26.3/bin/go \
  --vendor /path/to/disposable/pinned-sing-box \
  --native-package /path/to/verified/host-tor-package \
  --output /tmp/routervpn-tor-outbound-gate
```

The gate verifies the immutable native DNS preparation guard, then runs actual
obfs4, meek, WebTunnel, and Snowflake application payload fixtures in the single
native module dependency graph, links the Libbox host APIs, and tests captured
proof request cancellation and health. In each of two fresh native processes,
it runs 12 alternating pairs of actual C Tor sessions requesting its owned
in-process obfs4 transport and ordinary relay TCP. The ordinary sessions run the
shipping native constructor, send real TLS ClientHello bytes through the
captured predecessor, and delete each disposable Libbox runtime after stopping.
Each native session must stop, drain its captured pending transport work, and
quiesce before the same C invocation is reused. The final deliberately late PT
dial in one process and ordinary TCP dial in the other must time out, retain
ownership, and quarantine native Tor permanently. Captured
test dialers carry no public bridge traffic, so these native lifecycle fixtures
cannot satisfy or fabricate the public Tor exit proof.

## Snowflake bootstrap DNS

Snowflake additionally requires its existing native dialer's explicitly named
`domain_resolver`, or the same Box's explicit route default. An explicit resolver
on a literal predecessor dialer captures the pinned resolver option semantics
without replacing the entry's separate underlay hostname resolver. The selected remote
DNS transport and all of its DNS bootstrap dependencies must use the exact Tor
predecessor detour. Direct Tor uses the captured protected direct owner; Tor
after an encrypted or multihop predecessor uses that predecessor. No public
resolver, default host network, or DNS final-route guess is supplied here.

The native adapter captures the DNS/network managers, resolver options, actual
transport and predecessor identities, and a copy of their interface prefixes.
Before Tor acquisition, it rejects missing/circular dependencies, Tor reentry,
local or uncaptured DNS, and a resolver detour that differs from the predecessor.
Late DNS answers and lower sockets are rejected after cancellation or native
owner replacement and remain counted until their real operations complete.
Application DNS through the final Tor exit is a separate saved host policy.

Final native app packaging, host selection, and an actual mobile session's
final traffic proof remain required before the host can report Connected.
The isolated fixtures do not claim public Tor traffic or device execution.
Pion uses the real
captured UDP socket; it does not invent source binding or UDP support for a
TCP-only predecessor. See the PT README for STUN and bridge argument limits.
