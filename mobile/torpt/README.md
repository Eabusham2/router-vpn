# In-process mobile Tor bridge transports

This module is the Go transport portion of the native Tor host. It is intended
to be compiled into the existing Libbox mobile runtime. It does not run a Tor
executable, create another system VPN, or load a second Go runtime.

The module embeds real obfs4, meek, WebTunnel, and Snowflake clients. Its local
SOCKS5 listeners accept only exact targets and transport arguments from the
session's validated bridge plan. Physical or detoured networking is supplied
by the active VPN owner's captured callbacks. An individual transport attempt
owns its own sockets, so handshake failure closes that attempt's connections
without borrowing another session's network.

The upstream client parses arguments anew for every obfs4 connection, including
generating a fresh ephemeral ntor key. Handshakes are canceled by closing owned
sockets. Disconnect closes half-open SOCKS handshakes, active relay pumps,
transport connections, and pending lower dials, and waits for them to finish.
A timed-out close retains ownership and can be retried; it is never a proof of
drain.

## Source pins

| Dependency | Version / source commit |
| --- | --- |
| Lyrebird | `v0.0.0-20261008205628-362a60bb4e3f`, commit `362a60bb4e3fa434130ef81a9990d83d6d8eaea5` |
| goptlib | `v1.6.0`, commit `f4bb5dd5725833bd880347b8fbaf60522ed0a710` |
| WebTunnel HTTP upgrade / TLS | `v0.0.7`, commit `11334a222c1beeb45759d436b7aef963a10600b2` |
| uTLS | `v1.8.2`; exact module checksum in `go.sum` |
| Snowflake | `v2.15.1`, commit `4f0256ed4f948d1c90fef465466c6b1e252cb3c4` |
| Pion | WebRTC `v4.2.18`, ICE `v4.4.1`, transport `v4.1.0` |
| Private KCP owner | `v5.6.72`, commit `78a2a3914a97fe8414b3f63054fad36c0a6e2e7c` |
| Private smux owner | `v1.5.57`, commit `3b4ec04d359934256b3adea7133374e3c93a0622` |

`SOURCE_LOCK.json` and `go.sum` record every exact required module version and checksum. `LICENSE-DEPENDENCIES.json` preserves the license and notice files from those verified archives. This nested test module
keeps PT dependencies out of the router's standard-library-only module. Native
preparation must copy these sources and the shared controller into the pinned
Libbox tree and preserve upstream licenses in the generated mobile artifacts.
The adapted meek, WebTunnel, and HTTP-upgrade packages retain their original
licenses and `UPSTREAM.json` manifests with source commits, module checksums,
original file hashes, and the reasons for each adaptation.

Meek's request worker now cancels active HTTP requests and blocked channel
operations, closes idle HTTP connections, and joins before its connection is
closed. A shared HTTP owner also freezes new physical operations, closes its captured sockets, and joins actual dial/read/write/close work, including TLS work that outlives a returned `RoundTrip`. Late standard-library housekeeping cannot touch the lower network. This fixes the pinned upstream deadlock when unread data and pending
writes both fill their queues. Bridge URL/front details are not emitted in logs.
Both spellings of the meek TLS fingerprint setting and the shared profile
grammar's multiple fronts are retained.

WebTunnel preserves application data buffered with its HTTP upgrade headers,
closes raw sockets on failed handshakes, and retains URL queries and IPv6
endpoint formatting. The previous HTTP-upgrade reader could discard the first
tunnel bytes when they arrived in the same read as the upgrade headers.

The pinned uTLS randomized generator chooses ML-KEM support and ML-KEM key
shares independently, while its TLS 1.3 retry handler cannot generate a missing
hybrid share. The adapter preserves the requested randomized hello and ensures
that a selected ML-KEM exchange is both advertised and backed by fresh real key
material. It uses uTLS's public spec/application APIs; certificate validation,
hybrid cryptography, and non-randomized fingerprints retain their normal path.

## Captured Snowflake networking

`StartWithNetwork` requires an explicit DNS callback, a copied native interface
snapshot, and the current VPN owner's packet callback for Snowflake. Its Pion
network has no system resolver, hardcoded public DNS server, fallback dialer,
or raw-socket escape. Broker names and STUN names use that captured resolver;
TCP and UDP use the same physical or predecessor socket owner. The native
outbound validates the exact resolver and predecessor dependency graph before
Tor acquisition, including domain strategy, cache, TTL, subnet, and timeout
options. DNS and socket operations that return late remain owned until they
actually finish.

The broker keeps the supplied HTTPS URL, query, front/SNI, HTTP Host, selected
TLS fingerprint, and bridge fingerprint. It bounds replies, rejects redirects,
and verifies certificates. Actual Pion WebRTC carries the upstream DTLS/SCTP,
TurboTunnel token/client ID, KCP, and smux protocols. Every VPN session creates
a fresh TurboTunnel identity. Replacing a transient proxy within that session
retains its identity for reliable stream recovery, as upstream specifies.

NAT discovery is an owned, bounded RFC 5780 worker. A timeout or an unsupported
response stays unknown; it is a broker matching hint and never connection
proof. Shutdown joins peer setup, graceful Pion close, retry packet pumps, NAT,
KCP and smux workers, broker physical IO, and the captured DNS/socket owner.
The private KCP and smux copies preserve their upstream protocol and add an
external completion hook; the KCP updater is session-owned instead of retaining
closed sessions in a process-global scheduler.

The native packet callback provides a destination/family hint, not an explicit
local bind API. Host ICE candidates are rejected if the actual socket address
does not match their claimed interface; no detoured socket is relabeled as a
physical interface. Server-reflexive gathering uses the actual captured UDP
socket. Local addresses are removed from shipping offers. The pinned Pion path
supports `stun:` over captured UDP; `stuns:` is explicitly rejected rather than
downgraded or silently skipped. The upstream Tor SOCKS argument size limit also
still applies to unusually long bridge arguments.

## Executable gate

From this directory, using Go 1.26.3:

```sh
go test -race -count=1 ./...
```

The gate transfers application bytes through a real local obfs4 server, repeats
eight handshakes against its shared replay filter, verifies that only the
captured network is used, rejects different bridge targets and arguments,
cancels an actual obfs4 handshake and an incomplete SOCKS handshake, and checks
that an intentionally late dial cannot escape the close barrier. It contacts no
public bridges or Tor relays. It also carries payloads through certificate-
verified meek HTTPS fronting and WebTunnel TLS/HTTP upgrade, rejects a wrong
certificate name, verifies distinct meek connection identities, and negotiates
actual X25519MLKEM768 traffic against a server requiring that hybrid exchange.
The unchanged uTLS client is required to fail its deterministic hybrid retry
negative control before the corrected hello is tested.

For reproducible source-based negative controls and a checksum evidence file,
run from the repository root with a new output directory:

```sh
python3 deploy/test-mobile-tor-pt.py --go /path/to/go1.26.3/bin/go \
  --output /tmp/routervpn-torpt-gate --upstream-negative-controls
```

That command verifies every pinned archive, dependency license notice, and
adapted source manifest. It then runs the same backpressure, physical TLS IO,
buffered stream, pending Snowflake dial, KCP reader, and smux reader regressions
against unchanged upstream production sources. All six original failures are
required; compilation failures and timeouts do not count. Finally it runs the
full race suite and verifies that no source input changed during the gate.

The Snowflake traffic fixture negotiates a real TLS broker and STUN server,
then transfers application bytes through actual WebRTC and original KCP/smux
server implementations. It exercises captured DNS, TCP, and UDP, distinct
session identities, and the shipping local-address removal policy. Additional
fixtures verify alternate-address NAT replies and transaction IDs, and show
that the actual private SOCKS bridge owner retains a delayed native DNS call.
These are local protocol and lifetime proofs, not public Tor exit traffic.

## Remaining runtime boundary

This module's gate does not enable Android or iOS Tor capability or prove a
mobile artifact was packaged. Native C dependency packaging, the single
Libbox/VPN host integration, and dynamic Tor exit traffic proof are separate
required gates. Tor core quiescence and transport drain are both prerequisites
for reusing a resident Tor process with another session's bridge configuration.
A bounded close wait that expires retains the old owner; it never certifies
that an unfinished operation drained.
