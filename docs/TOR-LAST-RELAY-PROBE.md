# Captured Tor last-relay probe prerequisite

The pinned Tor runtime contains an owner-only `BEGIN_DIR` stream operation. It
can reach the directory service of the last relay on the exact circuit of a
retained external stream. It returns native ownership and byte accounting; it
does not return a latency, score, or fabricated network success.

This is a prerequisite for Tor Local / Server / Compare. Public Compare
admission remains separate until both candidates carry client-origin probes,
the same selected external endpoint, valid proofs, cancellation, and exact
restoration through their shipping hosts.

## Measurement boundary

The last-relay stream sends exactly:

```http
GET /tor/robots.txt HTTP/1.0

```

The wire request uses CRLF, including the final blank line. It is 32 bytes. The
directory handler's successful body is the 28-byte robots exclusion response.
The relay operation is standard Tor `BEGIN_DIR`: it opens the relay's own
directory handler without resolving a hostname or opening an external TCP
connection. A relay that cannot serve it rejects the stream; it receives no
measurement or score. The client must validate the bounded complete HTTP
response and EOF.

The candidate handle retains the chosen external TCP/TLS connection
before measuring. It measures the last-relay HTTP request and, separately, one
external HTTP request through that same captured circuit. Both clocks belong to
the client and run from request transmission through complete valid response.
Control round trips, circuit setup, cached SENDME timing, and server-local
elapsed time cannot replace either operand. The user's formula remains
`(last_node_response_time + external_server_response_time) / 2`.

Protocol reference: [Tor opening streams specification](https://spec.torproject.org/tor-spec/opening-streams.html).

## Authenticated Server candidate

`ServerTorClient.OpenLastRelay` implements the common captured comparison
handle for Server execution. The shipping Server outbound on desktop and
mobile delegates only after its full native Box, private entry, selected DNS,
and existing Tor lease have been proved. The full client Box source identity
and the authenticated Server policy source remain separate captured values.

The no-TUN Server worker installs a private comparison handler on its existing
exact-peer, authenticated lease front. This uses a distinct SOCKS command
(`0xf0`), never an ordinary CONNECT to a magic hostname. Ordinary CONNECT to
the reserved namespace is rejected independently by the front. A missing
handler, invalid private operation, or expired capability has no DNS or normal
outbound fallback.

The private protocol has bounded, strictly parsed request/response frames for
open, control, probe, verify, and close. Every frame names the immutable lease,
source, registry, DNS policy, handle, selected target, and a fresh one-use
challenge. Only the two approved numeric HTTPS comparison endpoints can be
selected. The Server opens that actual Tor SOCKS connection and derives its
native ANCHOR using the connection's real local socket address and the owned
SOCKS isolation. The resulting circuit and relay path remain fixed across both
operands; verification rejects a replacement stream or path.

After admission, the open stream carries end-to-end TLS and HTTP bytes to the
client. The separate probe stream carries the actual relay-local HTTP request
and response. The client validates the external TLS identity, complete HTTP
responses, native identities, and exact probe byte counts. It measures each
HTTP request through its own complete valid response. No Server control-frame
timestamp or Server-local duration enters either score.

Both the client and the native Server require fresh selected-DNS and Tor path
proof. Their captured proof lifetime is at most 30 seconds; the independent
native one-use probe grant remains at most 10 seconds. The Server's ordinary
data-expiry owner also gates the measurement socket's entered reads and writes,
including when a control request is still finishing. Control forwarding allows
only INFO, CAPTURE, STATUS, and CLOSE for this exact retained anchor. It cannot
select a different native controller or forward general Tor commands.

Measurement Close retains issued control work, entered socket I/O, the native
probe, and its external anchor until their actual cleanup is acknowledged. It
does not stop the entire candidate on success. An ambiguous native response
keeps ownership pending. Whole-candidate teardown can still send the exact
authenticated lease DELETE, join the actual Server child, and retry comparison
cleanup using that independently verified stop acknowledgment. A closed socket,
expired wait, or a replacement owner's stop is insufficient.

The executable tests exercise real loopback front authentication, TLS and HTTP
byte transfer, target and ownership rejection, nonce reuse, pending-command
cancellation, independent expiry, and retained I/O cleanup. Their native reply
fixture is deliberately separate from the actual pinned C test suite below.
The generated Server worker tests also start the verified client-only Tor
binary with networking disabled and check that neither an invented proof nor
a private probe token can enable unproved traffic. These tests do not establish
physical-device, off-LAN, or public Tor network acceptance.

## Native ownership

All operations use `ROUTERVPN_LASTRELAY` on the actual authenticated owning
controller. The command parser wipes private input after handling it.

| Operation | Purpose |
|---|---|
| `INFO` | Read exact protocol version, fixed bounds, and generation high-water mark. |
| `ANCHOR` | Find exactly one open ordinary stream from the retained SOCKS socket's actual local IP/port, private SOCKS isolation, and selected numeric external target. |
| `CAPTURE` | Capture that native stream, its circuit, full relay path, final relay, one-use nonce, and absolute expiry. |
| `STATUS` | Read the captured immutable identities, actual request/response byte counts, stream IDs, END reason, and current lifecycle. |
| `CLOSE` | Revoke the exact capture and report whether its native stream has drained, without closing its external anchor or a replacement owner. |

`ANCHOR` scans at most 4096 registered native connections. It rejects absent or
ambiguous matches, nonliteral or private external targets, unfinished streams,
different isolation, and a stream no longer attached to its eligible native
circuit. It derives circuit, final-relay fingerprint, and full-path hash from
native objects. Echoed source/session hashes are not proof of a host owner:
the caller must independently bind them to its captured policy, fresh DNS/path
proof, and retained socket.

Captures use full anonymous circuits of three through eight hops. One-hop,
internal, unavailable, changed, and Conflux circuits are rejected. A capture
has a 100–10000 ms absolute grant and a strictly increasing generation. It
cannot be renewed or replace a stream that is still draining.

The returned reserved SOCKS address binds generation and a 256-bit nonce. It
can be used once, with the exact captured SOCKS credentials, on port 1. Missing,
expired, reused, mapped, or noncanonical capabilities fail before ordinary
address mapping, DNS, circuit selection, or CONNECT fallback. The actual
BEGIN_DIR stream attaches only to the captured circuit's last hop. It cannot
use optimistic data, retry on another circuit, send another HTTP request, or
accept more than 8192 response bytes.

Native timer, send, and receive paths recheck ownership. Expiry, changed
configuration, controller loss, anchor closure, changed circuit/path/isolation,
or malformed replies revoke the probe. The source, session, anchor, circuit,
path, final relay, and assigned stream identities remain readable during drain.
Only actual native close acknowledges a stopped stream. A conforming
BEGIN_DIR CONNECTED payload is ignored as the Tor specification requires;
duplicate CONNECTED, premature DATA, empty END, foreign-hop data, and exceeded
byte bounds are rejected.

## Build and executable evidence

The existing `mobile/tor/padding-source-lock.json` and integration patch now
describe the combined final native source state for circuit cover and this
probe. Shared relay/control hooks have one exact hash-checked final state.
The source pin, embedding ABI, and shipping client-only configure flags remain
unchanged. The lock includes both extensions and all six copied native source,
header, and test files.

Desktop and Server package gates execute:

```sh
src/test/test routervpn_padding/.. routervpn_lastrelay/.. relaycrypt/.. cellqueue/..
```

The native mobile host gate runs the same selectors before its resident
lifecycle scenarios. Upstream Tor's unit-test target deliberately enables
relay/directory objects for test peers. Its offline fixture exercises actual
three-hop cell encryption, stream attachment, directory request handling,
explicit EXITPOLICY and NOTDIRECTORY rejection, client socket response/EOF,
ownership, bounds, expiry, and drain. It does not build a public Tor circuit or
create a real network latency result.

The separate production executable and embedded host retain their client-only
configuration. With `DisableNetwork=1`, actual runtime smoke tests verify the
owned `INFO` capability and reject absent ANCHOR/CAPTURE requests. Desktop and
Server receipts also require rejection of a non-owning controller. These
runtime checks and the native test selectors are required by package
verification; source markers alone cannot satisfy them.
