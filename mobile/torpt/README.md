# In-process mobile Tor bridge transports

This module is the Go transport portion of the native Tor host. It is intended
to be compiled into the existing Libbox mobile runtime. It does not run a Tor
executable, create another system VPN, or load a second Go runtime.

The current tested increment embeds real obfs4, meek, and WebTunnel clients. Its local
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

`go.sum` records the exact module content checksums. This nested test module
keeps PT dependencies out of the router's standard-library-only module. Native
preparation must copy these sources and the shared controller into the pinned
Libbox tree and preserve upstream licenses in the generated mobile artifacts.
The adapted meek, WebTunnel, and HTTP-upgrade packages retain their original
licenses and `UPSTREAM.json` manifests with source commits, module checksums,
original file hashes, and the reasons for each adaptation.

Meek's request worker now cancels active HTTP requests and blocked channel
operations, closes idle HTTP connections, and joins before its connection is
closed. This fixes the pinned upstream deadlock when unread data and pending
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

That command extracts the checksum-verified upstream module archives and runs
the exact same backpressure and buffered-stream tests against the original
implementations. Both original failures are required; compilation failures and
timeouts do not count as successful negative controls.

## Remaining runtime boundary

This increment does not enable the Android or iOS Tor capability. The Snowflake
adapter and its worker shutdown boundary, native C dependency packaging,
existing VPN host integration, and dynamic Tor
traffic proof must be completed before mobile Tor can be selected. Tor core
quiescence and transport drain are separate prerequisites for reusing a
resident Tor process with another session's bridge configuration.
