# In-process mobile Tor bridge transports

This module is the Go transport portion of the native Tor host. It is intended
to be compiled into the existing Libbox mobile runtime. It does not run a Tor
executable, create another system VPN, or load a second Go runtime.

The current tested increment embeds Lyrebird's real obfs4 client. Its local
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

`go.sum` records the exact module content checksums. This nested test module
keeps PT dependencies out of the router's standard-library-only module. Native
preparation must copy these sources and the shared controller into the pinned
Libbox tree and preserve upstream licenses in the generated mobile artifacts.

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
public bridges or Tor relays.

## Remaining runtime boundary

This increment does not enable the Android or iOS Tor capability. Meek,
WebTunnel, and Snowflake transport adapters, their worker shutdown boundaries,
native C dependency packaging, existing VPN host integration, and dynamic Tor
traffic proof must be completed before mobile Tor can be selected. Tor core
quiescence and transport drain are separate prerequisites for reusing a
resident Tor process with another session's bridge configuration.
