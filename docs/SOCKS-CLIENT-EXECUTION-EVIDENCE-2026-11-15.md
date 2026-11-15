# SOCKS client execution source and controller evidence

This increment adds a distinct typed schema-3 client preparation and policy for
one WG/AWG entry, the original SOCKS5 import, and the original paired SS2022
final. It builds on the typed remote server suffix published in `c7f43af4`.
It does not establish native Box, desktop, Android, or Apple Server/Compare
acceptance. Those adapters are the next integration work.

`NewNodeChainSOCKSExecutionPreparation` retains the exact original
`NodeChainSOCKSSource` and private local runtime. The generic preparation,
policy, restoration, and launch APIs remain closed to this family. A distinct
canonical restoration parser creates a fresh typed construction; it cannot
lend that source pointer to another live preparation. Policies from fresh
authenticated discovery and original restoration proposals bind to the same
preparation and source. Native implementations must separately provide the
required original SOCKS observer before discovery or runtime construction.

The Local SOCKS outbound retains its original credentials, packet-prefix
detour, and actual UDP-association configuration. The original SS final retains
that SOCKS detour. Neither gains CONNECT UDP-over-TCP. The separate
authenticated private server front retains its existing UoT-v2 contract and
lease credentials. Both choices retain the original selected DNS policy and
physical packet-entry inventory. The application gate starts closed.

The shared runtime continues to use the average of final-node HTTP response
time and response time from the same random external HTTP endpoint. Both
candidates and the fresh winner proof use that same endpoint. A timeout makes
the candidate ineligible; the winner gets a separate trial and must prove its
original path before application activation. Restoration keeps the original
choice and private proposal instead of repeating Compare.

## Executed evidence

On the exact source of this increment, the following command passed in
160.013 seconds with Go 1.26.3 and the race detector:

```sh
GOTOOLCHAIN=local GOMAXPROCS=2 GOGC=50 GOMEMLIMIT=1800MiB \
  go test -race -p=1 ./internal/mobilemultihop \
  -run '^TestNodeChain(SOCKSExecution|CONNECTExecution|Execution(Preparation|Runtime|Discovery|SelectedDNS))' \
  -count=1
```

The new tests cover WG, AWG2-fast and AWG2-strong with password and no-auth
SOCKS sources, Server and Compare, canonical restoration, unchanged original
outbounds, separate front credentials, source/owner replacement, copied
bindings, missing/failed/cancelled observers, wrong schema/request families,
authenticated discovery, joined server lease stop, same-endpoint scoring,
fresh winner proof, timeout disqualification, retained restoration, and failed
public/DNS/final proofs. Existing CONNECT and generic execution tests also ran.

The runtime fixtures execute real HTTP/TLS clients and the actual lease
Manager, controller, comparison, and restore logic. Their native registry,
routing, selected DNS, and remote worker I/O boundaries are explicitly modeled.
These tests do not prove encrypted traffic, a native TUN, a kernel firewall,
or any installed platform. The earlier mandatory hosted encrypted SOCKS
server component gate remains required; the local nonloopback/netlink
environment boundary in the server-owner evidence record still applies.

## Remaining scope

Native Box construction, original association observation and joined close,
durable Last integration, and desktop/mobile adapters must adopt this typed
preparation before users can select SOCKS Server/Compare on those platforms.
This increment deliberately refuses longer SOCKS Server/Compare sources and
does not claim arbitrary mixed imported chains or the full historical
requirements complete.
