# SOCKS native execution construction evidence

This increment connects the typed schema-3 client preparation published in
`74f6f3db` to the native Box execution owner. It preserves the original SOCKS5
association capture and unchanged paired SS2022 final, while the separately
authenticated server front uses the existing private UoT-v2 contract.

The distinct construction retains one original preparation, source, registry
capture, complete closed graph digest, and Box. Construction is single-use;
another source, preparation, Box, copied construction, or changed graph cannot
borrow it. Every native execution observation also checks the original SOCKS
outbound and its captured packet predecessor. The existing original manager,
selector, gate, TUN, DNS, and source checks remain in force.

Public middle measurement uses the original selected resolver for Local. Server
sends only the authorized measurement hostname through the original private
front, retaining remote selected-DNS authority. Selection changes, including
away-and-back changes during a request, invalidate the operation. The shared
native Last path binds the schema-3 policy to its original preparation and
fresh authenticated discovery; saved results never grant application readiness.

Preclose retains the original association capture even after source
cancellation. A bounded caller can stop waiting while the original close
continues; only that retained close may satisfy a later join. This is separate
from the actual Box close receipt and cannot establish native DOWN by itself.

## Executed native component evidence

The exact source was projected through the canonical preparation into pinned
sing-box `1ac1a339cb1223e9c70eae14c44411c75033c02d`, including its original source
ownership records. With Go 1.26.3, the following race run passed in 64.839 seconds:

```sh
GOTOOLCHAIN=local GOMAXPROCS=2 GOGC=50 GOMEMLIMIT=1800MiB \
  go test -race -p=1 -mod=readonly \
  -tags=with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego \
  -ldflags=-checklinkname=0 . \
  -run '^TestRouterVPN(ExecutionNativeSOCKS|CONNECTExecutionNative)' \
  -count=1 -timeout=120s
```

The nine new root tests cover the three packet-entry modes in Server and Compare;
actual native SOCKS and SS constructors; fresh discovery and gate-closed adoption;
changed sources, preparations, Boxes, copied constructions and options; retired
or cancelled owners; a held original close and its later join; selected resolver
and public hostname restrictions; original private-front credentials; real
SOCKS5 password authentication and UDP ASSOCIATE through loopback TCP/UDP peers;
UDP payload round-trip and joined control retirement; wrong credentials;
source cancellation; original Last discovery and cancellation/retry; and refusal
to mix Local and execution construction authority. Existing CONNECT native
execution tests ran in the same command.

The existing generic `NativeLastUsesOriginalDiscovery` and
`NativeRetainsOneGraphThroughDiscovery` race regressions passed separately in
3.253 seconds. All five changed native templates were byte-compared against
their exact tested canonical projections.

The registry, native protocol factories, managers, selector, application gate,
authentication, UDP association, and socket ownership run their actual code.
The TUN, OS monitor, packet predecessor, and selected DNS transport are explicit
component fixtures. The loopback packet predecessor provides no encrypted or
physical routing evidence. The final SS constructor is real, but this suite
does not claim encrypted final traffic, an installed TUN, kernel protection,
or Android/Apple device acceptance. The separate hosted encrypted SOCKS server
suffix gate remains mandatory.

Android and iOS native builds now run these exact new roots in a separate
90-second command, preserving the existing families and their original bounds.
The desktop build's existing complete compiled-root discovery includes them
in its execution phase. Preparation checks verify that the new templates are
owned, idempotent, and selected by each shipping build.
The node-chain preparation suite passed all 18 checks, CONNECT preparation
passed all 5 checks, and execution-owner preparation passed all 10 checks,
including the executable original daemon-close fixture.

## Remaining integration

The mobile CommandServer, retained mobile MTU restoration, desktop physical
owners, and platform UI/host adapters still need to adopt this native
construction. This increment does not make those unimplemented paths ready,
does not expand the trio-only SOCKS Server/Compare topology, and does not claim
the full historical requirements complete.
