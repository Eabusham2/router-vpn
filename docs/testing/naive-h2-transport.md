# Native Naive H2 transport ownership

The pinned Cronet runtime can request a UDP socket while starting an H2
connection, even with QUIC disabled. The H2 outbound now rejects that request
before it reaches the retained lower dialer. Application datagrams continue
through the original UoT-v2 TCP stream. H3 retains the exact original dialer.

## Original failure and cause

Two isolated Linux/AMD64 native executions failed the original no-lower-UDP
assertion in all eight cases. The second execution retained the assertion and
recorded the exact request: `udp [2001:4860:4860::8888]:443`. The lower fixture
refused it before network I/O. Valid credentials still carried real H2 TCP and
UoT-v2 payloads; wrong username, password, SNI and certificate refused payload.
Those payload observations did not turn the original failed witness into a pass.

Both the pinned Cronet wrapper and library identify native submodule
`SagerNet/naiveproxy` revision `72a06c9fca0e2d228588c7f3074bf7efff3ff686`.
Its [original host resolver source](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/src/net/dns/host_resolver_manager.cc)
uses that IPv6 address in `StartIPv6ReachabilityCheck`. It creates a datagram
socket, connects it to port 443 and inspects the local address. This is separate
from a selected DNS query and has no authority to use an H2 lower UDP transport.

## Declared shipping change

`deploy/native_naive_transport_policy.py` verifies sing-box revision
`1ac1a339cb1223e9c70eae14c44411c75033c02d` and the complete original Naive/UoT
source inventory. It changes one Cronet option in `protocol/naive/outbound.go`:
the dialer becomes `routerVPNNaiveTransport(outboundDialer, options.QUIC)`.
The separate DNS resolver closure still captures the original `ResolveDialer`,
including its selected transport and query options.

For H2, the helper forwards canonical TCP calls with their original context,
destination, connection and error. All other `DialContext` networks and every
`ListenPacket` call fail before lower I/O. For H3, the helper returns the original
dialer object and preserves TCP, UDP and packet-listener behavior.

Mobile Libbox, relay/server and standalone desktop preparation all apply this
policy. Their input closures include the original policy and tests. Mobile and
desktop native source checks require the exact declared output. Preparation
validates the entire plan before writing, refuses source drift and linked or
shared output owners, and supports idempotent preparation and read-only
verification. The native runner requires all 13 transport-policy verdicts and
keeps the original physical-bypass and H3-downgrade controls.

No selected DNS transport, bootstrap dependency, socket grant, operation budget,
or imported-H2 admission changes in this unit.

## Executed evidence

The fixed run completed on 2026-11-09 at 03:30:11 UTC. It used the unchanged
original failing witness, SHA256
`5ac6523a24d0ef6f50473a9096290146bd71483fded9678f780446f51e505fb5`, with its
unchanged 90-second runtime limit. The Linux/AMD64 Cronet library was
11,915,768 bytes with SHA256
`23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294`.

- The actual core policy passed 13 race-enabled verdicts across H2 and H3.
- Three executable causal controls failed at the intended policy assertions:
  unwrapped H2, admitted H2 datagram dialing and wrapped H3.
- The unchanged real native witness passed its root and eight leaves. Every
  leaf recorded zero lower UDP calls. Valid literal IPv4 endpoints with a
  different TLS SNI carried authenticated TCP and UoT-v2 UDP payloads. Both
  captured UDP and TCP bootstrap metadata were retained without DNS queries.
- Wrong user, password, SNI and certificate prevented authenticated payload.
  A deliberate native-only hostname mutation still made four calls through
  the original DNS resolver closure and reached neither lower TCP nor the TLS
  peer. The last positive case owns a fresh peer.
- Source, prepared-byte, witness and native-library identities were verified
  before and after execution. The fixed image SHA256 was
  `d67a84b11eeb24eb34baddd8e01d8b79c643d3a5c843c208d61cb9fe27c3139d`.

The frozen execution was based on `fb924d4849b448d519c573a78e021b595a216007`.
After preserving the Tor caller and ordinary Stop changes through
`b16656f53faf55f4a59e7c6f1f2f3ac7cee506cc`, the complete prepared source
comparison confirmed unchanged compiled native components. Only runner and
contract-test receipt entries changed. All 59 Unix and 46 Windows production
negative controls still construct from the exact prepared source, including
both original Naive controls. Existing native baseline, routing, Windows scope
and orchestration contracts also passed.

This evidence establishes the H2 transport boundary. It does not establish
imported-H2 graph acceptance, a real network bootstrap exchange, encrypted H3
peer acceptance, TUN/firewall activation, device acceptance or release status.
The literal endpoint witness does not remove the deliberately retained
bootstrap dependency or authorize UDP bootstrap through a TCP-only entry.
