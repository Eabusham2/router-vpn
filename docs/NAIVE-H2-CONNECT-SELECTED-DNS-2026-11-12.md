# Naive H2 over CONNECT: selected DNS and dormant lower resolver trees

## Admission boundary

The imported compiler now admits the original selected UDP, TCP, TLS, HTTPS,
and HTTP/3 DNS policies for a strictly validated literal Naive H2 transport,
including a selected resolver hostname with its explicit bootstrap. An optional
final AES/XOR peer must also retain its original literal address.

Both complete resolver trees remain in the executable graph. The selected DNS
and its explicit bootstrap use the established final Naive owner. The lower
resolver copies remain attached to the original CONNECT/final-layer owner;
they are recorded in desktop capture without manufacturing a lower UDP socket.
Exact tree equality, endpoint, port, TLS name, path, query options, original
credentials, strict transport validation, and retained-source identity checks
remain required. Hostname lower peers do not acquire this exception.

The Apple picker/save precheck follows the same boundary. Android continues to
use the shared compiler. The desktop capture test now requires the accepted
selected DNS transport, endpoint, TLS/path and complete lower tree while its
physical egress remains only the original CONNECT TCP tuple.

## Actual pinned native evidence

The runtime was prepared from clean Git checkouts at sing-box
`1ac1a339cb1223e9c70eae14c44411c75033c02d` and Xray
`50231eaff98ccc31b5cbd247a721c16e97fe5ec1` using the shipping preparers.
Go `go1.26.3` compiled the race-enabled native image. During final fixture
iteration, one explicitly declared test overlay supplied the updated
`node_naive_dns_test.go.tmpl`; it did not replace production transport source
or relabel another prepared-source receipt.

The official Cronet module was checksum-verified and staged using packaging's
own helper. Its version is `v0.0.0-20260912104006-c10c03c318db`, the Linux amd64
library is 11,915,768 bytes, and its SHA-256 is
`23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294`.
The formerly available older fixture library has the same digest, but the
actual execution used the freshly staged official module.

Three independently bounded native phases passed exact RUN/PASS inventories:

| Native phase | Required verdicts, including root |
| --- | ---: |
| Naive selected DNS over CONNECT | 49 |
| Existing literal Naive endpoint controls | 24 |
| Existing literal Naive over CONNECT and final-layer controls | 53 |
| Total | 126 |

The new phase covers seven selected DNS forms across HTTP/HTTPS CONNECT and
no final layer/AES/AES-XOR: UDP, TCP, TLS, HTTPS, HTTP/3, hostname HTTPS with
explicit UDP bootstrap, and hostname HTTP/3 with explicit UDP bootstrap.
Separate refusal cases change the selected port, path, TLS name, trust, or
explicit bootstrap port. Query-shape controls reject foreign question names,
classes, types, IDs and message shapes.

Every transport case retained zero lower DNS exchanges/lookups and zero lower
UDP attempts. Native selected DNS returned the exact expected A answer with
one application receipt; hostname cases also required one explicit bootstrap
receipt. The pinned TCP/TLS multiplexer asynchronously sends ID 1/A and
ID 2/AAAA connection-reuse probes. These are counted separately, exactly once,
and joined inside the existing operation deadline; they cannot satisfy the
application receipt. The HTTPS peer serves HTTP/2, avoiding an unrelated
HTTP/1 fallback and its second hostname lookup.

Image, declared overlay, and Cronet hashes remained unchanged across all three
phases. The image SHA-256 was
`9e860610702cd6c20a725f287141f5ef6b6d71b8100f114c14da68f931f9169a`;
the declared overlay SHA-256 was
`3c1cb6ebc55d9e7c97e4cbbc1d28c11451fcaad627aa1af9669e7f5b09fbcf9c`.
The selected-policy log SHA-256 was
`3da14486568164d88fd57cb3a0c6884a5e4a53efa66993ddb0eec3dd24c606b9`.

This is actual pinned encrypted loopback/native-DNS evidence, not OS TUN,
physical-interface, device or live-router acceptance. Those existing release
gates remain mandatory. The new phase retains its own 90-second execution
bound; no existing deadline or negative-control inventory was reduced.

## Producer and source checks

- Shared Naive H2 race tests passed, including the complete original independent
  layer inventory and selected-DNS ownership/refusal cases.
- The new complete-tree regression covers both CONNECT carriers, all three
  final layers, HTTPS/HTTP3 selected policy and UDP/TCP explicit bootstrap.
  Missing, foreign, cyclic, changed-port, changed-transport, changed-TLS and
  physical-bypass lower trees are rejected.
- Official Swift 6.4.2 picker/save checks linked to the actual Go compiler passed
  all 122 checks. The Apple graph producer passed 81 separate shipping
  Swift/actual-Go graphs and 4,427 checks. Linux's existing test crypto bridge
  was used; this does not claim execution on an Apple device.
- Mandatory-runner tests retain every original verdict, add the complete new
  inventory, and reject missing, duplicated, skipped or failed results.
