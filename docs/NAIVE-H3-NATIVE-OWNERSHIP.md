# Naive H3 captured transport and native name resolution

## Shipping behavior

A captured literal Naive H3 endpoint owns one UDP tuple: its original IP address
and port. The Cronet transport callback now admits only UDP to that exact tuple.
It rejects TCP, alternate ports or addresses, noncanonical literals and packet
listeners before invoking the retained lower dialer. Application TCP and UDP
still travel through authenticated Naive H3; application datagrams retain UoT-v2.
The original caller context, returned connection and lower error are preserved.

Cronet can request an unrelated IPv6 reachability socket even when an outbound
has one captured server. The original native diagnostic observed and refused
`[2001:4860:4860::8888]:443` at its strict lower owner. The new literal guard
prevents that callback from reaching the lower owner. It supplies no synthetic
probe result and grants no substitute destination.

The checksum-bound Cronet projection now applies the existing IPv6 literal
mapping and terminal-dot-free runtime name to H3 as well as H2. The exact
hostname maps only to the original captured IPv6 literal, preserving its port.
The derived runtime name is used consistently for URL, resolver alias and TLS
SNI, following [RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).
Saved options, source identity, credentials, certificate trust and selected DNS
are unchanged. Strict ASCII hostname validation prevents wildcard or resolver
instruction injection. The native Cronet library is unchanged.

## Raw hostname compatibility and scope

Shipping paired/imported Naive compilers validate a literal server. The broader
underlying native constructor also accepts raw hostnames. This unit returns the
identical original H3 dialer for that raw-hostname path, preserving its existing
DNS callback and lower-owner enforcement. It introduces no DNS-answer grant
observer, alternate resolver, ambient lookup or public-UDP exception.

The pinned outbound changes only the Cronet `Dialer` argument. Reversing that
one exact edit must recover the complete original source SHA-256
`9e01f79402408a0325b7e14334c0c8e72183f7963ca5efcc80bf201ea14c59f3`.
The original `DNSResolver` closure and its `ResolveDialer` remain byte-identical.
All mobile, relay/server and desktop preparations include the policy and its
source closure. The private Cronet copy retains the complete checksum/reversal,
ownership and drift checks documented in [the H2 resolution unit](NAIVE-H2-NATIVE-RESOLUTION.md).

## Validation on 2026-11-09

The final production-order preparation passed `go mod verify`, then the following
strict gates without skipped verdicts:

| Gate | Observed result |
| --- | --- |
| Policy/source contracts | 18 roots passed, including seven transport and five resolver/name causal mutations |
| Existing runner/source-authority contracts | 64 roots passed |
| Prepared transport helpers | All 40 verdicts passed under the race detector |
| Projected Cronet helpers | All 83 verdicts passed under the race detector |
| Real native H2 and H3 peers | All 48 verdicts passed under the race detector, 24 for each protocol |
| Separate native causal overlays | All three failed at their intended boundary: unwrapped H3, removed IPv6 mapping, and removed dotted-name derivation |

The native peers retained the original IPv4/IPv6, UDP/TCP bootstrap, username,
password, TLS-name, certificate and fresh-owner controls. Wrong identity or
trust delivered no authenticated payload. Positive captured-literal cases
performed real authenticated TCP and UoT-v2 exchanges with zero upstream
bootstrap queries and zero unexpected lower callbacks. Removing only the H3
wrapper restored the unrelated callback; removing only the IPv6 mapping or
wire-name derivation restored the corresponding name/handshake failure.

The first literal-only run passed every actual literal case but failed the two
negative cases that deliberately replace the endpoint with a raw hostname.
Their former blanket zero-callback assertion did not match the chosen raw
compatibility scope. The corrected negatives require the exact original
refusal and exact original DNS authority; they do not permit any additional
lower I/O. The initial failure, final source and causal overlays are separate
records.

A separate test-only overlay compared the published original production at
`8be50dbfbd16173980ce672aa91dfba2cee65cc7` against this unit, using the same strict
lower owner and original resolver. Both A cases made one A query, opened one
owned UDP connection and delivered one authenticated TCP and one UoT payload.
Both still failed the strict unowned-callback diagnostic because the original
lower refused one unrelated reachability request. Both AAAA-only cases made
two A queries and no AAAA queries, failed name resolution, and opened no owned
UDP connection or authenticated payload path. Those failed diagnostics confirm
unchanged raw behavior; they are not successful generic hostname acceptance.

The actual native image SHA-256 was
`b97f181521e84aa2f06482388afaa997b07dcd0a7ac82ab6f943e8714b28b283`.
The frozen shipping source receipt contained 3,142 files with digest
`02a23a6922253ab1e3cee478f4ac7c66ebb02095324b77d763800a99390c5863`;
the 4,711 prepared entries had digest
`4a98b43bb3061de53fb9f7f7c5fecc2a197367399171a481f189cf20e5715e9f`.
The unchanged Linux AMD64 Cronet library SHA-256 was
`23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294`.
Source, prepared bytes and native library were read back after the final native
execution at 07:15:32 UTC and raw comparison at 07:17:32 UTC.

These measurements used the declared unit on base `8be50dbf`, not an existing
release artifact. The subsequent rebase preserves the tested unit bytes.
Current package/release source receipts must be regenerated for the combined
main tree; these protocol measurements do not substitute for them.

## Evidence limits

The native cases exercise actual pinned TLS/QUIC authentication, TCP payload and
UoT-v2 datagrams, with exact original lower tuples and independently captured
trust. The IPv6 tuple is remapped only to the owned local peer. This establishes
native protocol behavior; it does not establish a physical IPv6 route, system
TUN/WFP acceptance, an installed device result, or a completed current release.

The deliberately forced-hostname negative cases leave the literal scope. They
require the exact original lower rejection, a live original DNS request for
`unowned-bootstrap.invalid.`, the captured resolver with cache disabled, and
zero lower sockets, QUIC traffic or authenticated payload. Every actual literal
case separately requires zero unexpected lower callbacks and zero upstream
bootstrap queries. No failed raw-hostname diagnostic is counted as successful
literal ownership or generic raw-AAAA support.

An earlier experimental hostname-answer observer is explicitly superseded. Its
A/CNAME/TTL-zero controls did not establish raw-AAAA compatibility: the real
AAAA-only diagnostic requested A records, requested no AAAA records, and failed
before reaching the peer. That observer and its additional shipping gates are
absent from this unit. The experiment and initial fixture-scope failures remain
separate evidence, not native acceptance for the published source.

The imported H3 graph inventories, real entry-peer matrix, Windows protected
composition and package/release gates remain separate required evidence.
This standalone policy does not claim those feature gates are complete.
