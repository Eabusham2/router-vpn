# Captured mobile DNS comparison

This package measures real DNS answers through an already-proved native Tor or
ordinary external connection. It contains no system dialer, resolver fallback,
profile writer or connection starter. The mobile native adapter supplies the
exact captured final outbound, selected DNS router and activity lifetime.

## What a result measures

The public catalog contains the primary and secondary IPv4 and IPv6 endpoints
of Cloudflare, Google and Quad9. Each run uses one explicitly selected transport:
TCP DNS on port 53, authenticated DNS over TLS on 853, or authenticated DNS over
HTTPS on 443 with `/dns-query`. TLS certificate names remain bound to the chosen
provider while socket dials use literal catalog addresses. There is no ambient
hostname lookup, HTTP proxy, redirect, transport downgrade, UDP or HTTP/3 fallback.

A public sample includes a fresh native TCP connection, TLS setup when selected,
and a complete matching DNS A answer for `example.com`. It is a complete-query
time, not ICMP latency or an isolated server processing time. A usable median
requires all three samples to succeed. Invalid, truncated, mismatched, error or
unusable answers never become a positive timing result. DNS messages, HTTP
headers and response bodies are bounded.

The separate **Selected DNS** row queries the actual captured native DNS router
with its local caches disabled. It retains its saved transport and route: Home
AdGuard may traverse the private paired entry even when public candidates use
the external exit. Its timing is labelled separately because its connection
reuse, transport and destination can differ from the public comparison. Resolver
side caches are not controlled by this package.

IPv6-Off omits IPv6 socket attempts and reports those rows as unavailable. The
native adapter enforces the same restriction before calling an outbound. A
policy-filtered or unreachable candidate cannot win a fastest selection.

Catalog references:

- [Cloudflare resolver addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/), [DoT](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/) and [DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/).
- [Google resolver addresses](https://developers.google.com/speed/public-dns/docs/using), [DoT](https://developers.google.com/speed/public-dns/docs/dns-over-tls) and [DoH](https://developers.google.com/speed/public-dns/docs/doh).
- [Quad9 addresses, TLS name and DoH endpoint](https://quad9.net/service/service-addresses-and-features/).

## Ownership and cleanup

Factories require a successful proof for the exact running CommandServer/Box,
source, native session, node, DNS configuration and TUN. They retain the same
native activity exclusion used by measurement and MTU work. Network changes,
proof retirement, service replacement and a changed identity invalidate results.

Every Start uses a fresh 32-character lowercase hexadecimal nonce. Cancel records
a tombstone even before Start, so a queued callback cannot reopen that request.
Sampling uses four workers, a five-second sample deadline and a 75-second total
sampling budget. Those deadlines request cancellation; they do not establish
that native workers or sockets have finished closing.

The service retains every returned native socket, including a socket returned
alongside a dial error or after cancellation. Unknown close failures keep the
socket and native activity owned for retry. Drain acknowledges completion only
after workers, cancellation callbacks and socket closure have joined. A timed-out
drain keeps the operation and MTU hold pending. Terminal `net.ErrClosed` and
`io.ErrClosedPipe` report an already-closed socket; other errors are not treated
as cleanup proof.

Android retains its exact service owner across UI dismissal and keeps retrying
native drain. Apple IPC distinguishes the provider epoch from the native proof
session and reserves the nonce before acknowledging Info. A system disconnect
can remove provider messaging, so the provider also records an exact drained
receipt in the shared App Group after native cleanup. That receipt contains no
measurement results or credentials and can release only the matching cleanup
hold. It cannot select DNS or prove another connection.

If provider retirement temporarily cannot close its native owner or persist a
receipt, one retained session timer retries at a two-second cadence. Success
stops the timer. This does not release a separate native-runtime quarantine or
infer cleanup from an operating-system disconnect; process death before a
receipt is written remains unknown.

## Result adoption and verification

Hosts validate the receipt's schema, identities, transport, bounded fixed catalog,
sample counts and complete/drained state. Measured public rows can fill an
explicit next-connection DNS draft with the exact protocol, address, port, TLS
name and path. Applying the draft requires an idle validated Save. Measurement
does not change the active resolver, initiate Connect, or write the legacy
`fastest_dns_*` fields, which lack this transport and route provenance.

Selectable results expire after 120 seconds using a monotonic clock. A chosen
draft can survive an explicit Disconnect, but Save rechecks its exact saved
external source and paired entry. Changing that source invalidates the draft;
the editor does not silently attach old measurements to a new path.

The Go race tests exercise real DNS framing, certificate verification, local
TLS/HTTP exchanges, identity changes, cancellation and retained socket failures.
Prepared pinned-native tests cover the actual DNS router and external/Tor dial
adapters. Java and Swift fixtures execute host ownership and result validation;
Apple additionally tests the real cleanup-receipt filesystem and iOS SDK surface.
These checks do not establish a public Tor circuit, physical-device routing,
device signing or live deployment.
