# Raw-tunnel DNS proxy

`router-vpn-dns` is the package-owned local UDP/TCP DNS service used by raw
WireGuard, AmneziaWG and Rosenpass paths. The captured node policy supplies the
upstream protocol, literal IP, port, TLS certificate name and request path. The
controller separately verifies that captured policy against the runtime hint,
then sends its randomized DNS-query proof through this local service.

## Selected DoH3 behavior

`--protocol h3` and `--protocol doh3` use HTTP/3 over QUIC v1. The selected
literal IPv4/IPv6 address is the only dial destination. `--server-name` is the
TLS certificate identity and HTTP authority; it is never resolved through the
ordinary network. The selected port and local absolute request path are
preserved. TLS 1.3 and certificate validation are mandatory, and DNS data is
sent only after the handshake. The helper has no insecure certificate option.

One service owns one reusable HTTP/3 transport, QUIC connection pool and UDP
socket. Queries use POST with `application/dns-message`. A request must return
HTTP 200, the DNS media type, a bounded complete body and a correctly framed
response matching the actual query. Redirects, wrong certificates, wrong DNS
questions/IDs, oversized bodies, truncated HTTP bodies and DNS TC responses
fail. There is no HTTP/2, TCP or plaintext DNS fallback for H3. The separately
selected **Rescue** mode retains its explicit existing fallback policy.

Each request has a four-second upper bound and receives the captured service
context. Shutdown cancels both local listeners, joins admitted UDP/TCP workers,
joins pending H3 dialing and connections, retires the QUIC packet reader, and
closes the exact owned socket. A cancelled operation cannot write a response
for a replacement owner. The local listener has a bounded 256-worker limit.

Home resolver identity remains a node policy responsibility. The proxy does
not invent an AdGuard address or silently switch an unavailable Home resolver
to a public service. Encrypted Home DNS requires a real server certificate
trusted by the device and matching the captured certificate name (or IP SAN).

## Build and notices

The nested `cmd/dnsproxy` module uses installed **Go 1.26.3** and
**quic-go v0.64.1**. Keeping it separate preserves the root controller/server
module's Go contract. The checksum-pinned runtime dependency closure is
quic-go, qpack, x/crypto, x/net, x/sys and x/text. The build helper validates
the exact module files, module-cache h1 content checksums, actual compiled
dependency versions/checksums, license text and final binary metadata.

```sh
python3 deploy/build-dnsproxy.py test
python3 deploy/build-dnsproxy.py build linux/amd64 /tmp/router-vpn-dns
python3 deploy/build-dnsproxy.py notices /tmp/DNS-PROXY-NOTICES.json
```

`test` runs the nested module's complete race suite explicitly; root
`go test ./...` does not enter this module. `build` accepts the existing
Windows/macOS/Linux and qualified Unix target matrix, uses readonly modules
with CGO disabled, and never installs or replaces the Go toolchain. Existing
package scripts, the CI-built initialization image and its bounded client-only
package fallback all use this helper. Production server deployment remains
image-only.

Windows ARM64 uses `test --without-race` because Go1.26.3 has no race detector
for that native host. It executes the same full H3/CLI tests. That option is
rejected on hosts where the pinned toolchain supports race instrumentation.

The exact notices are both embedded in the binary (`router-vpn-dns --licenses`)
and staged as `DNS-PROXY-NOTICES.json` beside it. Generic package assembly
includes that file in the existing exact-source package manifest/checksums.
Checkout builds retain Go VCS metadata; source-archive builds retain the
enclosing package's source-SHA provenance rather than inventing a Git checkout.

## Verification boundary

Tests perform real loopback QUIC/TLS/HTTP3 exchanges with a private test CA,
real subprocess CLI startup, UDP/TCP forwarding and the same DNS probe used
by kernel connection proof. A TCP listener on the H3 endpoint detects an
unwanted HTTPS downgrade. Negative tests cover certificate, selected path,
response framing, cancellation and resource ownership failures. These are
automated local tests; they do not establish physical-device behavior, a live
AdGuard endpoint, live tunnel routing or private deployment acceptance.
