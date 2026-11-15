# Imported Shadowsocks Server packet-prefix evidence

This increment extends the existing schema-2 server suffix from a single
imported Shadowsocks node and paired final to the existing ordered capacity:
one to six paired WG/AWG prefixes in the complete path, one penultimate
Shadowsocks 2022 import, and the original paired Shadowsocks final. The entry
remains client-owned; up to five additional packet prefixes belong to the
server suffix. This does not yet extend the client Server/Compare controller.

The operator plan captures each server-side packet prefix independently.
Every position retains its node identity, source, keys, Start Layer, and proof;
the imported member retains its distinct public-path identity and remains
penultimate. Physical admission belongs to the first actual server prefix.
The imported endpoint stays literal and gains no ambient resolver authority.
Selected DNS and the paired final keep their original owners. SOCKS and
CONNECT retain their separate schema-3/schema-4 trio boundaries.

The existing maximum path length and transport-capacity limits are unchanged.
Deep layered configurations that exceed the original Local packet capacity
are still rejected. This change does not permit arbitrary imported positions
or multiple imports.

## Executed checks

Using Go 1.26.3 with the race detector and constrained build concurrency:

```sh
go test -p=1 -race ./internal/mobilemultihop ./internal/multihoprelay \
  -run 'TestNodeChainServer|TestNodeChainImportedServer|TestNodeChainImportedPrefixCapture' \
  -count=1 -timeout=120s
go test -p=1 -race ./internal/mobilemultihop \
  -run '^TestNodeChainImportedServerPrefixStartLayers$' -count=1 -timeout=60s
python3 deploy/test_server_node_chain_encrypted_runner.py
```

The first command passed in 77.529 seconds and 1.973 seconds for its two
packages. The Start Layer/capacity command passed eighteen cases in 23.731
seconds. All twenty-three strict runner tests passed, including omission,
duplicate, failed-cleanup, packet-position, and wrong-key receipt controls.
A compiled causal overlay restoring the old server compiler rejects the first
longer four-node case; the new positive test fails at that actual admission.

Canonical preparation used fresh checkouts at the existing pinned native
core and Xray identities. The actual race-built native driver passed all
twenty-two imported source cases in 7.774 seconds. The native peer component
passed WG/AWG packet-prefix compositions one through five in 1.256 seconds,
using the actual cryptographic devices and exact next-packet routing. The
canonical source verification checked 2,717 owned input records.

## Required remaining evidence

The encrypted Linux gate preserves its eight original imported cases and
requires fourteen additional longer cases. These include WG/AWG variants,
the maximum suffix, original authentication/DNS/LAN/retirement controls, and
wrong keys at the first and a later packet prefix. The original readiness and
native execution deadlines are unchanged.

Local compilation and loopback peer checks do not establish namespace
readiness, installed-client networking, a published release, or private
deployment. The hosted AMD64/ARM64 encrypted cases remain required. The
longer schema-2 client preparation, discovery, Server/Compare measurements,
restoration, and platform adapters are follow-on work.
