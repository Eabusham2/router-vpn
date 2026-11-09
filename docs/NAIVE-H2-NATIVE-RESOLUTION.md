# Naive H2 native address and TLS-name resolution

## Behavior

Naive H2 keeps its captured TCP lower transport and application UoT-v2. Its
Cronet client now treats the original IPv6 server address as a literal even
when the verified TLS name is a DNS hostname. An exact hostname-to-literal
resolver rule prevents Chromium's unrelated IPv6 reachability heuristic from
suppressing that address. The rule grants no UDP socket and introduces no
resolver address.

An absolute DNS name such as `captured-naive.test.` remains unchanged in the
caller's options, saved graph and source receipt. The H2 client derives
`captured-naive.test` for its runtime URL and resolver alias. This matches
[RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3),
which excludes a trailing dot from wire SNI. The derived name preserves the
original DNS identity, case, port, credentials and certificate trust. It does
not change the captured endpoint or selected DNS transport.

Only exact ASCII DNS labels are admitted into the resolver rule or dotted-name
derivation. Wildcards, rule separators, whitespace, escapes, malformed labels,
oversized names and address zones are rejected. Already encoded IDNA labels
retain their original spelling. The original H2 unit left H3 unchanged; its
later captured transport and name-resolution hardening is documented in the
[Naive H3 ownership unit](NAIVE-H3-NATIVE-OWNERSHIP.md).

## Source preparation and required gates

`deploy/native_naive_literal_policy.py` creates an owned private copy of
`github.com/sagernet/cronet-go` at
`v0.0.0-20260912104727-0d28acc44093`. It verifies the whole original module
against `h1:CsvsLVIli53L6nzgEpyRjjWnRRhTds4D3eh5sEnF5Sw=` and the original
`naive_client.go` against SHA-256
`367a29cbc783270e07f00d28d77f6b463033805bf4e100b53100f9373bf0f5a5`.
Exactly two source anchors derive the H2 wire name and install the IPv6 rule.
Reversing both anchors must recover the complete original module checksum.
The native Cronet library is unchanged.

The existing Naive transport policy invokes this preparation from the shipping
mobile, relay/server and desktop preparations. Their source receipts include
the complete copied module and exact helper templates. Preparation refuses an
unrelated module replacement, altered source, partial projection, linked file
or shared file owner. It never edits the shared Go module cache.

The release source audit runs both policy suites:

```sh
python3 deploy/test_native_naive_transport_policy.py
python3 deploy/test_native_naive_literal_policy.py
```

The prepared native host runner retains its original H2/H3 transport suite and
requires `TestRouterVPNDesktopNodeNaiveLiteral` with all 23 leaves and its
parent verdict. Missing, duplicated, skipped or replaced verdicts fail the
gate. The source authority and native library must pass the existing runner's
readback before and after execution.

## Validation on 2026-11-09

The first real native baseline failed both captured IPv6 endpoint cases with
`name not resolved`; its eight original IPv4, credential and DNS controls
passed. An exact original-startup control then confirmed that a dotted IPv4
name also failed before reaching its TLS peer. The untrimmed native resolver
alias did not match the DNS question. With IPv6 mapping installed alone, the
dotted IPv6 case reached the correct peer, which rejected the trailing dot in
wire SNI. Those failures were retained separately from the final passing run.

The final production-order prepared source passed:

- 18 policy/source contract tests, including eight deliberate policy mutations
  that each failed at the intended boundary.
- 64 existing native-runner and source-authority contract tests.
- All 13 original prepared H2/H3 transport verdicts under the race detector.
- All 47 actual projected Cronet rule/name verdicts under the race detector.
- All 24 shipping native peer verdicts, plus all 11 verdicts from the unchanged
  original IPv6 witness, under the race detector.

The native peer cases used real TLS, the pinned Naive H2 client and inbound,
authenticated TCP and UoT-v2 payloads, captured UDP/TCP bootstrap definitions,
and separate wrong-user, password, TLS-name and certificate refusals. Dotted
IPv4 and IPv6 names both authenticated successfully; their wrong-host and
wrong-trust variants still failed. The caller's original native options were
checked byte-for-byte after construction/startup. Successful literal cases
made zero upstream DNS queries and zero lower UDP calls.

Two separate declared native overlays removed one anchor at a time. Removing
the IPv6 rule restored the original IPv6 failure. Removing wire-name derivation
restored the dotted IPv4 and IPv6 failures. Both controls retained the TCP-only
guard, native peer assertions and all other prepared source. The final source,
native library and executable identities were read back after execution.

## Evidence limits

This is a native protocol and source-preparation result. The captured IPv6
tuple was checked exactly and then mapped only to the owned local TLS peer;
the test does not establish a physical IPv6 route, system-TUN operation,
installed application behavior or current release acceptance. These H2
measurements alone do not establish native H3 IPv6 behavior; the separate
[H3 ownership unit](NAIVE-H3-NATIVE-OWNERSHIP.md) records that later evidence.

Zero bootstrap lookups in these literal cases do not authorize removing the
compiled resolver dependency or changing a captured UDP resolver to TCP.
Imported H2 graph admission, all producer inventories, physical peer matrices
and default Home-DNS compatibility have their own required source and native
checks. This unit preserves those boundaries.
