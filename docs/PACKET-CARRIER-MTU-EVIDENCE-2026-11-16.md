# Captured SS2022 packet envelopes — November 16, 2026

## Change

The MTU plan validator now follows a captured WG/AWG packet through every
intervening SS2022 datagram carrier to the original preceding packet interface.
The old check examined one wrapper. The new helper rejects missing, duplicate
or cyclic ownership and bounds the complete walk to sixteen owners.

The calculation includes each literal IPv4/IPv6 destination address, AES
identity-key headers, ChaCha's nonce, both request and response framing, and
port-53 control-packet padding from the pinned sing-shadowsocks v0.2.8 packet
writers. Only the outermost carrier contributes an IP/UDP header. Original AWG
handshake, cookie, enabled junk and transport padding remain part of the budget.
The existing `EndpointEnvelope` and `PacketEnvelope.Capacity` implementations
are unchanged; minimum MTU, fixed-budget rejection and control limits remain.

The helper preserves native-valid UDP network representations and explicitly
disabled UDP-over-TCP options. It refuses enabled UDP-over-TCP, TCP-only paths,
malformed options, invalid literal endpoints or ports, and more than 64 keys.
The native parser rejects a literal empty network string; it is not treated as
the valid absent/empty-list default. Selected source bytes are never rewritten.

Implementation and regression sources:

- [Captured carrier arithmetic](../internal/awgpolicy/packet_carriers.go)
- [Envelope and boundary cases](../internal/awgpolicy/packet_carriers_test.go)
- [MTU plan integration](../internal/mobilemtu/policy.go)
- [Complete-path and option compatibility cases](../internal/mobilemtu/packet_carriers_test.go)

## Exact local validation

This independent four-file unit was composed on published parent
`4636b2341d203a9c5d4f77f32b5b7327efe8753d`. The complete package suites ran on
that composition with Go 1.26.3, Linux AMD64 and the race detector:

```text
go test -race -p=1 -count=1 -timeout=180s ./internal/awgpolicy ./internal/mobilemtu
```

Both package verdicts passed: awgpolicy 1.036 seconds and mobilemtu 2.037 seconds.
The joined command took 7.784 seconds within its unchanged 300-second process
bound. All captured Go/module inputs were byte-identical before and after the
run. The nonverbose package output does not provide an individual test count.

The source inventory SHA-256 is
`7a0be9f6cfad6e1ded1a09ab19de4cdc7d2800a456fa273dd6985f49b0b8fdc6`;
the actual test log SHA-256 is
`98a1e1996c11f287729a1caf7a380c61eddcc41b2ac6698436e44b8c2a9bfd59`.

## Delivery boundary

This unit changes packet-envelope validation. It does not by itself expose
multiple imported nodes in a native app, project a later packet endpoint's
Auto setting, measure live PMTU, or establish native/device acceptance. The
schema-six compiler and native host work require their separate shipping
integration and execution evidence. No deployment or complete-release result
is claimed by these package tests.
