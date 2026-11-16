# Candidate measurement projection capture — 2026-11-16

The shared measurement engine now verifies its original execution projection along with runtime, trial and owner. The entry-candidate constructor did not initialize that captured projection. Its valid selected-path measurements were consequently rejected as stale.

The constructor now retains `p.projection` when it creates the shared measurement engine. The existing identity and stale-owner guards remain intact; no connection is reopened and no Compare selection is repeated.

## Actual validation

All nine existing entry-candidate roots and their 41 required verdicts passed with Go 1.26.3, race detection and default vet. These cover the original fifty-connection measurement, Server and both Compare winners, source/position refusals, original authority, metadata, typed SOCKS/CONNECT/OpenVPN sources, dormant owners, copied measurements, runtime activity and cancelled-drain ownership.

A separate compiled overlay restored the exact published preimage. The original Server measurement then failed with the required stale-route witness (two expected failure verdicts). This reproduces the defect without modifying the test.

Both phases retained their 180-second Go and 240-second process bounds and joined their original process groups. All 6,297 tracked source inputs remained unchanged. Local verification receipt SHA-256: `8dff093d507a9321d157082f14f8a0c40ad1c75d72d1ce069c2f5caac55cab90`.

This evidence covers the shared entry-candidate implementation; native packaging, release publication and device acceptance remain separate gates.
