# Bound repeated public-point validation — 2026-11-16

The actual encrypted Server jobs for `17092d376b2708caa5c1ccbe5493ce617b703989`
(run `43806025753`) passed the one-prefix WireGuard and AmneziaWG cases, then
failed `http-connect/prefix-max-five` under the existing 15-second readiness
window on both Linux ARM64 and AMD64. All five private prefix identities had
been proved. The ARM64 snapshot had not reached CONNECT; AMD64 had opened its
stream without completing the public proof. These are later failures than the
already-fixed transport retirement and AWG receipt encoding issues.

## Observed cause and change

A race-instrumented component using the real five-prefix WireGuard Server Box,
CONNECT provider and Shadowsocks final spent 4,863 ms on 20 ordinary native
capture observations. Its CPU profile identified repeated fixed-scalar X25519
public-point checks through descriptor, request and capture validation. These
checks repeated for the same immutable public bytes during each observation.

`nodeChainPacketPublic` now retains up to 256 successful public-point results,
keyed by the complete copied 32 bytes. Canonical base64, public-field encoding,
and high-bit alias checks still run **before every lookup**. Every miss runs
the exact previous X25519 `NewPublicKey` / fixed scalar `NewPrivateKey` / `ECDH`
sequence and clears the temporary shared value. Failed checks are never cached.
A short mutex protects bounded FIFO insertion and lookup; cryptography runs
outside the mutex, and concurrent misses are checked again before insertion.

The cache stores only a mathematical property of an immutable public point.
It stores no credential, descriptor, session, lease, policy, network observation,
DNS result, connection proof, or execution choice. All corresponding freshness,
identity, duplicate-owner and teardown checks continue to execute. No deadline,
probe count, network policy, public-key alias rule, or negative control changed.

## Verification

The exact source passed 643 selected Go race-instrumented test records, with
zero failures or skips. These include the new warm-cache/cold-cache equivalence,
low-order and malformed encoding cases, bounded eviction and concurrent use;
the existing complete ordered capture and packet-prefix identity matrices; and
external packet wrong-owner/key/alias and concurrent canonical-owner cases.
The Go execution took 7.946 seconds under the original 120-second bound;
compile plus execution took 12.119 seconds under the 180-second outer bound.

Three separately compiled source mutations failed at their intended witnesses:

- Removing the canonical check admitted a newline alias through an already
  warmed entry and failed `TestNodeChainPacketPublicMemoCanonicalCacheHit`.
- Skipping the original ECDH miss check failed the comparison with the complete
  previous canonical/ECDH validator on a rejected point.
- Removing bounded eviction failed the fixed-memory and revalidation test.

The same actual five-prefix native component was rebuilt with only the point
cache substituted into its original shared implementation. The previous ECDH
body was checked byte-for-byte. Both builds used the same original 300-second
compiler bound; both component runs retained their existing two-second proof
request and 85/90-second test/process bounds.

| Actual component observation | Before | With bounded point cache |
| --- | ---: | ---: |
| 20 native capture observations | 4,863 ms | 683 ms |
| Five private prefix responses | 176–197 ms each | 32–42 ms each |
| CONNECT public proof | Failed its 2-second request bound | 372 ms |
| Final private node proof | Not reached | 233 ms |
| Selected DNS through final SS UoT | Not reached | Passed |
| Original captured stream/packet shutdown | No positive completion | All original owners closed and joined |

The changed component test completed in 2.58 seconds; the process, including
race/profiling shutdown, completed in 3.782 seconds. These are single observed
component timings, not a general product benchmark. This fixture exercises real
encrypted transports and native Box owners, with explicit first-physical-tuple
and OS-interface-monitor adapters. It does not replace the full command worker,
kernel carrier, mixed-prefix hosted gate, installed applications or device tests.
The exact-SHA hosted Server jobs must establish that separate acceptance.

## Reproducible evidence identities

- Shared race log SHA-256:
  `18021ef83c8921d0fade591a7c0d60b820b3b36f88ca65f2b01645f6d2a591d4`.
- Unchanged cache source SHA-256:
  `493e939967eab7fed29a9348aae188a3f5ff020848e54033427270805bed0663`.
- Before-component log SHA-256:
  `506bf627918268fdadc46f3e8f2f44f966b892de471cadca659650a362412605`.
- Changed-component log SHA-256:
  `26ed66cc985a14b257cb06f8a88d4fc0c7a47c4f6a6a4dc87ab43fb72a23d5df`.

The source-only, native-component and hosted release evidence remain separate.
This change is a performance repair, not a declaration that all Router VPN
requirements, private deployment, or physical-device acceptance are complete.
