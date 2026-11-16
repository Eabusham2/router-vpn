# Encrypted Server DNS failure diagnostic — 2026-11-16

The actual encrypted Server acceptance case `prefix-hostname-wg-one` reported
`hostname-question-aaaa` on both Linux architectures at `3f6e8420`.
The exact captured transport policy requested an IPv4-only question. Bare and
actual Shadowsocks-constructor reproductions retained IPv4-only lookup, so they
did not identify the full worker's failing call path.

This change adds a failure-only diagnostic replay. The original unmodified
worker, reference peer and acceptance case remain the release authority. Only
the observed hostname/AAAA failure triggers a separately identified Go overlay.
Regardless of the diagnostic result, the original exception is re-raised.
The original predicates, required cases, deadlines and successful receipt
conditions are unchanged.

The overlay observes Router and Client Lookup, Exchange and ExchangeAsync
entries, then executes their original bodies unchanged. Output is limited to
24 unique tuples drawn from fixed phase, question-type, domain-class, transport,
strategy and caller categories. It never emits an actual domain, address,
credential, config, stack or native error. The joined driver validates and
re-encodes the allowed fields before printing them. The helper remains a
template and cannot enter an ordinary Go package build.

Both diagnostic inputs are registered in the runtime build cache inputs.
A helper-only correction therefore invalidates cached validation.

## Executed validation

Validation used the complete current source closure at
`473b600727c87b944cb9233a27043ca239433745` over the original pinned relay core,
without modifying that core:

- Three actual race-instrumented helper/filter/SS roots passed, including real
  Shadowsocks TCP, UDP and ListenPacket lookup, direct AAAA Exchange
  classification, concurrent output bounds and private/duplicate-field controls.
- All 28 original and new encrypted-runner tests passed. These include proving
  that a successful or failed diagnostic cannot replace the original failure.
- The complete diagnostic shipping worker compiled under race instrumentation
  in 94.10 seconds.
- The actual encrypted acceptance driver compiled under race instrumentation
  in 37.33 seconds.
- The original 600-second compilation bounds and native/process/namespace
  bounds remain unchanged. Source and overlay identities were checked before
  and after each phase.

Worker SHA-256:
`3f551994aa497541ccca0d9ded643b9a7880ef9d76367d84dfb0b7e8dea56f26`.

Driver SHA-256:
`76e69e14e1beb632c55d055123a123c89adc518d99bcd8c7d7ede17dfb1df52f`.

Validation receipt SHA-256:
`94567f21957d6f82e2516f3aad24ff6337a5b370434692bfb56f5c68369b8883`.

The disjoint native client owner commit `3b605c0c` is preserved during
integration. Its only owned-file overlap is the runtime builder; only the two
diagnostic input entries are added there.

## Remaining evidence

The local namespace check could enter a user namespace, but the required veth
setup failed with `Cannot open netlink socket: Operation not permitted`.
No full encrypted-worker execution or hostname defect repair is claimed by
these compilation results. CI must supply the original failed case and the
separate diagnostic output before selecting a production fix.

