# OpenVPN mobile execution bridge — 2026-11-16

This change connects the original schema-five OpenVPN execution preparation to
the actual libbox CommandServer factory. It preserves the sealed Local launch,
independent Local and Server credentials, selected execution, saved Last record
and opaque restoration. Android and Apple host admission are separate changes;
this bridge alone does not establish an installed mobile connection.

## Behavior

Distinct OpenVPN constructors parse original Local source or its sealed launch.
The execution envelope has its own kind and retains the complete preparation,
source/configuration digests and optional Last record. Reopening requires an
exact canonical envelope. Generic execution parsing remains closed to this
family.

The factory creates the exact caller-local outbound registry and supplies the
original preparation to the native Box context. Bind and subsequent native
readback require the same plan, preparation, source, CommandServer,
StartedService, registry and private owner. An ordinary server, equal-content
replacement or copied owner cannot satisfy that association. A second factory
reservation is refused, including conflicting CONNECT or SOCKS ownership.

Opaque restoration selects the original OpenVPN policy from the retained
restore owner. It does not rerun Compare or replace the already proved choice.
The native retirement checks published in the preceding source unit remain in
force.

Both mobile build paths select the new bridge tests with the concrete OpenVPN
build tag. The mandatory bridge gate includes the new factory omission. All
three bridge validation scripts now participate in the mobile and desktop
runtime cache input closures. A validation-only change cannot retain the prior
runtime evidence identity.

## Executed evidence

Validation used base `3f1b4fc33f765967e33102d3e6448e5f39a566f5`, the actual
mobile-prepared core pinned to `1ac1a339cb1223e9c70eae14c44411c75033c02d`
and Go 1.26.3:

- The complete current libbox/daemon execution inventory passed under race
  instrumentation: 47 roots and 164 required records. This includes the new
  OpenVPN source and factory cases as well as the existing native lifecycle,
  measurement, MTU, saved Last and restoration cases.
- One independently compiled omission removed the original OpenVPN factory
  check. Its exact ordinary-server leaf failed with the required witness,
  `ordinary service borrowed typed factory`. A build failure, timeout, panic
  or race report would not count as the expected refusal.
- Seventeen preparation controls and seventeen runner controls passed. The
  preparation checks verify actual mobile and desktop input-closure membership.
- The actual mobile preparation completed after the cache-input correction.
  All captured source inputs and the prepared core remained unchanged during
  the compiled gate.

The cache-closure regression initially failed because the validation scripts
were absent from the input lists. Adding the missing entries closed that
specific failure; the failed source-phase logs were retained. No production
ownership or rejection rule was weakened.

Prepared-core source identity:
`3972a223412736891ceff5ebfafd9f5fff790bd6d692bb4160335e913b1ce659`.
Source manifest SHA-256:
`9285bb43ffc897a9669c8793ff5ead1957ba42559419039362636e6c9867925c`.
Compiled validation receipt SHA-256:
`60b9f01763a4cc51fbba98fbedc433f15fce48e20ac7d434d5d03546e38023b8`.
Positive log SHA-256:
`ee32919f4728153937f51c2e202a76ce540646bb2d093d9599216dbf5e8d7074`.
New omission log SHA-256:
`f924d9b0cdf0349f5d3a2da750bded51272158653b9015aa547cfb50386a6fdb`.

## Boundaries

The bridge tests exercise actual shared preparation and CommandServer
construction with explicit platform/runtime component fixtures. They do not
start an encrypted OpenVPN provider or a device tunnel. Previous compiled
omissions remain mandatory in the shipping gate but were not all rerun in this
focused local validation. Generated mobile bindings, app-host compilation,
exact-SHA release, signing, private deployment and physical-device acceptance
require their own evidence.
