# November 26: retain the original registered source generation

Ordered relay authorization now remains attached to the exact private file that
was registered and read. Replacing that file with another inode containing the
same bytes cannot keep an existing worker authorized. Changing its raw bytes
while retaining an equivalent normalized policy also retires the original
authority. A bootstrap checks this ownership before native I/O; a revoked owner
can still finish its original Stop and joined cleanup.

The agent captures the original inode, size, modification time and byte digest.
Its live checks retain the existing complete policy recompilation. The private
state reader keeps its existing four-MiB bound. The native worker now obtains
both its bytes and its retained identity from the same open descriptor, and
supplies that original identity on full revalidation. This closes the interval
between reading a file and separately inspecting its path.

The same rule now covers the independently registered response credential. A
confirmed in-place edit could retain the original inode, size and restored
modification time. Candidate response authority now also rechecks the raw
SHA-256 digest from its original open, so both that edit and an equal-byte
replacement retire the existing operation before another response can use it.

## Native source and required verdicts

Desktop imported-execution projection produces both the common process fixture
and its Linux native lease companion. The projector and both affected Darwin
source gates now require that exact pair and inspect both original outputs.
The resulting Linux native package compiled with the pinned Go 1.26.3 toolchain,
verified PQ archive, complete native build tags and race detector. Both required
original process roots were present in the executable. The observed image was
141,847,592 bytes with SHA-256
`811cd541e9575c7febe0bf33fbf277c57817a49ca8a9800ffc6bfe2be351f190`.
This is compilation evidence, not a claim that either projected process root
completed a physical network test in that build.

The existing mandatory worker command root includes
`private-source-generation`. Its original and run/pass verdict are now explicitly
required by the receipt verifier. The inventory contains 27 roots and 138
required root/leaf verdicts. An independently altered verifier input that omits
both records is rejected. The `response-source-content` child is also mandatory; omitting either its
run or pass record is rejected. No prior required case was removed.

The mobile bridge inventory also includes its fourth existing OpenVPN root,
the selected imported OpenVPN TCP candidate. Both real native build selectors
must retain all four roots. This repairs an obsolete three-root assertion.

## Retained verification

The [evidence directory](evidence/owned-source-2026-11-26/) contains the original
small transcripts and [file hashes](evidence/owned-source-2026-11-26/SHA256SUMS).

| Check | Observed result | Evidence boundary |
| --- | --- | --- |
| Extracted original native file-generation code | Race test passed in 1.026 seconds | Actual filesystem generations and shipping read/capture functions |
| Omit the opened-generation guard | Failed at the equal-byte replacement witness | A behavioral regression, not a compile-error rejection |
| Native worker runner and receipt controls | 21 tests passed in 30.665 seconds | Includes compiled ownership/retirement controls and required transcript inventory |
| Original native candidate credential guard | Race test passed in 1.017 seconds | Shipping read/capture functions with same-inode, same-size, restored-time edit and equal-byte replacement |
| Omit credential digest or opened-generation check | Both failed at their distinct expected witness | Behavioral rejection controls |
| Complete pinned native relay command package | 27 roots and all 138 required verdicts passed with the race detector | Original 90-second bound, executable SHA-256 and prepared-source hashes retained in the JSON receipt |
| Canonical worker source preparation | 11 tests passed | Source projection and preparation |
| Mobile execution bridge preparation | 19 tests passed in 1.071 seconds | Both real native build selectors and their omission controls |
| Naive H2 shared graph exports | 81 passed | Shared compilation and exported graphs |
| Naive literal, CONNECT and DNS loopback controls | 126 root/leaf verdicts passed locally | One original race-enabled native image; no physical-interface acceptance |
| Hosted Naive proxy and packet reference | 365 proxy and 294 packet verdicts passed | Both original native roots on d887; retained same executable and Cronet hashes; no OS TUN acceptance |

The Naive loopback receipt identifies prepared source, input inventory, native
Cronet library and executable hashes. Its three original inventories contain
24 literal, 53 CONNECT-literal and 49 CONNECT-DNS verdicts. The full proxy parent
and the previously crashing packet leaf reached the host's denied interface
discovery (`netlinkrib: operation not permitted`) before Cronet execution. The [hosted continuation](evidence/naive-h2-native-2026-11-26/README.md)
subsequently passed both complete original proxy and packet reference roots,
659 required verdicts in total. Their native receipt still explicitly excludes
OS TUN, installed-device and production-router acceptance. The earlier local
loopback record remains retained with its original scope.

## iOS captured-control fixture repair

The hosted iOS source job exposed two stale mutation targets after the shipping
constructor began retaining `capture.controlMember.profile`. Both fixtures now
target that original comparison. The complete OpenVPN source target passed
576 actual Swift/shared-Go checks and all four original compiled controls;
imported Shadowsocks passed 804 checks and all four original controls.
[The complete success logs, original hosted failure and hashes](evidence/ios-source-control-2026-11-26/README.md)
are retained. The hosted failure occurred before Xcode app compilation, so
these results do not replace an exact-revision app build or device acceptance.

## Release qualification

Desktop status now reports `ordered_external_final_executions` independently of
other route families, with the currently qualified preference `local`. The
separately staged Server/Compare implementation requires its own complete
controller, worker, retained-history, native encrypted-path and capacity proofs.

The [Build all workflow](../.github/workflows/build-all.yml) remains the sole
publisher. A release requires the complete source revision, native gates,
packages, manifest, ARM64 images and generated production Compose to agree.
These repairs and source checks do not replace that exact-revision release or
the installed-device and live deployment acceptance requirements.
