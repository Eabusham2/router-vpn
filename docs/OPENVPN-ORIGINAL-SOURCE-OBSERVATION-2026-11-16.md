# Preserve original OpenVPN source observations — 2026-11-16

Repeated OpenVPN execution observations were reparsing the same complete
schema-five JSON source after the original constructor had already validated
and retained it. A profiled shared execution path identified this parsing in
`NodeChain.validateCapture` among the remaining costs of bounded restoration.

This change follows the existing schema-two imported-source receipt pattern.
The schema-five constructor now retains its exact canonical source, original
middle input, bounded member count, and private chain/member/policy/node owners.
Every observation freshly compares those values and the receipt's own identity
and seal. It therefore does not need to deserialize those unchanged source bytes
again merely to recover their already captured schema, count and middle slot.

The constructor still performs its full source parsing, schema and identity
validation, independent packet-key checks and complete graph compilation before
issuing the receipt. Authorized projections still use that constructor and
receive distinct owners. The source is never reconstructed from a selected node
name or from a copied receipt.

## Checks that remain fresh

`validateCapture` still checks the complete chain seal, every original paired
node, the imported OpenVPN member, its `ExternalPolicy.DesktopCapture`, and the
complete proof positions, identities and roles. Connected remote, generation,
capacity, cancellation, DNS and runtime proof checks are unchanged. The receipt
stores source provenance; it stores no reusable validation or connection result.

The additional exact policy-pointer check also refuses a same-content replacement
of the original imported member's policy. A replacement receipt cannot borrow
authority by copying its fields because the receipt retains its own pointer.

## Executable verification

Go 1.26.3 race-instrumented validation completed all 15 selected OpenVPN test
roots, covering **252 distinct root/subtest records**. This includes:

- 56 new cases spanning minimum/maximum route length and TCP/UDP. They reject
  copied or foreign receipts, altered and resealed sources, changed member,
  policy and prefix owners, bad counts, missing receipts, changed private
  selection/policy, and altered proof roles.
- Fresh projection owners for Linux, Windows, macOS, Android and iOS.
- Every existing one-to-six-prefix WireGuard, AWG Fast and AWG Strong source and
  projection case over both OpenVPN transports.
- Existing generation/capacity, source-substitution, independent Local/Server
  pairing, Server proof, and role-substitution checks.

The first combined local invocation exhausted its **120-second aggregate test
budget** while iterating the existing projection matrix. That failure is retained
as evidence, not relabeled as a successful aggregate. Its two completed roots
were preserved. The same immutable race binary then completed every remaining
root in 18 bounded groups; the full prefix matrix was partitioned by original
mode and transport, with all six counts required in each group. Each group kept
the 120-second test limit. No source, case, production deadline or probe count
changed to complete this inventory.

Three separately compiled defects were rejected at their intended witnesses:
removing the receipt-self check, the original-source comparison, or the original
policy-pointer comparison. Their compile/run durations were 26.24, 26.60 and
24.46 seconds under the existing 30-second test/90-second process limits.

## Evidence identity and limits

The positive race image was compiled against `0b47442293da2bded515fbcfce975ad5a16d0151`
plus the three changed Go files. Subsequent unrelated REALITY work in
`75d012763f27634c52621ac21e0bde1ae99bc51a` was preserved; the three negative-control
builds also compiled that newer package source. The three OpenVPN file hashes
remained unchanged throughout the positive and negative checks.

- Race image SHA-256:
  `d67cd8d5193f9045fe413d18a1b26ebf8a05ca982305d852272588e476549725`.
- Retained initial aggregate log SHA-256:
  `4b368e5ead5d9e5e19d1372026f96e04824b3b6dd55d8c2f88818c12967115b6`.
- Original-source owner implementation SHA-256:
  `e3012352bc34e6083f4fb4b90d094081cae102e317e757689730ebda8d373d1f`.
- New source-observation tests SHA-256:
  `7969d5dc110e987ac201ab13672c3a7a2c2aabfa737dd0c70fb8389f1b1f83d4`.

This is an independently tested source-observation repair. It does not establish
completed native OpenVPN Server/Compare client integration, an exact-SHA release,
private deployment, or physical-device acceptance. Those remain separate gates.
