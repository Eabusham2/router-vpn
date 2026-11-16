# Complete desktop next-hop proposals

Date: 2026-11-16. This is a bounded source and controller change for the
reconciled external-node, routed-candidate measurement and complete connection
profile requirements. It is not a whole-project completion statement.

## Problem and resulting behavior

The old desktop proposal builder copied only the measured prefix, appended the
candidate, and sometimes reattached the final node. That could discard other
saved members. It also replaced the requested execution with Local.

The proposal now copies the complete original two-to-eight-node selection and
replaces exactly the next slot after the measured prefix. Every other member
and the retained final control profile remain unchanged. An imported transport
must fit its supported position in that complete graph. An incompatible
candidate cannot acquire Save by shortening the original path.

Connected candidate catalogs and Save read the execution from the original
bound execution preparation. This preserves Server or Compare even when the
saved profile still says Local. Temporary saved-path preparation retains its
captured choice. A foreign execution owner cannot provide that choice.

The complete proposal runs the actual generic, SOCKS or CONNECT source compiler.
Server and Compare proposals also run their actual execution-preparation
compiler. The corresponding OpenVPN branch retains its distinct compiler.
These calls compile and validate sources; saving a proposal does not start a
tunnel or grant a Connected or authenticated-node proof.

Saving keeps reference-only private-node associations. Explicit Load applies
the complete profile transactionally. Source, policy, execution, ownership and
fresh-result checks remain required. This change does not alter the 50-sample
TCP measurement's meaning or turn it into HTTP, ICMP or credential proof.

## Relevant source

- `cmd/client/ordered_candidates.go`: complete next-slot replacement and bound
  execution selection for the connected catalog.
- `cmd/client/ordered_candidates_profile.go`: complete family and execution
  compilation before source-bound Save.
- `cmd/client/ordered_candidate_complete_proposal_test.go`: complete Local,
  Server and Compare proposals, original-source retention and refusal cases.
- `cmd/client/ordered_socks_candidates_profile_test.go`: the paired positive
  fixture replaces the actual final slot; it no longer depends on truncation.

## Validation at publication — runtime checks still pending

The retained driver compiles the whole canonical `cmd/client` package with its
pinned Go toolchain, race instrumentation, ordinary optimization and vet. It
requires 19 complete test roots and 155 exact test records: 35 existing closed
prefix receipt/cleanup records, 120 complete-proposal/source/Save records, and
three separately compiled legacy-proposal rejection controls.

The new complete-proposal matrix covers three, four and eight nodes with
imported Shadowsocks 2022, SOCKS5, HTTP CONNECT and HTTPS CONNECT, under Local,
Server and Compare. It checks the complete node list, retained independent
source identities, final policy, real family and execution compilers, saved
record, append/rollback and the public Load endpoint. Separate negatives cover
unsupported placement, duplicate identities, invalid execution, replaced
private sources and foreign captured execution ownership.

The existing native-receipt and physical-observation doubles remain explicit.
These controller checks do not execute a new encrypted transport, installed
desktop package, physical device or private production server. Exact-SHA native
builds/release and live acceptance remain separate evidence.

The first local positive run exposed a fixture mismatch: Load normalizes legacy
empty Base/DNS fields. The fixture now starts from explicit saved preferences;
strict whole-profile retention assertions remain intact. A subsequent full
compiler was killed before producing a test image. The final local retry used
one Go worker, `GOGC=25` and a 700 MiB Go memory target. It reached the original
240-second compiler timeout without an image or executed test roots. The
shipping compilation, race instrumentation, vet, 120-second test-root limits
and all negative controls remain unchanged. No successful runtime verdict is
claimed for the corrected fixtures at publication; the full hosted suite must
verify this exact committed source.

The initial full race compilation completed in 136.592 seconds on the recorded
`5fce4d2c` composition. Its production bodies match this change; its Local root
failed the explicit preference-fixture check described above. The final
publication composes the unchanged four owned paths on `4ae6a3c4`, preserving
the concurrent Hysteria2 final-layer implementation. The initial, killed and
timeout attempt receipts are retained with SHA-256 identities respectively:

```text
5f6b88367b2957f0ca5a15ead336400cbf36107fafa5d36bf3b6ffdc4fdb1948
557ec525137e8e2d0aaa275932ea1a11ccc37edaa4d4405ee85b01ddaeeb28a6
4558e0bb7776f8db4aa88426791ad8f5359dbafd4bd33e1231c2236b6da2fd93
```
