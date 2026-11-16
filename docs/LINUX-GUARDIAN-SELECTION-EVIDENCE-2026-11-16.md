# Linux guardian test selection — November 16, 2026

The existing namespace runner grouped a complete `root/subtest` path inside
one regular expression. Go's test matcher splits paths only at slashes outside
regexp groups. Consequently, leaf selections such as
`NodeHostTUN/selected` matched no top-level test. A Go test executable still
returns zero with `PASS` when it selects no tests; the existing strict native
verdict checks correctly reject the missing required roots and leaves.

`namespace_test_selector` now anchors each path component and alternates
complete paths independently. It preserves exact top-level groups, nested
leaves, literal regexp characters and multiple leaves under one root. It does
not form a Cartesian product between different roots and their children.
Empty, partial and duplicate paths are refused.

## Actual validation

`deploy/test_linux_guardian_selection.py` compiled an ordinary Go testing
fixture with the selected Go 1.26.3 compiler and the race detector. Nine tests
passed in 0.912 seconds. The fixture exercises test selection only; it does not
claim TUN, nftables, private-server or physical-device acceptance.

- Exact root and leaf selection passed, including nested and literal names.
- Reintroducing the original grouped path ran zero tests and returned zero;
  the actual native verdict parser refused that output.
- An unanchored leaf selected an additional sibling and was refused.
- A Cartesian product selector selected unrelated children and was refused.
- The original namespace function is checked to use the tested selector once.
- All 14 existing Linux CONNECT host-runner tests passed separately in
  0.048 seconds, including the original finite per-case timeouts.

Fixture source SHA-256:
`b705dc3534bfbf6623257b1ee30b484e7ccdeb04121d5f0468dc94a7282f4cfa`.

Compiled test image SHA-256 for this local observation:
`f9b30672c3c64605d05c0539f3f4fe4ea48533b679addda7dd8522816f52f60c`.

The regression is required by the existing AMD64/ARM64 namespace workflow and
the full Linux guardian validation. Its source is included in the native
runtime's exact-source identity. Existing kernel-case deadlines, namespace
isolation, privilege checks, ownership checks and verdict requirements are
unchanged. Hosted execution of the actual networking cases remains separate.
