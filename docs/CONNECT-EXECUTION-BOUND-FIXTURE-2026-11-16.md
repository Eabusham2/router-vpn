# CONNECT execution length regression fixture

The iOS workflow [43819049116](https://github.com/Eabusham2/router-vpn/actions/runs/43819049116)
at `58a73bcf284d0d91a1dc22ac98c164c90f51e7aa` failed its shared Go tests at
`TestNodeChainCONNECTExecutionPreparationRejectsChangedAuthority/long`.
The case still expected a valid four-member CONNECT source to be refused after
the implementation had gained complete three-through-eight-member prefixes.
The obsolete case remained in the current source at `9bbc2dee`.

The corrected case first constructs the supported eight-member source and
requires both Server and Compare preparation to retain its original source
pointer. It then adds an independently captured ninth member. Before requiring
the oversized CONNECT source to fail, the test proves that its eight paired
members still form a valid ordinary chain. Duplicate keys, malformed profiles,
or a misplaced imported member cannot substitute for the length check.

The other ten authority refusals remain in the same root: unselected execution,
foreign source/runtime/observer, copied binding, missing or failed observation,
cancelled observation, and replacement during observation. The original
complete-prefix test still exercises three, four and eight members, WG and both
AWG modes, HTTP and HTTPS, retained native projections, proof/DNS inventories,
and private Server captures. No production constructor, validation, timeout,
or native admission changes in this repair.

## Executed verification

The full `internal/mobilemultihop` test package compiled with Go 1.26.3 and race
instrumentation in 81.669 seconds under a 300-second local compiler bound.
No production or test source files were omitted from that compilation. The
immutable image then passed all 44 run/pass records from these three roots,
with each complete root retaining its 120-second Go alarm:

| Original executable root | Records, including parent | Elapsed seconds |
|---|---:|---:|
| `TestNodeChainCONNECTExecutionPreparationRejectsChangedAuthority` | 12 | 6.151 |
| `TestNodeChainCONNECTExecutionPreparationRetainsClosedOriginalTrio` | 13 | 6.896 |
| `TestNodeChainCONNECTExecutionCompletePrefixes` | 19 | 40.508 |

The driver required each expected root and child exactly once, a final package
pass, and no skipped, failed, raced or fatal record. All tracked inputs were
unchanged throughout compilation and execution. The proof base was `9bbc2dee`;
publication preserves the intervening Android change `faa73227`, whose diff
does not change any compiled Go input. This is a shared-source fixture repair,
not an Xcode, packaged iOS, device, or full-release acceptance result.

## Evidence identities

| Evidence | SHA-256 |
|---|---|
| Downloaded failing iOS job log | `81bf06c3250e0b8a51bd0087f52f9bf76311f3fee92b1445918344510b97a169` |
| Frozen compile/source manifest | `7fbc9e57623005a7378d46842d75fc53916b95edbcf44ba78927afcc2f665ac4` |
| Race-instrumented full-package image | `fa2e38b44385e27688b35f74a9bcf7a8b8b3a722a3d16f82e8c66ec4d16e020d` |
| Complete three-root validation receipt | `6c8e1c81bc557a72fd938c76c89eca99c78fb5c74f95d6ad1d8b21c4e44af2df` |
| Authority refusal log | `5164a61fccd0fd36c22a65c2f3b111a1ab100028a93a343ce1eb0885021ac236` |
| Original trio log | `b3a214f76e5d21beee339a36b3d3d7d038d287382abc6f5c088ee756fb554dcc` |
| Complete prefix log | `14e30f0af228842d2e0ff8e4468a4e23ef8e3fb2e5d99ac23fe5013bc67fad89` |
