# Complete Go source-contract package budget

The three workflows that run the complete `go test ./...` inventory use the same finite fifteen-minute **per-package** test budget as the existing complete controller gates. This is a CI aggregate allowance; production timeouts, individual test deadlines, negative controls, test filters and package selection are unchanged.

## Observed cause

Two hosted runs of exact commit `587ebb69b7ebbdfbeec061ff8e8d86831d51a45e` distinguish cumulative suite duration from a stalled operation:

| Hosted evidence | Command and result |
|---|---|
| [Recovered requirements source-contract job](https://github.com/Eabusham2/router-vpn/actions/runs/42548734993/job/128939412931) | `go test ./...` reached Go's default ten-minute package alarm; `cmd/client` ended at **600.036 seconds**. The currently running Tor test root was only **two seconds** old and its current leaf was **zero seconds** old. There was no preceding assertion failure. |
| [Release gap audit job](https://github.com/Eabusham2/router-vpn/actions/runs/42548734897/job/128939417139) | `go test ./cmd/client ./internal/common -timeout=15m` completed the whole controller package in **670.490 seconds**. It reported the separate **0.51-second** external-MTU cancellation assertion failure rather than a package timeout. This is evidence of suite completion and duration, not a passing package claim. |

Both runs checked out the same SHA and used the same Ubuntu 24.04 image (`20261101.360.1`) and actual Go 1.26.3 toolchain. Both reported empty `GOFLAGS` and `GOEXPERIMENT`; neither invocation enabled race instrumentation, build tags, test filtering or skipping. The release-gap setup action requested an older toolchain series, but its captured Go environment confirms the actual compiler was 1.26.3.

Earlier full-suite evidence at `13fb0b75` already measured **534.447 seconds** for `cmd/client`. Subsequent imported-MTU, caller-lifetime and PQ test matrices increased the complete inventory. The current timeout's goroutine snapshot is insufficient to attribute failure to its last displayed Tor/Netlink operation; the same-source completed controller run directly demonstrates that the normal suite can exceed 600 seconds.

## Bounded correction

Commit `0ab1606cf663c7faf215e2a804a76ed652f76322` had already established `-timeout=15m` for `.github/workflows/multihop-contract.yml` and `.github/workflows/release-gap-audit.yml`, based on earlier full passes and aggregate alarms in different freshly started tests. This correction applies that same finite package allowance to the three remaining complete-inventory commands:

- `.github/workflows/requirements-closure.yml`
- `.github/workflows/release-candidate.yml`
- `.github/workflows/client-apps-ci.yml`

Each command remains `go test ./...`, with only `-timeout=15m` appended. Every package, test and negative case still runs. A runtime deadlock or individual operation timeout remains a failure. The independently reported external-MTU assertion requires its own cause-specific correction.

## Validation and limits

The workflow structure audit and existing authoritative release-gate contracts verify the edited wiring and continued complete controller coverage. A new local full-suite replay is not used as substitute evidence: this sandbox's Netlink restrictions differ from the hosted Linux execution, and the exact-source hosted 670.490-second completion already provides the relevant aggregate timing. The next exact-head hosted run must establish a passing complete suite after its independent assertion fixes.
