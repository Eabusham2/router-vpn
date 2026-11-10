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

## MTU and shared multihop follow-up

At `83c0ae617858e331bbb7bc1fd3385120938d45c6`, the [MTU Unix job](https://github.com/Eabusham2/router-vpn/actions/runs/42583227226/job/129046744193) passed its targeted original-caller MTU gate, then ran the entire controller with `go test ./cmd/client -count=1`. The package exhausted the implicit ten-minute budget at **600.034 seconds**. The displayed `TestDesktopTorPlainSpeedLabRestoresProvedExecutionAndSource` root was only **four seconds** old and its `saved-router/router` leaf was **one second** old. Together with the completed 670.490-second controller run above, this supports applying the same explicit `-timeout=15m` allowance to this complete command. It does not establish that every controller assertion passes. The MTU workflow's mandatory `deploy/test_mtu_throughput_budget.py` contract rejects omission, filtering, skipping, shortened or unbounded budgets, cached runs, conditional execution and ignored failure. Original operation deadlines and the Windows MTU selector remain unchanged.

The [Android shared multihop job](https://github.com/Eabusham2/router-vpn/actions/runs/42583227061/job/129046737967) at the same SHA completed its first six race-enabled phases in **140.380, 16.086, 18.798, 55.396, 58.259 and 66.511 seconds**. Its remaining **222-root** group then exhausted the **180-second** package budget, ending at **180.086 seconds**. At the alarm, `TestImportedNaiveH3IndependentLayers` was only **one second** old and its current Hysteria2 layer-pair leaf was **zero seconds** old. A focused local race run of that root completed successfully in **3.026 seconds**; the snapshot does not establish a hung transport.

`deploy/test_mobile_multihop_groups.py` now divides that growing remainder into desktop execution, imported transports and the continuing catch-all. The discovered inventory of **536 roots** remains assigned exactly once: the first six groups retain **50, 18, 12, 14, 29 and 191** roots; the new groups contain **94, 73 and 55** roots. Explicit exclusions keep desktop predecessor tests in the original node phase and imported-entry tests in the original external phase. Future Test, Example and Fuzz roots still enter a phase or the catch-all. Every phase retains `-race -count=1 -timeout=180s`, its 240-second subprocess limit, checked exit status and an exact selector generated from the complete current compiler inventory. Android and native-Xray workflows already invoke this shared runner, so no additional workflow or source checkout is introduced.

All three affected groups passed locally with the unchanged race and 180-second bounds: desktop **128.374 seconds**, imported **117.641 seconds**, and the catch-all **15.992 seconds**. Their combined **262.007 seconds** explains why one 180-second aggregate allowance was insufficient; these local durations are not asserted to reproduce hosted timings exactly.

All five partition self-tests and four MTU budget contract tests passed. Partition controls retain omitted, duplicated, unknown, empty and malformed inventory rejection and add explicit split-boundary and future-name controls. The MTU budget contract uses command and gate mutations to ensure that its complete package execution cannot silently become filtered or nonblocking. Hosted reruns remain required to establish the final result under native privileges; a local Tor replay encountered the sandbox's physical-interface Netlink restriction and is not claimed as a successful runtime validation.
