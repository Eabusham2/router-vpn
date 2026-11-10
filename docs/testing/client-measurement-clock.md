# Checked client DNS and RTT measurement clocks

This source unit adopts the existing checked `hopmeasure.StartInterval` clock
in four client measurement paths:

| Path | Preserved measurement meaning |
| --- | --- |
| Selected DNS OS-resolver proof | One bounded resolver question after verification of the captured selected DNS runtime |
| Quick node latency and Fastest | Actual direct TCP handshakes, with discovery outside the measured samples |
| Active private-path latency | Complete HTTP response RTT, with the paired node identity proved for every sample |
| Durable node statistics | Separate disconnected direct TCP benchmark, with at least 50 and at most 200 samples |

Windows uses the checked native performance counter; other platforms retain
the shared monotonic clock. The existing request deadlines, pacing, drain and
cancellation completion clocks, wall-clock receipt dates, selected resolvers,
HTTP credentials and labels retain their original roles.

Each sample captures its own interval before measured network work. A start or
read failure, zero/backward interval, or nonfinite result cannot earn a score.
Error-returning paths preserve the original clock cause; the DNS proof and
HTTP handler retain their existing reason/message response shapes. A cancelled
caller cannot adopt a clock readback. DNS verifies the original registered
runtime again after readback. Durable publication still requires the original
tracker, session, profile, physical network, selection and mutation admission.
A late timing failure returns before persistence and leaves saved statistics
unchanged; a failed network sample retains its original incomplete/disqualified
meaning.

The durable benchmark previously used `math.Max(0.001, elapsed)` after
microsecond truncation. That invented minimum is removed. Ordinary results
retain three-decimal display rounding; when that rounding would erase a real
positive interval, the original measured value is retained. A stable incremental
mean prevents repeated addition from placing a constant tiny interval below
its observed minimum and incorrectly disqualifying a valid Fastest result.
The Fastest completeness and failed-sample rules are unchanged.

## Executable evidence

Go 1.26.3 on Linux produced **212 passing race verdicts across 45 test roots**
for the focused client selection. The selection covers the new clock tests and
existing private-node identity, DNS ownership, cancellation, Fastest, telemetry
and profile-statistics contracts:

```sh
go test -race -count=1 ./cmd/client \
  -run '^Test(Client(RTT|DNSClock|DurableLatencyClock|ClockUses)|PrivateLatency|ProfileLatency|Fastest|DNSProof|SelectedDNSLookup|NativeMultihopDNSRuntimeSnapshot|ConnectionTelemetry|ConnectionLive)' \
  -skip '^Test(ProfileLatencyTerminalSaveOwnsCancellationAndProfile|ProfileLatencyPartialActualTCPPreservesSavedBenchmark)$' \
  -timeout=180s
```

The new tests run real TCP handshakes and paired HTTP exchanges with deterministic
per-call clock readings. The selected-DNS tests retain a real registered private
runtime snapshot and a bounded resolver callback. Positive nanosecond and
submillisecond values, ordinary display precision, initialization/read failures,
zero/negative/nonfinite readings, cancellation during readback, and replacement
of the registered DNS runtime are exercised. The actual durable handler performs
50 measured handshakes plus separate discovery; a fault on sample 25 cannot
salvage earlier values, overwrite saved statistics, or start further samples.
Replacing the process tracker before publication also prevents persistence.

A disposable source overlay reinstated the original 0.001 ms floor in the
actual durable sample loop. The tiny-interval handler test then failed because
all persisted/distributed values became 0.001 instead of the supplied actual
0.000001 ms. No repository test or source was modified by this control.

The two roots excluded above were attempted first without exclusions. This
container cannot read the required physical network metadata. The terminal-save
root refused all six scenarios before its first measured TCP connection; the
partial-TCP fixture consequently waited for a listener it never reached.
An overlay of the original `extras.go`, `telemetry.go` and `dns_proof.go`
reproduced both failures exactly. The tests remain unchanged and required in
the normal matching-host suite; these are local execution limits, not passes.

The shipping `cmd/client` executable cross-compiled for Windows AMD64 and ARM64.
`deploy/test_desktop_native_dependencies.py` passed all 21 tests, including the
actual builder source inventory and link/dependency boundary. `git diff --check`
passed. The cross-builds do not establish Windows counter execution or package
release acceptance.

## Remaining scope

This unit covers the four paths above. Other routed-candidate and throughput
timers, including `via_entry_candidates.go` and `multihop_execution.go`, require
their own adoption and contract verification. Matching-host execution, exact-SHA
packages, physical selected-path measurements and network-transition acceptance
remain separate requirements.
