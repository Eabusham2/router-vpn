# Checked elapsed time for Speed Lab throughput

Speed Lab now measures each single transfer, joined parallel round and complete
load window with a checked platform duration. Its private per-call clock factory
preserves nanosecond durations without a floating-point round trip. Public
transfer and measurement signatures remain unchanged, including the callers
that measure the original imported entry lane.

Scheduling still uses the existing monotonic timeout/pacing clocks. Each
transfer interval starts immediately before HTTP work and ends at the original
body-read boundary, before deferred response cleanup. Parallel timing brackets
all streams and their joined completion. The whole-load interval begins at the
load window and ends after its final round, before loaded-sampler cancellation
and join overhead. A stalled final tail therefore remains in the throughput
denominator. Pattern generation and setup remain outside the load window.

## Bytes, acknowledgement and cancellation

The existing exact download limits, consumed upload-body counts, HTTP status and
bounded complete upload response checks remain intact. Failed upload streams
still contribute zero bytes to a parallel round. An ordinary administrative
direction deadline can retain bytes actually received in a partial download or
only the fully acknowledged upload streams. An outer request cancellation
always rejects the result.

A distinct clock-failure sentinel preserves the original clock cause and cannot
be classified as an ordinary deadline, including when joined with cancellation
or `DeadlineExceeded` from the same request. Failed clock initialization sends
no work for that interval. Nonpositive durations or failed readback cannot
salvage earlier completed rounds or acknowledged upload bytes into a successful
measurement. Parallel aggregation retains a clock failure even when another
stream first failed for a different reason.

Rates use actual byte counts and measured durations. Tiny positive whole-load
seconds and imported-entry millisecond output survive display rounding rather
than becoming zero. Ordinary display precision, jitter and latency behavior are
unchanged; no duration floor or fallback clock is introduced.

## Test reference clocks

Two existing upload fixtures compared the production outer duration with a
transport/acknowledgement duration measured by `time.Since`. On Windows, a coarse
timing tick can overstate that inner interval relative to the actual QPC
interval, making the ordering assertion invalid. Both fixture reference
intervals now use checked Duration readback. Their cancellable ticker waits,
outer-versus-inner ordering assertions and byte/acknowledgement/cancellation
checks are retained without wider tolerances or waits.

## Executable evidence

The new HTTP tests exercise successful one-nanosecond and ordinary intervals,
initialization/read errors and nonpositive durations through both single and
parallel download/upload operations. Actual transferred bytes, provider,
headers, independently owned interval counts and no work after initialization
failure are checked.

Direction tests send a verified partial download and stall the final body until
the real administrative deadline. A separately controlled whole-load interval
must determine the reported denominator. Failures at transfer, parallel or
whole-load readback must return no result. Upload tests first complete and
acknowledge one payload, then stall the second acknowledgement: a clock failure
at any level must invalidate the entire result, preserving the earlier byte
accounting without publishing it as successful throughput.

The final focused race run passed **101 verdicts across 18 roots**. It includes
the published RTT clock tests, loaded-sampler stop semantics, existing provider
failure/cancellation/partial-byte tests and original imported-entry proof and
transfer-count tests. A further captured-tunnel regression run passed **16
verdicts across 6 roots**, including actual public TLS transfer, foreign TLS and
redirect rejection, late response/dial cancellation and separate admission and
socket lifetime. All five code/test files exactly matched the isolated copies.

Commands (Go 1.26.3, workspace build cache and temporary directory):

```sh
go test -race ./cmd/client -run '^TestSpeedLab(TransferCheckedClock|DirectionCheckedClock|UploadDeadlineCannotHideClockFailure|TransferUploadRequiresConsumedRequestBytes|TransferDoesNotInheritEnvironmentProxy|TransferParallelRejectsPartialUploads|Direction|RoundCalibration|ImportedHopUsesOriginalEntryLaneAndActualTransferCounts|AndHopLaneUseCheckedIntervals|LatencyStatisticsRetainMeasuredTinyValues|ProbeProductionClockAndCancelledCaller|LoadedSamplerDoesNotCountIntentionalStopAsFailure)' -count=1
go test -race ./cmd/client -run '^TestSpeedLab(CapturedTunnel|MeasurementConstructors)' -count=1
```

Two source overlays completed with the expected assertion failures:

- Removing clock-failure precedence from context-error classification made both
  partial-download cases and both acknowledged-upload cases incorrectly publish
  successful results. All four cases failed: the mutated download retained 256
  bytes, and the mutated upload published its earlier 65,536 acknowledged bytes
  despite a clock failure on the final tail.
- Replacing only the whole-load checked interval with `time.Since` failed the
  controlled denominator case: it reported `0.351 s` instead of
  the supplied `2 s` interval and never read the original whole-load clock.

Both overlays were external to the repository. The shipping source remains the
passing checked implementation. Validation uses the isolated `a0fbb61d` checkout plus precisely this
unit because unrelated Linux platform capture files were concurrently under
construction in the shared checkout. Initial shared-tree attempts stopped at
those unrelated compilation errors before executing tests.

## Scope

This is source and Linux local HTTP/race evidence, not a claim of native Windows
or mobile device throughput. Captured path ownership, endpoint identity,
Compare ranking, imported transport policy and restoration remain with their
existing callers. Matching-host runtime validation remains separate.
