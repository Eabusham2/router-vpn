# Checked throughput on the original reserved hop lane

`measureRoutedProfileSpeedViaProxyContext` now starts a checked platform interval
for each real download and upload, through a private per-call factory. The
original public signatures and reserved proxy client remain unchanged. This
adopts the published direct-transfer duration/rate validation for the separate
proxy-lane implementation without merging the two transport paths.

The same paired node is still proved before any transfer and again after the
complete successful upload. Clock initialization follows the initial proof;
failure sends no benchmark request for that direction. A download clock failure
prevents upload, and upload failure cannot salvage a download-only result.
Both proofs still use the captured private API/token and original reserved lane.
Cancellation after the final proof is checked before returning the measurement.

Each elapsed interval includes the original request and complete bounded body;
upload still requires its exact byte acknowledgement. Random payload generation
is outside the upload interval. Unrounded measured elapsed determines Mbps;
real positive tiny durations survive millisecond formatting. Invalid timing or
rates return an empty result, preserving original error/cancellation causes.
No fallback timer, duration floor or proof retry is introduced.

## Verification

The new actual reserved-lane HTTP matrix exercises both direction clocks and
checks both successful identity proofs, wrong initial/final identities, wrong
acknowledgements, clock initialization/read errors, invalid timing, rate
overflow, cancellation, exact bytes, endpoint/token identity and tiny/ordinary
measurements. Existing lane, upload boundary, routed ownership and published
RTT tests are included in the selected race run.

The selected Linux race run passed **118 verdicts across 17 roots**, including
the full existing routed/standalone owner cases on both reserved lanes and the
published Speed Lab/hop-lane RTT clock tests. No existing negative cases were
changed. Command:

```sh
go test -race ./cmd/client -run '^Test(ProxyThroughput|MultihopLane|MultihopUploadAcknowledgement|SpeedLabAndHopLaneUseCheckedIntervals|SpeedLabLatencyStatisticsRetainMeasuredTinyValues|SpeedLabProbeProductionClockAndCancelledCaller|RoutedSpeedRequests|RoutedSpeedCancelsWhenEitherHopProfileChanges|StandaloneThroughput)' -count=1
```

A source overlay replaced proxy throughput interval readback with an invented
`1 ms` success. All four actual HTTP read/cancel-read cases failed as expected: the
mutated source returned a completed throughput result despite the original
clock failure. The overlay lived outside the repository; the shipping source
retains the checked readback and its passing results.

## Limits

These are Linux race tests with real local HTTP exchanges and explicitly modeled
paired node responses. They do not establish native Windows device throughput
results. Speed Lab's independent transfer and whole-load clocks remain a
separate source unit. The captured graph/MTU/admission owners and cleanup rules
are unchanged.
