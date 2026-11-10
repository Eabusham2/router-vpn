# Checked Speed Lab and per-hop HTTP latency

The fixed one-byte Speed Lab probe and the private paired-node hop-lane
sampler now capture a checked platform interval for each actual HTTP exchange.
The original HTTP client, resolver/path capture, deadlines, byte limits,
credentials, identity proof and cancellation remain in place. These are HTTP
response measurements, not ICMP pings.

A failed clock initialization sends no request. Failed readback, nonpositive or
nonfinite timing, and cancellation cannot produce a successful sample. The hop
sampler discards the whole observation if a later clock or paired-node proof
fails; earlier samples cannot be reused as proof of that failed observation.
Speed Lab retains its existing failed-probe accounting and requires the same
minimum number of valid idle and loaded samples.

The latency summaries retain real positive tiny values when ordinary display
rounding would erase them. Ordinary values keep the existing three-decimal
precision. The stable incremental mean preserves a constant tiny sample, and
zero jitter remains valid for equal samples. Speed Lab statistics reject
nonpositive/nonfinite input rather than emitting invalid JSON values or a
fabricated successful latency.

## Observed checks

Go 1.26.3/Linux completed the new clock suite with **23 passing race verdicts
across three roots** in 1.466 seconds. The tests use an actual isolated TLS peer
for the fixed Speed Lab request and the actual reserved HTTP proxy for the
paired-node lane. Clock factories are private per-call seams; production has no
mutable global clock or request override.

The cases cover initialization/read errors, true tiny and ordinary timings,
zero/negative/nonfinite readings, cancellation during readback, wrong response
length, a late wrong node identity, and late failure after a good hop sample.
They check the original private token/URL, one-byte provider contract, sample
counts, error cause, no network work after initialization failure, and the
production interval on a real TLS exchange.

Existing cancellation, direction deadline, partial/acknowledged upload,
captured-tunnel, redirect, provider-failure and lane-ownership regressions
completed with **49 passing race verdicts across 26 roots** in 6.814 seconds:

```sh
go test -race -count=1 ./cmd/client \
  -run '^Test(SpeedLab(Direction|Transfer|RoundCalibration|CapturedTunnel|MeasurementConstructors|Duration|Pattern|Stable)|MultihopLane|ConnectedMultihopLatency|MultihopLiveLatency)' \
  -timeout=150s
```

A disposable source overlay quantized each actual successful sample before
publication. Both exact tiny-value tests failed: the TLS probe returned zero
after one exchange and the paired lane returned zero after two authenticated
exchanges. The control completed with test failures, not a compile failure.
The overlay did not alter repository source. Whitespace validation passed.

This unit concerns latency. Throughput transfer/round/whole-load timing has
separate code and must preserve actual transferred bytes and acknowledged
uploads when adopting checked clocks. Current-SHA native packages, physical
path/network-transition acceptance and private deployment remain distinct.
