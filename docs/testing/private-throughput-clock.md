# Checked private-node throughput intervals

The direct private-node throughput implementation in `telemetry_hops.go` now
uses a separate checked platform interval for each HTTP download and upload.
The existing `telemetry.go` connection-speed endpoint and per-node routed-speed
endpoints share this implementation. Public signatures, request timeout,
selected API/token, exact requested byte count, admission and captured path
observers remain unchanged.

Each clock starts immediately before its original HTTP request. Download timing
ends only after the exact bounded body is read and closed. Upload timing ends
after the complete bounded acknowledgement body is read and closed, preserving
acknowledged-byte validation. Random payload preparation remains outside the
upload interval. Mbps uses the actual byte count and the unrounded checked
milliseconds; only the resulting display value is rounded. Millisecond output
retains real tiny positive measurements instead of truncating them to zero.

Initialization/read errors, cancellation, nonpositive/nonfinite durations and
nonfinite or nonpositive rounded rates return an empty result. Download timing
failure prevents the upload. Upload failure cannot return a successful partial
download score. Original clock and cancellation causes remain discoverable.
There is no fallback clock, minimum duration, retry or substitute measurement.
Wall-clock timestamps still identify when the result was produced.

## Executable evidence

`throughput_clock_test.go` exercises the shipping transfer implementation against
actual ephemeral HTTP listeners with only the per-call interval factory modeled.
Its matrix covers both directions, one-nanosecond/fractional/ordinary intervals,
clock initialization/read failures, invalid timing, rate overflow and caller
cancellation during readback. It verifies exact transferred bytes, original
credentials, encoding, selected node identity and proof label, server timing,
no network on initial clock failure and no upload after failed download timing.

Additional tests reject short/excess download bodies, rejected HTTP status,
redirects, malformed/wrong/oversized acknowledgements, and verify a real platform
clock through the unchanged production entry point. A server holds the upload
acknowledgement after flushing its first bytes: interval readback must wait for
the complete body. This distinguishes full acknowledged transfer timing from
request transmission or response-header timing.

The final selected Linux race run passed **70 verdicts across 13 roots**. A
separate existing owner regression run passed **16 verdicts across 5 roots**,
selecting the single-hop and connection cases to avoid overlapping reserved
proxy ports used by other work. These cover active node/session/profile
replacement, request cancellation, unproved preflight, successful transfers,
shared admission, captured MTU retirement and keeping the original VPN running.
No existing negative cases were removed or weakened.

Commands (Go 1.26.3, workspace `GOCACHE` and `GOTMPDIR`):

```sh
go test -race ./cmd/client -run '^Test(PrivateThroughput|PrivateTelemetryBoundary|PrivateBenchmarkRequestContext|RoutedSpeedRejectsProfileReplacedBeforeObserverStarts|ProfileSpeedTestRejectsNonActiveSingleHopNode|StandaloneThroughputWaits)' -count=1
go test -race ./cmd/client -run '^Test(RoutedSpeedRequests|RoutedSpeedCancelsWhenEitherHopProfileChanges|StandaloneThroughputSharesAdmission)/(single|connection)$' -count=1
```

A source overlay deliberately reinstated a `.001 ms` floor independently in
both transfer directions. The actual HTTP tests failed for both tiny samples:
`0.000001 ms` became `0.001 ms`, changing the corresponding measured Mbps by a
factor of 1,000. The overlay was external to the repository; the shipping files
remain the passing source. This demonstrates sensitivity to fabricated timing
and rates, rather than only the existence of a clock helper.

## Scope

This unit covers direct private-node transfers only. The separate reserved proxy
lane and Speed Lab transfer loops still require their own checked interval
adoption. It does not claim native Windows throughput runtime evidence or alter
Compare ranking, packet protection, path restoration, or endpoint ownership.
