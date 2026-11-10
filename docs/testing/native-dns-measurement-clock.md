# Checked native DNS measurement clock adoption

The shared `internal/dnsmeasure` sample path now captures
`hopmeasure.StartInterval` before issuing either the selected native DNS query
or a public comparison query. Windows therefore uses the checked performance
counter already owned by native hop measurements; other targets retain their
monotonic clock. Query deadlines still use the original caller's bounded
context. A clock initialization failure stops the sample before DNS work.

Both paths read that same interval after a complete answer and the existing
native identity validation. Read failures retain their original error cause.
Zero, negative and nonfinite results cannot become a score, and positive
fractional milliseconds are not rounded or raised to an invented minimum.
The caller and captured engine identity are checked again after clock readback.
The original public socket still closes and joins its cancellation watcher
before a sample returns; a close failure continues to invalidate the sample.

The clock factory is a private, per-call test seam. Production always supplies
`startProbeInterval`; there is no mutable clock override on a service or in
package state, no alternate resolver and no wall-clock timing fallback.

## Native source projection

Mobile preparation already relocates both `dnsmeasure` and `hopmeasure` through
its declared shared package list. Desktop's later DNS copy now applies its
existing declared import relocation as well, so it cannot overwrite that copy
with an import of the parent repository's internal package. The independent
SOCKS/REALITY source checker permits exactly the new `hopmeasure` namespace
relocation and continues comparing every other source byte.

## Verification

With Go 1.26.3 on Linux:

- `go test -race -count=1 ./internal/dnsmeasure ./internal/hopmeasure` passed.
  This includes actual framed TCP, TLS and HTTP DNS exchanges, answer matching,
  cancellation, native owner changes, admission, draining and close failures.
- The DNS clock tests retain the original zero/backward-clock and
  nanosecond/submillisecond precision cases, now through complete selected and
  public sample paths. They additionally cover nonfinite results, initialization
  and read failures, original error causes, exact one-time clock capture/read,
  socket closure, and cancellation or owner replacement during clock readback.
- Two disposable Go overlays provided causal controls. Replacing interval
  readback with a fabricated 1 ms value failed 20 sample cases. Removing the
  final owner/caller check failed all four selected/public cancellation and
  replacement cases. The overlays did not alter repository source or tests.
- The actual desktop relocation/write functions copied both packages into a
  disposable native module namespace. Every DNS copy matched the independent
  import-only transformation; both relocated package race suites passed.
- The DNS package and tests cross-compiled for Windows AMD64. This establishes
  compilation, not Windows performance-counter execution.
- Both edited Python files passed `py_compile`; `git diff --check` passed.

## Remaining evidence and scope

This is shared native DNS timing adoption. It does not complete the remaining
client telemetry/throughput clock adoption, other multihop capability gaps,
full pinned-native build execution, current-SHA release packages, or physical
selected-path and network-transition acceptance. The disposable namespace run
is not labeled as a full native-core or device run. Matching-host Windows
counter execution and the normal complete native preparation gates remain
required in their existing release workflows.
