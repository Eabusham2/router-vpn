# Checked clocks for routed candidates and Compare responses

This source unit changes the two routed RTT samplers in
`via_entry_candidates.go` and `multihop_execution.go`. It leaves request
lifetimes, receipt expiry, pacing, startup and cleanup clocks unchanged.

The candidate sampler still opens TCP through the exact captured entry lane.
Discovery remains separate from the requested samples. Each measured handshake
now owns a checked `hopmeasure` interval through the existing client clock
helper. An initialization or read failure, or a nonpositive/nonfinite interval,
ends that candidate without a score. Clock failure during port discovery does
not try another port; failure after successful samples cannot salvage a partial
score. The returned socket closes before timing failure returns. A nil socket
cannot establish a successful handshake. Real network failures retain their
original failed-sample count and disqualification behavior.

The previous `math.Max(.001, elapsed)` fabricated a minimum routed RTT. It is
removed. A real tiny positive sample keeps the already published client
summary precision behavior and can be ranked without being replaced by an
invented minimum. Existing candidate ranking still uses the 10% trimmed mean,
requires all 50 samples, and rejects failed or out-of-bounds results. Both entry
proofs, private lane ownership, candidate cleanup, stale receipt rejection and
unchanged Home/profile state retain their existing code.

The Compare response sampler uses `hopmeasure.Interval.Duration` directly,
retaining complete nanoseconds without a millisecond round trip. Clock failures
preserve their cause, and zero or negative durations are rejected at the sampler.
After readback, the original session/command/graph identity and paired node proof
still validate before a duration is returned. Cancellation cannot adopt a late
read. Both last-node and external-response methods use this shared sampler.

The exact Compare formula, one randomly selected endpoint for the entire
comparison, both winner re-probes, teardown, fallback and restoration logic are
unchanged. They remain owned by the existing routechoice and execution code.

## Verification

The focused new client race tests passed on Go 1.26.3/Linux. Candidate tests
exercise the actual sample loop through an explicitly modeled captured lane
with owned connections, checking 50 samples plus discovery, tiny and ordinary
values, initialization/read failures, invalid values, late failure, cancellation,
retired lane, missing socket and a real failed-sample result. Compare tests use
the actual reserved HTTP proof proxy and original session checks; only the
physical inventory and retained process handle are modeled. They verify exact
nanosecond/fractional durations, no HTTP on clock initialization failure, no
retries, original error cause, cancellation, replaced command, changed graph
and wrong paired node proof.

The complete `internal/routechoice` race suite passed **45 verdicts across 19
roots**, including exact score arithmetic, target capture, both probes and final
rechecks, cleanup failure, original caller/deadline and score clearing. The
broader selected run produced **155 passing client verdicts across 53 roots**
and **42 passing hopmeasure verdicts across 16 roots**.

That broader run was not an all-pass result: its unrelated nested
`TestDesktopMultihopCandidateContextOwnsPreflight` recompilation was killed
(`compile: signal: killed`) before assertions. The existing pinned native CLI
case skipped because no exact native executable was supplied. Neither test was
changed or relabeled as passing. Full matching-host native execution remains
required. A later control attempt initially encountered a full `/home/agent`
tmpfs; rerunning uses a copied build cache on the workspace filesystem and a
bounded compiler memory setting.

## Causal controls and limits

Two disposable source-overlay controls retain the same executable tests:

- Reinstating the candidate's 0.001 ms floor failed the tiny-value case after
  all 51 original connections had opened and closed. The returned 50-sample
  distribution showed 0.001 instead of the original 0.000001 ms values.
- Replacing Compare duration readback with a fabricated nanosecond failed nine
  sample cases, including fractional precision, read errors, zero/negative
  readings, cancellation and replaced owners. Read-count assertions also reject
  substituting a plausible duration without reading the retained clock.

The overlays did not modify repository files. Both controls completed after
moving their build-cache writes off the exhausted home tmpfs.

These are source/component results. They do not prove current-SHA packages,
physical routing, actual Windows performance-counter execution, deployment,
or remaining throughput-clock adoption. No Compare capability exclusion or
original product requirement is removed by this change.
