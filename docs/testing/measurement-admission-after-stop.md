# Measurement admission after Stop

## Observed failure and cause

The complete source-security job `128939429684` on
`587ebb69b7ebbdfbeec061ff8e8d86831d51a45e` reported
`TestDesktopTorOrdinaryStartupLastAndCompleteSetupRetainExactEntry/hysteria2`
failing after 0.16 seconds. Immediately before that assertion, the controller
logged that Startup Last was skipped because another connection or settings
transaction was active. Restoration had not entered its native startup path.
The separate ten-minute package alarm is documented in
[the complete-suite budget guide](go-source-contract-budget.md).

A successful Tor Connect already commits the saved Last choice, rechecks the
captured native proof and sets Connected before returning. The asynchronous
selected-DNS observer can still be finishing its own result. Ordinary Stop
retires the runtime, while that observer rejects obsolete results through its
captured session and path binding. Previously, measurement adoption acquired
the general transaction lock before validating that binding. A result arriving
after Stop could therefore reserve the lock briefly, then discover it belonged
to the retired session. An immediate replacement request could be refused
during that interval.

## Source correction

`beginAsyncMeasurementAdoption` now reserves its transaction through an
asynchronous-measurement-specific admission helper. The helper holds the
captured tracker and application locks, checks controller retirement and the
existing complete session/path binding, then attempts `operationMu.TryLock`
inside that same critical section. This reservation never waits for another
transaction while holding the tracker/application locks.

Those two locks are released before the existing protection-recovery and
via-entry cleanup guards run. Both guards receive the original measurement
context. Adoption still reacquires its original locks and performs the full
final validation before exposing a result to the caller. The compatibility
`beginNodeBoundOperation` helper and other callers retain their existing
behavior.

## Bounded evidence

The regression test creates the real selected-DNS path context, holds its
tracker against periodic invalidation, executes `stopModeWithIntent` under the
connection transaction, and then submits the old captured result with the
application owner held. It observes either a context-aware wait before
reservation or actual transaction ownership by the old implementation.
Unmodified source failed the reservation assertion in **0.01 seconds**; its
package finished in **0.061 seconds**. This is a captured-DNS adoption control
with a real Stop state transition, not a native-device test.

Additional controls exercise current and stale protection bootstrap admission,
retained Off and via-entry guards, cancellation before reservation, cancellation
inside an admitted guard, and an entered recovery callback whose cleanup is
held after cancellation. The entered callback must retain the transaction
until cleanup joins and retain its exact failed recovery receipt afterward.
The modeled native read callback must remain uncalled when bootstrap fails.

The final focused controller gate passed **120 verdicts across 24 roots**
under the race detector, with no failure or skip; the package ran in
**3.740 seconds**. The backend session transaction audit and all **seven**
selected-DNS gate contracts also passed. The command is:

```sh
go test -race -json ./cmd/client \
  -run '^(TestStoppedDNS|TestAsyncMeasurementAdoption|TestStaleMeasurement|TestMeasurement(Adoption|Observer|TorObservation|OwnedNodeObservation)|TestLiveMeasurementsCannotPersistAcrossAnotherTransaction|TestSessionDNSWorker|TestDNSProofPath|TestDesktopNodeRecoveryContext)' \
  -count=1 -timeout=5m
python3 deploy/backend-session-transaction-audit.py
python3 deploy/test_recovered_dns_proof_gate.py
```

The original eight-protocol Tor lifecycle root was also attempted unchanged.
Every local leaf stopped at its initial Connect, with `Tor preparation could
not capture its physical network`, before the restoration assertion. The full
attempt is retained as an unavailable local integration boundary. The existing
hosted test remains required; local admission controls do not establish its
native restoration result.

## Remaining lifecycle boundary

This correction prevents an obsolete result from reserving a replacement
connection transaction or entering another owner's protection recovery. It
does not implement a new nonterminal selected-DNS cancel-and-join phase inside
ordinary Stop. The reusable observer, its original deadlines and periodic
cancellation remain unchanged. Terminal controller shutdown still uses its
separate DNS-worker retirement and join path. A broader reusable DNS drain
requires its own lifecycle design and evidence.
