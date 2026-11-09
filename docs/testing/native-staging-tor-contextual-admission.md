# Native staging caller errors and Tor contextual admission

## Scope

This repair addresses two failures reported on published commit
`7c4a3eed6be826cfdb846394290a0404daca93a3` by the source test jobs
`128991862808` and `128991862947`. It preserves native staging refusal,
physical-network validation, captured runtime ownership and existing deadlines.

`stageDesktopNodeLaunchContext` already rejected an expired original caller
before creating a private runtime directory. Its early error discarded both the
original `context.Canceled` or `context.DeadlineExceeded` cause and the existing
`errConnectionOperationCancelled` identity. The repair distinguishes a missing
caller from a caller that has expired, and retains both cancellation identities
with the original diagnostic. A live ambient connection context cannot replace
the expired original caller.

The prepared Tor Speed Lab fixture changed the legacy `networkIdentity`
callback. Shipping admission reads its captured `networkIdentityContext`, which
correctly remained unchanged. The fixture now changes that contextual callback.
The production Tor admission check is unchanged: a different, empty, failed or
noncontextual observation cannot authorize a prepared trial or fall back to a
matching legacy observer.

## Executed evidence

The focused tests ran with Go 1.26.3 and the race detector on parent
`1e2ba67ac12bebc10d83fc174db8aee26f267597`. The three relevant production files
were byte-identical to the failing published revision before the staging repair.

The original-source baseline reproduced the existing staging assertion and the
new cancellation and deadline assertions. The missing-caller case and all five
contextual Tor observation cases passed on the original production source.
After the narrow staging correction, all 11 Go test verdicts passed: three root
tests and eight subtests, with no failures or skips. The executed package took
1.084 seconds; compilation is separate from that test duration.

```sh
go test -race -p=1 ./cmd/client \
  -run '^Test(DesktopNativeStaging(OwnsExactDirectoryAndEnvironment|PreservesOriginalCallerRefusal)|SpeedLabTorPreparedAdmissionUsesCapturedContextualNetwork)$' \
  -count=1 -timeout=180s
```

The tests exercise the actual staging and prepared-admission methods. The Tor
unit models only physical observation and uses unstarted command identities; it
is not a native Tor, host routing or device test. It checks that the original
context and deadline reach the captured observer, and that observation does not
change the prior runtime, temporary owner, profile, command or caller lifetime.

## Causal controls

A separate Go overlay restored the original staging error branch and removed
only the prepared-trial contextual network rejection. It changed no working
production files. The cancellation and deadline leaves failed at the original
caller-refusal assertions. All four network refusal leaves failed at the
captured-network admission assertions, while the unchanged contextual observer
and missing-caller cases still passed. The run produced the expected eight
failing verdicts, including the two parent tests, and two passing verdicts, with
no skip, race report or panic. Source hashes were unchanged before and after
all runs.

## Physical observation boundary

The corrected existing process test was attempted once:

```sh
go test -race -p=1 ./cmd/client \
  -run '^TestSpeedLabTorPreparedTrialRejectsStaleAdmissionBeforeStop$/^network$' \
  -count=1 -timeout=180s
```

Its initial public Connect was refused with `operation not permitted` and
`Tor preparation could not capture its physical network`, before the stale-trial
admission boundary. The physical guard was retained, with no local retry or
replacement observer added to that process fixture. Its final hosted result
remains a separate gate. These local results do not establish packaged native,
router, full-suite or release acceptance.
