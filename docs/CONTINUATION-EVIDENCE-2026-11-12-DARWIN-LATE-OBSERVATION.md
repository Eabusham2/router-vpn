# Retain Darwin native diagnostics through joined close, 2026-11-12

The macOS physical socket job [130883815005](https://github.com/Eabusham2/router-vpn/actions/runs/43127680035/job/130883815005) at source `ab6c3609` failed `TestDesktopDarwinGuardianKernelSocketRetirementReusesCapacity` at sequential socket 19 after 74.98 seconds. Its first recorded loss was `control-receive-probe`, with `observed_ms=1794448153507`, `lost_ms=1794448156930`, `age_ms=3423`, and the idle/no-pending-frame error. No bounded native observation was printed. Those facts do not establish which native readback command or scheduling stage caused the probe to miss its deadline.

## Reproduced missing diagnostic

The failure fixture already reads observations before cleanup and after broker drain. However, successful policy Close closes the observation reader during broker drain. If the independent native cancellation observer reports after the initial trace, the final trace attempts to read a closed file and silently loses the bytes.

The existing executable observation regression omitted this actual close call from its modeled broker boundary. Adding the exact shipping `closeObservation` method and invoking it after the actual observer writes to the actual pipe reproduces the loss: the expected after-broker-drain observation is absent. This is a diagnostic lifecycle defect independently of the original native timeout's cause.

## Repair

Policy close now retains at most the existing 16 KiB read bound before closing its original reader. A synchronized diagnostic read consumes those final bytes once after close; repeated close preserves the unread snapshot and repeated read cannot replay it. The original nonblocking single-write reporter and full-pipe drop behavior remain unchanged. No observer can refresh Current, supply a permit, replace source ownership or alter any operation deadline.

The fixture uses the policy's bounded diagnostic read. Its executable regression now includes the actual close method and proves late delivery through the real pipe and cleanup stack. A mutation discarding bytes before close reproduces the missing snapshot; removing the final trace leaves unread retained evidence; removing the native observer and blocking the output pipe retain their existing causal failures. Original probe failure remains a failure in all diagnostic variants.

The two focused guardian runner tests passed in 8.569 seconds: all six observation variants and all four SOCKS cleanup-order variants execute real Go race-enabled subprocesses. `git diff --check` passed. This proves bounded diagnostic retention, not macOS PF acceptance or a fix for the original timeout. The native/probe/control/proof-age deadlines remain unchanged at 2/2/3/5 seconds. A current-source macOS run remains necessary to attribute the native timeout. Publishing this source change triggers the existing macOS physical socket workflow through its normal path filter.
