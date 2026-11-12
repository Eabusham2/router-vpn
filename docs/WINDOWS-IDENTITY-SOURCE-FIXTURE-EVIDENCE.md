# Windows identity source-copy fixture

## Failure and correction

The Windows native contract run [43157301549](https://github.com/Eabusham2/router-vpn/actions/runs/43157301549), job 130981823334, failed at the source-copy fixture on `53ceb91433025b5940936c4b4aaf3a1e0db0f77d`.
The shipping desktop preparer now invokes the ordered application gate, admission,
and native owner preparers. Those require the actual pinned native checkout.
The source-copy fixture intentionally uses an empty directory and already replaces
its other native prerequisites with explicit component boundaries.

The fixture now includes the three ordered preparers in that same explicit
boundary and requires each actual shipping dispatch to receive the original
resolved directory exactly once. The real shared-source copying loop, byte-level
checks, and incomplete or changed source refusals continue to execute. Production
preparation and its original-core checks are unchanged.

## Recorded checks

- Before the correction, the same source-copy test reproduced the hosted failure:
  `git rev-parse HEAD` exited 128 in the non-Git fixture directory.
- All 24 Windows identity runner checks passed after the correction.
- A causal control removed the three dispatches from the actual preparer function;
  the corrected fixture rejected the missing calls.
- `git diff --check` passed.

These local checks establish the fixture composition and source-copy contract.
They do not establish native Windows socket, token, ALE, or WFP execution; those
remain required in the hosted Windows job for the published commit.
