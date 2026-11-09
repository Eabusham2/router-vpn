# MTU final adoption and checked rollback

The shared MTU controller can measure and select a new TUN size before a
platform's retained native lease accepts its final commit. If that final
adoption fails, the controller must not keep the candidate configuration while
the native owner has already restored the original interface. A later Retest
would otherwise compare the original interface against the failed candidate's
configuration.

`FinalizationRollbackOwner` is an optional, observation-only contract. It uses
the failed operation's existing cleanup authority and cannot renew its deadline
or submit another mutation. The returned session, path and MTU must match the
original pre-run capture. The controller separately captures the current
interface again, validates the complete pre-run configuration, and restores
that exact configuration only if both observations agree. Failure remains a
failure; the result is restored and unmeasured. The final controller mutex
admission checks the same cleanup context again, so waiting for admission cannot
extend the authority of an earlier observation.

The executable test runs the real shared selection and finalization path with
controlled platform TUN readers. It measures a distinct winner, rejects final
adoption, restores the original owned reader, and then runs a second Retest
using the restored configuration. Negative cases reject another session, path,
reader or MTU, an unconfirmed or cancelled rollback, and replacement after the
first rollback observation.

Validation used Go 1.26.3 on Linux:

```sh
go test -json -race ./internal/mobilemtu -count=3
```

All 61 root tests and 152 verdicts passed per iteration, including the eight
finalization rollback cases. After adding the final admission check, a focused
race run of `^TestFinalizedRollback` passed two root tests and ten verdicts. The
additional causal test holds the actual final admission mutex, closes the
original cleanup authority after the live proof/configuration validation, and
then releases admission; no restoration may be published.

The fixtures exercise shared policy, selection, cancellation and configuration
ownership. They do not establish physical interface operation or packaged native
application acceptance.
