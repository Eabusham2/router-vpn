# Original caller during connection and protection admission

## Published behavior

Connection admission can retain an explicit caller through application and
protection locks, private runtime preparation, measurement invalidation and
the final connection transaction. A cancelled caller cannot publish a new
requested connection after waiting for another owner. The admitted operation
keeps that caller's values and deadline. Finishing the original operation does
not cancel or clear a replacement.

Retained protection, pending Off and Linux parent/service observations use the
same caller. Cancellation is an observation failure, never evidence that a
policy is absent. Existing parent and service observation caps remain in force;
an earlier caller deadline also bounds them. No kernel or physical-interface
guard is relaxed.

Recovery and Off admission retain their original caller through the captured
application, protection slot and profile observations. Once Off has completed
native removal and durable publication, joined cleanup keeps that exact result.
Cancellation during later readback cannot pretend that the saved preference
was rolled back or substitute another removal owner.

Compatibility entry points retain their existing behavior. Explicit Tor
public/preflight propagation, fresh Windows native recovery callback contexts
and the final Off rename check are separate follow-ups; this unit does not
claim those additional callers are already converted.

## Executed evidence

The race-instrumented controller image was built with Go 1.26.3 from integrated
snapshot `4fae999264ac44c4d17c2a8ffd7ed250510d3610`. Its exact executable SHA-256
is `1ee10feefad8af34b81e90241297b2f33ee9245f90dd7bfbea7260d2e049c160`. The following focused groups
completed with no failures or skips:

| Selector | Roots | Root and child verdicts |
|---|---:|---:|
| `^TestConnectionAdmissionContext` | 8 | 26 |
| `^TestDesktop(NodeRecoveryContext\|ProtectionOffContext)` | 5 | 25 |
| `TestDesktopNodeJournalOffSavedResultRetryKeepsTokenAndOwner` and `TestDesktopNodeRecoveryOffRetriesActualSavedResult` | 2 | 7 |

Held-lock controls wait until the actual contextual mutex admission observes
the caller, then cancel while the mutex stays held. They do not use a scheduling
delay to infer entry. They retain the original source, slot, controller and
measurement owners and check that an unentered native exchange does not run.
The Linux service tests distinguish a live receipt from one returned after
cancellation. Durable Off retry tests exercise the actual saved file and
retained removal token.

The integration snapshot also contains separately tracked imported Windows
parent changes. This unit's focused admission/recovery tests do not establish
physical Windows WFP behavior, actual Linux parent/service networking, native
packages, publication of those separate features, private deployment or device
acceptance. The follow-up native tests remain required.
