# Comparison identity keeps the probe caller

Local/Server comparison proves both routed operands and pins one session
identity across them. Native identity observation may acquire retained locks or
perform IPC. Giving those observations an unrelated background context would
let cancelled or expired measurement work wait beyond its original authority.

The optional `routechoice.ContextIdentitySession` capability supplies
`IdentityContext(context.Context) (string, error)`. The comparison engine uses
it for initial identity capture and every post-proof/probe identity check. The
initial capture and path proof share the same original proof deadline; each
post-probe identity uses that probe's exact context before it is cancelled.
An identity error, empty identity, replacement or value returned after
cancellation disqualifies the candidate without a score or legacy fallback.
The lowest valid mean, one shared random external endpoint, repeated final
probes and owned teardown remain unchanged.

Existing synchronous `Session.Identity` implementations remain compatible and
joined, with caller checks before and after. This shared contract does not make
those legacy callbacks interruptible. Shipping native hosts must explicitly
implement the context capability.

All nineteen shared route-choice test roots pass with race instrumentation
(45 verdicts). New controls retain original context values and exact per-phase
deadlines, reject identity failures/cancellation at all four observation
boundaries, and revoke a winning candidate whose identity changes after its
final external probe. The surviving candidate must reprove both operands
through the same captured target; the prior candidate is closed first.

## Desktop native host wiring

The desktop Tor comparison session and the desktop multihop execution session
now implement the contextual capability. The Tor driver carries the caller
through its captured application, selected profile, entry source, physical
network, temporary Speed Lab owner and native comparison identity. A changed
or missing observer cannot fall back to an ambient observation. Probe and
retained-path checks use the same context, including after native measurement
workers drain.

The combined desktop controller compiled with Go 1.26.3 race instrumentation.
Sixteen focused Tor comparison roots passed all 65 root/subtest verdicts. This
includes four new host identity roots and the existing native mailbox,
original-caller, cancellation, replacement, retryable-close and actual-process
join controls. The tests retain actual private IPC files and child processes;
their timing receipts are fixtures, not evidence of a Tor network circuit or
physical-device acceptance.

This identity change bounds comparison identity and probe admission. The
durable-choice follow-up below closes a separate caller boundary; public
connection capture, preflight and prelaunch propagation remain in progress.

## Durable choice and final adoption

Saving a proved Tor choice now retains both its original connection operation
and the original request/adoption lifetime. The resulting caller preserves the
request's values and the earlier deadline, and either original can cancel it.
Native proof, source and physical-network observations, application/native
locks, profile persistence and Startup Last persistence use that same caller.
Recorded Disconnect intent rejects admission even before the original cancel
callback has returned. Cleanup keeps its separately owned authority.

The final atomic rename rechecks the caller and exact current owner. A rejected
write preserves the original file and rolls back only this operation's in-memory
choice. A completed durable profile write remains recorded if later adoption
fails; it is not falsely reported as rolled back. Connected still requires the
fresh retained proofs and the original current path after persistence.

The integrated race binary at
`0de31ff7103622fa999da523061581623dece47c` passed all 23 verdicts across five new
runtime roots. They exercise held application/proof/native-owner locks,
independently cancelled original lifetimes, the actual Disconnect function with
its cancel callback held, actual private atomic writes and a retained private
IPC proof process. The final-rename cases preserve the old inode and contents
when admission fails. The controller AST contract passed ten verdicts; all 43
Python Tor source-audit tests also passed, including removed-guard controls.

The broader selector additionally reached twelve older physical-capture cases,
which failed before their assertions because this environment cannot capture
the physical network. Those twelve leaves and their parent are retained as
failed results, not passed or skipped cases. The local controlled-observer
checks do not replace the hosted native gate, a real Tor circuit, or device
acceptance. Public connection preflight remains a separate unfinished unit.
