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

This change bounds comparison identity and probe admission. Public connection
preflight and final durable choice/adoption still have separate caller
propagation work; this result does not close those requirements.
