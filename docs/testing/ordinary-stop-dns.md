# Ordinary Stop and selected-DNS worker retirement

An ordinary desktop Stop now cancels and joins its captured selected-DNS worker
before runtime teardown. The drain precedes the MTU hold because that hold can
itself retire the original native engine to settle an unresolved MTU lease. The
same outer drain covers retained native Stop returns and legacy cleanup.

## Ownership and retry

The Stop receipt retains the exact registered tracker, worker and observation
epoch. The existing 15-second Stop cleanup context bounds cancellation and join;
no application, tracker, native-owner or MTU lock is held while waiting for the
worker's completion receipt. The ordinary operation lock still serializes
teardown. The existing 30-second whole-DNS budget and shorter native operation
deadlines remain unchanged.

Worker admission stays fenced until both DNS cleanup and runtime retirement
succeed. Observations carry an epoch captured with application state. Stop
advances that epoch at retirement admission and again at successful completion,
so a connected snapshot captured before or during Stop cannot start a worker
after a fast reconnect to the same profile and runtime.

A timeout or runtime cleanup error retains the exact fence for an owned Stop
retry. Connect refuses that pending state before preparing a runtime or changing
connection state, including when presentation is already `failed` or `off`.
Session status reports that selected-DNS admission is paused until Stop
completes. A late worker return alone does not clear the fence. A successful Stop
retry reopens the same reusable tracker; terminal controller retirement never
reopens it. Old receipts cannot cancel or clear a replacement tracker, worker or
retirement receipt.

The unified Windows, macOS and Linux primary buttons now expose **Retry
Disconnect** with the exact outstanding receipt, including failed/off
presentation. The [owned retry guide](owned-stop-retry.md) records its dedicated
route, stale-click refusal and separate validation. The macOS Advanced Product
Disconnect, Windows Emergency disconnect and Linux Emergency Stop actions also
remain available. Repeated Connect attempts deliberately keep returning the
pending-cleanup error until an owned Stop retry completes.

## Regression evidence and limits

The original source at `5b76d2fa8a1f09048bfc92890727eb4314aa441f` failed the
actual `stopModeWithIntent` control in 0.01 seconds: Stop returned success while
the entered selected-DNS probe still retained its cleanup. The control holds
cleanup through a channel and checks the original completion receipt; no
observer delay or physical-network failure supplies the expected rejection.

The focused controls exercise actual Stop cancellation, the existing cleanup
deadline, retained failure and explicit retry, same-tracker connection admission
and fresh DNS proof, old observation epochs, exact replacement ownership,
terminal closure, concurrent first status, and contextual connection admission.
The reconnect fixture uses real transaction/session/DNS-worker methods with
modeled runtime publication. It does not establish a native package, physical
device, resolver-network or deployed-router acceptance result.

The focused race run passed 107 test verdicts across 35 roots with no failures
or skips, both before and after rebasing onto
`fb924d4849b448d519c573a78e021b595a216007`. The final execution took 1.582 seconds.
The Stop deadline case uses Go's deterministic test clock; the shipping deadline
remains 15 seconds. Existing backend transaction, kill-switch transition and
seven recovered selected-DNS source-contract controls also passed.

The final publication preserves the concurrent Tor caller change at
`cbc279a744a1ff4a9197951f3ede8708a27a7909`. The Stop production and regression
files are byte-identical to that focused run. Its backend source audit was
aligned with the newly shipping `beginConnectionOperationContext(r.Context())`
call for external Connect; the required original HTTP context replaces the
obsolete context-free marker. Both backend transaction and kill-switch source
audits passed on the combined tree. This rebase is not reported as another
execution of the earlier race matrix.

The existing stale-measurement admission control separately retains the actual
immutable capture and original live caller after joining its periodic observer.
This keeps owner validation independently testable: incidental observer
cancellation cannot make the old operation-reservation order pass.
A temporary source overlay restoring only that old reservation call failed the
updated admission control at its intended assertion in 0.01 seconds, with the
new Stop implementation still present.

The later [public Stop cancellation repair](public-stop-dns-cancellation.md)
adds a captured reservation before public Disconnect and Emergency Stop wait
for `operationMu`. It cancels the original selected-DNS caller at that earlier
boundary, retains the same receipt through admission and join, and refuses a
delayed caller after another owned retry completes. The evidence above remains
the original ordinary-drain component's execution; the later guide records its
separate public-handler, connection-publication and candidate-admission controls.
