# Owned pending-Stop retry in the desktop primary action

Windows, macOS and Linux unified shells now show **Retry Disconnect** while an
ordinary Stop still owns unfinished cleanup, including when connection
presentation is already `failed` or `off`. The controller preserves the original
`connected`, phase and runtime fields. It adds `stop_pending` and, only for an
outstanding receipt, its opaque `stop_token` to the authenticated status response.
No error-message parsing supplies this state.

## Captured action and cleanup ownership

Each original Stop receipt owns a fresh random token as well as its registered
tracker, selected-DNS worker and observation epoch. Status captures that receipt
with application presentation in tracker-then-application lock order. It does
not start an observer merely to read status. A missing or replaced owner,
malformed receipt or cancelled status caller produces an error instead of a
false idle view.

The rendered primary button retains its token independently of later polls.
Clicking Retry posts only that token to `POST /api/disconnect/retry`. The dedicated
route acquires the transaction with the original HTTP caller, validates the exact
current receipt before even connection cancellation, and passes the required
receipt into the existing Stop drain. The drain cannot recapture a replacement
receipt. A consumed or replaced token returns a conflict without changing the
new connection. The UI never falls through from a stale Retry to Connect or an
unconditional Disconnect.

The ordinary Disconnect route and its cancellation behavior remain available.
An owned retry uses a non-preempting local request: it cannot cancel another
native UI operation before the controller validates ownership. Windows also
excludes this request from both its queued post-cancel Disconnect and its
completion fallback. An in-progress Stop disables duplicate primary actions.
Existing 15-second Stop cleanup and platform request budgets are unchanged.

## Persistent mutations and protection recovery

A pending receipt keeps ordinary settings and node mutation controls busy.
The shared controller admission enforces the same rule for ordinary requests
and trusted internal mutations, so an editor opened before Stop cannot write
through `failed` or `off` presentation. New Connect remains fenced by the
published ordinary-Stop guard.

Explicit protection Off retains its existing captured recovery path. Native
UI guards still require a known, disconnected, stable status and the original
captured protection request; enabling protection and ordinary edits cannot use
that exception. The controller checks the parsed policy and refuses every
non-Off preference while Stop is pending. Existing protection ownership,
absence, durable-save and caller checks remain mandatory. Completing Off does
not consume the separate Stop receipt; Retry Disconnect still owns that work.

Windows' Emergency disconnect, Linux's Emergency Stop and the macOS advanced
Disconnect action remain available. The primary Retry action now gives the
pending receipt a direct visible recovery path.

## Executed evidence

The controller run was based on published
`ef8d3762ee2e9e5f8f742c66ea3a8f44baa9ba8b` plus this change. Go 1.26.3 with the
race detector passed **46 verdicts across 19 roots**, with zero failures or
skips, in **1.448 seconds** of test execution. It includes:

- Original ordinary Stop failure, token-bound cleanup, same-tracker reconnect
  and a subsequent stale retry that cannot affect that reconnect.
- Consumed receipts, replacement trackers with the same epoch, changed tokens,
  controller closure, queued receipt replacement and original caller expiry.
- Status cancellation behind tracker/application locks, unchanged Connected
  presentation, invalid owners and no observer creation for a status-only read.
- Required-receipt drain refusal, strict request decoding, ordinary/internal
  mutation rejection in both failed/off phases, non-Off protection refusal and
  successful owned Off with the Stop fence retained.
- The existing ordinary Stop join, deadline, observation-epoch, replacement,
  terminal-retirement and independent stale-measurement admission controls.

Before publication the unit was rebased onto
`fcc6f47a1d73d6665aff505333e5fb2f8ec7cac6`, preserving its four unrelated MAX
runner/generator repairs. Every tested production, test and workflow file was
byte-identical after that rebase. This comparison is not another execution of
the earlier race or host-callback gates.

Three bridge tests also passed with the race detector, in 1.035 seconds. The
actual framed bridge preserved the retry route, token bytes and HTTP conflict.
The controller bearer-owner test includes the new route, and the executable
Windows managed target validator accepts its canonical local path while
refusing foreign authorities and path aliases. Authentication and native IPC
allowlists were not widened.

The actual transformed Windows PowerShell, macOS Swift and Linux C primary
callbacks were executed with modeled window/dispatch/HTTP boundaries. The
Windows test used PowerShell 7.6.9, the Swift test used Swift 6.4.2, and the C test
used real json-glib. Their positive cases cover rendered and freshly observed
retry tokens, replacement status, server refusal, malformed receipts, ordinary
Connect/Disconnect, local operation ownership, ordinary mutation blocking and
explicit Off recovery. Eleven deliberate source mutations were rejected: five
Windows controls, three Swift controls and three C controls. The Linux fixture
also executes the transformed refresh prefix that paints and binds the button.
Existing protection and compact-DNS ownership/serialization fixtures passed on
all three host runtimes. The Windows/Linux shipping mutation audits, macOS
shipping Swift parse/audit, backend transaction audit, kill-switch contract and
native workflow parity audit also passed.

The new host callback gate is mandatory in the focused native workflows and
matching Windows/macOS/Linux release jobs. Windows jobs require both
PowerShell 7 and Windows PowerShell 5.1; Linux release jobs cover both existing
architectures. Source-audit controls reject removal or optional execution of
these steps. These workflow requirements are not reported as already completed
native package executions.

The local callback fixtures do not establish a WPF/AppKit/GTK application run,
real firewall removal, physical-device networking, a complete native package,
current release acceptance or deployment. The successful protection Off test
uses the existing modeled kernel owner while executing real controller methods.
The separate earlier wait before a public Disconnect acquires `operationMu`
still needs its captured-owner cancellation hook; this retry UX does not claim
to close that boundary.
