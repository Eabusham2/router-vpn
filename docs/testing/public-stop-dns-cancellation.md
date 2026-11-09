# Public Stop cancellation before transaction admission

Desktop `POST /api/disconnect` and `POST /api/emergency-stop` now cancel their
captured selected-DNS worker before waiting for the connection transaction.
This closes the earlier admission gap left by the
[ordinary Stop drain](ordinary-stop-dns.md): a DNS result can own `operationMu`
while entering an existing native protection guard, so waiting for that lock
before cancelling its caller could leave Disconnect waiting for the DNS budget.

## Captured reservation and caller

Public Stop reserves the exact registered tracker, selected-DNS worker,
observation epoch and random retry token. Tracker and application state are
captured in that order. It cancels the original DNS context and the captured
connection, startup and recovery contexts, and cancels the candidate owner
under its original control. These are nonjoining context cancellations. The
application lock is released before acquiring candidate control; no native or
DNS join takes place under the tracker, application or candidate-control locks.

The reservation remains visible through the existing `stop_pending` and
`stop_token` status fields. Public operation-lock admission uses the original
HTTP caller. After admission it requires the same receipt pointer, registered
tracker, worker, epoch and token. It cannot recapture an owner after another
Stop or owned Retry has completed the original request. A late caller returns a
conflict and cannot cancel or disconnect a replacement connection.

A caller cancelled before capture creates no Stop receipt and changes no
session history. Emergency Stop records its reason only after successful owned
capture. Expiry after capture retains the receipt for explicit Retry Disconnect.
The selected-DNS drain uses the original HTTP caller within the existing
15-second Stop cleanup ceiling. The DNS worker's 30-second whole-operation
budget and shorter native operation deadlines are unchanged.

`POST /api/disconnect/retry` still validates its displayed token under
`operationMu` before cancellation. It now carries the same caller and required
receipt through cancellation and DNS cleanup. Public candidate cancellation
and cleanup also retain that caller, with the existing 10-second candidate
cleanup ceiling. Entered candidate cleanup remains joined; cancellation does
not authorize detaching its original owner.

These caller-aware waits do not change every legacy runtime teardown helper.
Existing subprocess, protection, MTU and native retirement semantics remain
in place; this change does not claim a new end-to-end deadline for all possible
platform cleanup operations.

## Admission while Stop is pending

A transition which already owned `operationMu` may retire its original runtime,
but its internal Stop cannot consume a public reservation. The reservation is
cleared only after successful cleanup using that exact required receipt, or by
terminal shutdown after the tracker has permanently closed. A timeout or native
cleanup error preserves the original retry state. Successful owned Retry permits
a new connection and a fresh selected-DNS proof on the same reusable tracker.

Connection context publication now rechecks the pending receipt atomically
with application state, after the existing filesystem and protection preflight.
This covers a Stop arriving after the early admission check but before the new
connection context exists. A context published first is cancelled as the
original owner; a Stop reserved first prevents later publication.

Candidate benchmarks have a separate operation-owner publication point. That
publication now holds tracker, candidate-control and application locks in that
order and rejects a pending Stop, including `failed` or `off` presentation. When
no tracker exists, it holds candidate control and application state, rechecks
registration, and retries if a tracker appeared. It creates no observer merely
to start a benchmark. An already admitted candidate remains the exact owner
cancelled and joined by public Stop.

Terminal controller shutdown keeps its existing permanent admission barrier,
observer cancellation and selected-DNS retirement before operation-lock
admission. It does not reopen the reusable public fence or adopt a replacement
tracker.

## Executable evidence and limits

On original source `e2b21c875195df3a75065f27230ffa1774d977a3`, the actual
registered DNS worker reached its normal terminal adoption and owned
`operationMu` while waiting for the protection mutex. Both actual public routes
then failed the cancellation-order control in **0.055 seconds**: the original
DNS caller remained live at the existing connection-cancellation boundary.
The test releases its held mutex and joins its worker without advancing the
30-second DNS deadline. An earlier fixture used `synctest.Wait` with a plain
mutex waiter; its 60-second timeout is retained as fixture diagnosis and is not
counted as the causal rejection.

The focused execution covers both public routes, original caller cancellation
before capture and during lock/join waits, exact registry/epoch/worker
replacement, repeated Stop, internal cleanup while a public reservation is
pending, delayed public calls after owned Retry and reconnect, atomic actual
Connect publication, actual candidate handler admission, and terminal closure.
Existing ordinary Stop, owned Retry, measurement admission, recovery and
candidate lifecycle controls remain included. Source contracts retain the
original DNS-before-MTU/native teardown order and reject removal of caller or
required-receipt propagation in the public handlers.

The final Go 1.26.3 race run passed **151 verdicts across 62 roots**, with no
failures or skips, in **20.477 seconds**. It ran on published parent
`f23dea2f6d1650bac010cd569ee27392651b539d` plus this frozen unit. The earlier
146-verdict run is retained as intermediate evidence; the final run also
includes the exact Retry cancellation and candidate cleanup caller controls.
The backend transaction audit, owned retry route/removal contracts and
kill-switch transition contract passed with the updated call chain.

One isolated overlay image exercised three disjoint causal controls against
the same final tests. Restoring the earlier connection publication code made
the actual transaction publish a new context after Stop captured cancellation.
Removing public-reservation retention let an internal transition consume the
waiting Stop receipt. Removing the candidate pending check let the actual
handler publish a measured receipt in both failed/off cases. All three roots
failed at those intended assertions in **2.549 seconds**, with seven failing
root/subtest verdicts and no panic or data-race report. Each root reaches only
its corresponding altered boundary. The overlay did not modify shipping
files; all frozen source and contract hashes were verified afterward.

The tests execute the shipping controller and DNS/candidate ownership methods.
Resolver responses, candidate lanes and platform protection helpers are
explicitly modeled where needed. They do not establish device networking,
firewall removal, a complete native package, a deployed router or release
acceptance. Physical-network guards and native acceptance gates are unchanged.
