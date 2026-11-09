# Selected DNS worker retirement

The session tracker now retains each asynchronous selected-DNS proof from
admission through completion. Its original 30-second worker budget reaches
tracker, app and path admission as well as resolver work. A session, node,
runtime, base or profile change cancels a worker even before the detailed path
observer has been installed. The next proof cannot replace an unjoined worker.

Controller shutdown closes DNS-proof admission and cancels the captured worker
before waiting for the connection transaction. It joins that same worker under
a five-second cleanup wait and retains it for retry if cleanup is incomplete.
The native connection fixture also retires and joins its own captured tracker.
An old tracker cannot retire or publish into a replacement tracker with the
same visible session ID.

This addresses the asynchronous DNS setup remaining in the synctest bubble
after `TestDesktopNodePublicSpeedLabCancellationRestoresExactWinner` exited in
the source job for commit `2926063d498d7e4a5889fc3e73f3fc399fb536c5`
(Actions run `42413089753`, job `128525252342`). That observation establishes a
missing fixture lifetime/join; it does not establish a permanent device deadlock.

## Focused verification

Go 1.26.3, Linux AMD64, November 8, 2026 (America/Chicago):

```sh
go test -race -json ./cmd/client \
  -run '^(TestSessionDNSWorker|TestDNSProofPath|TestControllerShutdown(CancelsBeforeWaiting|RejectsForeign|RetainsTerminal|BindFailure))' \
  -count=1 -timeout=90s
```

All 52 test verdicts passed. The new tests exercise held app admission,
cancelled entered resolver work, retained cleanup and retry, controller drain,
same-ID tracker replacement, and stale observation before path admission.
The existing DNS path tests retain graph, credential, policy and publication
rejection coverage.

Four source mutations were separately rejected by the intended assertions:

| Mutation | Observed rejection |
| --- | --- |
| Replace the original admission context with Background | Cancelled setup cannot join while the original app lock is held |
| Remove worker cancellation from terminal retirement | The original admission outlives the cleanup deadline |
| Return without joining an entered probe | Retirement reports success while its resolver remains entered |
| Remove cancellation at stale observation | Seven changed-owner cases remain live; the unchanged capture still passes |

The full public Speed Lab fixture and an existing Speed Lab shutdown fixture
cannot reach their assertions in this local workspace: physical interface
capture returns `operation not permitted`. They remain enabled for native CI.
This focused verification does not substitute for native networking, leak,
device, or exact-release acceptance.
