# Native node MTU caller and cleanup ownership

The desktop node-MTU mailbox now has context-aware acquisition, read, mutation,
commit, rollback and close operations. Admission to its owner mutex and private
workspace, immutable command publication, command consumption and the final
commit observation retain the original caller. A cancelled call keeps a pending
command or unconfirmed one-shot commit capability until bounded owned cleanup
drains and restores it. Legacy callers keep their existing method signatures.
Publication admission distinguishes a command that never entered the original
private file creation from a command that may already have been consumed. A
cancelled, unsubmitted begin acquires no lease; an unsubmitted set or commit
retains its prior active lease for rollback. Possible publication still requires
the exact consumed acknowledgement or checked runtime retirement.

`cmd/client/desktop_node_mtu_context_test.go` exercises held owner and mailbox
locks, cancellation while the real private mailbox has an unconsumed mutation,
and cancellation inside the successful final commit observer. Cleanup must use
the exact original lease and, after commit, its original revert capability.
The begin/set/commit publication controls explicitly wait for the held workspace
admission before cancelling, then verify that no request was written and that
cleanup neither strands a nonexistent nonce nor drops the real prior lease.
The private-file child fixture supplies controlled interface readers; these
tests do not claim a physical platform TUN mutation.

Validation on Go 1.26.3, Linux AMD64, November 8, 2026:

- The complete `TestDesktopNodeMTU` selection compiled. The new context tests
  and the existing nonphysical mailbox, replay, replacement, commit, expiry and
  cleanup controls passed.
- Two existing physical-inventory test families stopped during capture with
  `MTU capture has no physical network identity`:
  `TestDesktopNodeMTULateCommitReceiptRestoresExactLiveAndDurableOwner` and
  `TestDesktopNodeMTUCapturedHTTPBridgeCommitsOrRestoresExactNativeReader`.
  Their platform acceptance is unproved in this environment; their guards and
  tests are unchanged.
- The remaining explicit selection passed three consecutive runs:

```sh
go test ./cmd/client -count=3 -run '^TestDesktopNodeMTU(Context|Acknowledgement|CommittedRead|RejectedMutation|ReadBinds|AckWaits|ActualMailbox|FailedBegin|WorkspaceReplacement|ConfirmedCommit|InactiveUnconfirmed|FailedCommitRevert|CloseAccepts|CheckedRuntime|CommitValidation)'
```

This is a prerequisite for the imported-entry MTU adapter. It does not itself
enable imported Auto/Retest or establish physical-device release acceptance.
