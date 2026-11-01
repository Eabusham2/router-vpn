package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// This executes the original private mailbox, including consumption and the
// one-shot commit-revert nonce. The fixture controls its reader; this is not
// evidence that a platform kernel TUN changed.
func TestDesktopNodeMTUCommitValidationRetainsOriginalRevert(t *testing.T) {
	for _, outcome := range []string{"accepted", "rejected"} {
		t.Run(outcome, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			commands := startDesktopNodeMTUFixtureChild(t, fixture, nil)
			kernel, err := openDesktopNodeMTUOwner(fixture.launch, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: fixture.base.MTU}, strings.Repeat("a", 32))
			if err != nil {
				t.Fatal(err)
			}
			owner := kernel.(*desktopNodeMTUOwner)
			defer func() {
				if err := owner.Close(); err != nil {
					t.Error(err)
				}
			}()
			before, err := owner.Read()
			if err != nil {
				t.Fatal(err)
			}
			next, err := owner.Change(before, 1380)
			if err != nil || next.MTU != 1380 {
				t.Fatal("original native candidate was not applied", next, err)
			}
			rejected := errors.New("original host changed after commit acknowledgement")
			calls := 0
			err = owner.commitWithValidation(func() error {
				calls++
				if owner.pending != nil || owner.record.Active || owner.record.MTU != 1380 || owner.unconfirmedCommit == nil ||
					owner.unconfirmedCommit.Request != owner.record.Request || owner.unconfirmedCommit.Generation != owner.record.Generation ||
					!desktopMTURequestPattern.MatchString(owner.unconfirmedCommit.RevertToken) || owner.committed {
					t.Error("final host validation preceded the consumed original commit or lost its revert capability")
				}
				if _, readErr := readDesktopRuntimeFile(fixture.launch, "node-mtu-request.json", 4096); !errors.Is(readErr, os.ErrNotExist) {
					t.Error("final validation ran before the exact original command was consumed", readErr)
				}
				if outcome == "rejected" {
					return rejected
				}
				return nil
			})
			if calls != 1 || outcome == "rejected" && !errors.Is(err, rejected) || outcome == "accepted" && err != nil {
				t.Fatal("native commit lost its exact final validation result", calls, err)
			}
			var commit desktopNodeMTUCommand
			for _, action := range []string{"begin", "set", "commit"} {
				request := <-commands
				if request.Action != action {
					t.Fatal("private native command order changed", request.Action, action)
				}
				if action == "commit" {
					commit = request
				}
			}
			if outcome == "rejected" {
				if owner.committed || owner.unconfirmedCommit == nil || *owner.unconfirmedCommit != commit || owner.closed {
					t.Fatal("failed final host readback discarded the exact unconfirmed revert")
				}
				if err := owner.Close(); err != nil {
					t.Fatal("failed final validation could not revert its original commit", err)
				}
				revert := <-commands
				if revert.Action != "revert-unconfirmed-commit" || revert.CommitRequest != commit.Request || revert.CommitGeneration != commit.Generation ||
					revert.RevertToken != commit.RevertToken || revert.Lease != commit.Lease || revert.Session != commit.Session || revert.Config != commit.Config || revert.Path != commit.Path {
					t.Fatal("post-validation rollback substituted its original private commit capability", revert)
				}
				state, restored := owner.CleanupRestored()
				if !restored || state.MTU != fixture.base.MTU || !owner.closed || owner.pending != nil || owner.unconfirmedCommit != nil {
					t.Fatal("checked original rollback omitted its exact final readback", state, restored)
				}
			} else {
				if !owner.committed || owner.unconfirmedCommit != nil || owner.record.Restored || owner.Close() != nil {
					t.Fatal("accepted final validation did not release its completed private commit")
				}
				if _, restored := owner.CleanupRestored(); restored {
					t.Fatal("accepted commit fabricated a rollback receipt")
				}
			}
			select {
			case request := <-commands:
				t.Fatal("final native cleanup emitted another unowned command", request.Action)
			default:
			}
		})
	}
}
