package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type desktopNodeMTUWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *desktopNodeMTUWaitingContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

func TestDesktopNodeMTUContextUnsubmittedCommandCannotStrandLease(t *testing.T) {
	for _, action := range []string{"begin", "set", "commit"} {
		t.Run(action, func(t *testing.T) {
			fixture := newDesktopNodeMTUFixture(t)
			owner := fixture.owner(action != "begin")
			fixture.base = owner.record
			if err := fixture.publish(owner.record, false); err != nil {
				t.Fatal(err)
			}
			fixture.launch.workspaceMu.Lock()
			var released sync.Once
			unlock := func() { released.Do(fixture.launch.workspaceMu.Unlock) }
			defer unlock()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &desktopNodeMTUWaitingContext{Context: parent, waiting: make(chan struct{})}
			done := make(chan error, 1)
			go func() {
				owner.mu.Lock()
				defer owner.mu.Unlock()
				value := 0
				if action == "set" {
					value = 1380
				}
				done <- owner.exchangeContext(ctx, action, value)
			}()
			// Done is first requested by LockContext after TryLock failed on
			// the retained workspace. The command exists but cannot be published.
			select {
			case <-ctx.waiting:
			case <-time.After(time.Second):
				unlock()
				<-done
				t.Fatal("command did not reach original publication admission")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				unlock()
				<-done
				t.Fatal("unsubmitted command outlived cancellation")
			}
			unlock()
			if owner.pending != nil || owner.unconfirmedCommit != nil || owner.committed || owner.closed != (action == "begin") {
				t.Fatal("unsubmitted command retained an impossible acknowledgement or discarded an existing lease")
			}
			if _, err := readDesktopRuntimeFile(fixture.launch, "node-mtu-request.json", 4096); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancelled publication wrote a request", err)
			}
			commands := startDesktopNodeMTUFixtureChild(t, fixture, nil)
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := owner.CloseContext(cleanup); err != nil {
				t.Fatal("unsubmitted command stranded checked cleanup", err)
			}
			if action != "begin" {
				request := <-commands
				if request.Action != "rollback" || request.Lease != owner.lease || request.Reader != fixture.base.Reader {
					t.Fatal("cleanup did not retain only the prior active lease", request)
				}
			} else if _, restored := owner.CleanupRestored(); restored {
				t.Fatal("unsubmitted begin fabricated a numeric restoration")
			}
			select {
			case request := <-commands:
				t.Fatal("unsubmitted command emitted an extra operation", request)
			default:
			}
		})
	}
}

// Held locks are released only after cancellation is observed. These exercise
// admission to the real owner and private mailbox without a scheduling race or
// a substituted kernel observation.
func TestDesktopNodeMTUContextCancelsHeldOwnerAndMailbox(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context, *desktopNodeMTUOwner) error
	}{
		{"read", func(ctx context.Context, owner *desktopNodeMTUOwner) error {
			_, err := owner.ReadContext(ctx)
			return err
		}},
		{"change", func(ctx context.Context, owner *desktopNodeMTUOwner) error {
			_, err := owner.ChangeContext(ctx, owner.state(), 1380)
			return err
		}},
		{"commit", func(ctx context.Context, owner *desktopNodeMTUOwner) error { return owner.CommitContext(ctx) }},
		{"restore", func(ctx context.Context, owner *desktopNodeMTUOwner) error {
			_, err := owner.RestoreContext(ctx)
			return err
		}},
		{"close", func(ctx context.Context, owner *desktopNodeMTUOwner) error { return owner.CloseContext(ctx) }},
	}
	for _, where := range []string{"owner", "mailbox"} {
		for _, operation := range operations {
			t.Run(where+"/"+operation.name, func(t *testing.T) {
				fixture := newDesktopNodeMTUFixture(t)
				owner := fixture.owner(true)
				if err := fixture.publish(owner.record, false); err != nil {
					t.Fatal(err)
				}
				before := owner.record
				lock := &owner.mu
				if where == "mailbox" {
					lock = &fixture.launch.workspaceMu
				}
				lock.Lock()
				var release sync.Once
				unlock := func() { release.Do(lock.Unlock) }
				defer unlock()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				started, done := make(chan struct{}), make(chan error, 1)
				go func() { close(started); done <- operation.run(ctx, owner) }()
				<-started
				cancel()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Fatal("held operation lost the original cancellation", err)
					}
				case <-time.After(time.Second):
					unlock()
					<-done
					t.Fatal("held original owner or mailbox outlived its caller")
				}
				if owner.record != before || owner.pending != nil || owner.unconfirmedCommit != nil || owner.closed || owner.committed {
					t.Fatal("cancelled lock admission changed the original MTU owner")
				}
			})
		}
	}
}

func TestDesktopNodeMTUContextOpenCancelsOriginalMailbox(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	fixture.launch.workspaceMu.Lock()
	var release sync.Once
	unlock := func() { release.Do(fixture.launch.workspaceMu.Unlock) }
	defer unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		owner, err := openDesktopNodeMTUOwnerContext(ctx, fixture.launch, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: 1420}, strings.Repeat("a", 32))
		if owner != nil {
			err = errors.Join(err, errors.New("cancelled unopened mailbox manufactured a native lease"))
		}
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		unlock()
		<-done
		t.Fatal("native lease acquisition blocked behind an expired original caller")
	}
}

func TestDesktopNodeMTUContextPendingMutationRetainsOwnedRollback(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	arrived, release := make(chan desktopNodeMTUCommand, 1), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	commands := startDesktopNodeMTUFixtureChild(t, fixture, func(command desktopNodeMTUCommand, _ *desktopNodeMTURecord) {
		if command.Action == "set" {
			arrived <- command
			<-release
		}
	})
	defer unblock()
	kernel, err := openDesktopNodeMTUOwnerContext(context.Background(), fixture.launch, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: 1420}, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	owner := kernel.(*desktopNodeMTUOwner)
	before, err := owner.ReadContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := owner.ChangeContext(ctx, before, 1380); done <- err }()
	var pending desktopNodeMTUCommand
	select {
	case pending = <-arrived:
	case <-time.After(time.Second):
		t.Fatal("original set command did not reach the private mailbox")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("pending change lost its original cancellation", err)
		}
	case <-time.After(time.Second):
		unblock()
		<-done
		t.Fatal("native acknowledgement wait outlived the cancelled caller")
	}
	if owner.pending == nil || *owner.pending != pending || owner.state() != before || owner.committed || owner.closed {
		t.Fatal("cancelled native mutation discarded or adopted an unconsumed command")
	}
	unblock()
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := owner.CloseContext(cleanup); err != nil {
		t.Fatal("owned cleanup could not drain and roll back the exact pending mutation", err)
	}
	for _, action := range []string{"begin", "set", "rollback"} {
		request := <-commands
		if request.Action != action || request.Lease != pending.Lease || request.Session != pending.Session || request.Config != pending.Config || request.Path != pending.Path {
			t.Fatal("cancellation rollback changed the captured native command owner", request)
		}
	}
	state, restored := owner.CleanupRestored()
	if !restored || state.MTU != 1420 || state.Identity == before.Identity || owner.pending != nil {
		t.Fatal("pending mutation did not restore through its actual returned reader", state, restored)
	}
}

func TestDesktopNodeMTUContextCommitCancellationRetainsOneShotRevert(t *testing.T) {
	fixture := newDesktopNodeMTUFixture(t)
	commands := startDesktopNodeMTUFixtureChild(t, fixture, nil)
	kernel, err := openDesktopNodeMTUOwnerContext(context.Background(), fixture.launch, mtuLiveSnapshot{Interface: fixture.base.Interface, Family: 4, OriginalMTU: 1420}, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	owner := kernel.(*desktopNodeMTUOwner)
	state, err := owner.ReadContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ChangeContext(context.Background(), state, 1380); err != nil {
		t.Fatal(err)
	}
	type key struct{}
	value := new(int)
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, value), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	calls := 0
	err = owner.commitWithValidationContext(ctx, func(observed context.Context) error {
		calls++
		actual, ok := observed.Deadline()
		if observed.Value(key{}) != value || !ok || !actual.Equal(deadline) || owner.pending != nil || owner.unconfirmedCommit == nil || owner.record.Active || owner.committed {
			t.Error("post-commit validation did not retain the exact caller and private commit capability")
		}
		cancel()
		return nil // A racing successful observer cannot revive its caller.
	})
	if calls != 1 || !errors.Is(err, context.Canceled) || owner.committed || owner.unconfirmedCommit == nil || owner.closed {
		t.Fatal("cancelled final observation accepted a late commit", calls, err)
	}
	commit := *owner.unconfirmedCommit
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := owner.CloseContext(cleanup); err != nil {
		t.Fatal("cancelled final validation could not restore its unconfirmed original commit", err)
	}
	for _, action := range []string{"begin", "set", "commit", "revert-unconfirmed-commit"} {
		request := <-commands
		if request.Action != action {
			t.Fatal("owned commit cleanup order changed", request)
		}
		if action == "revert-unconfirmed-commit" && (request.Lease != commit.Lease || request.CommitRequest != commit.Request || request.CommitGeneration != commit.Generation || request.RevertToken != commit.RevertToken) {
			t.Fatal("late commit cleanup did not use its one-shot original capability", request)
		}
	}
	if actual, restored := owner.CleanupRestored(); !restored || actual.MTU != 1420 {
		t.Fatal("cancelled commit manufactured restoration without original readback", actual, restored)
	}
}
