//go:build windows && routervpn_windows_protection_native

package windowsprotection

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowscontroller"
)

// These tests exercise the real created child, authenticated pipe and protected
// journal files. Only the independent BFE read is modeled, through the private
// admission seam; no fixture hash is passed to the exported native BFE reader.
func journalAdmissionStart(t *testing.T, fixture *journalChannelNative, role string) (*journalChannelChild, JournalRecord) {
	t.Helper()
	child := fixture.launch(t, role, fixture.server.PipeName())
	fixture.receive(child)
	result := fixture.received(t)
	if result.err != nil || result.record.Validate() != nil || result.record.Sequence != 2 || result.record.Phase != "intent" || result.record.Intent == nil || result.record.Intent.Candidate.Engine == nil {
		t.Fatal("native admission did not retain its actual successful commit phase", result.err)
	}
	// The wrong-candidate child can already have closed its protocol pipe.
	// Capture from the retained creation handle, never by reopening its PID.
	process, err := child.child.RetainProcess()
	if err != nil {
		t.Fatal("native admission lost its actual first-phase child", err)
	}
	imageErr := process.VerifyImage(fixture.image)
	engine, _, captureErr := journalProcessCapture(process)
	closeErr := process.Close()
	if imageErr != nil || captureErr != nil || closeErr != nil || engine != *result.record.Intent.Candidate.Engine || engine.PID != child.child.PID() {
		t.Fatal("native admission intent substituted the created engine identity", imageErr, captureErr, closeErr)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, result.record) {
		t.Fatal("native admission began without its exact persisted first phase", err)
	}
	return child, result.record
}

func journalAdmissionSameRecord(left, right JournalRecord) bool {
	leftRaw, leftErr := CanonicalJournalRecord(left)
	rightRaw, rightErr := CanonicalJournalRecord(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func journalAdmissionRun(fixture *journalChannelNative, read func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error) <-chan journalChannelResult {
	result := make(chan journalChannelResult, 1)
	go func() {
		record, err := fixture.server.admit(fixture.ctx, read)
		result <- journalChannelResult{record: record, err: err}
		if err != nil {
			// A rejected server must close its actual channel so the child
			// can report the denial, rather than waiting for a read deadline.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = fixture.server.Close(ctx)
		}
	}()
	return result
}

func journalAdmissionResult(t *testing.T, fixture *journalChannelNative, result <-chan journalChannelResult) journalChannelResult {
	t.Helper()
	select {
	case returned := <-result:
		return returned
	case <-fixture.ctx.Done():
		t.Fatal("native admission callback did not join", fixture.ctx.Err())
		return journalChannelResult{}
	}
}

func journalAdmissionRequireDenied(t *testing.T, report journalChannelReport) {
	t.Helper()
	if !report.Accepted || report.Replayed || report.Premature || report.Admitted || report.AdmissionReplayed || !report.Closed || report.Failure == "" {
		t.Fatal("native admission acknowledged an unproved or replaced checkpoint", report)
	}
}

func TestWindowsProtectionJournalAdmissionTwoPhaseCheckpoint(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "admission-client")
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int32
	result := journalAdmissionRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		call := reads.Add(1)
		if ctx.Err() != nil || target != *intent.Intent.Candidate.Target || call > 2 {
			return errors.New("modeled prepared read changed its exact target, lifetime or count")
		}
		selection, err := fixture.store.Snapshot(ctx)
		expected := intent
		if call == 2 {
			expected = settled
		}
		if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, expected) {
			return errors.Join(err, errors.New("prepared reads did not bracket the actual checkpoint flush"))
		}
		return nil
	})
	report := fixture.report(t, child, true)
	returned := journalAdmissionResult(t, fixture, result)
	if !report.Accepted || report.Replayed || report.Premature || !report.Admitted || report.AdmissionReplayed || !report.Closed || report.Failure != "" || returned.err != nil || reads.Load() != 2 {
		t.Fatal("native admission did not acknowledge one independently bracketed checkpoint", report, reads.Load(), returned.err)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, settled) || !journalAdmissionSameRecord(returned.record, settled) ||
		selection.Record.Committed.Engine == nil || *selection.Record.Committed.Engine != *intent.Intent.Candidate.Engine {
		t.Fatal("native admission lost its durable live-engine checkpoint", err)
	}
	if err := child.child.Alive(); err != nil {
		t.Fatal("settled admission incorrectly required the live engine to retire", err)
	}
	if _, err := fixture.server.admit(fixture.ctx, func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error {
		reads.Add(1)
		return nil
	}); err == nil || reads.Load() != 2 {
		t.Fatal("native admission reused its already acknowledged server phase")
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalAdmissionPreparedReadFailures(t *testing.T) {
	for _, stage := range []struct {
		name string
		call int32
	}{{"before-flush", 1}, {"after-flush", 2}} {
		t.Run(stage.name, func(t *testing.T) {
			fixture := newJournalChannelNative(t, nil)
			child, intent := journalAdmissionStart(t, fixture, "admission-client")
			failure := errors.New("modeled exact prepared owner is no longer present")
			var reads atomic.Int32
			result := journalAdmissionRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
				if ctx.Err() != nil || target != *intent.Intent.Candidate.Target {
					return errors.New("modeled failed read lost its captured target")
				}
				if reads.Add(1) == stage.call {
					return failure
				}
				return nil
			})
			report := fixture.report(t, child, true)
			returned := journalAdmissionResult(t, fixture, result)
			if !errors.Is(returned.err, failure) || reads.Load() != stage.call {
				t.Fatal("native admission omitted its failed independent read", reads.Load(), returned.err)
			}
			expected := intent
			if stage.call == 2 {
				var err error
				expected, err = DeriveJournalAdmissionSettlement(intent)
				if err != nil || !journalAdmissionSameRecord(returned.record, expected) {
					t.Fatal("post-flush failure discarded its durable live-engine checkpoint", err)
				}
			} else if returned.record.Validate() == nil {
				t.Fatal("pre-flush failure fabricated a durable settled checkpoint")
			}
			journalAdmissionRequireDenied(t, report)
			selection, err := fixture.store.Snapshot(fixture.ctx)
			if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, expected) {
				t.Fatal("failed prepared read erased or replaced the actual journal state", err)
			}
			fixture.finish(t, child)
		})
	}
}

func TestWindowsProtectionJournalAdmissionSettlementWriteFailure(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "admission-client")
	// Sequence two is already durably acknowledged. Reduce only the next
	// captured slot's actual handle rights; the predecessor remains intact.
	file := fixture.store.slots[1-fixture.store.current.Slot]
	original := file.handle
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var limited syscall.Handle
	if err := syscall.DuplicateHandle(process, original, process, &limited, 0x00120089, false, 0); err != nil {
		t.Fatal(err)
	}
	file.handle = limited
	var restored bool
	restore := func() {
		if restored {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := fixture.server.Close(ctx); err != nil {
			t.Error("readonly admission fixture retains its unjoined slot owner", err)
			return
		}
		file.handle = original
		restored = true
		if err := syscall.CloseHandle(limited); err != nil {
			t.Error("readonly admission fixture did not close its exact duplicate", err)
		}
	}
	// Both cleanup attempts run before the fixture releases its store. Never
	// swap or release an exact handle while an entered append still owns it.
	t.Cleanup(restore)
	t.Cleanup(restore)
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || !journalAdmissionSameRecord(selection.Record, intent) {
		t.Fatal("readonly duplicate could not independently read the previous checkpoint", err)
	}
	var reads atomic.Int32
	result := journalAdmissionRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		reads.Add(1)
		if ctx.Err() != nil || target != *intent.Intent.Candidate.Target {
			return errors.New("readonly fixture lost its exact modeled prepared target")
		}
		return nil
	})
	report := fixture.report(t, child, true)
	returned := journalAdmissionResult(t, fixture, result)
	if !errors.Is(returned.err, syscall.ERROR_ACCESS_DENIED) || returned.record.Validate() == nil || reads.Load() != 1 || fixture.store.pending == nil ||
		!journalAdmissionSameRecord(fixture.store.current.Record, intent) {
		t.Fatal("failed actual settlement write acknowledged or erased its retained pending owner", reads.Load(), returned.err)
	}
	journalAdmissionRequireDenied(t, report)
	if _, err := fixture.store.Snapshot(fixture.ctx); err == nil {
		t.Fatal("failed admission settlement forgot its pending native file write")
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalAdmissionOperationReplacement(t *testing.T) {
	failure := errors.New("captured application operation changed after the admission flush")
	var rejected atomic.Bool
	fixture := newJournalChannelNative(t, func(store *ProtectionJournal) error {
		selection, err := store.Snapshot(context.Background())
		if err != nil {
			return err
		}
		if selection.Record.Sequence == 3 {
			rejected.Store(true)
			return failure
		}
		return nil
	})
	child, intent := journalAdmissionStart(t, fixture, "admission-client")
	var reads atomic.Int32
	result := journalAdmissionRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		reads.Add(1)
		if ctx.Err() != nil || target != *intent.Intent.Candidate.Target {
			return errors.New("replacement fixture lost its exact modeled prepared target")
		}
		return nil
	})
	report := fixture.report(t, child, true)
	returned := journalAdmissionResult(t, fixture, result)
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil || !rejected.Load() || reads.Load() != 2 || !errors.Is(returned.err, failure) || !journalAdmissionSameRecord(returned.record, settled) {
		t.Fatal("late operation replacement acquired admission or lost its durable checkpoint", reads.Load(), returned.err, err)
	}
	journalAdmissionRequireDenied(t, report)
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, settled) {
		t.Fatal("late admission rejection erased the actual settled live engine", err)
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalAdmissionCandidateMismatch(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "admission-wrong-candidate")
	var reads atomic.Int32
	result := journalAdmissionRun(fixture, func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error {
		reads.Add(1)
		return nil
	})
	report := fixture.report(t, child, true)
	returned := journalAdmissionResult(t, fixture, result)
	if returned.err == nil || returned.record.Validate() == nil || reads.Load() != 0 {
		t.Fatal("native journal admission accepted a substituted prepared candidate", reads.Load(), returned.err)
	}
	journalAdmissionRequireDenied(t, report)
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, intent) {
		t.Fatal("candidate rejection settled an unproved target", err)
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalAdmissionCloseJoinsPreparedRead(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "admission-client")
	entered := make(chan context.Context, 1)
	resume := make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	result := journalAdmissionRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		if target != *intent.Intent.Candidate.Target || ctx.Err() != nil {
			return errors.New("held prepared read changed its exact target or operation")
		}
		entered <- ctx
		<-resume
		return ctx.Err()
	})
	var held context.Context
	select {
	case held = <-entered:
	case <-fixture.ctx.Done():
		t.Fatal("actual second phase did not enter its captured prepared read")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.server.Close(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled admission close acknowledged an unjoined prepared read", err)
	}
	select {
	case <-held.Done():
	case <-fixture.ctx.Done():
		t.Fatal("admission close did not revoke its entered prepared-read context")
	}
	select {
	case <-fixture.server.retired:
		t.Fatal("admission server released ownership before its real prepared read joined")
	default:
	}
	if err := child.child.Alive(); err != nil {
		t.Fatal("unjoined admission close discarded its exact created engine", err)
	}
	release()
	report := fixture.report(t, child, true)
	returned := journalAdmissionResult(t, fixture, result)
	journalAdmissionRequireDenied(t, report)
	joined, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := fixture.server.Close(joined); err != nil {
		t.Fatal("same admission server could not join after its prepared read returned", err)
	}
	if !errors.Is(returned.err, context.Canceled) || returned.record.Validate() == nil {
		t.Fatal("cancelled prepared read acknowledged a new checkpoint", returned.err)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, intent) {
		t.Fatal("cancelled prepared read changed the first-phase journal intent", err)
	}
	fixture.finish(t, child)
}

// This isolates phase-three retirement deterministically, using an actual
// native pipe and explicitly modeled callback entry. The real authenticated
// cancellation path is exercised above; no authority or flush is fabricated.
func TestWindowsProtectionJournalAdmissionRetainedAdmissionClose(t *testing.T) {
	protectionRequireNative(t)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		pipe, err := windowscontroller.NewPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer pipe.Close()
		server := &JournalCommitServer{ctx: ctx, cancel: cancel, pipe: pipe,
			joined: make(chan struct{}), admissionJoined: make(chan struct{}), retired: make(chan struct{})}
		close(server.joined)
		server.state.Store(3)
		release := sync.OnceFunc(func() { close(server.admissionJoined) })
		defer release()
		result := make(chan error, 2)
		go func() { result <- server.Close(context.Background()) }()
		synctest.Wait()
		go func() { result <- server.Close(context.Background()) }()
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatal("journal admission close returned before its entered second phase joined", err)
		default:
		}
		if ctx.Err() == nil || server.state.Load() != 2 {
			t.Fatal("joined admission retirement failed to revoke new operations immediately")
		}
		release()
		synctest.Wait()
		for range 2 {
			if err := <-result; err != nil {
				t.Fatal("joined admission close lost its retained result", err)
			}
		}
		if err := server.Close(context.Background()); err != nil {
			t.Fatal("duplicate admission close lost the joined second phase", err)
		}
	})
}
