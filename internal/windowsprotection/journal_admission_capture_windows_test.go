//go:build windows && routervpn_windows_protection_native

package windowsprotection

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

// The created child, authenticated channel and journal are native. The private
// read callback models BFE, and the prepared callback checks the captured-host
// contract without manufacturing an application slot or TUN admission.
func journalAdmissionCapturedRun(fixture *journalChannelNative, read func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error, prepared func(context.Context, JournalRecord) error) <-chan journalChannelResult {
	result := make(chan journalChannelResult, 1)
	go func() {
		record, err := fixture.server.admitCaptured(fixture.ctx, read, prepared)
		result <- journalChannelResult{record: record, err: err}
		if err != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = fixture.server.Close(ctx)
		}
	}()
	return result
}

func journalAdmissionCapturedBytes(t *testing.T, intent JournalRecord) []byte {
	t.Helper()
	settled, err := DeriveJournalAdmissionSettlement(intent)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalJournalRecord(settled)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func journalAdmissionMatchesBytes(record JournalRecord, expected []byte) bool {
	raw, err := CanonicalJournalRecord(record)
	return err == nil && bytes.Equal(raw, expected)
}

func TestWindowsProtectionJournalAdmissionCapturedCheckpoint(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "admission-client")
	expected := journalAdmissionCapturedBytes(t, intent)
	entered, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	var reads, captures atomic.Int32
	var completed atomic.Bool
	result := journalAdmissionCapturedRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		reads.Add(1)
		if ctx.Err() != nil || target != *intent.Intent.Candidate.Target {
			return errors.New("captured-host fixture changed its modeled prepared owner")
		}
		return nil
	}, func(ctx context.Context, record JournalRecord) error {
		if captures.Add(1) != 1 || reads.Load() != 2 || ctx.Err() != nil || !journalAdmissionMatchesBytes(record, expected) {
			return errors.New("captured host did not receive its exact twice-read live-engine checkpoint")
		}
		selection, err := fixture.store.Snapshot(ctx)
		if err != nil || selection.Incomplete || !journalAdmissionMatchesBytes(selection.Record, expected) ||
			record.Committed.Engine == nil || *record.Committed.Engine != *intent.Intent.Candidate.Engine || record.Committed.Engine.PID != child.child.PID() {
			return errors.Join(err, errors.New("captured host ran before the actual settlement flush or lost its created engine"))
		}
		close(entered)
		<-resume
		// All three mutations are confined to the caller's copied record.
		// The immutable expected bytes cannot self-compare through an alias.
		record.Committed.Target.BaselineSHA256 = strings.Repeat("e", 64)
		record.Committed.Engine.StartTimeUTCTicks++
		record.Committed.ProfileID = "changed-only-in-the-host-copy"
		completed.Store(true)
		return nil
	})
	select {
	case <-entered:
	case returned := <-result:
		t.Fatal("native admission omitted its captured host before acknowledgment", returned.err)
	case <-fixture.ctx.Done():
		t.Fatal("native admission never entered its actual captured-host callback")
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionMatchesBytes(selection.Record, expected) {
		t.Fatal("held captured host did not own the actual settled checkpoint", err)
	}
	if err := child.child.Alive(); err != nil {
		t.Fatal("captured host lost the still-retained actual engine", err)
	}
	// The shipping call sequence invokes this callback before WriteFrame.
	// Holding its real entry proves the callback lifetime without relying on
	// a sleep-based assertion about the absence of child scheduling.
	release()
	report := fixture.report(t, child, true)
	returned := journalAdmissionResult(t, fixture, result)
	if !completed.Load() || captures.Load() != 1 || reads.Load() != 2 || returned.err != nil || !report.Accepted || report.Replayed || report.Premature || !report.Admitted || report.AdmissionReplayed || !report.Closed || report.Failure != "" {
		t.Fatal("native admission did not complete one captured host before the actual child report", captures.Load(), reads.Load(), report, returned.err)
	}
	selection, err = fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionMatchesBytes(selection.Record, expected) || !journalAdmissionMatchesBytes(returned.record, expected) ||
		fixture.server.attempted == nil || !journalAdmissionMatchesBytes(*fixture.server.attempted, expected) ||
		fixture.server.commit == nil || !journalAdmissionSameRecord(fixture.server.commit.intent, intent) {
		t.Fatal("captured host callback changed the retained checkpoint through an alias", err)
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalAdmissionCapturedOwnerFailure(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "admission-client")
	expected := journalAdmissionCapturedBytes(t, intent)
	failure := errors.New("captured application slot rejected its exact prepared owner")
	var reads, captures atomic.Int32
	result := journalAdmissionCapturedRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		reads.Add(1)
		if ctx.Err() != nil || target != *intent.Intent.Candidate.Target {
			return errors.New("failed captured-host fixture changed its modeled prepared owner")
		}
		return nil
	}, func(ctx context.Context, record JournalRecord) error {
		if captures.Add(1) != 1 || reads.Load() != 2 || ctx.Err() != nil || !journalAdmissionMatchesBytes(record, expected) {
			return errors.New("rejected captured host received another checkpoint")
		}
		return failure
	})
	report := fixture.report(t, child, true)
	returned := journalAdmissionResult(t, fixture, result)
	if captures.Load() != 1 || reads.Load() != 2 || !errors.Is(returned.err, failure) || !journalAdmissionMatchesBytes(returned.record, expected) {
		t.Fatal("captured host rejection was ignored or discarded its flushed checkpoint", captures.Load(), reads.Load(), returned.err)
	}
	journalAdmissionRequireDenied(t, report)
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionMatchesBytes(selection.Record, expected) {
		t.Fatal("captured host rejection erased its durable live engine", err)
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalAdmissionRequiresCapturedOwner(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "admission-client")
	expected := journalAdmissionCapturedBytes(t, intent)
	var rejectedReads atomic.Int32
	returned, err := fixture.server.admitCaptured(fixture.ctx, func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error {
		rejectedReads.Add(1)
		return errors.New("missing host callback must reject before any prepared read")
	}, nil)
	if err == nil || returned.Validate() == nil || rejectedReads.Load() != 0 || fixture.server.state.Load() != 1 {
		t.Fatal("missing captured host consumed a native admission read or phase", rejectedReads.Load(), err)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionSameRecord(selection.Record, intent) {
		t.Fatal("missing captured host changed its first-phase journal", err)
	}
	var reads, captures atomic.Int32
	result := journalAdmissionCapturedRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		reads.Add(1)
		if ctx.Err() != nil || target != *intent.Intent.Candidate.Target {
			return errors.New("captured-host retry changed its exact modeled prepared owner")
		}
		return nil
	}, func(ctx context.Context, record JournalRecord) error {
		captures.Add(1)
		if ctx.Err() != nil || !journalAdmissionMatchesBytes(record, expected) {
			return errors.New("captured-host retry received another durable engine")
		}
		return nil
	})
	report := fixture.report(t, child, true)
	completed := journalAdmissionResult(t, fixture, result)
	if completed.err != nil || !journalAdmissionMatchesBytes(completed.record, expected) || reads.Load() != 2 || captures.Load() != 1 ||
		!report.Accepted || report.Replayed || report.Premature || !report.Admitted || report.AdmissionReplayed || !report.Closed || report.Failure != "" {
		t.Fatal("missing-callback rejection destroyed its still-owned valid retry", reads.Load(), captures.Load(), report, completed.err)
	}
	fixture.finish(t, child)
}

func TestWindowsProtectionJournalAdmissionCloseJoinsCapturedOwner(t *testing.T) {
	fixture := newJournalChannelNative(t, nil)
	child, intent := journalAdmissionStart(t, fixture, "admission-client")
	expected := journalAdmissionCapturedBytes(t, intent)
	entered := make(chan context.Context, 1)
	resume := make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	var reads, captures atomic.Int32
	result := journalAdmissionCapturedRun(fixture, func(ctx context.Context, target mobiletor.DesktopWindowsProtectionTarget) error {
		reads.Add(1)
		if ctx.Err() != nil || target != *intent.Intent.Candidate.Target {
			return errors.New("held captured host lost its exact modeled prepared owner")
		}
		return nil
	}, func(ctx context.Context, record JournalRecord) error {
		if captures.Add(1) != 1 || reads.Load() != 2 || ctx.Err() != nil || !journalAdmissionMatchesBytes(record, expected) {
			return errors.New("held captured host received another durable checkpoint")
		}
		entered <- ctx
		<-resume
		return ctx.Err()
	})
	var held context.Context
	select {
	case held = <-entered:
	case returned := <-result:
		t.Fatal("native admission omitted its held captured owner", returned.err)
	case <-fixture.ctx.Done():
		t.Fatal("native admission did not enter its held captured owner")
	}
	if record, err := fixture.server.DrainAttempt(context.Background()); err == nil || record.Validate() == nil {
		t.Fatal("live captured callback supplied a joined journal drain", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.server.Close(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled close acknowledged an unjoined captured host", err)
	}
	select {
	case <-held.Done():
	case <-fixture.ctx.Done():
		t.Fatal("captured-host close did not revoke the callback context")
	}
	if record, err := fixture.server.DrainAttempt(context.Background()); err == nil || record.Validate() == nil {
		t.Fatal("revoked but unjoined captured callback supplied a durable journal drain", err)
	}
	if err := child.child.Alive(); err != nil {
		t.Fatal("unjoined captured callback lost its exact actual engine", err)
	}
	release()
	report := fixture.report(t, child, true)
	returned := journalAdmissionResult(t, fixture, result)
	if captures.Load() != 1 || reads.Load() != 2 || !errors.Is(returned.err, context.Canceled) || !journalAdmissionMatchesBytes(returned.record, expected) {
		t.Fatal("cancelled captured owner acknowledged or discarded its settled checkpoint", captures.Load(), reads.Load(), returned.err)
	}
	journalAdmissionRequireDenied(t, report)
	joined, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := fixture.server.Close(joined); err != nil {
		t.Fatal("captured-owner retirement did not join after callback release", err)
	}
	durable, err := fixture.server.DrainAttempt(joined)
	if err != nil || !journalAdmissionMatchesBytes(durable, expected) {
		t.Fatal("joined captured callback lost its exact already-durable checkpoint", err)
	}
	selection, err := fixture.store.Snapshot(fixture.ctx)
	if err != nil || selection.Incomplete || !journalAdmissionMatchesBytes(selection.Record, expected) {
		t.Fatal("captured-owner cancellation changed its durable live-engine generation", err)
	}
	fixture.finish(t, child)
}
