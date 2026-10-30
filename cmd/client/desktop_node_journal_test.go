package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/windowsprotection"
)

// Native storage/BFE/process creation have separate mandatory Windows gates.
// These models exercise the actual application slot and durable retry order.
type desktopNodeJournalFixtureStore struct {
	head                            windowsprotection.JournalRecord
	failRead, failWrite, incomplete bool
	lateCancel                      context.CancelFunc
	failClose                       bool
	closes                          int
	writes                          int
	pending                         *windowsprotection.JournalRecord
}

func (s *desktopNodeJournalFixtureStore) Snapshot(ctx context.Context) (windowsprotection.JournalSelection, error) {
	if ctx.Err() != nil || s.failRead || s.pending != nil {
		return windowsprotection.JournalSelection{}, errors.New("fixture actual journal read is pending")
	}
	raw, err := windowsprotection.CanonicalJournalRecord(s.head)
	if err != nil {
		return windowsprotection.JournalSelection{}, err
	}
	digest, err := windowsprotection.JournalRecordSHA256(raw)
	copy, copyErr := copyDesktopNodeJournalRecord(s.head)
	return windowsprotection.JournalSelection{Record: copy, SHA256: digest, Incomplete: s.incomplete}, errors.Join(err, copyErr)
}
func (s *desktopNodeJournalFixtureStore) Append(ctx context.Context, previous string, next windowsprotection.JournalRecord) (windowsprotection.JournalSelection, error) {
	raw, err := windowsprotection.CanonicalJournalRecord(s.head)
	if err != nil {
		return windowsprotection.JournalSelection{}, err
	}
	digest, _ := windowsprotection.JournalRecordSHA256(raw)
	if ctx.Err() != nil || previous != digest || windowsprotection.CheckJournalTransition(s.head, next) != nil || s.pending != nil && !reflect.DeepEqual(*s.pending, next) {
		return windowsprotection.JournalSelection{}, errors.New("fixture journal append changed its captured state")
	}
	s.writes++
	copy, _ := copyDesktopNodeJournalRecord(next)
	if s.failWrite {
		s.pending = &copy
		return windowsprotection.JournalSelection{}, errors.New("fixture journal flush failed")
	}
	s.head, s.pending = copy, nil
	selection, err := s.Snapshot(ctx)
	if s.lateCancel != nil {
		s.lateCancel()
		err = context.Canceled
	}
	return selection, err
}
func (s *desktopNodeJournalFixtureStore) Close() error {
	s.closes++
	if s.failClose {
		return errors.New("fixture native journal lock is still owned")
	}
	return nil
}

type desktopNodeJournalFixtureProcess struct {
	desktopOwnedNodeTestProcess
	outcome windowsprotection.JournalRecord
}

func (p *desktopNodeJournalFixtureProcess) AdmitProtection(context.Context) error { return nil }
func (p *desktopNodeJournalFixtureProcess) JournalOutcome() (windowsprotection.JournalRecord, error) {
	if !p.closed {
		return windowsprotection.JournalRecord{}, errors.New("fixture child has not joined")
	}
	return copyDesktopNodeJournalRecord(p.outcome)
}

func desktopNodeJournalFixture(t *testing.T, live bool) (*desktopNodeProtectionSlot, *desktopNodeProtectionAttempt, *desktopNodeProtectionFixture, *desktopNodeJournalFixtureStore, *desktopNodeJournalFixtureProcess) {
	t.Helper()
	policy := desktopNodeProtectionPolicy(t, "1", "always", 0)
	kernel := &desktopNodeProtectionFixture{}
	slot := &desktopNodeProtectionSlot{backend: kernel.backend()}
	launch := &desktopNodeLaunch{ownedNode: &desktopOwnedNodeRuntime{}}
	attempt, err := slot.begin(context.Background(), launch, policy)
	if err != nil {
		t.Fatal(err)
	}
	controller := windowsprotection.Controller{PID: 101, StartTimeUTCTicks: 638000000000000000, SID: "S-1-5-21-100-200-300-1001", AuthenticationID: 123, SessionID: 2}
	head := windowsprotection.JournalRecord{Schema: 1, Kind: windowsprotection.JournalRecordKind, JournalID: strings.Repeat("a", 32), Sequence: 1, Controller: controller, Phase: "settled"}
	capture := windowsprotection.JournalCommitCapture{Schema: 1, Kind: windowsprotection.JournalCommitCaptureKind, Head: head, ProfileID: policy.Metadata().ProfileID, ProfileRevision: strings.Repeat("f", 64), Transfer: attempt.transfer}
	raw, err := windowsprotection.CanonicalJournalCommitCapture(capture)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := windowsprotection.JournalCommitCaptureSHA256(raw)
	target := desktopNodeProtectionInstalled(policy)
	request := windowsprotection.JournalCommitRequest{Schema: 1, Kind: windowsprotection.JournalCommitRequestKind, CaptureSHA256: digest, Nonce: strings.Repeat("b", 64), Candidate: target}
	engine := controller
	engine.PID++
	engine.StartTimeUTCTicks++
	intent, err := windowsprotection.DeriveJournalCommitIntent(capture, request, engine)
	if err != nil {
		t.Fatal(err)
	}
	current := intent
	if live {
		current, err = windowsprotection.DeriveJournalAdmissionSettlement(intent)
		if err != nil {
			t.Fatal(err)
		}
	}
	store := &desktopNodeJournalFixtureStore{head: current}
	process := &desktopNodeJournalFixtureProcess{desktopOwnedNodeTestProcess: desktopOwnedNodeTestProcess{started: true}, outcome: current}
	launch.ownedNode.process = process
	slot.journal = store
	kernel.target, kernel.locked = copyDesktopNodeProtectionTarget(&target), true
	return slot, attempt, kernel, store, process
}

func TestDesktopNodeJournalCapturedPreparedPrecedesPermission(t *testing.T) {
	slot, attempt, kernel, store, _ := desktopNodeJournalFixture(t, true)
	record, _ := copyDesktopNodeJournalRecord(store.head)
	if err := slot.captureJournalPrepared(context.Background(), attempt, record, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if attempt.prepared == nil || *attempt.prepared != *record.Committed.Target || kernel.prepared != 1 || store.writes != 0 {
		t.Fatal("native admission did not capture its independently proved durable target before permission")
	}
	record.Committed.Target.BaselineSHA256 = strings.Repeat("f", 64)
	if *attempt.prepared != *store.head.Committed.Target {
		t.Fatal("admitted native target retained callback storage")
	}
}

func TestDesktopNodeJournalCapturedPreparedRejectsChangedOwners(t *testing.T) {
	for _, fault := range []string{"journal-read", "incomplete", "foreign-profile", "foreign-target", "replaced-attempt", "stale", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			slot, attempt, kernel, store, _ := desktopNodeJournalFixture(t, true)
			record, _ := copyDesktopNodeJournalRecord(store.head)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			current := func() bool { return fault != "stale" }
			switch fault {
			case "journal-read":
				store.failRead = true
			case "incomplete":
				store.incomplete = true
			case "foreign-profile":
				record.Committed.ProfileID += "other"
			case "foreign-target":
				record.Committed.Target.BaselineSHA256 = strings.Repeat("f", 64)
			case "replaced-attempt":
				slot.active = &desktopNodeProtectionAttempt{}
			case "cancelled":
				cancel()
			}
			if err := slot.captureJournalPrepared(ctx, attempt, record, current); err == nil || attempt.prepared != nil || store.writes != 0 {
				t.Fatal("changed native checkpoint acquired application admission", fault, err)
			}
			if kernel.releases != 0 {
				t.Fatal("rejected admission changed native policy")
			}
		})
	}
}

func TestDesktopNodeJournalSettlementRequiresJoinedExactOutcome(t *testing.T) {
	for _, live := range []bool{false, true} {
		slot, attempt, kernel, store, process := desktopNodeJournalFixture(t, live)
		target := copyDesktopNodeProtectionTarget(kernel.target)
		if live {
			if err := slot.captureJournalPrepared(context.Background(), attempt, store.head, func() bool { return true }); err != nil {
				t.Fatal(err)
			}
		}
		if err := slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, target), func(context.Context) error { return errors.New("fixture no checked join") }); err == nil || store.writes != 0 || slot.active != attempt {
			t.Fatal("unjoined process acquired durable settlement", err)
		}
		join := func(context.Context) error { process.closed = true; kernel.locked = false; return nil }
		if err := slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, target), join); err != nil {
			t.Fatal(err)
		}
		if slot.active != nil || !reflect.DeepEqual(slot.target, target) || store.head.Committed.Engine != nil || store.head.Phase != "settled" || store.writes != 1 {
			t.Fatal("joined native outcome did not settle before releasing its application attempt")
		}
	}
}

func TestDesktopNodeJournalSettlementRetriesExactFailedFlush(t *testing.T) {
	for _, late := range []bool{false, true} {
		slot, attempt, kernel, store, process := desktopNodeJournalFixture(t, true)
		target := copyDesktopNodeProtectionTarget(kernel.target)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if late {
			store.lateCancel = cancel
		} else {
			store.failWrite = true
		}
		join := func(context.Context) error { process.closed = true; kernel.locked = false; return nil }
		if err := slot.finish(ctx, attempt, desktopNodeProtectionRetired(attempt, target), join); err == nil || slot.active != attempt || attempt.settlement == nil {
			t.Fatal("failed journal settlement discarded its exact attempt", err)
		}
		pending, _ := copyDesktopNodeJournalRecord(*attempt.settlement)
		store.failWrite = false
		store.lateCancel = nil
		if err := slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, target), join); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(store.head, pending) || slot.active != nil {
			t.Fatal("journal retry replaced its captured flushed bytes")
		}
		if late && store.writes != 1 {
			t.Fatal("late successful flush was appended twice")
		}
	}
}

func TestDesktopNodeJournalAbortedIntentKeepsProvedPredecessor(t *testing.T) {
	slot, attempt, kernel, store, process := desktopNodeJournalFixture(t, false)
	kernel.target = nil
	kernel.locked = false
	if err := slot.abandonUnchanged(context.Background(), attempt, func(context.Context) error { process.closed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if slot.active != nil || slot.target != nil || store.head.Phase != "settled" || store.head.Committed.Target != nil || store.writes != 1 {
		t.Fatal("aborted intent was mistaken for its uncommitted candidate")
	}
}

func TestDesktopNodeJournalDoesNotUseCallbackFreeRemoval(t *testing.T) {
	slot, attempt, kernel, store, process := desktopNodeJournalFixture(t, true)
	if err := slot.finish(context.Background(), attempt, desktopNodeProtectionRetired(attempt, kernel.target), func(context.Context) error { process.closed = true; kernel.locked = false; return nil }); err != nil {
		t.Fatal(err)
	}
	before, _ := copyDesktopNodeJournalRecord(store.head)
	if err := slot.release(context.Background()); err == nil || kernel.releases != 0 || !reflect.DeepEqual(store.head, before) || slot.target == nil {
		t.Fatal("journal protection used a callback-free removal")
	}
}

func TestDesktopNodeJournalReceiptlessChildUsesOnlyRecordedOutcome(t *testing.T) {
	for _, outcome := range []string{"previous", "candidate", "unknown", "unjoined"} {
		t.Run(outcome, func(t *testing.T) {
			slot, attempt, kernel, store, process := desktopNodeJournalFixture(t, false)
			kernel.locked = false
			if outcome == "previous" {
				kernel.target = nil
			}
			if outcome == "unknown" {
				kernel.target.BaselineSHA256 = strings.Repeat("f", 64)
			}
			join := func(context.Context) error {
				if outcome == "unjoined" {
					return errors.New("fixture child is still entered")
				}
				process.closed = true
				return nil
			}
			err := slot.finishJournalWithoutReceipt(context.Background(), attempt, join)
			if outcome == "unknown" || outcome == "unjoined" {
				if err == nil || slot.active != attempt || store.writes != 0 {
					t.Fatal("unproved receiptless child erased its durable owner", err)
				}
				return
			}
			if err != nil || slot.active != nil || !reflect.DeepEqual(slot.target, kernel.target) || store.writes != 1 || store.head.Committed.Engine != nil {
				t.Fatal("recorded receiptless outcome did not settle after exact child join", err)
			}
		})
	}
}

func TestDesktopNodeJournalEmptyReleaseRetainsFailedNativeClose(t *testing.T) {
	slot, attempt, kernel, store, process := desktopNodeJournalFixture(t, false)
	kernel.target, kernel.locked = nil, false
	if err := slot.abandonUnchanged(context.Background(), attempt, func(context.Context) error { process.closed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if slot.provedEmpty() || !slot.retained() {
		t.Fatal("empty kernel slot discarded its still-owned native journal")
	}
	store.failClose = true
	if err := slot.release(context.Background()); err == nil || slot.journal != store || !slot.journalClosing || slot.provedEmpty() || store.closes != 1 {
		t.Fatal("failed journal close released its exact owner", err)
	}
	store.failClose = false
	store.failRead = true // A partially closed owner must retry Close, not reopen/read it.
	if err := slot.release(context.Background()); err != nil || slot.journal != nil || slot.journalClosing || !slot.provedEmpty() || store.closes != 2 {
		t.Fatal("exact journal close retry did not finish owned empty retirement", err)
	}
}

var _ desktopNodeProcess = (*desktopNodeJournalFixtureProcess)(nil)
var _ desktopNodeJournalAdmission = (*desktopNodeJournalFixtureProcess)(nil)
