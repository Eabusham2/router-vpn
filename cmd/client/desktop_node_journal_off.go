package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"sync/atomic"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

// Native absence does not settle explicit Off. Its immutable intent survives
// until the accepted result profile is actually saved and read back. Only ACK
// crosses the native callback boundary; other state is held by the slot lock.
type desktopNodeJournalOff struct {
	store        desktopNodeProtectionJournal
	head         windowsprotection.JournalRecord
	intent       windowsprotection.JournalRecord
	settlement   windowsprotection.JournalRecord
	target       mobiletor.DesktopWindowsProtectionTarget
	acknowledged atomic.Bool
	settled      bool
	storeClosed  bool
	recovered    bool
}

func (s *desktopNodeProtectionSlot) captureJournalOffLocked(ctx context.Context, capture *desktopNodeProtectionOff) (*desktopNodeJournalOff, error) {
	if !s.offCurrentLocked(capture) || s.journal == nil || s.journalClosing || s.backend.recoverWithBarrier == nil ||
		!desktopNodeProcessHex(capture.sourceRevision, 32) || !desktopNodeProcessHex(capture.resultRevision, 32) ||
		capture.profileWritten.Load() || capture.profileSaved.Load() {
		return nil, errors.New("durable Off lost its retained source, exact profile transition or native barrier")
	}
	selection, err := s.journal.Snapshot(ctx)
	if err != nil || selection.Incomplete || selection.Record.Validate() != nil || selection.Record.Phase != "settled" ||
		selection.Record.Sequence > math.MaxUint64-2 || selection.Record.Committed.Engine != nil ||
		selection.Record.Committed.Target == nil || *selection.Record.Committed.Target != capture.target || selection.Record.Committed.ProfileID != capture.profileID {
		return nil, errors.Join(err, errors.New("durable Off requires the exact settled, joined journal target"))
	}
	head, err := copyDesktopNodeJournalRecord(selection.Record)
	if err != nil {
		return nil, err
	}
	raw, err := windowsprotection.CanonicalJournalRecord(head)
	digest, digestErr := windowsprotection.JournalRecordSHA256(raw)
	if err != nil || digestErr != nil || digest != selection.SHA256 || ctx.Err() != nil {
		return nil, errors.Join(err, digestErr, ctx.Err(), errors.New("durable Off changed its captured journal digest"))
	}
	j := &desktopNodeJournalOff{store: s.journal, head: head, target: capture.target}
	var request [16]byte
	if _, err := rand.Read(request[:]); err != nil {
		return nil, err
	}
	j.intent, err = copyDesktopNodeJournalRecord(head)
	if err != nil {
		return nil, err
	}
	j.intent.Sequence++
	j.intent.PreviousSHA256, j.intent.Phase = selection.SHA256, "intent"
	j.intent.Intent = &windowsprotection.JournalIntent{Action: "off", RequestID: hex.EncodeToString(request[:]),
		ProfileID: capture.profileID, ProfileRevision: capture.profileRevision, ResultProfileRevision: capture.resultRevision}
	if err := windowsprotection.CheckJournalTransition(head, j.intent); err != nil {
		return nil, err
	}
	raw, err = windowsprotection.CanonicalJournalRecord(j.intent)
	digest, digestErr = windowsprotection.JournalRecordSHA256(raw)
	if err != nil || digestErr != nil {
		return nil, errors.Join(err, digestErr)
	}
	j.settlement, err = copyDesktopNodeJournalRecord(j.intent)
	if err != nil {
		return nil, err
	}
	j.settlement.Sequence++
	j.settlement.PreviousSHA256, j.settlement.Phase, j.settlement.Intent = digest, "settled", nil
	j.settlement.Committed = windowsprotection.JournalState{}
	if err := windowsprotection.CheckJournalTransition(j.intent, j.settlement); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *desktopNodeJournalOff) barrier(ctx context.Context, change mobiletor.DesktopWindowsProtectionCommit) error {
	if j == nil || ctx == nil || ctx.Err() != nil || change.Validate() != nil || change.Action != "off" ||
		change.Previous == nil || *change.Previous != j.target || change.Candidate != nil {
		return errors.New("durable Off barrier changed its accepted native removal")
	}
	// Called inside the native BFE transaction. Do not acquire slot/app locks
	// or query BFE here; the captured store alone flushes the immutable intent.
	if j.recovered {
		// Restart already flushed the exact accepted Off under its checked new
		// controller. Retrying removal verifies that same intent inside BFE's
		// write transaction; it never invents a second request or profile pair.
		if err := j.readExact(ctx, j.intent); err != nil {
			return err
		}
	} else {
		if err := writeDesktopNodeJournalReleaseRecord(ctx, j.store, j.head, j.intent); err != nil {
			return err
		}
	}
	j.acknowledged.Store(true)
	return ctx.Err()
}

func (s *desktopNodeProtectionSlot) recoveredJournalOffLocked(selectedID string, result windowsprotection.JournalRecoveryResult,
	joined desktopNodeJournalRecovery) (*desktopNodeProtectionOff, error) {
	record := result.Selection.Record
	if s.journal == nil || s.backend.recoverWithBarrier == nil || joined == nil || record.Phase != "intent" || record.Intent == nil ||
		record.Intent.Action != "off" || record.Committed.Target == nil || record.Committed.Engine != nil || record.Sequence == math.MaxUint64 ||
		!desktopNodeProcessHex(record.Committed.ProfileRevision, 32) {
		return nil, errors.New("recovered Off lost its exact joined source, intent or native barrier")
	}
	intent, err := copyDesktopNodeJournalRecord(record)
	if err != nil {
		return nil, err
	}
	settlement, err := copyDesktopNodeJournalRecord(record)
	if err != nil {
		return nil, err
	}
	settlement.Sequence++
	settlement.PreviousSHA256, settlement.Phase, settlement.Intent = result.Selection.SHA256, "settled", nil
	settlement.Committed = windowsprotection.JournalState{}
	if err := windowsprotection.CheckJournalTransition(record, settlement); err != nil {
		return nil, err
	}
	journal := &desktopNodeJournalOff{store: s.journal, head: intent, intent: intent, settlement: settlement,
		target: *record.Committed.Target, recovered: true}
	capture := &desktopNodeProtectionOff{profileID: record.Intent.ProfileID, profileRevision: record.Intent.ProfileRevision,
		resultRevision: record.Intent.ResultProfileRevision, sourceRevision: record.Committed.ProfileRevision,
		target: *record.Committed.Target, journal: journal, recovered: true, selectedID: selectedID}
	if result.Observed.Target == nil {
		// This is the real joined native recovery owner, carrying process death
		// and BFE absence proof. A no-op release or a decoded record cannot stand
		// in for it. Later retries still independently read current absence.
		capture.owner, capture.prepared, capture.joined = joined, true, true
		capture.removed, capture.absenceProved = true, true
		journal.acknowledged.Store(true)
	} else if *result.Observed.Target != capture.target {
		return nil, errors.New("recovered Off substituted another native target")
	}
	return capture, nil
}

func (j *desktopNodeJournalOff) readExact(ctx context.Context, expected windowsprotection.JournalRecord) error {
	read, err := j.store.Snapshot(ctx)
	want, wantErr := windowsprotection.CanonicalJournalRecord(expected)
	actual, actualErr := windowsprotection.CanonicalJournalRecord(read.Record)
	if err != nil || wantErr != nil || actualErr != nil || read.Incomplete || !bytes.Equal(actual, want) || ctx.Err() != nil {
		return errors.Join(err, wantErr, actualErr, ctx.Err(), errors.New("durable Off observed a replaced journal owner"))
	}
	return nil
}

func (s *desktopNodeProtectionSlot) offJournalCurrentLocked(capture *desktopNodeProtectionOff) bool {
	j := capture.journal
	return s.offCurrentLocked(capture) && j != nil && j.target == capture.target && j.intent.Intent != nil &&
		j.intent.Intent.ProfileID == capture.profileID && j.intent.Intent.ProfileRevision == capture.profileRevision && j.intent.Intent.ResultProfileRevision == capture.resultRevision &&
		(j.storeClosed && s.journal == nil && !s.journalClosing || !j.storeClosed && s.journal == j.store)
}

func (s *desktopNodeProtectionSlot) applyJournalOffLocked(ctx context.Context, capture *desktopNodeProtectionOff, check func() error) error {
	if capture.journal == nil {
		journal, err := s.captureJournalOffLocked(ctx, capture)
		if err != nil {
			return err
		}
		capture.journal = journal
	}
	if !s.offJournalCurrentLocked(capture) || s.backend.recoverWithBarrier == nil {
		return errors.New("durable Off belongs to another native or journal owner")
	}
	j := capture.journal
	if capture.owner != nil && !capture.prepared {
		if err := capture.owner.Close(ctx); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		if err := s.backend.read(ctx, &capture.target); err != nil {
			return err
		}
		if err := j.readExact(ctx, j.head); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		capture.owner = nil
	}
	if capture.owner == nil {
		if err := s.backend.read(ctx, &capture.target); err != nil {
			return err
		}
		if err := j.readExact(ctx, j.head); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		owner, err := s.backend.recoverWithBarrier(ctx, capture.target, j.barrier)
		if owner != nil {
			capture.owner, capture.prepared = owner, err == nil
		}
		if err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		if owner == nil {
			return errors.New("durable Off did not retain its exact native operation")
		}
	}
	if !capture.joined {
		if err := capture.owner.Close(ctx); err != nil {
			return err
		}
		capture.joined = true
		if err := check(); err != nil {
			return err
		}
	}
	if !j.acknowledged.Load() {
		return errors.New("durable Off joined without its flushed intent acknowledgment")
	}
	capture.absenceProved = false
	if err := s.backend.read(ctx, nil); err != nil {
		return err
	}
	capture.removed, capture.absenceProved = true, true
	if err := check(); err != nil {
		return err
	}
	// Settlement retries may own a pending exact flush. Before saving at all,
	// however, the accepted Off intent must still be the observed journal head.
	if !capture.profileWritten.Load() {
		if err := j.readExact(ctx, j.intent); err != nil {
			return err
		}
	}
	return check()
}

func (s *desktopNodeProtectionSlot) finishJournalOffLocked(ctx context.Context, capture *desktopNodeProtectionOff, current func() bool) error {
	if !s.offJournalCurrentLocked(capture) || !capture.joined || !capture.journal.acknowledged.Load() ||
		!capture.profileWritten.Load() || !capture.profileSaved.Load() || !current() {
		return errors.New("durable Off has no exact saved result and joined native owner")
	}
	j := capture.journal
	if !j.settled {
		if err := writeDesktopNodeJournalReleaseRecord(ctx, j.store, j.intent, j.settlement); err != nil {
			return err
		}
		j.settled = true
	}
	if ctx.Err() != nil || !current() {
		return errors.Join(ctx.Err(), errors.New("durable Off lost its acknowledged result before journal close"))
	}
	if !j.storeClosed {
		err := s.closeEmptyJournalLocked(ctx)
		j.storeClosed = s.journal == nil && !s.journalClosing
		if err != nil {
			return err
		}
	}
	return nil
}
