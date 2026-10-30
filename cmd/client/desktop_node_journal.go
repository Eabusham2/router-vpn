package main

import (
	"bytes"
	"context"
	"errors"

	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

type desktopNodeProtectionJournal interface {
	Snapshot(context.Context) (windowsprotection.JournalSelection, error)
	Append(context.Context, string, windowsprotection.JournalRecord) (windowsprotection.JournalSelection, error)
	Close() error
}

type desktopNodeJournalAdmission interface {
	AdmitProtection(context.Context) error
	JournalOutcome() (windowsprotection.JournalRecord, error)
}

// Native absence does not close the separate file/lock owner. Preserve that
// exact owner through a failed close; no later slot may inherit its handles.
func (s *desktopNodeProtectionSlot) closeEmptyJournalLocked(ctx context.Context) error {
	if s.journal == nil {
		return ctx.Err()
	}
	if !s.journalClosing {
		selection, err := s.journal.Snapshot(ctx)
		if err != nil || selection.Incomplete || selection.Record.Validate() != nil || selection.Record.Phase != "settled" ||
			selection.Record.Committed.Target != nil || selection.Record.Committed.Engine != nil {
			return errors.Join(err, errors.New("empty native slot still has an unsettled journal owner"))
		}
		s.journalClosing = true
	}
	if err := s.journal.Close(); err != nil {
		return err
	}
	s.journal, s.journalClosing = nil, false
	return ctx.Err()
}

func copyDesktopNodeJournalRecord(record windowsprotection.JournalRecord) (windowsprotection.JournalRecord, error) {
	raw, err := windowsprotection.CanonicalJournalRecord(record)
	if err != nil {
		return windowsprotection.JournalRecord{}, err
	}
	return windowsprotection.ParseJournalRecord(raw)
}

// This callback enters before native prepared admission is acknowledged. The
// journal has already flushed the exact live-engine checkpoint; the same lock
// captures its target in the application attempt before the child can open TUN.
func (s *desktopNodeProtectionSlot) captureJournalPrepared(ctx context.Context, attempt *desktopNodeProtectionAttempt,
	record windowsprotection.JournalRecord, current func() bool) error {
	if s == nil || ctx == nil || ctx.Err() != nil || attempt == nil || current == nil || !current() ||
		record.Validate() != nil || record.Phase != "settled" || record.Committed.Target == nil || record.Committed.Engine == nil {
		return errors.New("native journal admission lost its captured live-engine checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal == nil || attempt.policy == nil || record.Committed.ProfileID != attempt.policy.Metadata().ProfileID {
		return errors.New("native journal admission belongs to another application profile")
	}
	selection, err := s.journal.Snapshot(ctx)
	expected, encodeErr := windowsprotection.CanonicalJournalRecord(record)
	actual, actualErr := windowsprotection.CanonicalJournalRecord(selection.Record)
	if err != nil || encodeErr != nil || actualErr != nil || selection.Incomplete || !bytes.Equal(expected, actual) {
		return errors.Join(err, encodeErr, actualErr, errors.New("native journal admission changed its actual durable checkpoint"))
	}
	return s.provePreparedLocked(ctx, attempt, *record.Committed.Target, current)
}

// Called with the slot locked only after its exact process/Job joined and the
// target was independently read from BFE. The process carries the last exact
// acknowledged or drained attempt; a newer or foreign journal cannot be adopted.
func (s *desktopNodeProtectionSlot) settleJournalLocked(ctx context.Context, attempt *desktopNodeProtectionAttempt,
	target *mobiletor.DesktopWindowsProtectionTarget) error {
	if s.journal == nil {
		return nil
	}
	if attempt.settlement != nil {
		captured := attempt.settlement.Committed.Target
		if (captured == nil) != (target == nil) || target != nil && *captured != *target {
			return errors.New("native journal settlement retry changed its proved target")
		}
		return s.writeJournalSettlementLocked(ctx, attempt)
	}
	process, ok := desktopOwnedNodeProcess(attempt.launch).(desktopNodeJournalAdmission)
	if !ok {
		return errors.New("native journal settlement lost its retained process channel")
	}
	last, err := process.JournalOutcome()
	if err != nil {
		return err
	}
	selection, err := s.journal.Snapshot(ctx)
	lastRaw, lastErr := windowsprotection.CanonicalJournalRecord(last)
	headRaw, headErr := windowsprotection.CanonicalJournalRecord(selection.Record)
	if err != nil || lastErr != nil || headErr != nil || selection.Incomplete || !bytes.Equal(lastRaw, headRaw) {
		return errors.Join(err, lastErr, headErr, errors.New("native journal settlement changed the captured child outcome"))
	}
	head := selection.Record
	if head.Phase == "intent" && (head.Intent.Action != "successor" || head.Intent.RequestID != attempt.transfer.SessionID ||
		head.Intent.ProfileID != attempt.policy.Metadata().ProfileID) {
		return errors.New("native journal settlement belongs to another mutation")
	}
	states, err := windowsprotection.JournalRecoveryCandidates(head)
	if err != nil {
		return err
	}
	var proved *windowsprotection.JournalState
	for _, state := range states {
		if (target == nil) == (state.Target == nil) && (target == nil || *target == *state.Target) {
			copy := state
			copy.Engine = nil // Only the independently joined process reaches here.
			proved = &copy
			break
		}
	}
	if proved == nil {
		return errors.New("native journal has no exact joined kernel outcome")
	}
	if head.Phase == "settled" && head.Committed.Engine == nil {
		return nil
	}
	next, err := copyDesktopNodeJournalRecord(head)
	if err != nil {
		return err
	}
	next.Sequence++
	next.PreviousSHA256, next.Phase, next.Intent, next.Committed = selection.SHA256, "settled", nil, *proved
	if err := windowsprotection.CheckJournalTransition(head, next); err != nil {
		return err
	}
	attempt.settlement = &next // Preserve the exact bytes across a short write or failed flush.
	return s.writeJournalSettlementLocked(ctx, attempt)
}

func (s *desktopNodeProtectionSlot) writeJournalSettlementLocked(ctx context.Context, attempt *desktopNodeProtectionAttempt) error {
	next := *attempt.settlement
	want, wantErr := windowsprotection.CanonicalJournalRecord(next)
	if wantErr != nil {
		return wantErr
	}
	// A flush can succeed just before cancellation. Confirm those exact bytes
	// on retry instead of attempting another append or reporting stale success.
	written, readErr := s.journal.Snapshot(ctx)
	got, gotErr := windowsprotection.CanonicalJournalRecord(written.Record)
	if readErr == nil && gotErr == nil && !written.Incomplete && bytes.Equal(want, got) {
		return ctx.Err()
	}
	written, err := s.journal.Append(ctx, next.PreviousSHA256, next)
	got, gotErr = windowsprotection.CanonicalJournalRecord(written.Record)
	if err != nil || wantErr != nil || gotErr != nil || written.Incomplete || !bytes.Equal(want, got) {
		return errors.Join(err, wantErr, gotErr, errors.New("native journal joined settlement is not durable"))
	}
	return ctx.Err()
}

// A killed child cannot publish a final file. Its retained, joined channel's
// durable record bounds the only acceptable outcomes; no missing file or
// failed probe is treated as successful absence.
func (s *desktopNodeProtectionSlot) finishJournalWithoutReceipt(ctx context.Context, attempt *desktopNodeProtectionAttempt, join func(context.Context) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil || attempt == nil || join == nil {
		return errors.New("native journal retirement has no captured attempt")
	}
	if err := join(ctx); err != nil {
		return err
	}
	process, ok := desktopOwnedNodeProcess(attempt.launch).(desktopNodeJournalAdmission)
	if !ok {
		return errors.New("native journal retirement lost its checked process outcome")
	}
	last, err := process.JournalOutcome()
	if err != nil {
		return err
	}
	states, err := windowsprotection.JournalRecoveryCandidates(last)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.active != attempt || s.journal == nil || s.backend.read == nil {
		s.mu.Unlock()
		return errors.New("native journal retirement belongs to another active owner")
	}
	var target *mobiletor.DesktopWindowsProtectionTarget
	proved := false
	for _, state := range states {
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return err
		}
		if s.backend.read(ctx, state.Target) == nil {
			if proved {
				s.mu.Unlock()
				return errors.New("native journal retirement has ambiguous kernel outcomes")
			}
			target, proved = copyDesktopNodeProtectionTarget(state.Target), true
		}
	}
	s.mu.Unlock()
	if !proved {
		return errors.New("native journal retirement proved no exact recorded kernel outcome")
	}
	return s.finish(ctx, attempt, desktopNodeProtectionRetirement(attempt, target), join)
}

func desktopNodeProtectionRetirement(attempt *desktopNodeProtectionAttempt, target *mobiletor.DesktopWindowsProtectionTarget) mobiletor.DesktopProtectionRetirementRecord {
	return mobiletor.DesktopProtectionRetirementRecord{Schema: 1, Kind: "routervpn-windows-protection-retired-v1", TransferSHA256: attempt.digest, Target: copyDesktopNodeProtectionTarget(target)}
}
