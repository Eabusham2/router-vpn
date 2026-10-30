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

// The slot retains this whole transaction, not just its kernel cleanup handle.
// Intent and settlement keep their exact bytes across failed flushes, cancelled
// native calls and a final journal-close failure. Only the barrier's atomic ACK
// is shared with a native operation that may outlive its cancelled caller.
type desktopNodeJournalRelease struct {
	store           desktopNodeProtectionJournal
	head            windowsprotection.JournalRecord
	intent          windowsprotection.JournalRecord
	settlement      windowsprotection.JournalRecord
	target          mobiletor.DesktopWindowsProtectionTarget
	binding         desktopNodeProtectionBinding
	profileRevision string
	generation      uint64
	native          desktopNodeProtectionRelease
	prepared        bool
	joined          bool
	settled         bool
	storeClosed     bool
	acknowledged    atomic.Bool
}

func (r *desktopNodeJournalRelease) Close(ctx context.Context) error {
	if r == nil || r.native == nil {
		return errors.New("durable release has no retained native operation")
	}
	return r.native.Close(ctx)
}

func (s *desktopNodeProtectionSlot) captureJournalReleaseLocked(ctx context.Context) (*desktopNodeJournalRelease, error) {
	if s.journal == nil || s.journalClosing || s.target == nil || s.target.Validate() != nil ||
		s.backend.releaseWithBarrier == nil || s.binding.ProfileID == "" || s.binding.SourceSHA256 != s.target.Capture.SourceSHA256 ||
		!desktopNodeProcessHex(s.profileRevision, 32) || s.generation == math.MaxUint64 {
		return nil, errors.New("durable release lost its exact joined target, profile revision or native barrier")
	}
	selection, err := s.journal.Snapshot(ctx)
	if err != nil || selection.Incomplete || selection.Record.Validate() != nil || selection.Record.Phase != "settled" ||
		selection.Record.Committed.Engine != nil || selection.Record.Committed.Target == nil || *selection.Record.Committed.Target != *s.target ||
		selection.Record.Committed.ProfileID != s.binding.ProfileID {
		return nil, errors.Join(err, errors.New("durable release has no exact settled journal owner"))
	}
	head, err := copyDesktopNodeJournalRecord(selection.Record)
	if err != nil {
		return nil, err
	}
	raw, err := windowsprotection.CanonicalJournalRecord(head)
	digest, digestErr := windowsprotection.JournalRecordSHA256(raw)
	if err != nil || digestErr != nil || digest != selection.SHA256 || ctx.Err() != nil {
		return nil, errors.Join(err, digestErr, ctx.Err(), errors.New("durable release changed its captured journal digest"))
	}
	r := &desktopNodeJournalRelease{store: s.journal, head: head, target: *s.target, binding: s.binding,
		profileRevision: s.profileRevision, generation: s.generation}
	if r.target.Policy == "always" {
		return r, nil // Normal disconnect preserves Always without a removal intent.
	}
	if head.Sequence > math.MaxUint64-2 {
		return nil, errors.New("durable release has no sequence capacity for intent and settlement")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	r.intent, err = copyDesktopNodeJournalRecord(head)
	if err != nil {
		return nil, err
	}
	r.intent.Sequence++
	r.intent.PreviousSHA256, r.intent.Phase = selection.SHA256, "intent"
	r.intent.Intent = &windowsprotection.JournalIntent{Action: "release", RequestID: hex.EncodeToString(nonce[:]),
		ProfileID: r.binding.ProfileID, ProfileRevision: r.profileRevision, ResultProfileRevision: r.profileRevision}
	if err := windowsprotection.CheckJournalTransition(head, r.intent); err != nil {
		return nil, err
	}
	intentRaw, err := windowsprotection.CanonicalJournalRecord(r.intent)
	intentDigest, digestErr := windowsprotection.JournalRecordSHA256(intentRaw)
	if err != nil || digestErr != nil {
		return nil, errors.Join(err, digestErr)
	}
	r.settlement, err = copyDesktopNodeJournalRecord(r.intent)
	if err != nil {
		return nil, err
	}
	r.settlement.Sequence++
	r.settlement.PreviousSHA256, r.settlement.Phase, r.settlement.Intent = intentDigest, "settled", nil
	r.settlement.Committed = windowsprotection.JournalState{}
	if err := windowsprotection.CheckJournalTransition(r.intent, r.settlement); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *desktopNodeJournalRelease) barrier(ctx context.Context, change mobiletor.DesktopWindowsProtectionCommit) error {
	if r == nil || ctx == nil || ctx.Err() != nil || r.target.Policy != "on-connect" || change.Validate() != nil ||
		change.Action != "release" || change.Previous == nil || *change.Previous != r.target || change.Candidate != nil {
		return errors.New("durable release barrier changed its exact native removal")
	}
	// The native write transaction is held here. Never re-enter BFE or the
	// slot mutex; the captured store alone flushes this immutable intent.
	if err := writeDesktopNodeJournalReleaseRecord(ctx, r.store, r.head, r.intent); err != nil {
		return err
	}
	r.acknowledged.Store(true)
	return ctx.Err()
}

// A write may have completed just before cancellation, or may still be pending
// its exact flush. The same immutable next record handles both retries. A
// different successful snapshot cannot be accepted or replaced by this owner.
func writeDesktopNodeJournalReleaseRecord(ctx context.Context, store desktopNodeProtectionJournal,
	previous, next windowsprotection.JournalRecord) error {
	if ctx == nil || ctx.Err() != nil || store == nil || windowsprotection.CheckJournalTransition(previous, next) != nil {
		return errors.New("durable release write lost its captured transition")
	}
	want, err := windowsprotection.CanonicalJournalRecord(next)
	before, beforeErr := windowsprotection.CanonicalJournalRecord(previous)
	if err != nil || beforeErr != nil {
		return errors.Join(err, beforeErr)
	}
	read, readErr := store.Snapshot(ctx)
	actual, actualErr := windowsprotection.CanonicalJournalRecord(read.Record)
	if readErr == nil {
		if actualErr != nil || read.Incomplete {
			return errors.Join(actualErr, errors.New("durable release observed an incomplete journal"))
		}
		if bytes.Equal(actual, want) {
			return ctx.Err()
		}
		if !bytes.Equal(actual, before) {
			return errors.New("durable release observed a replacement journal generation")
		}
	}
	written, err := store.Append(ctx, next.PreviousSHA256, next)
	actual, actualErr = windowsprotection.CanonicalJournalRecord(written.Record)
	if err != nil || actualErr != nil || written.Incomplete || !bytes.Equal(actual, want) {
		return errors.Join(err, actualErr, errors.New("durable release did not flush its exact journal record"))
	}
	return ctx.Err()
}

func (r *desktopNodeJournalRelease) unchanged(ctx context.Context) error {
	read, err := r.store.Snapshot(ctx)
	want, wantErr := windowsprotection.CanonicalJournalRecord(r.head)
	actual, actualErr := windowsprotection.CanonicalJournalRecord(read.Record)
	if err != nil || wantErr != nil || actualErr != nil || read.Incomplete || !bytes.Equal(actual, want) || ctx.Err() != nil {
		return errors.Join(err, wantErr, actualErr, ctx.Err(), errors.New("durable release changed its original settled journal"))
	}
	return nil
}

// The caller holds the slot lock. Partial native owners join before another
// constructor; an armed owner and its immutable intent are never replaced.
// Clearing the target happens only after checked absence, durable settlement
// and the retained journal's complete close.
func (s *desktopNodeProtectionSlot) releaseJournalLocked(ctx context.Context) error {
	r, ok := s.retirement.(*desktopNodeJournalRelease)
	if s.retirement != nil && !ok {
		return errors.New("durable release found another retained native operation")
	}
	if r == nil {
		var err error
		r, err = s.captureJournalReleaseLocked(ctx)
		if err != nil {
			return err
		}
		s.retirement, s.retirementPrepared = r, true
	}
	if s.target == nil || *s.target != r.target || s.binding != r.binding || s.profileRevision != r.profileRevision ||
		s.generation != r.generation || r.storeClosed && s.journal != nil || !r.storeClosed && s.journal != r.store {
		return errors.New("durable release belongs to a replaced application owner")
	}
	if r.native != nil && !r.prepared {
		if err := r.Close(ctx); err != nil || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if err := s.backend.read(ctx, &r.target); err != nil || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if err := r.unchanged(ctx); err != nil {
			return err
		}
		r.native = nil
	}
	if r.native == nil {
		if s.backend.releaseWithBarrier == nil {
			return errors.New("durable release lost its native commit barrier")
		}
		if err := s.backend.read(ctx, &r.target); err != nil || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if err := r.unchanged(ctx); err != nil {
			return err
		}
		owner, err := s.backend.releaseWithBarrier(ctx, r.target, r.barrier)
		if owner != nil {
			r.native, r.prepared = owner, err == nil
		}
		if err != nil || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if owner == nil {
			return errors.New("durable release did not retain its native operation")
		}
	}
	if !r.joined {
		if err := r.Close(ctx); err != nil {
			return err
		}
		r.joined = true
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	var expected *mobiletor.DesktopWindowsProtectionTarget
	if r.target.Policy == "always" {
		expected = &r.target
	} else if !r.acknowledged.Load() {
		return errors.New("durable release joined without its exact intent acknowledgment")
	}
	if err := s.backend.read(ctx, expected); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if expected != nil {
		if err := r.unchanged(ctx); err != nil {
			return err
		}
	} else {
		if !r.settled {
			if err := writeDesktopNodeJournalReleaseRecord(ctx, r.store, r.intent, r.settlement); err != nil {
				return err
			}
			r.settled = true
		}
		if !r.storeClosed {
			err := s.closeEmptyJournalLocked(ctx)
			r.storeClosed = s.journal == nil && !s.journalClosing
			if err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.advanceGenerationLocked(); err != nil {
		return err
	}
	if expected == nil {
		s.binding, s.profileRevision = desktopNodeProtectionBinding{}, ""
	}
	s.target, s.retirement, s.retirementPrepared = copyDesktopNodeProtectionTarget(expected), nil, false
	return nil
}
