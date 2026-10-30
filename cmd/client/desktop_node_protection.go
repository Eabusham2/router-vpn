package main

import (
	"context"
	"errors"
	"sync"

	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
	"router-vpn/internal/windowsprotection"
)

type desktopNodeProtectionRelease interface{ Close(context.Context) error }

// This backend is selected by the native host, never by imported metadata.
// Tests model the kernel explicitly; production uses the exact BFE readers and
// target-bound release constructor. No callback may adopt a current baseline.
type desktopNodeProtectionBackend struct {
	read               func(context.Context, *mobiletor.DesktopWindowsProtectionTarget) error
	prepared           func(context.Context, mobiletor.DesktopWindowsProtectionTarget) error
	release            func(context.Context, mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error)
	recover            func(context.Context, mobiletor.DesktopWindowsProtectionTarget) (desktopNodeProtectionRelease, error)
	releaseWithBarrier func(context.Context, mobiletor.DesktopWindowsProtectionTarget, mobiletor.DesktopWindowsProtectionCommitBarrier) (desktopNodeProtectionRelease, error)
}

type desktopNodeProtectionAttempt struct {
	launch          *desktopNodeLaunch
	policy          *mobilemultihop.DesktopNodePolicy
	transfer        mobiletor.DesktopProtectionTransferRecord
	digest          string
	prepared        *mobiletor.DesktopWindowsProtectionTarget
	settlement      *windowsprotection.JournalRecord
	profileRevision string
}

// The succession slot outlives each runtime directory. A restored original
// graph consumes the most recent joined trial target (A -> B -> A'), not A's
// already replaced baseline. Only exact independent readback changes the slot.
type desktopNodeProtectionSlot struct {
	mu                 sync.Mutex
	backend            desktopNodeProtectionBackend
	known              bool
	target             *mobiletor.DesktopWindowsProtectionTarget
	active             *desktopNodeProtectionAttempt
	retirement         desktopNodeProtectionRelease
	retirementPrepared bool
	generation         uint64
	binding            desktopNodeProtectionBinding
	off                *desktopNodeProtectionOff
	journal            desktopNodeProtectionJournal
	journalClosing     bool
	profileRevision    string // Exact private profile revision captured by the joined successor.
}

func copyDesktopNodeProtectionTarget(target *mobiletor.DesktopWindowsProtectionTarget) *mobiletor.DesktopWindowsProtectionTarget {
	if target == nil {
		return nil
	}
	copy := *target
	return &copy
}

func (s *desktopNodeProtectionSlot) begin(ctx context.Context, launch *desktopNodeLaunch, policy *mobilemultihop.DesktopNodePolicy) (*desktopNodeProtectionAttempt, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || launch == nil || policy == nil || policy.Validate() != nil {
		return nil, errors.New("native protection transfer has no captured launch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != nil || s.retirement != nil || s.off != nil || s.journalClosing || s.backend.read == nil || s.backend.prepared == nil || s.backend.release == nil {
		return nil, errors.New("native protection still belongs to an active or retiring attempt")
	}
	expected := copyDesktopNodeProtectionTarget(s.target)
	// For a newly allocated slot, nil is an explicit expectation, never a
	// request to discover or adopt whatever a previous controller left behind.
	if err := s.backend.read(ctx, expected); err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	meta := policy.Metadata()
	transfer := mobiletor.DesktopProtectionTransferRecord{Schema: 1, Kind: "routervpn-windows-protection-transfer-v1",
		SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, Predecessor: expected}
	digest, err := mobiletor.DesktopProtectionTransferRecordSHA256(transfer)
	if err != nil {
		return nil, err
	}
	attempt := &desktopNodeProtectionAttempt{launch: launch, policy: policy, transfer: transfer, digest: digest}
	if launch.ownedNode != nil {
		attempt.profileRevision = launch.ownedNode.profileToken
	}
	if err := s.advanceGenerationLocked(); err != nil {
		return nil, err
	}
	s.known, s.active = true, attempt
	return attempt, nil
}

func (s *desktopNodeProtectionSlot) provePrepared(ctx context.Context, attempt *desktopNodeProtectionAttempt, target mobiletor.DesktopWindowsProtectionTarget, current func() bool) error {
	if s == nil || ctx == nil || ctx.Err() != nil || attempt == nil || current == nil || !current() || target.Validate() != nil {
		return errors.New("native protection handoff lost its current process or capture")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.provePreparedLocked(ctx, attempt, target, current)
}

func (s *desktopNodeProtectionSlot) provePreparedLocked(ctx context.Context, attempt *desktopNodeProtectionAttempt, target mobiletor.DesktopWindowsProtectionTarget, current func() bool) error {
	if s.active != attempt || attempt.policy == nil || attempt.policy.Validate() != nil {
		return errors.New("native protection handoff belongs to another attempt")
	}
	meta := attempt.policy.Metadata()
	if target.Capture.SessionID != meta.SessionID || target.Capture.SourceSHA256 != meta.SourceSHA256 || target.Policy != meta.KillSwitchPolicy ||
		attempt.prepared != nil && *attempt.prepared != target {
		return errors.New("native protection handoff substituted its exact target")
	}
	if err := s.backend.prepared(ctx, target); err != nil || ctx.Err() != nil || !current() {
		return errors.Join(err, ctx.Err(), errors.New("native protection handoff did not retain its proved owner"))
	}
	attempt.prepared = copyDesktopNodeProtectionTarget(&target)
	return nil
}

// finish joins the exact child and its Job before consulting the retired BFE
// expectation. A private receipt or process-exit observation alone is never
// sufficient. On any error the same attempt and workspace remain owned.
func (s *desktopNodeProtectionSlot) finish(ctx context.Context, attempt *desktopNodeProtectionAttempt, record mobiletor.DesktopProtectionRetirementRecord, join func(context.Context) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil || attempt == nil || join == nil {
		return errors.New("native protection retirement lost its captured child")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != attempt || record.Validate(attempt.transfer) != nil {
		return errors.New("native protection retirement belongs to another attempt")
	}
	target := copyDesktopNodeProtectionTarget(record.Target)
	if attempt.prepared != nil && (target == nil || *target != *attempt.prepared) {
		return errors.New("admitted native protection did not retain its proved successor")
	}
	if err := join(ctx); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if err := s.backend.read(ctx, target); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if err := s.settleJournalLocked(ctx, attempt, target); err != nil {
		return err
	}
	if err := s.advanceGenerationLocked(); err != nil {
		return err
	}
	if target == nil {
		s.binding = desktopNodeProtectionBinding{}
		s.profileRevision = ""
	} else if target.Capture.SessionID == attempt.policy.Metadata().SessionID && target.Capture.SourceSHA256 == attempt.policy.Metadata().SourceSHA256 {
		// A failed trial may return its unchanged predecessor. Only a proved
		// successor acquires the new profile/source binding.
		meta := attempt.policy.Metadata()
		s.binding = desktopNodeProtectionBinding{ProfileID: meta.ProfileID, SourceSHA256: meta.SourceSHA256}
		s.profileRevision = attempt.profileRevision
	}
	s.target, s.active, s.known = target, nil, true
	return nil
}

// A failed process creation can be discarded only after exact child/Job join
// and proof that the original expected baseline is unchanged. A committed or
// unknown successor cannot be disguised as an unstarted launch.
func (s *desktopNodeProtectionSlot) abandonUnchanged(ctx context.Context, attempt *desktopNodeProtectionAttempt, join func(context.Context) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil || attempt == nil || join == nil {
		return errors.New("native protection has no captured failed launch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != attempt || attempt.prepared != nil {
		return errors.New("native protection cannot discard an admitted or foreign attempt")
	}
	if err := join(ctx); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	expected := copyDesktopNodeProtectionTarget(attempt.transfer.Predecessor)
	if err := s.backend.read(ctx, expected); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if err := s.settleJournalLocked(ctx, attempt, expected); err != nil {
		return err
	}
	if err := s.advanceGenerationLocked(); err != nil {
		return err
	}
	s.target, s.active, s.known = expected, nil, true
	return nil
}

func (s *desktopNodeProtectionSlot) release(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("native protection release has no current capture")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.known || s.active != nil || s.off != nil || s.backend.read == nil || s.backend.release == nil {
		return errors.New("native protection is still active or unknown")
	}
	if _, durable := s.retirement.(*desktopNodeJournalRelease); durable || s.journal != nil && s.target != nil {
		return s.releaseJournalLocked(ctx)
	}
	if s.target == nil {
		if s.retirement != nil {
			return errors.New("native protection retirement lost its exact target")
		}
		if err := s.backend.read(ctx, nil); err != nil || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		return s.closeEmptyJournalLocked(ctx)
	}
	target := *s.target
	if s.retirement != nil && !s.retirementPrepared {
		// A constructor can return an unarmed partial native owner. Its Close
		// joins entered work but deliberately preserves the original baseline.
		// Retain that exact owner until both join and unchanged-target proof
		// succeed; only then may this retry prepare a fresh exact release.
		if err := s.retirement.Close(ctx); err != nil || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if err := s.backend.read(ctx, &target); err != nil || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		s.retirement, s.retirementPrepared = nil, false
	}
	if s.retirement == nil {
		owner, err := s.backend.release(ctx, target)
		if owner != nil {
			s.retirement = owner
			// The constructor's result is authoritative. Cancellation after a
			// successful return does not turn its armed owner into a partial one.
			s.retirementPrepared = err == nil
		}
		if err != nil || ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if owner == nil {
			return errors.New("native protection release did not retain its operation")
		}
	}
	if err := s.retirement.Close(ctx); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	var expected *mobiletor.DesktopWindowsProtectionTarget
	if target.Policy == "always" {
		expected = copyDesktopNodeProtectionTarget(&target)
	}
	if err := s.backend.read(ctx, expected); err != nil || ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	if err := s.advanceGenerationLocked(); err != nil {
		return err
	}
	if expected == nil {
		s.binding = desktopNodeProtectionBinding{}
		s.profileRevision = ""
	}
	s.target, s.retirement, s.retirementPrepared = expected, nil, false
	return nil
}

func (s *desktopNodeProtectionSlot) retained() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active != nil || s.retirement != nil || s.target != nil || s.off != nil || s.journal != nil
}
