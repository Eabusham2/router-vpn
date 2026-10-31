package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sync/atomic"

	"router-vpn/internal/mobiletor"
)

type desktopNodeProtectionBinding struct {
	ProfileID    string `json:"profile_id"`
	SourceSHA256 string `json:"source_sha256"`
}

// The view is copied under the slot lock. A UI revision binds this exact
// source owner and generation; callers never supply a native target or PID.
type desktopNodeProtectionView struct {
	Generation       uint64                                    `json:"generation"`
	Known            bool                                      `json:"known"`
	Target           *mobiletor.DesktopWindowsProtectionTarget `json:"target"`
	Binding          desktopNodeProtectionBinding              `json:"binding"`
	Active           bool                                      `json:"active"`
	Retiring         bool                                      `json:"retiring"`
	PendingOff       bool                                      `json:"-"`
	Removed          bool                                      `json:"-"`
	AbsenceProved    bool                                      `json:"-"`
	ProfileWritten   bool                                      `json:"-"`
	ProfileSaved     bool                                      `json:"-"`
	OriginalRevision string                                    `json:"-"`
	ResultRevision   string                                    `json:"-"`
	RecoveryPending  bool                                      `json:"-"`
}

// An accepted Off request keeps its original target even after native absence
// is proved. The slot is not empty until that same profile preference is saved.
// No private profile contents or credential copies are retained here.
type desktopNodeProtectionOff struct {
	profileID       string
	profileRevision string
	resultRevision  string
	sourceRevision  string
	savedPath       string // Published once under app.mu before profileWritten is set.
	profileWritten  atomic.Bool
	profileSaved    atomic.Bool
	token           string
	generation      uint64
	binding         desktopNodeProtectionBinding
	target          mobiletor.DesktopWindowsProtectionTarget
	owner           desktopNodeProtectionRelease
	prepared        bool
	joined          bool
	removed         bool
	absenceProved   bool
	journal         *desktopNodeJournalOff
	recovered       bool
	selectedID      string // Startup selection is preserved separately from the recorded Off profile.
}

func (s *desktopNodeProtectionSlot) advanceGenerationLocked() error {
	if s.generation == math.MaxUint64 {
		return errors.New("native protection generation is exhausted; retained cleanup is required")
	}
	s.generation++
	return nil
}

func (s *desktopNodeProtectionSlot) viewLocked() desktopNodeProtectionView {
	v := desktopNodeProtectionView{Generation: s.generation, Known: s.known,
		Target: copyDesktopNodeProtectionTarget(s.target), Binding: s.binding,
		Active: s.active != nil, Retiring: s.retirement != nil, PendingOff: s.off != nil}
	v.RecoveryPending = s.backend.bootstrap != nil && (s.recovery == nil || !s.recovery.ready)
	if s.off != nil {
		v.Removed = s.off.removed
		v.AbsenceProved = s.off.absenceProved
		v.ProfileWritten, v.ProfileSaved = s.off.profileWritten.Load(), s.off.profileSaved.Load()
		v.OriginalRevision, v.ResultRevision = s.off.profileRevision, s.off.resultRevision
	}
	return v
}

func (s *desktopNodeProtectionSlot) view() desktopNodeProtectionView {
	if s == nil {
		return desktopNodeProtectionView{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked()
}

func (v desktopNodeProtectionView) token(profileRevision string) string {
	// Pending/removed are deliberately excluded. An accepted operation retains
	// the same revision through cleanup and off-unsaved retries. Completion or
	// any ordinary succession changes the generation and invalidates it.
	if v.PendingOff && (profileRevision == v.OriginalRevision || profileRevision == v.ResultRevision) {
		profileRevision = v.OriginalRevision
	}
	raw, _ := json.Marshal(struct {
		Kind            string                    `json:"kind"`
		ProfileRevision string                    `json:"profile_revision"`
		Protection      desktopNodeProtectionView `json:"protection"`
	}{"routervpn-owned-protection-revision-v1", profileRevision, v})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (s *desktopNodeProtectionSlot) pendingOff() *desktopNodeProtectionOff {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.off
}

func (s *desktopNodeProtectionSlot) captureOff(ctx context.Context, profileID, profileRevision, resultRevision, token string) (*desktopNodeProtectionOff, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || profileID == "" || !desktopNodeProcessHex(profileRevision, 32) || !desktopNodeProcessHex(resultRevision, 32) || token == "" {
		return nil, errors.New("protection Off has no current selected-node revision")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.known || s.active != nil || s.retirement != nil || s.target == nil || s.target.Validate() != nil ||
		s.binding.ProfileID != profileID || s.binding.SourceSHA256 != s.target.Capture.SourceSHA256 ||
		s.backend.read == nil || s.backend.recover == nil || s.generation == math.MaxUint64 ||
		s.viewLocked().token(profileRevision) != token {
		return nil, errors.New("protection Off requires the retained disconnected owner and its current selected-node revision")
	}
	if s.off != nil {
		if s.off.profileID != profileID || s.off.currentProfileRevision() != profileRevision || s.off.resultRevision != resultRevision || s.off.token != token || !s.offCurrentLocked(s.off) {
			return nil, errors.New("another protection Off operation is still pending")
		}
		return s.off, nil
	}
	capture := &desktopNodeProtectionOff{profileID: profileID, profileRevision: profileRevision, resultRevision: resultRevision, sourceRevision: s.profileRevision, token: token,
		generation: s.generation, binding: s.binding, target: *s.target}
	s.off = capture
	return capture, nil
}

func (capture *desktopNodeProtectionOff) currentProfileRevision() string {
	if capture.profileWritten.Load() {
		return capture.resultRevision
	}
	return capture.profileRevision
}

func (capture *desktopNodeProtectionOff) capturedSelection() string {
	if capture.recovered {
		return capture.selectedID
	}
	return capture.profileID
}

func (s *desktopNodeProtectionSlot) offCurrentLocked(capture *desktopNodeProtectionOff) bool {
	return capture != nil && s.off == capture && s.known && s.active == nil && s.retirement == nil &&
		s.generation == capture.generation && s.binding == capture.binding &&
		s.profileRevision == capture.sourceRevision &&
		s.target != nil && *s.target == capture.target
}

func (s *desktopNodeProtectionSlot) offReadyToSave(capture *desktopNodeProtectionOff) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offCurrentLocked(capture) && capture.removed && capture.absenceProved && capture.owner != nil && capture.prepared &&
		(capture.journal == nil && s.journal == nil || s.offJournalCurrentLocked(capture) && capture.joined && capture.journal.acknowledged.Load())
}

// current must not acquire the slot lock. The application holds operationMu
// around this accepted transaction, and the guard rechecks only app/profile
// identity. Failed native operations stay attached to this exact capture.
func (s *desktopNodeProtectionSlot) applyOff(ctx context.Context, capture *desktopNodeProtectionOff, current func() bool) error {
	if s == nil || ctx == nil || ctx.Err() != nil || current == nil || !current() {
		return errors.New("protection Off lost its captured application operation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.offCurrentLocked(capture) || s.backend.read == nil || s.backend.recover == nil {
		return errors.New("protection Off belongs to a replaced retained owner")
	}
	check := func() error {
		if ctx.Err() != nil || !current() {
			return errors.Join(ctx.Err(), errors.New("protection Off no longer has its captured selected-node revision"))
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	if s.journal != nil || capture.journal != nil {
		return s.applyJournalOffLocked(ctx, capture, check)
	}
	if capture.removed {
		// Saving can fail after native removal. Retrying never creates a second
		// removal operation or guesses a replacement baseline.
		capture.absenceProved = false
		if err := s.backend.read(ctx, nil); err != nil {
			return err
		}
		capture.absenceProved = true
		return check()
	}
	if capture.owner != nil && !capture.prepared {
		// A failed constructor may own entered native work without authority to
		// remove the target. Join it and prove the original before preparing again.
		if err := capture.owner.Close(ctx); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		if err := s.backend.read(ctx, &capture.target); err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		capture.owner = nil
	}
	if capture.owner == nil {
		owner, err := s.backend.recover(ctx, capture.target)
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
			return errors.New("protection Off did not retain its native removal operation")
		}
	}
	if err := capture.owner.Close(ctx); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if err := s.backend.read(ctx, nil); err != nil {
		return err
	}
	capture.removed, capture.absenceProved = true, true
	if err := check(); err != nil {
		return err
	}
	return nil
}

func (s *desktopNodeProtectionSlot) finishOffSave(ctx context.Context, capture *desktopNodeProtectionOff, current func() bool) error {
	if s == nil || ctx == nil || ctx.Err() != nil || current == nil || !current() {
		return errors.New("protection Off lost its pending save owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.offCurrentLocked(capture) || !capture.removed || !capture.absenceProved || capture.owner == nil || !capture.prepared || !capture.profileSaved.Load() {
		return errors.New("protection Off cannot finish before exact native absence and preference persistence")
	}
	if capture.journal != nil {
		if err := s.finishJournalOffLocked(ctx, capture, current); err != nil {
			return err
		}
	}
	if ctx.Err() != nil || !current() {
		return errors.Join(ctx.Err(), errors.New("saved Off lost its captured application owner"))
	}
	if err := s.advanceGenerationLocked(); err != nil {
		return err
	}
	s.target, s.off, s.binding = nil, nil, desktopNodeProtectionBinding{}
	s.profileRevision = ""
	return nil
}
