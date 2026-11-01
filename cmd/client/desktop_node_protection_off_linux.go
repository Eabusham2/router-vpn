//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"router-vpn/internal/common"
	"router-vpn/internal/linuxprotection"
)

// One accepted saved-policy change retains the actual closed native creator,
// original journal, selection and immutable before/after profile revisions.
// All mutable fields are protected by session.gate; native journal callbacks
// also hold transaction.gate. A failed request never replaces this capability.
type desktopLinuxNodeProtectionOff struct {
	session         *desktopLinuxNodeSession
	transaction     *desktopLinuxNodeTransaction
	journal         *desktopLinuxNodeJournal
	original        linuxprotection.JournalSelection
	profileID       string
	profileRevision string
	resultRevision  string
	requestID       string
	token           string
	savedPath       string
	absenceProved   bool
	profileWritten  bool
	profileSaved    bool
	settled         bool
}

func (off *desktopLinuxNodeProtectionOff) currentRevision() string {
	if off.profileWritten {
		return off.resultRevision
	}
	return off.profileRevision
}

// No native capability is derived from these digests. This check only keeps an
// already accepted removal tied to its selected private profile and idle app.
func (off *desktopLinuxNodeProtectionOff) currentAppLocked(a *app, cleanup bool) bool {
	if off == nil || off.session == nil || off.transaction == nil || off.session.parent == nil ||
		off.session.parent.app != a || off.session.parent.currentAppLocked(true) != nil || a.nodeProtection != nil ||
		a.cmd != nil || a.state.Connected || a.connectionContext != nil || a.connectionCancel != nil ||
		a.profiles.SelectedID != off.profileID || !cleanup && (a.closing || profileSettingsBusy(a.state.Connected, a.state.Phase)) ||
		off.profileWritten && a.cfg.ProfilesFile != off.savedPath {
		return false
	}
	profile, exists := a.profileByIDLocked(off.profileID)
	if !exists || profileStartupSettingsToken(profile) != off.currentRevision() {
		return false
	}
	_, legacy := desktopNodeOwners.Load(a)
	return !legacy
}

func (off *desktopLinuxNodeProtectionOff) currentApp(cleanup bool) bool {
	if off == nil || off.session == nil || off.session.parent == nil || off.session.parent.app == nil {
		return false
	}
	a := off.session.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	return off.currentAppLocked(a, cleanup)
}

// The session gate is held. Parent/process authority is independently read;
// matching saved text or an nft name is never enough to authorize removal.
func (s *desktopLinuxNodeSession) protectionOffCurrentLocked(ctx context.Context, off *desktopLinuxNodeProtectionOff, cleanup bool) error {
	if ctx == nil || ctx.Err() != nil || off == nil || s.off != off || off.session != s || s.closed || s.released ||
		s.active != nil || s.predecessor != off.transaction || s.journal != off.journal || s.journalErr != nil ||
		off.transaction.off != off || !sameDesktopLinuxParentCapture(s.parent, off.transaction.parent) || !off.currentApp(cleanup) {
		return errors.New("Linux saved-policy Off lost its exact disconnected session or private profile")
	}
	if err := s.parent.retirementCurrent(ctx); err != nil {
		return err
	}
	p := s.parent.parent
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.gate:
	}
	defer func() { p.gate <- struct{}{} }()
	_, retained := p.dependents[s]
	_, journalOwned := p.dependents[s.journal]
	if p.session != s || !retained || !journalOwned {
		return errors.New("Linux saved-policy Off lost its original parent registration")
	}
	return nil
}

func (s *desktopLinuxNodeSession) applyProtectionOff(ctx context.Context, view *desktopPlatformProtectionCapture, capture profileProtectionCapture) (common.RouterProfile, error) {
	if err := s.enter(ctx); err != nil {
		return common.RouterProfile{}, err
	}
	defer func() { s.gate <- struct{}{} }()
	if view == nil || view.failure != nil || view.session != s || view.active != nil || s.active != nil ||
		s.predecessor == nil || s.predecessor != view.predecessor || s.journal != view.journal || s.off != view.off ||
		s.journalErr != nil || s.closed || s.released || !samePlatformProtectionCapture(capture.platform, view) || capture.slot != nil ||
		!desktopNodeProcessHex(capture.revision, 32) || !desktopNodeProcessHex(capture.resultRevision, 32) ||
		view.token(capture.revision) != capture.token {
		return common.RouterProfile{}, errors.New("Linux Off requires its exact disconnected retained source")
	}
	if s.off == nil {
		if err := s.currentLocked(ctx); err != nil {
			return common.RouterProfile{}, err
		}
		t := s.predecessor
		if err := t.enter(ctx); err != nil {
			return common.RouterProfile{}, err
		}
		captureErr := func() error {
			if !t.complete || !t.retired || !t.engineJoined || !t.nativeCommitted || t.closed || t.released || t.superseded ||
				t.successor != nil || t.off != nil || t.pending != nil || t.baseline == nil || t.baselineReleased ||
				!sameDesktopLinuxParentCapture(t.parent, s.parent) || t.journal != s.journal ||
				t.head.Record.Phase != "settled" || t.head.Record.Intent != nil || !reflect.DeepEqual(t.head, view.head) {
				return errors.New("Linux Off cannot adopt an active, incomplete or foreign native creator")
			}
			expected, err := t.joinedCandidate()
			if err != nil || !reflect.DeepEqual(expected, t.head.Record.Committed) || expected.ProfileID != view.profileID {
				return errors.Join(err, errors.New("Linux Off changed its original joined journal target"))
			}
			if err := t.checkHead(ctx); err != nil {
				return err
			}
			if err := t.baseline.ObserveClosed(ctx); err != nil {
				return err
			}
			var request [16]byte
			if _, err := rand.Read(request[:]); err != nil {
				return err
			}
			off := &desktopLinuxNodeProtectionOff{session: s, transaction: t, journal: s.journal,
				original: t.head, profileID: t.profileID, profileRevision: capture.revision, resultRevision: capture.resultRevision,
				requestID: hex.EncodeToString(request[:]), token: capture.token}
			off.original.Record = linuxprotection.CloneRecord(t.head.Record)
			if !off.currentApp(false) || ctx.Err() != nil {
				return errors.New("Linux Off lost its selected profile before accepting removal")
			}
			s.off, t.off = off, off
			cancelPendingStartupPolicy(s.parent.app)
			return nil
		}()
		t.gate <- struct{}{}
		if captureErr != nil {
			return common.RouterProfile{}, captureErr
		}
	}
	off := s.off
	if off.token != capture.token || off.currentRevision() != capture.revision || off.resultRevision != capture.resultRevision {
		return common.RouterProfile{}, errors.New("Linux Off retry changed its accepted original or result revision")
	}
	return s.resumeProtectionOffLocked(ctx, off, false)
}

func (off *desktopLinuxNodeProtectionOff) intent() *linuxprotection.JournalIntent {
	return &linuxprotection.JournalIntent{Action: "off", RequestID: off.requestID, ProfileID: off.profileID,
		ProfileRevision: off.profileRevision, ResultProfileRevision: off.resultRevision}
}

// The caller owns session.gate and operationMu. Native release precedes saving
// Off; private-store verification precedes empty journal settlement. Every
// failure keeps this same accepted capability and exact pending journal bytes.
func (s *desktopLinuxNodeSession) resumeProtectionOffLocked(ctx context.Context, off *desktopLinuxNodeProtectionOff, cleanup bool) (common.RouterProfile, error) {
	if err := s.protectionOffCurrentLocked(ctx, off, cleanup); err != nil {
		return common.RouterProfile{}, err
	}
	t := off.transaction
	if err := t.enter(ctx); err != nil {
		return common.RouterProfile{}, err
	}
	updated, err := func() (common.RouterProfile, error) {
		if !t.complete || !t.retired || !t.engineJoined || !t.nativeCommitted || t.superseded || t.successor != nil ||
			t.baseline == nil || t.off != off || !off.settled && (t.closed || t.released) {
			return common.RouterProfile{}, errors.New("Linux Off retry lost its original joined native creator")
		}
		if err := t.flushPending(ctx); err != nil {
			return common.RouterProfile{}, err
		}
		if err := t.checkHead(ctx); err != nil {
			return common.RouterProfile{}, err
		}
		if t.head.Record.Phase == "settled" && reflect.DeepEqual(t.head.Record.Committed, off.original.Record.Committed) {
			if !reflect.DeepEqual(t.head, off.original) || off.settled || t.baselineReleased {
				return common.RouterProfile{}, errors.New("Linux Off cannot replace another settled generation")
			}
			next := t.nextRecord()
			next.Phase, next.Intent = "intent", off.intent()
			if err := t.appendRecord(ctx, next); err != nil {
				return common.RouterProfile{}, err
			}
		}
		settled := t.head.Record.Phase == "settled" && t.head.Record.Intent == nil && reflect.DeepEqual(t.head.Record.Committed, linuxprotection.JournalState{})
		if !settled && (t.head.Record.Phase != "intent" || !reflect.DeepEqual(t.head.Record.Intent, off.intent()) ||
			!reflect.DeepEqual(t.head.Record.Committed, off.original.Record.Committed)) || settled && (!off.profileWritten || !t.baselineReleased) {
			return common.RouterProfile{}, errors.New("Linux Off cannot consume another accepted durable change")
		}
		if err := s.protectionOffCurrentLocked(ctx, off, cleanup); err != nil {
			return common.RouterProfile{}, err
		}
		off.absenceProved = false
		if !t.closed {
			if err := t.baseline.Release(ctx); err != nil {
				return common.RouterProfile{}, err
			}
			t.baselineReleased = true
		}
		if err := t.observeReleasedCandidate(ctx); err != nil {
			return common.RouterProfile{}, err
		}
		off.absenceProved = true
		if err := s.protectionOffCurrentLocked(ctx, off, cleanup); err != nil {
			return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
		}
		updated, err := off.persistProfile(ctx, cleanup)
		if err != nil {
			return common.RouterProfile{}, err
		}
		if !settled {
			next := t.nextRecord()
			next.Phase, next.Intent, next.Committed = "settled", nil, linuxprotection.JournalState{}
			if err := t.appendRecord(ctx, next); err != nil {
				return common.RouterProfile{}, err
			}
		}
		off.settled = true
		return updated, nil
	}()
	t.gate <- struct{}{}
	if err != nil {
		return common.RouterProfile{}, err
	}
	if err := s.protectionOffCurrentLocked(ctx, off, cleanup); err != nil {
		return common.RouterProfile{}, err
	}
	if err := t.Close(ctx); err != nil {
		return common.RouterProfile{}, err
	}
	// Keep the original journal for the next connection and eventual checked
	// terminal cleanup; clearing these owners cannot adopt crash leftovers.
	s.predecessor, s.off = nil, nil
	return updated, nil
}

func (off *desktopLinuxNodeProtectionOff) persistProfile(ctx context.Context, cleanup bool) (common.RouterProfile, error) {
	a := off.session.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || !off.absenceProved || !off.transaction.baselineReleased || !off.currentAppLocked(a, cleanup) {
		return common.RouterProfile{}, errDesktopProtectionOffUnsaved
	}
	profile, _ := a.profileByIDLocked(off.profileID)
	updated, err := profileProtectionOffResult(profile)
	if err != nil || profileStartupSettingsToken(updated) != off.resultRevision {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
	}
	if !off.profileWritten {
		for index := range a.profiles.Profiles {
			if a.profiles.Profiles[index].ID != off.profileID {
				continue
			}
			a.profiles.Profiles[index] = updated
			if err := a.persistProfilesLocked(); err != nil {
				a.profiles.Profiles[index] = profile
				return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
			}
			off.savedPath, off.profileWritten = a.cfg.ProfilesFile, true
			break
		}
	}
	if err := off.verifyProfileLocked(ctx, a); err != nil {
		return common.RouterProfile{}, err
	}
	return updated, nil
}

// Both the initial save and the durable settlement read the complete private
// store. A partial save/readback cannot be replaced by a UI preference or by
// a different selected profile with coincidentally similar connection fields.
func (off *desktopLinuxNodeProtectionOff) verifyProfileLocked(ctx context.Context, a *app) error {
	off.profileSaved = false
	if ctx == nil || ctx.Err() != nil || !off.profileWritten || a.cfg.ProfilesFile != off.savedPath {
		return errDesktopProtectionOffUnsaved
	}
	want, err := json.MarshalIndent(a.profiles, "", "  ")
	if err != nil {
		return errors.Join(errDesktopProtectionOffUnsaved, err)
	}
	raw, err := readPrivateRegular(off.savedPath, maxPrivateStoreBytes)
	var saved common.RouterProfileStore
	if err != nil || !bytes.Equal(raw, append(want, '\n')) || json.Unmarshal(raw, &saved) != nil || saved.SelectedID != off.profileID {
		return errors.Join(errDesktopProtectionOffUnsaved, err, errors.New("saved Linux Off did not read back its complete private store"))
	}
	proved := false
	for _, profile := range saved.Profiles {
		if profile.ID == off.profileID && profile.KillSwitchPolicy == "off" && !profile.KillSwitch && profileStartupSettingsToken(profile) == off.resultRevision {
			proved = true
		}
	}
	if !proved || ctx.Err() != nil {
		return errDesktopProtectionOffUnsaved
	}
	off.profileSaved = true
	return nil
}

// Journal authorization is deliberately separate from shape validation. Only
// this already-retained native creator plus its accepted saved-profile change
// may append Off; ordinary retirement cannot manufacture the same authority.
func (t *desktopLinuxNodeTransaction) checkProtectionOffIntent(ctx context.Context, next linuxprotection.JournalRecord) error {
	off := t.off
	if off == nil || off.transaction != t || off.journal != t.journal || off.session == nil || !t.retired ||
		t.baseline == nil || t.baselineReleased || off.settled || !off.currentApp(true) ||
		!reflect.DeepEqual(next.Intent, off.intent()) || !reflect.DeepEqual(t.journal.current, off.original) ||
		!reflect.DeepEqual(next.Committed, off.original.Record.Committed) {
		return errors.New("Linux journal Off has no original accepted profile removal")
	}
	return t.baseline.ObserveClosed(ctx)
}

func (t *desktopLinuxNodeTransaction) checkProtectionOffSettlement(ctx context.Context, next linuxprotection.JournalRecord) error {
	off := t.off
	if off == nil || off.transaction != t || off.journal != t.journal || !off.profileWritten || !off.absenceProved ||
		!reflect.DeepEqual(t.journal.current.Record.Intent, off.intent()) || !reflect.DeepEqual(next.Committed, linuxprotection.JournalState{}) ||
		!off.currentApp(true) {
		return errors.New("Linux journal cannot settle Off before its exact saved profile and native absence")
	}
	if err := t.observeReleasedCandidate(ctx); err != nil {
		return err
	}
	a := off.session.parent.app
	a.mu.Lock()
	defer a.mu.Unlock()
	if !off.currentAppLocked(a, true) {
		return errors.New("Linux Off settlement changed its original private profile")
	}
	return off.verifyProfileLocked(ctx, a)
}
