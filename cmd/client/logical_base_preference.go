package main

import (
	"context"
	"errors"

	"router-vpn/internal/mobiletor"
)

// A logical request saves its explicit preference before the native graph
// captures the complete profile. The saved value is part of the same source
// token as readiness, measurements and the durable protection journal.
type logicalBasePreferenceTransaction struct {
	operation      context.Context
	profileID      string
	previousBase   string
	stagedRevision string
	slot           *desktopNodeProtectionSlot
	protection     logicalBaseProtectionCapture
}

type logicalBaseProtectionCapture struct {
	generation      uint64
	known           bool
	target          *mobiletor.DesktopWindowsProtectionTarget
	binding         desktopNodeProtectionBinding
	profileRevision string
	journal         bool
}

func logicalBaseProtectionIdleLocked(slot *desktopNodeProtectionSlot) bool {
	return slot == nil || slot.active == nil && slot.retirement == nil && slot.off == nil && !slot.journalClosing &&
		(slot.backend.bootstrap == nil || slot.recovery != nil && slot.recovery.ready) &&
		(slot.recovery == nil || slot.recovery.ready && !slot.recovery.closing)
}

func captureLogicalBaseProtectionLocked(slot *desktopNodeProtectionSlot) logicalBaseProtectionCapture {
	if slot == nil {
		return logicalBaseProtectionCapture{}
	}
	return logicalBaseProtectionCapture{slot.generation, slot.known, copyDesktopNodeProtectionTarget(slot.target),
		slot.binding, slot.profileRevision, slot.journal != nil}
}

func logicalBaseProtectionEmptyLocked(slot *desktopNodeProtectionSlot) bool {
	return slot != nil && logicalBaseProtectionIdleLocked(slot) && slot.known && slot.target == nil && slot.journal == nil &&
		slot.binding == (desktopNodeProtectionBinding{}) && slot.profileRevision == ""
}

// The caller holds operationMu. Slot callbacks may take app.mu, so both save
// and rollback acquire the slot first and then recheck its app binding.
func (a *app) stageLogicalBasePreference(operation context.Context, requested string) (*logicalBasePreferenceTransaction, error) {
	base := normalizeBase(requested)
	if base == "auto" {
		return nil, nil
	}
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	if slot != nil {
		slot.mu.Lock()
		defer slot.mu.Unlock()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ownerPresent := desktopNodeOwners.Load(a)
	if operation == nil || operation.Err() != nil || a.connectionContext != operation || a.controllerClosingLocked() ||
		a.nodeProtection != slot || a.cmd != nil || a.state.Connected || ownerPresent {
		return nil, errors.New("logical base preference lost its idle captured connection operation")
	}
	for i := range a.profiles.Profiles {
		profile := &a.profiles.Profiles[i]
		if profile.ID != a.profiles.SelectedID {
			continue
		}
		if profile.BaseTunnel == base {
			return nil, nil
		}
		if !logicalBaseProtectionIdleLocked(slot) {
			return nil, errors.New("logical base preference cannot change an active or unjoined protection owner")
		}
		capture := &logicalBasePreferenceTransaction{operation: operation, profileID: profile.ID,
			previousBase: profile.BaseTunnel, slot: slot, protection: captureLogicalBaseProtectionLocked(slot)}
		profile.BaseTunnel = base
		capture.stagedRevision = profileStartupSettingsToken(*profile)
		if err := a.persistProfilesLocked(); err != nil {
			profile.BaseTunnel = capture.previousBase
			return nil, err
		}
		return capture, nil
	}
	return nil, errors.New("no selected router profile")
}

func (capture *logicalBasePreferenceTransaction) protectionUnchangedLocked(slot *desktopNodeProtectionSlot) bool {
	if slot == nil {
		// Checked on-connect release detaches its empty slot. The caller locks
		// that exact former slot before accepting its independently joined absence.
		return capture.slot == nil || logicalBaseProtectionEmptyLocked(capture.slot)
	}
	if capture.slot != nil && slot != capture.slot || !logicalBaseProtectionIdleLocked(slot) {
		return false
	}
	// A newly allocated slot is safe only after actual joined absence. Unknown
	// state and a retained successor cannot be relabeled with an old preference.
	if logicalBaseProtectionEmptyLocked(slot) {
		return true
	}
	if slot != capture.slot {
		return false
	}
	before := capture.protection
	if slot.binding != before.binding || slot.profileRevision != before.profileRevision ||
		(slot.target == nil) != (before.target == nil) || slot.target != nil && *slot.target != *before.target {
		return false
	}
	if slot.target != nil {
		// A failed attempt can join back to its exact predecessor while advancing
		// generation. Its original source and journal revision must remain exact.
		return before.known && slot.known
	}
	// Preparation may fail before the first native read. Only the same untouched
	// slot may then retain its original unknown/empty state.
	return slot.generation == before.generation && slot.known == before.known && (slot.journal != nil) == before.journal
}

// Cancellation does not invalidate rollback ownership: Disconnect waits for
// operationMu. A replacement operation, changed profile, unjoined child or new
// retained protection target does. Never change a captured runtime's token.
func (a *app) rollbackLogicalBasePreference(capture *logicalBasePreferenceTransaction) error {
	if capture == nil {
		return nil
	}
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	guarded := slot
	if guarded == nil {
		guarded = capture.slot
	}
	if guarded != nil {
		guarded.mu.Lock()
		defer guarded.mu.Unlock()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ownerPresent := desktopNodeOwners.Load(a)
	if capture.operation == nil || a.connectionContext != capture.operation || a.nodeProtection != slot ||
		a.profiles.SelectedID != capture.profileID || a.cmd != nil || a.state.Connected || ownerPresent ||
		!capture.protectionUnchangedLocked(slot) {
		return errors.New("logical base preference remains saved for a changed or retained connection owner")
	}
	for i := range a.profiles.Profiles {
		profile := &a.profiles.Profiles[i]
		if profile.ID != capture.profileID {
			continue
		}
		if profileStartupSettingsToken(*profile) != capture.stagedRevision {
			return errors.New("logical base rollback cannot replace a changed private profile")
		}
		stagedBase := profile.BaseTunnel
		profile.BaseTunnel = capture.previousBase
		if err := a.persistProfilesLocked(); err != nil {
			profile.BaseTunnel = stagedBase
			return errors.Join(err, errors.New("logical base rollback was not saved; the staged preference remains current"))
		}
		return nil
	}
	return errors.New("logical base rollback lost its captured profile")
}
