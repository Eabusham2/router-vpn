package main

import (
	"context"
	"errors"
	"strings"

	"router-vpn/internal/common"
)

var errDesktopProtectionOffUnsaved = errors.New("kill switch is off, but its preference could not be saved; retry Off to save the same change")

type profileProtectionCapture struct {
	slot     *desktopNodeProtectionSlot
	view     desktopNodeProtectionView
	revision string
	token    string
}

func (a *app) captureProfileProtection(profile common.RouterProfile) profileProtectionCapture {
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	capture := profileProtectionCapture{slot: slot, revision: profileStartupSettingsToken(profile)}
	capture.token = capture.revision
	if slot != nil {
		capture.view = slot.view()
		capture.token = capture.view.token(capture.revision)
	}
	return capture
}

func protectionSettingsWithCapture(profile common.RouterProfile, capture profileProtectionCapture) profileProtectionSettings {
	result := profileProtectionSettings{ProfileID: profile.ID, ProfileToken: capture.token, KillSwitchPolicy: desktopOwnedNodeProtectionPolicy(profile)}
	if capture.slot == nil {
		return result
	}
	v := capture.view
	result.ProtectionProfileID = v.Binding.ProfileID
	if v.PendingOff {
		result.ProtectionStatus, result.EffectivePolicy = "off-pending", "unknown"
		result.Message = "Turning the kill switch off is pending. Retry Off to finish the same change."
		if v.Removed && v.AbsenceProved {
			result.ProtectionStatus, result.EffectivePolicy = "off-unsaved", "off"
			result.Message = errDesktopProtectionOffUnsaved.Error()
		}
	} else if !v.Known || v.Retiring {
		result.ProtectionStatus, result.EffectivePolicy = "pending", "unknown"
		result.Message = "Protection cleanup is pending. Finish disconnecting before changing protection."
	} else if v.Target != nil {
		result.ProtectionStatus, result.EffectivePolicy = "retained", v.Target.Policy
		if v.Active {
			result.ProtectionStatus = "active"
		}
		if v.Binding.ProfileID != profile.ID {
			result.Message = "Protection still belongs to another node. Select that node to turn its kill switch off."
		}
	}
	return result
}

func (a *app) desktopProtectionOffPending() bool {
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	return slot != nil && slot.pendingOff() != nil
}

func (a *app) guardDesktopProtectionOffPending() error {
	if a.desktopProtectionOffPending() {
		return errors.New("finish the pending Kill Switch Off change before starting a connection or changing node settings")
	}
	return nil
}

// Broader settings editors cannot silently turn a retained native policy into
// a saved-only Off value. Explicit removal uses the narrow authenticated route.
func (a *app) guardDesktopProtectionPreference(policy string) error {
	if strings.EqualFold(strings.TrimSpace(policy), "off") && a.retainedDesktopNodeProtection() {
		return errors.New("use the Kill switch control to finish turning retained protection off before saving Off here")
	}
	return nil
}

func (a *app) capturedProtectionOffCurrent(slot *desktopNodeProtectionSlot, capture *desktopNodeProtectionOff, cleanup bool) bool {
	if slot == nil || capture == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(capture.profileID)
	if !exists || a.nodeProtection != slot || a.profiles.SelectedID != capture.profileID ||
		profileStartupSettingsToken(profile) != capture.profileRevision || a.cmd != nil || a.state.Connected {
		return false
	}
	// Shutdown may resume an already accepted Off while Stop is in its checked
	// stopping phase. It cannot capture a new removal operation through here.
	return cleanup || !a.closing && !profileSettingsBusy(a.state.Connected, a.state.Phase)
}

// The caller owns operationMu. Native operations run without a.mu; persistence
// takes a.mu only after the exact owner has joined and absence has been read.
func (a *app) resumeDesktopProtectionOff(ctx context.Context, slot *desktopNodeProtectionSlot, capture *desktopNodeProtectionOff, cleanup bool) (common.RouterProfile, error) {
	current := func() bool { return a.capturedProtectionOffCurrent(slot, capture, cleanup) }
	if err := slot.applyOff(ctx, capture, current); err != nil {
		return common.RouterProfile{}, err
	}
	if ctx.Err() != nil || !current() {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, ctx.Err())
	}
	a.mu.Lock()
	profile, exists := a.profileByIDLocked(capture.profileID)
	if !exists || a.nodeProtection != slot || a.profiles.SelectedID != capture.profileID ||
		profileStartupSettingsToken(profile) != capture.profileRevision || a.cmd != nil || a.state.Connected ||
		!cleanup && (a.closing || profileSettingsBusy(a.state.Connected, a.state.Phase)) || ctx.Err() != nil {
		a.mu.Unlock()
		return common.RouterProfile{}, errDesktopProtectionOffUnsaved
	}
	updated := cloneRouterProfile(profile)
	updated.KillSwitchPolicy, updated.KillSwitch = "off", false
	var saveErr error
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == profile.ID {
			a.profiles.Profiles[i] = updated
			saveErr = a.persistProfilesLocked()
			if saveErr != nil {
				a.profiles.Profiles[i] = profile
			}
			break
		}
	}
	a.mu.Unlock()
	if saveErr != nil {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, saveErr)
	}
	if err := slot.finishOffSave(capture); err != nil {
		return common.RouterProfile{}, err
	}
	a.mu.Lock()
	if a.nodeProtection == slot {
		a.nodeProtection = nil
	}
	a.mu.Unlock()
	cancelPendingStartupPolicy(a)
	return updated, nil
}
