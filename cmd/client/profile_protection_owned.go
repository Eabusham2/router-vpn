package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"router-vpn/internal/common"
)

var errDesktopProtectionOffUnsaved = errors.New("kill switch is off, but its preference could not be saved; retry Off to save the same change")

type profileProtectionCapture struct {
	slot           *desktopNodeProtectionSlot
	view           desktopNodeProtectionView
	revision       string
	resultRevision string
	token          string
}

func (a *app) captureProfileProtection(profile common.RouterProfile) profileProtectionCapture {
	a.mu.Lock()
	slot := a.nodeProtection
	a.mu.Unlock()
	capture := profileProtectionCapture{slot: slot, revision: profileStartupSettingsToken(profile)}
	if result, err := profileProtectionOffResult(profile); err == nil {
		capture.resultRevision = profileStartupSettingsToken(result)
	}
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
			if v.ProfileWritten {
				result.Message = "The kill switch is off. Its saved preference still needs verification; retry Off to finish."
			}
			if v.ProfileSaved {
				result.ProtectionStatus = "off-pending"
				result.Message = "The kill switch is off and its preference is saved. Retry Off to finish protection cleanup."
			}
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
		profileStartupSettingsToken(profile) != capture.currentProfileRevision() || a.cmd != nil || a.state.Connected ||
		capture.profileWritten.Load() && a.cfg.ProfilesFile != capture.savedPath {
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
	updated, err := a.persistCapturedProtectionOff(ctx, slot, capture, cleanup)
	if err != nil {
		return common.RouterProfile{}, err
	}
	if err := slot.finishOffSave(ctx, capture, current); err != nil {
		return common.RouterProfile{}, err
	}
	a.mu.Lock()
	if a.nodeProtection != slot {
		a.mu.Unlock()
		return common.RouterProfile{}, errors.New("saved Off completed for a replaced application slot")
	}
	a.nodeProtection = nil
	a.mu.Unlock()
	cancelPendingStartupPolicy(a)
	return updated, nil
}

func profileProtectionOffResult(profile common.RouterProfile) (common.RouterProfile, error) {
	updated := cloneRouterProfile(profile)
	updated.KillSwitchPolicy, updated.KillSwitch = "off", false
	// The result revision must be reproducible from the actual saved profile,
	// whose JSON contract normalizes defaults. Capture it before native removal.
	if err := common.NormalizeRouterProfile(&updated); err != nil {
		return common.RouterProfile{}, err
	}
	return updated, nil
}

// A successful publication immediately changes the allowed in-memory revision.
// Readback acknowledgment is separate, so a read error, cancellation, failed
// journal flush or failed close can retry this result without rewriting Off or
// rolling RAM back to the original preference after disk has already changed.
func (a *app) persistCapturedProtectionOff(ctx context.Context, slot *desktopNodeProtectionSlot, capture *desktopNodeProtectionOff, cleanup bool) (common.RouterProfile, error) {
	if ctx == nil || ctx.Err() != nil || !slot.offReadyToSave(capture) {
		return common.RouterProfile{}, errDesktopProtectionOffUnsaved
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	profile, exists := a.profileByIDLocked(capture.profileID)
	if !exists || a.nodeProtection != slot || a.profiles.SelectedID != capture.profileID ||
		profileStartupSettingsToken(profile) != capture.currentProfileRevision() || a.cmd != nil || a.state.Connected ||
		!cleanup && (a.closing || profileSettingsBusy(a.state.Connected, a.state.Phase)) || ctx.Err() != nil {
		return common.RouterProfile{}, errDesktopProtectionOffUnsaved
	}
	updated, err := profileProtectionOffResult(profile)
	if err != nil || profileStartupSettingsToken(updated) != capture.resultRevision {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
	}
	if !capture.profileWritten.Load() {
		for i := range a.profiles.Profiles {
			if a.profiles.Profiles[i].ID == profile.ID {
				a.profiles.Profiles[i] = updated
				if err := a.persistProfilesLocked(); err != nil {
					a.profiles.Profiles[i] = profile
					return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
				}
				capture.savedPath = a.cfg.ProfilesFile
				capture.profileWritten.Store(true)
				break
			}
		}
	}
	if !capture.profileWritten.Load() || a.cfg.ProfilesFile != capture.savedPath {
		return common.RouterProfile{}, errDesktopProtectionOffUnsaved
	}
	capture.profileSaved.Store(false)
	if err := ctx.Err(); err != nil {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
	}
	want, err := json.MarshalIndent(a.profiles, "", "  ")
	if err != nil {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
	}
	raw, err := readPrivateRegular(capture.savedPath, maxPrivateStoreBytes)
	var saved common.RouterProfileStore
	if err != nil || !bytes.Equal(raw, append(want, '\n')) || json.Unmarshal(raw, &saved) != nil || saved.SelectedID != capture.profileID {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err, errors.New("saved Off did not read back its exact private profile store"))
	}
	proved := false
	for _, value := range saved.Profiles {
		if value.ID == capture.profileID && value.KillSwitchPolicy == "off" && !value.KillSwitch && profileStartupSettingsToken(value) == capture.resultRevision {
			proved = true
		}
	}
	if !proved {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, errors.New("saved Off changed its captured result revision"))
	}
	capture.profileSaved.Store(true)
	if err := ctx.Err(); err != nil {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
	}
	return updated, nil
}
