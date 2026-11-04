//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"router-vpn/internal/common"
)

func (a *app) capturePlatformProfileProtection() *desktopPlatformProtectionCapture {
	a.mu.Lock()
	profilePath := a.cfg.ProfilesFile
	a.mu.Unlock()
	parent := a.captureDesktopParentProfileProtection()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	service := a.captureLinuxStandardServiceProtectionForParent(ctx, parent)
	capture := combineLinuxProtectionCaptures(parent, service)
	if capture != nil && capture.standard != nil {
		capture.standardProfilePath = profilePath
	}
	return capture
}

func combineLinuxProtectionCaptures(parent *desktopPlatformProtectionCapture, service *linuxStandardServiceProtectionCapture) *desktopPlatformProtectionCapture {
	if service == nil {
		return parent
	}
	if parent != nil {
		if service.ScopedAbsent && service.Failure == nil {
			return parent
		}
		// A neutral service observation must prove full absence, or the scoped
		// path above must prove no standard/shared protection beside the exact
		// current native parent. Unknown generic tables remain unresolved.
		if service.Available && !service.Owned && !service.Active && !service.Pending && service.Failure == nil && service.AbsenceProved {
			return parent
		}
		parent.standard = service
		parent.failure = errors.New("Linux protection has competing or unresolved desktop and standard-service owners; finish original cleanup before changing protection")
		return parent
	}
	if service.Absent && service.Failure == nil {
		return nil
	}
	if service.Available && !service.Owned && !service.Active && !service.Pending && service.AbsenceProved && service.Failure == nil {
		return nil
	}
	capture := &desktopPlatformProtectionCapture{standard: service}
	if !service.Available {
		capture.failure = errors.New("Linux standard protection has no authenticated original service observation")
	} else if service.Failure != nil {
		capture.failure = service.Failure
	} else if !service.Owned && !service.Active && !service.Pending {
		capture.failure = errors.New("Linux standard protection absence was not proved")
	}
	return capture
}

func (c *desktopPlatformProtectionCapture) standardToken(revision string) string {
	s := c.standard
	if s.Token != "" && (revision == s.ProfileRevision || s.Pending && revision == s.ResultRevision) {
		digest := sha256.Sum256([]byte("routervpn-standard-service-protection-v1\n" + s.Token + "\n" + s.ProfileRevision + "\n" + s.ProfileID + "\n" + c.standardProfilePath))
		return hex.EncodeToString(digest[:])
	}
	// The displayed node may differ from the retained original owner. Such a
	// view remains comparable but cannot authorize removal for that node.
	raw := "routervpn-standard-service-protection-v1\n" + s.Token + "\n" + revision + "\n" + s.ProfileID + "\n" + c.standardProfilePath
	if c.failure != nil {
		raw += "\nunresolved"
	}
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func (c *desktopPlatformProtectionCapture) standardSettings(value profileProtectionSettings) profileProtectionSettings {
	s := c.standard
	value.ProtectionProfileID = s.ProfileID
	switch {
	case c.failure != nil || s.Failure != nil || !s.Available:
		value.ProtectionStatus, value.EffectivePolicy = "pending", "unknown"
		value.Message = "The original standard protection owner is unresolved. Finish its cleanup before changing protection."
	case s.Pending:
		value.ProtectionStatus, value.EffectivePolicy = "off-pending", "unknown"
		value.Message = "Turning the kill switch off is pending. Retry Off to finish the same original change."
		if s.Removed && s.AbsenceProved {
			value.ProtectionStatus, value.EffectivePolicy = "off-unsaved", "off"
			value.Message = errDesktopProtectionOffUnsaved.Error()
			if s.ProfileSaved {
				value.ProtectionStatus = "off-pending"
				value.Message = "The kill switch is off and its preference is saved. Retry Off to finish original owner cleanup."
			}
		}
	case s.Owned || s.Active:
		value.ProtectionStatus, value.EffectivePolicy = "retained", s.Policy
		if s.Active {
			value.ProtectionStatus = "active"
		}
		if s.ProfileID != value.ProfileID {
			value.Message = "Protection still belongs to another node. Select that node to turn its kill switch off."
		}
	default:
		value.ProtectionStatus, value.EffectivePolicy = "pending", "unknown"
		value.Message = "Original native protection absence is still unproved."
	}
	return value
}

func (a *app) handleStandardServiceProfileProtection(w http.ResponseWriter, r *http.Request, profile common.RouterProfile, capture profileProtectionCapture, current *desktopPlatformProtectionCapture, policy string) bool {
	s := current.standard
	if current.failure != nil || s == nil || !s.Available || s.Failure != nil || s.Active || s.ProfileID != profile.ID || s.Pending && policy != "off" {
		http.Error(w, "select the original disconnected standard-service node and finish its pending protection change", http.StatusConflict)
		return true
	}
	if policy != "off" {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := a.standardServiceOffCurrent(ctx, profile.ID, capture, s); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return true
	}
	cancelPendingStartupPolicy(a)
	err := s.Release(ctx)
	var updated common.RouterProfile
	if err == nil {
		updated, err = a.persistStandardServiceProtectionOff(ctx, profile.ID, capture, s)
	}
	if err == nil {
		err = s.Complete(ctx)
	}
	if err != nil {
		a.mu.Lock()
		if latest, exists := a.profileByIDLocked(profile.ID); exists {
			profile = cloneRouterProfile(latest)
		}
		a.mu.Unlock()
		value := protectionSettingsWithCapture(profile, a.captureProfileProtection(profile))
		if value.Message == "" {
			value.Message = "The original protection change did not finish. Refresh and retry Off."
		}
		status := http.StatusServiceUnavailable
		if errors.Is(err, errDesktopProtectionOffUnsaved) {
			status = http.StatusInternalServerError
		}
		writeProfileProtectionValue(w, status, value)
		return true
	}
	writeProfileProtectionValue(w, http.StatusOK, protectionSettingsWithCapture(updated, a.captureProfileProtection(updated)))
	return true
}

func (a *app) standardServiceOffCurrent(ctx context.Context, profileID string, capture profileProtectionCapture, service *linuxStandardServiceProtectionCapture) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.standardServiceOffCurrentLocked(ctx, profileID, capture, service)
}

func (a *app) standardServiceOffCurrentLocked(ctx context.Context, profileID string, capture profileProtectionCapture, service *linuxStandardServiceProtectionCapture) error {
	profile, exists := a.profileByIDLocked(profileID)
	if ctx == nil || ctx.Err() != nil || !exists || a.profiles.SelectedID != profileID || a.closing || a.cmd != nil || a.nodeProtection != nil ||
		profileSettingsBusy(a.state.Connected, a.state.Phase) || capture.slot != nil || capture.platform == nil || capture.platform.standard == nil ||
		a.cfg.ProfilesFile != capture.platform.standardProfilePath ||
		!capture.platform.standard.same(service) || !service.currentAppLocked(a) || service.ProfileID != profileID ||
		profileStartupSettingsToken(profile) != capture.revision || capture.revision != service.ProfileRevision && capture.revision != service.ResultRevision {
		return errors.New("original standard-service Off no longer owns its selected profile, controller or disconnected operation")
	}
	return nil
}

// The native service retains the release milestone until Complete verifies the
// actual saved result. A write/readback/cancellation failure never substitutes
// a preference-only Off for release, nor drops the original retry authority.
func (a *app) persistStandardServiceProtectionOff(ctx context.Context, profileID string, capture profileProtectionCapture, service *linuxStandardServiceProtectionCapture) (common.RouterProfile, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.standardServiceOffCurrentLocked(ctx, profileID, capture, service); err != nil {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
	}
	profile, _ := a.profileByIDLocked(profileID)
	updated, err := profileProtectionOffResult(profile)
	if err != nil || profileStartupSettingsToken(updated) != service.ResultRevision || capture.resultRevision != service.ResultRevision {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err, errors.New("standard-service Off changed its captured result revision"))
	}
	found := false
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != profileID {
			continue
		}
		a.profiles.Profiles[i] = updated
		found = true
		if err = a.persistProfilesLocked(); err != nil {
			a.profiles.Profiles[i] = profile
			return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
		}
		break
	}
	if !found {
		return common.RouterProfile{}, errDesktopProtectionOffUnsaved
	}
	want, err := json.MarshalIndent(a.profiles, "", "  ")
	if err != nil {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err)
	}
	body, err := readPrivateRegular(a.cfg.ProfilesFile, maxPrivateStoreBytes)
	if err != nil || !bytes.Equal(body, append(want, '\n')) || ctx.Err() != nil {
		return common.RouterProfile{}, errors.Join(errDesktopProtectionOffUnsaved, err, ctx.Err(), errors.New("saved standard-service Off did not read back its exact private profile store"))
	}
	return updated, nil
}
