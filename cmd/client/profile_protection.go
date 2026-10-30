package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"router-vpn/internal/common"
)

type profileProtectionSettings struct {
	ProfileID           string `json:"profile_id"`
	ProfileToken        string `json:"profile_token"`
	KillSwitchPolicy    string `json:"kill_switch_policy"`
	ProtectionStatus    string `json:"protection_status,omitempty"`
	EffectivePolicy     string `json:"effective_policy,omitempty"`
	ProtectionProfileID string `json:"protection_profile_id,omitempty"`
	Message             string `json:"message,omitempty"`
}

func writeProfileProtectionSettings(w http.ResponseWriter, p common.RouterProfile) {
	writeProfileProtectionValue(w, http.StatusOK, profileProtectionSettings{
		ProfileID: p.ID, ProfileToken: profileStartupSettingsToken(p), KillSwitchPolicy: desktopOwnedNodeProtectionPolicy(p)})
}

func writeProfileProtectionValue(w http.ResponseWriter, status int, value profileProtectionSettings) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// Protection is common to Router and imported nodes. Its narrow transaction
// cannot rewrite an imported protocol or send disabled Router settings back as
// defaults. The revision is the private source snapshot, never the credentials.
func (a *app) profileProtectionSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		release, err := a.beginProtectionAwareMutationOperation(r, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		defer release()
	}
	a.mu.Lock()
	profile, ok := a.profileByIDLocked(a.profiles.SelectedID)
	profile = cloneRouterProfile(profile)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "add and select a node first", http.StatusBadRequest)
		return
	}
	capture := a.captureProfileProtection(profile)
	if r.Method == http.MethodGet {
		writeProfileProtectionValue(w, http.StatusOK, protectionSettingsWithCapture(profile, capture))
		return
	}
	// Response-only pending/effective fields are not accepted as authority.
	var q struct {
		ProfileID        string `json:"profile_id"`
		ProfileToken     string `json:"profile_token"`
		KillSwitchPolicy string `json:"kill_switch_policy"`
	}
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	var fields map[string]json.RawMessage
	if readErr != nil || decodeRelayControlJSON(raw, &q) != nil || json.Unmarshal(raw, &fields) != nil ||
		len(fields) != 3 || fields["profile_id"] == nil || fields["profile_token"] == nil || fields["kill_switch_policy"] == nil {
		http.Error(w, "invalid protection settings", http.StatusBadRequest)
		return
	}
	if q.ProfileID == "" || q.ProfileToken == "" || q.ProfileID != profile.ID || q.ProfileToken != capture.token {
		http.Error(w, "selected node or its policy changed; refresh before changing protection", http.StatusConflict)
		return
	}
	q.KillSwitchPolicy = strings.ToLower(strings.TrimSpace(q.KillSwitchPolicy))
	switch q.KillSwitchPolicy {
	case "off", "on-connect", "always":
	default:
		http.Error(w, "kill_switch_policy must be off, on-connect, or always", http.StatusBadRequest)
		return
	}
	if capture.slot != nil {
		view := capture.slot.view()
		if view.token(capture.revision) != capture.token || view.PendingOff && q.KillSwitchPolicy != "off" {
			http.Error(w, "protection ownership changed or Off is pending; refresh and finish the same change", http.StatusConflict)
			return
		}
	}
	a.mu.Lock()
	current, exists := a.profileByIDLocked(profile.ID)
	if !exists || a.profiles.SelectedID != profile.ID || profileStartupSettingsToken(current) != capture.revision || a.nodeProtection != capture.slot ||
		a.closing || a.cmd != nil || r.Context().Err() != nil || profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "node or connection changed; refresh when disconnected", http.StatusConflict)
		return
	}
	if q.KillSwitchPolicy == "off" && capture.slot != nil {
		a.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		pending, err := capture.slot.captureOff(ctx, profile.ID, capture.revision, capture.token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		cancelPendingStartupPolicy(a)
		updated, err := a.resumeDesktopProtectionOff(ctx, capture.slot, pending, false)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, errDesktopProtectionOffUnsaved) {
				status = http.StatusInternalServerError
			}
			value := protectionSettingsWithCapture(profile, a.captureProfileProtection(profile))
			if value.Message == "" {
				value.Message = "The protection change did not finish. Refresh and retry Off."
			}
			writeProfileProtectionValue(w, status, value)
			return
		}
		writeProfileProtectionValue(w, http.StatusOK, protectionSettingsWithCapture(updated, a.captureProfileProtection(updated)))
		return
	}
	updated := cloneRouterProfile(current)
	updated.KillSwitchPolicy, updated.KillSwitch = q.KillSwitchPolicy, q.KillSwitchPolicy != "off"
	var persistErr error
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != profile.ID {
			continue
		}
		a.profiles.Profiles[i] = updated
		persistErr = a.persistProfilesLocked()
		if persistErr != nil {
			a.profiles.Profiles[i] = current
		}
		break
	}
	a.mu.Unlock()
	if persistErr != nil {
		http.Error(w, "could not save protection settings", http.StatusInternalServerError)
		return
	}
	cancelPendingStartupPolicy(a)
	writeProfileProtectionValue(w, http.StatusOK, protectionSettingsWithCapture(updated, a.captureProfileProtection(updated)))
}
