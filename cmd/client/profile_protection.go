package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"router-vpn/internal/common"
)

type profileProtectionSettings struct {
	ProfileID        string `json:"profile_id"`
	ProfileToken     string `json:"profile_token"`
	KillSwitchPolicy string `json:"kill_switch_policy"`
}

func writeProfileProtectionSettings(w http.ResponseWriter, p common.RouterProfile) {
	policy := strings.ToLower(strings.TrimSpace(p.KillSwitchPolicy))
	if policy == "" {
		policy = "off"
		if p.KillSwitch {
			policy = "on-connect"
		}
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(profileProtectionSettings{p.ID, profileStartupSettingsToken(p), policy})
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
		release, err := a.beginMutationOperation(r)
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
	if r.Method == http.MethodGet {
		writeProfileProtectionSettings(w, profile)
		return
	}
	var q profileProtectionSettings
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&q); err != nil {
		http.Error(w, "invalid protection settings", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "one protection settings object is required", http.StatusBadRequest)
		return
	}
	if q.ProfileID == "" || q.ProfileToken == "" || q.ProfileID != profile.ID || q.ProfileToken != profileStartupSettingsToken(profile) {
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
	a.mu.Lock()
	current, exists := a.profileByIDLocked(profile.ID)
	if !exists || a.profiles.SelectedID != profile.ID || profileStartupSettingsToken(current) != q.ProfileToken ||
		a.closing || profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "node or connection changed; refresh when disconnected", http.StatusConflict)
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
	writeProfileProtectionSettings(w, updated)
}
