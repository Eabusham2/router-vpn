package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"router-vpn/internal/common"
)

// Startup has its own small transaction so an imported node never has to be
// rewritten through the Router-only settings form. The revision binds the
// editor to the selected node's credentials and policy without returning them.
type profileStartupSettings struct {
	ProfileID    string `json:"profile_id"`
	ProfileToken string `json:"profile_token"`
	NodeKind     string `json:"node_kind"`
	StartupMode  string `json:"startup_mode"`
	AutoConnect  bool   `json:"auto_connect"`
}

type profileStartupRequest struct {
	ProfileID    string `json:"profile_id"`
	ProfileToken string `json:"profile_token"`
	StartupMode  string `json:"startup_mode"`
	AutoConnect  *bool  `json:"auto_connect"`
}

func profileStartupSettingsToken(p common.RouterProfile) string {
	sum := sha256.Sum256([]byte(liveMeasurementProfileToken(p) + ":" + strconv.FormatBool(p.AutoConnect)))
	return hex.EncodeToString(sum[:])
}

func writeProfileStartupSettings(w http.ResponseWriter, p common.RouterProfile) {
	kind := "router-vpn"
	if p.External != nil || strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") {
		kind = "external"
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(profileStartupSettings{
		ProfileID: p.ID, ProfileToken: profileStartupSettingsToken(p), NodeKind: kind,
		StartupMode: p.StartupMode, AutoConnect: p.AutoConnect,
	})
}

func (a *app) profileStartupSettings(w http.ResponseWriter, r *http.Request) {
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
	p, ok := a.profileByIDLocked(a.profiles.SelectedID)
	p = cloneRouterProfile(p)
	a.mu.Unlock()
	if !ok {
		http.Error(w, "add and select a node first", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		writeProfileStartupSettings(w, p)
		return
	}
	var q profileStartupRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&q); err != nil {
		http.Error(w, "invalid startup settings", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "one startup settings object is required", http.StatusBadRequest)
		return
	}
	if q.ProfileID == "" || q.ProfileToken == "" || q.ProfileID != p.ID || q.ProfileToken != profileStartupSettingsToken(p) {
		http.Error(w, "selected node or its settings changed; reopen Settings", http.StatusConflict)
		return
	}
	q.StartupMode = strings.ToLower(strings.TrimSpace(q.StartupMode))
	switch q.StartupMode {
	case "manual", "auto", "smart-auto", "last":
	default:
		http.Error(w, "startup_mode must be manual, auto, smart-auto, or last", http.StatusBadRequest)
		return
	}
	if q.AutoConnect == nil || (*q.AutoConnect && q.StartupMode == "manual") {
		http.Error(w, "auto_connect is required and Manual must remain disconnected", http.StatusBadRequest)
		return
	}
	updated := cloneRouterProfile(p)
	updated.StartupMode, updated.AutoConnect = q.StartupMode, *q.AutoConnect

	a.mu.Lock()
	current, exists := a.profileByIDLocked(p.ID)
	if !exists || a.profiles.SelectedID != p.ID || profileStartupSettingsToken(current) != q.ProfileToken ||
		a.closing || profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "node or connection changed; reopen Settings when disconnected", http.StatusConflict)
		return
	}
	var persistErr error
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID != p.ID {
			continue
		}
		// Copy only these two values onto the current object. Measurement/display
		// updates outside the revision must not be replaced by the editor snapshot.
		updated = cloneRouterProfile(current)
		updated.StartupMode, updated.AutoConnect = q.StartupMode, *q.AutoConnect
		a.profiles.Profiles[i] = updated
		persistErr = a.persistProfilesLocked()
		if persistErr != nil {
			a.profiles.Profiles[i] = current
		}
		break
	}
	a.mu.Unlock()
	if persistErr != nil {
		http.Error(w, "could not save startup settings", http.StatusInternalServerError)
		return
	}
	// Editing startup never launches a connection in this already-open app and
	// explicitly retires any delayed intent captured before the edit.
	cancelPendingStartupPolicy(a)
	writeProfileStartupSettings(w, updated)
}
