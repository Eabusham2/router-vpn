package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"router-vpn/internal/common"
)

type externalProfileImportEnvelope struct {
	RouterProfiles   []common.RouterProfile `json:"routerProfiles"`
	SelectedRouterID string                 `json:"selectedRouterID"`
}

// externalProfileImport keeps external credentials in the private profile
// store while returning only the secret-free public node view. It accepts a
// single canonical schema-v4 external RouterProfile or a bundle envelope containing one
// selected external profile; Router VPN bundles remain on /api/profile/import
// because they require staged raw WG/sing-box identity assets.
func (a *app) externalProfileImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var raw json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&raw); err != nil {
		http.Error(w, "invalid external profile JSON", http.StatusBadRequest)
		return
	}
	p, err := decodeExternalImport(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err = common.NormalizeRouterProfile(&p); err != nil {
		http.Error(w, "invalid external profile: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.NodeKind != "external" || p.External == nil {
		http.Error(w, "profile is not an external custom node", http.StatusBadRequest)
		return
	}
	// Persist the same normalized DNS/kill-switch/runtime policy that Connect
	// will use. Otherwise an imported node could appear saved with blank/home
	// policy while the live runtime silently substitutes Rescue DNS later.
	policy, policyErr := externalRuntimePolicy(p)
	if policyErr != nil {
		http.Error(w, "external profile policy is not runnable: "+policyErr.Error(), http.StatusBadRequest)
		return
	}
	p = policy
	// Re-run the exact dataplane adapter validation before persisting secrets so
	// an imported profile cannot be stored as 'ready' if the native runtime would
	// reject it at connect time.
	if _, err = standardExitFromExternalProfile(p); err != nil {
		http.Error(w, "external profile is not runnable: "+err.Error(), http.StatusBadRequest)
		return
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer release()

	a.mu.Lock()
	defer a.mu.Unlock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		http.Error(w, "disconnect before importing an external node", http.StatusConflict)
		return
	}
	// Keep a caller-provided safe id when it is unique so node data can retain a
	// stable identity. Otherwise allocate a fresh local id rather than replacing
	// another node silently.
	if !validProfileID(p.ID) || profileIDExists(a.profiles.Profiles, p.ID) {
		p.ID = newID()
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "External " + strings.ToUpper(p.External.Protocol)
	}
	if strings.TrimSpace(p.Endpoint) == "" {
		if exit, exitErr := standardExitFromExternalProfile(p); exitErr == nil {
			p.Endpoint = exit.Server
		}
	}
	oldSelected := a.profiles.SelectedID
	oldRouterID := a.state.RouterID
	a.profiles.Profiles = append(a.profiles.Profiles, p)
	a.profiles.SelectedID = p.ID
	a.state.RouterID = p.ID
	if err = a.persistProfilesLocked(); err != nil {
		a.profiles.Profiles = a.profiles.Profiles[:len(a.profiles.Profiles)-1]
		a.profiles.SelectedID = oldSelected
		a.state.RouterID = oldRouterID
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "profile": publicProfileFor(p)})
}

func decodeExternalImport(raw []byte) (common.RouterProfile, error) {
	// Decide the wire shape before unmarshalling into RouterProfile. Its custom
	// UnmarshalJSON intentionally normalizes an omitted node_kind to router-vpn,
	// so using the normalized struct to distinguish a bundle envelope from a
	// direct profile misclassifies envelopes as blank Router VPN profiles.
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		return common.RouterProfile{}, errors.New("external import JSON must be an object")
	}
	if _, isEnvelope := shape["routerProfiles"]; !isEnvelope {
		var direct common.RouterProfile
		if err := json.Unmarshal(raw, &direct); err != nil {
			return common.RouterProfile{}, err
		}
		if direct.NodeKind != "external" || direct.External == nil {
			return common.RouterProfile{}, errors.New("direct import is not a canonical schema-v4 external node profile")
		}
		return direct, nil
	}

	var envelope externalProfileImportEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return common.RouterProfile{}, err
	}
	if len(envelope.RouterProfiles) == 0 {
		return common.RouterProfile{}, errors.New("external bundle contains no profiles")
	}
	var candidates []common.RouterProfile
	for _, candidate := range envelope.RouterProfiles {
		kind := strings.ToLower(strings.TrimSpace(candidate.NodeKind))
		if kind == "external" && candidate.External != nil {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return common.RouterProfile{}, errors.New("bundle contains no external custom node")
	}
	if envelope.SelectedRouterID != "" {
		for _, candidate := range candidates {
			if candidate.ID == envelope.SelectedRouterID {
				return candidate, nil
			}
		}
		return common.RouterProfile{}, errors.New("selected external profile is not present in the bundle")
	}
	if len(candidates) != 1 {
		return common.RouterProfile{}, errors.New("bundle contains multiple external nodes; import one selected external profile at a time")
	}
	return candidates[0], nil
}

func profileIDExists(profiles []common.RouterProfile, id string) bool {
	for _, p := range profiles {
		if p.ID == id {
			return true
		}
	}
	return false
}
