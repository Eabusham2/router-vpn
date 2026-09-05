package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"router-vpn/internal/common"
)

const connectionProfileStoreVersion = 4
const connectionProfileStoreMaxBytes = 1 << 20
const connectionProfileStoreMaxEntries = 64

type connectionProfilePreferences struct {
	HomeLANAccess          bool     `json:"home_lan_access"`
	KillSwitchPolicy       string   `json:"kill_switch_policy"`
	IPv6Mode               string   `json:"ipv6_mode"`
	AutoRequireEncrypted   bool     `json:"auto_require_encrypted"`
	AutoRequireObfuscation bool     `json:"auto_require_obfuscation"`
	BaseTunnel             string   `json:"base_tunnel"`
	BaseFallback           bool     `json:"base_fallback"`
	MTUPolicy              string   `json:"mtu_policy"`
	ManualMTU              int      `json:"manual_mtu,omitempty"`
	DAITAEnabled           bool     `json:"daita_enabled"`
	JumboTUN               bool     `json:"jumbo_tun"`
	SocksEnabled           bool     `json:"socks_enabled"`
	DNSMode                string   `json:"dns_mode"`
	DNSProtocol            string   `json:"dns_protocol,omitempty"`
	DNSHost                string   `json:"dns_host,omitempty"`
	DNSPort                int      `json:"dns_port,omitempty"`
	DNSServerName          string   `json:"dns_server_name,omitempty"`
	DNSPath                string   `json:"dns_path,omitempty"`
	MultihopEnabled        bool     `json:"multihop_enabled"`
	MultihopEntryID        string   `json:"multihop_entry_id,omitempty"`
	MultihopExitID         string   `json:"multihop_exit_id,omitempty"`
	CustomLayers           []string `json:"custom_layers,omitempty"`
}

type connectionProfileRecord struct {
	ID        string                        `json:"id"`
	Name      string                        `json:"name"`
	NodeID    string                        `json:"node_id"`
	Mode      string                        `json:"mode"`
	Prefs     *connectionProfilePreferences `json:"preferences,omitempty"`
	CreatedAt string                        `json:"created_at"`
	UpdatedAt string                        `json:"updated_at"`
}

type connectionProfileStore struct {
	Version  int                       `json:"version"`
	Profiles []connectionProfileRecord `json:"profiles"`
}

type connectionProfileSaveRequest struct {
	ID           string   `json:"id,omitempty"`
	Name         string   `json:"name"`
	Mode         string   `json:"mode,omitempty"`
	CustomLayers []string `json:"custom_layers,omitempty"`
}

type connectionProfileRefRequest struct {
	ID string `json:"id"`
}

func registerConnectionProfileRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/connection-profiles", a.listConnectionProfiles)
	h.HandleFunc("/api/connection-profile/save", a.saveConnectionProfile)
	h.HandleFunc("/api/connection-profile/update", a.updateConnectionProfile)
	h.HandleFunc("/api/connection-profile/load", a.loadConnectionProfile)
	h.HandleFunc("/api/connection-profile/delete", a.deleteConnectionProfile)
}

func connectionProfileStorePath(a *app) string {
	return filepath.Join(filepath.Dir(filepath.Clean(a.cfg.ProfilesFile)), "connection-profiles.json")
}

func loadConnectionProfileStore(a *app) (connectionProfileStore, error) {
	path := connectionProfileStorePath(a)
	raw, err := readPrivateRegular(path, connectionProfileStoreMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return connectionProfileStore{Version: connectionProfileStoreVersion, Profiles: []connectionProfileRecord{}}, nil
	}
	if err != nil {
		return connectionProfileStore{}, err
	}
	if len(raw) > connectionProfileStoreMaxBytes {
		return connectionProfileStore{}, errors.New("connection profile store is too large")
	}
	var store connectionProfileStore
	if err := json.Unmarshal(raw, &store); err != nil {
		return connectionProfileStore{}, fmt.Errorf("invalid connection profile store: %w", err)
	}
	storedVersion := store.Version
	if storedVersion == 0 {
		storedVersion = 1
	}
	if storedVersion < 1 || storedVersion > connectionProfileStoreVersion {
		return connectionProfileStore{}, fmt.Errorf("unsupported connection profile store version %d", store.Version)
	}
	store.Version = connectionProfileStoreVersion
	if len(store.Profiles) > connectionProfileStoreMaxEntries {
		return connectionProfileStore{}, errors.New("connection profile store contains too many entries")
	}
	seen := map[string]bool{}
	for i := range store.Profiles {
		p := &store.Profiles[i]
		if !validProfileID(p.ID) || seen[p.ID] {
			return connectionProfileStore{}, errors.New("connection profile store contains an invalid or duplicate id")
		}
		seen[p.ID] = true
		if err := validateConnectionProfileName(p.Name); err != nil {
			return connectionProfileStore{}, err
		}
		if p.NodeID == "" || !validProfileID(p.NodeID) {
			return connectionProfileStore{}, errors.New("connection profile references an invalid node id")
		}
		mode, err := normalizeConnectionProfileMode(p.Mode)
		if err != nil {
			return connectionProfileStore{}, err
		}
		p.Mode = mode
		if p.Prefs != nil {
			layers, err := normalizeConnectionProfileLayers(p.Prefs.CustomLayers)
			if err != nil {
				return connectionProfileStore{}, err
			}
			p.Prefs.CustomLayers = layers
		}
	}
	if storedVersion < connectionProfileStoreVersion {
		if err := persistConnectionProfileStore(a, store); err != nil {
			return connectionProfileStore{}, fmt.Errorf("migrate connection profile store to schema v%d: %w", connectionProfileStoreVersion, err)
		}
	}
	return store, nil
}

func persistConnectionProfileStore(a *app, store connectionProfileStore) error {
	store.Version = connectionProfileStoreVersion
	if len(store.Profiles) > connectionProfileStoreMaxEntries {
		return errors.New("too many saved connection profiles")
	}
	path := connectionProfileStorePath(a)
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > connectionProfileStoreMaxBytes {
		return errors.New("connection profile store is too large")
	}
	return atomicWritePrivate(path, append(raw, '\n'))
}

func validateConnectionProfileName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return errors.New("connection profile name must be 1-64 characters")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return errors.New("connection profile name contains a control character")
		}
	}
	return nil
}

func normalizeConnectionProfileMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "smart-auto"
	}
	if len(mode) > 80 {
		return "", errors.New("connection profile mode is too long")
	}
	for _, r := range mode {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == ':' || r == '.') {
			return "", errors.New("connection profile mode contains unsupported characters")
		}
	}
	return mode, nil
}

func normalizeConnectionProfileLayers(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, errors.New("too many CUSTOM layers in connection profile")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" {
			continue
		}
		if len(value) > 64 {
			return nil, errors.New("CUSTOM layer name is too long")
		}
		for _, r := range value {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
				return nil, errors.New("CUSTOM layer contains unsupported characters")
			}
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out, nil
}

func snapshotConnectionPreferences(p common.RouterProfile, customLayers []string) (*connectionProfilePreferences, error) {
	if strings.EqualFold(strings.TrimSpace(p.NodeKind), "external") || p.External != nil {
		return nil, nil
	}
	layers, err := normalizeConnectionProfileLayers(customLayers)
	if err != nil {
		return nil, err
	}
	return &connectionProfilePreferences{
		HomeLANAccess: p.HomeLANAccess, KillSwitchPolicy: p.KillSwitchPolicy, IPv6Mode: p.IPv6Mode,
		AutoRequireEncrypted: p.AutoRequireEncrypted, AutoRequireObfuscation: p.AutoRequireObfuscation,
		BaseTunnel: p.BaseTunnel, BaseFallback: p.BaseFallback, MTUPolicy: p.MTUPolicy, ManualMTU: p.ManualMTU,
		DAITAEnabled: p.DAITAEnabled, JumboTUN: p.JumboTUN, SocksEnabled: p.SocksEnabled,
		DNSMode: p.DNSMode, DNSProtocol: p.DNSProtocol, DNSHost: p.DNSHost, DNSPort: p.DNSPort,
		DNSServerName: p.DNSServerName, DNSPath: p.DNSPath,
		MultihopEnabled: p.MultihopEnabled, MultihopEntryID: p.MultihopEntryID, MultihopExitID: p.MultihopExitID,
		CustomLayers: layers,
	}, nil
}

func (a *app) listConnectionProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	store, err := loadConnectionProfileStore(a)
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(store)
}

func decodeConnectionProfileSave(w http.ResponseWriter, r *http.Request) (connectionProfileSaveRequest, error) {
	var q connectionProfileSaveRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return q, errors.New("bad json")
	}
	q.Name = strings.TrimSpace(q.Name)
	if err := validateConnectionProfileName(q.Name); err != nil {
		return q, err
	}
	mode, err := normalizeConnectionProfileMode(q.Mode)
	if err != nil {
		return q, err
	}
	q.Mode = mode
	q.CustomLayers, err = normalizeConnectionProfileLayers(q.CustomLayers)
	return q, err
}

func (a *app) saveConnectionProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer release()
	q, err := decodeConnectionProfileSave(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(q.ID) != "" {
		http.Error(w, "new connection profiles must not provide id; use update for an existing profile", http.StatusBadRequest)
		return
	}
	a.writeConnectionProfile(w, q, false)
}

func (a *app) updateConnectionProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer release()
	q, err := decodeConnectionProfileSave(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q.ID = strings.TrimSpace(q.ID)
	if !validProfileID(q.ID) {
		http.Error(w, "update requires a valid connection profile id", http.StatusBadRequest)
		return
	}
	a.writeConnectionProfile(w, q, true)
}

func (a *app) writeConnectionProfile(w http.ResponseWriter, q connectionProfileSaveRequest, updating bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		http.Error(w, "disconnect or let the active transition finish before saving a connection profile", http.StatusConflict)
		return
	}
	node, ok := a.profileByIDLocked(a.profiles.SelectedID)
	if !ok {
		http.Error(w, "select a Router VPN or external node first", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(strings.TrimSpace(node.NodeKind), "external") || node.External != nil {
		q.Mode = "external"
		q.CustomLayers = nil
	}
	prefs, err := snapshotConnectionPreferences(node, q.CustomLayers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if updating {
		found := false
		for i := range store.Profiles {
			if store.Profiles[i].ID != q.ID {
				continue
			}
			created := store.Profiles[i].CreatedAt
			store.Profiles[i] = connectionProfileRecord{ID: q.ID, Name: q.Name, NodeID: node.ID, Mode: q.Mode, Prefs: prefs, CreatedAt: created, UpdatedAt: now}
			found = true
			break
		}
		if !found {
			http.Error(w, "unknown connection profile", http.StatusNotFound)
			return
		}
	} else {
		if len(store.Profiles) >= connectionProfileStoreMaxEntries {
			http.Error(w, "connection profile limit reached", http.StatusConflict)
			return
		}
		q.ID = newID()
		store.Profiles = append(store.Profiles, connectionProfileRecord{ID: q.ID, Name: q.Name, NodeID: node.ID, Mode: q.Mode, Prefs: prefs, CreatedAt: now, UpdatedAt: now})
	}
	if err := persistConnectionProfileStore(a, store); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, profile := range store.Profiles {
		if profile.ID == q.ID {
			w.Header().Set("content-type", "application/json")
			w.Header().Set("cache-control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "profile": profile})
			return
		}
	}
	http.Error(w, "connection profile write could not be verified", http.StatusInternalServerError)
}

func (a *app) loadConnectionProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer release()
	var q connectionProfileRefRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&q) != nil || !validProfileID(strings.TrimSpace(q.ID)) {
		http.Error(w, "load requires a valid connection profile id", http.StatusBadRequest)
		return
	}
	q.ID = strings.TrimSpace(q.ID)

	a.mu.Lock()
	defer a.mu.Unlock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		http.Error(w, "disconnect or let the active transition finish before loading a connection profile", http.StatusConflict)
		return
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var saved *connectionProfileRecord
	for i := range store.Profiles {
		if store.Profiles[i].ID == q.ID {
			copy := store.Profiles[i]
			saved = &copy
			break
		}
	}
	if saved == nil {
		http.Error(w, "unknown connection profile", http.StatusNotFound)
		return
	}
	node, ok := a.profileByIDLocked(saved.NodeID)
	if !ok {
		http.Error(w, "saved connection profile references a node that is no longer linked", http.StatusConflict)
		return
	}
	updated := node
	if saved.Prefs != nil {
		if strings.EqualFold(strings.TrimSpace(node.NodeKind), "external") || node.External != nil {
			http.Error(w, "saved Router VPN preferences cannot be applied to an external node", http.StatusConflict)
			return
		}
		p := saved.Prefs
		if p.MultihopEnabled {
			if p.MultihopEntryID == "" || p.MultihopExitID == "" || p.MultihopEntryID == p.MultihopExitID {
				http.Error(w, "saved multihop profile is invalid", http.StatusConflict)
				return
			}
			for _, id := range []string{p.MultihopEntryID, p.MultihopExitID} {
				hop, exists := a.profileByIDLocked(id)
				if !exists || strings.EqualFold(strings.TrimSpace(hop.NodeKind), "external") || hop.External != nil {
					http.Error(w, "saved multihop profile references a missing or non-Router VPN hop", http.StatusConflict)
					return
				}
			}
		}
		req := profileSettingsRequest{
			HomeLANAccess: &p.HomeLANAccess, KillSwitchPolicy: &p.KillSwitchPolicy, IPv6Mode: &p.IPv6Mode,
			AutoRequireEncrypted: &p.AutoRequireEncrypted, AutoRequireObfuscation: &p.AutoRequireObfuscation,
			BaseTunnel: &p.BaseTunnel, BaseFallback: &p.BaseFallback, MTUPolicy: &p.MTUPolicy,
			ManualMTU: &p.ManualMTU, DAITAEnabled: &p.DAITAEnabled, JumboTUN: &p.JumboTUN, SocksEnabled: &p.SocksEnabled,
		}
		updated, err = applyProfileSettings(node, req)
		if err != nil {
			http.Error(w, "saved connection preferences are no longer valid: "+err.Error(), http.StatusConflict)
			return
		}
		if strings.TrimSpace(p.DNSMode) != "" {
			updated.DNSMode = p.DNSMode
			updated.DNSProtocol = p.DNSProtocol
			updated.DNSHost = p.DNSHost
			updated.DNSPort = p.DNSPort
			updated.DNSServerName = p.DNSServerName
			updated.DNSPath = p.DNSPath
		}
		updated.MultihopEnabled = p.MultihopEnabled
		updated.MultihopEntryID = p.MultihopEntryID
		updated.MultihopExitID = p.MultihopExitID
		if err := common.NormalizeRouterProfile(&updated); err != nil {
			http.Error(w, "saved connection preferences are no longer valid: "+err.Error(), http.StatusConflict)
			return
		}
	}

	old := cloneRouterProfileStore(a.profiles)
	oldState := a.state
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == updated.ID {
			a.profiles.Profiles[i] = updated
			break
		}
	}
	a.profiles.SelectedID = updated.ID
	a.state.RouterID = updated.ID
	if saved.Prefs != nil {
		a.syncProfileOptionStateLocked(updated)
	}
	if err := a.persistProfilesLocked(); err != nil {
		a.rollbackProfilesLocked(old)
		a.state = oldState
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "profile": saved, "selected_node_id": updated.ID, "mode": saved.Mode,
		"custom_layers": func() []string {
			if saved.Prefs == nil {
				return nil
			}
			return append([]string(nil), saved.Prefs.CustomLayers...)
		}(),
		"note": "connection choices loaded while disconnected; connect separately so the selected platform can establish and prove the requested dataplane",
	})
}

func (a *app) deleteConnectionProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	release, guardErr := a.beginMutationOperation(r)
	if guardErr != nil {
		http.Error(w, guardErr.Error(), http.StatusConflict)
		return
	}
	defer release()
	var q connectionProfileRefRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&q) != nil || !validProfileID(strings.TrimSpace(q.ID)) {
		http.Error(w, "delete requires a valid connection profile id", http.StatusBadRequest)
		return
	}
	q.ID = strings.TrimSpace(q.ID)
	a.mu.Lock()
	defer a.mu.Unlock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		http.Error(w, "disconnect or let the active transition finish before deleting a connection profile", http.StatusConflict)
		return
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]connectionProfileRecord, 0, len(store.Profiles))
	found := false
	for _, profile := range store.Profiles {
		if profile.ID == q.ID {
			found = true
			continue
		}
		out = append(out, profile)
	}
	if !found {
		http.Error(w, "unknown connection profile", http.StatusNotFound)
		return
	}
	store.Profiles = out
	if err := persistConnectionProfileStore(a, store); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}
