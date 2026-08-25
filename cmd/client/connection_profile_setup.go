package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
)

const connectionProfileSetupMetaVersion = 1

type connectionProfileSetupRequest struct {
	ID               string   `json:"id,omitempty"`
	Name             string   `json:"name"`
	Mode             string   `json:"mode,omitempty"`
	CustomLayers     []string `json:"custom_layers,omitempty"`
	MultihopEnabled  bool     `json:"multihop_enabled"`
	MultihopEntryID  string   `json:"multihop_entry_id,omitempty"`
	MultihopExitID   string   `json:"multihop_exit_id,omitempty"`
	MultihopExitMode string   `json:"multihop_exit_mode,omitempty"`
}

type connectionProfileSetupMeta struct {
	MultihopExitMode string `json:"multihop_exit_mode,omitempty"`
}

type connectionProfileSetupMetaStore struct {
	Version int                                   `json:"version"`
	Entries map[string]connectionProfileSetupMeta `json:"entries"`
}

func cloneConnectionProfileSetupMetaStore(store connectionProfileSetupMetaStore) connectionProfileSetupMetaStore {
	cloned := connectionProfileSetupMetaStore{Version: store.Version, Entries: make(map[string]connectionProfileSetupMeta, len(store.Entries))}
	for id, meta := range store.Entries {
		cloned.Entries[id] = meta
	}
	return cloned
}

type capturedResponse struct {
	*httptest.ResponseRecorder
}

func registerConnectionProfileSetupRoutes(h *http.ServeMux, a *app) {
	h.HandleFunc("/api/connection-profile/setup/save", a.saveConnectionProfileSetup)
	h.HandleFunc("/api/connection-profile/setup/update", a.updateConnectionProfileSetup)
	h.HandleFunc("/api/connection-profile/setup/load", a.loadConnectionProfileSetup)
	h.HandleFunc("/api/connection-profile/setup/delete", a.deleteConnectionProfileSetup)
}

func connectionProfileSetupMetaPath(a *app) string {
	return filepath.Join(filepath.Dir(filepath.Clean(a.cfg.ProfilesFile)), "connection-profile-setup-meta.json")
}

func loadConnectionProfileSetupMeta(a *app) (connectionProfileSetupMetaStore, error) {
	path := connectionProfileSetupMetaPath(a)
	raw, err := readPrivateRegular(path, 128<<10)
	if errors.Is(err, os.ErrNotExist) {
		return connectionProfileSetupMetaStore{Version: connectionProfileSetupMetaVersion, Entries: map[string]connectionProfileSetupMeta{}}, nil
	}
	if err != nil {
		return connectionProfileSetupMetaStore{}, err
	}
	if len(raw) > 128<<10 {
		return connectionProfileSetupMetaStore{}, errors.New("connection profile setup metadata is too large")
	}
	var store connectionProfileSetupMetaStore
	if err := json.Unmarshal(raw, &store); err != nil {
		return connectionProfileSetupMetaStore{}, errors.New("invalid connection profile setup metadata")
	}
	if store.Version == 0 {
		store.Version = connectionProfileSetupMetaVersion
	}
	if store.Version != connectionProfileSetupMetaVersion {
		return connectionProfileSetupMetaStore{}, errors.New("unsupported connection profile setup metadata version")
	}
	if store.Entries == nil {
		store.Entries = map[string]connectionProfileSetupMeta{}
	}
	for id, meta := range store.Entries {
		if !validProfileID(id) {
			return connectionProfileSetupMetaStore{}, errors.New("connection profile setup metadata contains an invalid id")
		}
		if _, err := normalizeConnectionProfileExitMode(meta.MultihopExitMode); err != nil {
			return connectionProfileSetupMetaStore{}, err
		}
	}
	return store, nil
}

func persistConnectionProfileSetupMeta(a *app, store connectionProfileSetupMetaStore) error {
	store.Version = connectionProfileSetupMetaVersion
	if store.Entries == nil {
		store.Entries = map[string]connectionProfileSetupMeta{}
	}
	path := connectionProfileSetupMetaPath(a)
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > 128<<10 {
		return errors.New("connection profile setup metadata is too large")
	}
	return atomicWritePrivate(path, append(raw, '\n'))
}

func normalizeConnectionProfileExitMode(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	switch value {
	case "shadowsocks", "hysteria2":
		return value, nil
	default:
		return "", errors.New("multihop_exit_mode must be shadowsocks or hysteria2")
	}
}

func decodeConnectionProfileSetup(w http.ResponseWriter, r *http.Request, updating bool) (connectionProfileSetupRequest, error) {
	var q connectionProfileSetupRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return q, errors.New("bad json")
	}
	q.ID = strings.TrimSpace(q.ID)
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
	if err != nil {
		return q, err
	}
	q.MultihopEntryID = strings.TrimSpace(q.MultihopEntryID)
	q.MultihopExitID = strings.TrimSpace(q.MultihopExitID)
	q.MultihopExitMode, err = normalizeConnectionProfileExitMode(q.MultihopExitMode)
	if err != nil {
		return q, err
	}
	if updating && !validProfileID(q.ID) {
		return q, errors.New("update requires a valid connection profile id")
	}
	if !updating && q.ID != "" {
		return q, errors.New("new connection profiles must not provide id")
	}
	if q.MultihopEnabled {
		if !validProfileID(q.MultihopEntryID) || !validProfileID(q.MultihopExitID) || q.MultihopEntryID == q.MultihopExitID {
			return q, errors.New("multihop setup requires different valid entry and exit node ids")
		}
		if q.MultihopExitMode == "" {
			q.MultihopExitMode = "shadowsocks"
		}
	} else {
		q.MultihopEntryID = ""
		q.MultihopExitID = ""
		q.MultihopExitMode = ""
	}
	return q, nil
}

func validateConnectionProfileSetupGraphLocked(a *app, q connectionProfileSetupRequest) error {
	if !q.MultihopEnabled {
		return nil
	}
	for _, id := range []string{q.MultihopEntryID, q.MultihopExitID} {
		hop, ok := a.profileByIDLocked(id)
		if !ok || strings.EqualFold(strings.TrimSpace(hop.NodeKind), "external") || hop.External != nil {
			return errors.New("multihop setup references a missing or non-Router VPN hop")
		}
	}
	return nil
}

func writeCaptured(w http.ResponseWriter, recorder *httptest.ResponseRecorder) {
	for key, values := range recorder.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(recorder.Code)
	_, _ = w.Write(recorder.Body.Bytes())
}

func (a *app) saveConnectionProfileSetup(w http.ResponseWriter, r *http.Request) {
	a.writeConnectionProfileSetup(w, r, false)
}

func (a *app) updateConnectionProfileSetup(w http.ResponseWriter, r *http.Request) {
	a.writeConnectionProfileSetup(w, r, true)
}

func (a *app) writeConnectionProfileSetup(w http.ResponseWriter, r *http.Request, updating bool) {
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
	q, err := decodeConnectionProfileSetup(w, r, updating)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	if profileSettingsBusy(a.state.Connected, a.state.Phase) {
		a.mu.Unlock()
		http.Error(w, "disconnect or let the active transition finish before saving a connection profile", http.StatusConflict)
		return
	}
	if err := validateConnectionProfileSetupGraphLocked(a, q); err != nil {
		a.mu.Unlock()
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	oldProfiles, err := loadConnectionProfileStore(a)
	if err != nil {
		a.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	oldMeta, err := loadConnectionProfileSetupMeta(a)
	oldMeta = cloneConnectionProfileSetupMetaStore(oldMeta)
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	innerBody := map[string]any{"name": q.Name, "mode": q.Mode, "custom_layers": q.CustomLayers}
	if updating {
		innerBody["id"] = q.ID
	}
	raw, _ := json.Marshal(innerBody)
	innerReq, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1/", bytes.NewReader(raw))
	innerReq.Header.Set("content-type", "application/json")
	innerReq = withInternalMutationContext(innerReq)
	recorder := httptest.NewRecorder()
	if updating {
		a.updateConnectionProfile(recorder, innerReq)
	} else {
		a.saveConnectionProfile(recorder, innerReq)
	}
	if recorder.Code < 200 || recorder.Code >= 300 {
		writeCaptured(w, recorder)
		return
	}
	var base map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &base); err != nil {
		http.Error(w, "connection profile write returned invalid json", http.StatusInternalServerError)
		return
	}
	profileMap, _ := base["profile"].(map[string]any)
	id, _ := profileMap["id"].(string)
	if !validProfileID(id) {
		http.Error(w, "connection profile write did not return a valid id", http.StatusInternalServerError)
		return
	}

	a.mu.Lock()
	store, err := loadConnectionProfileStore(a)
	if err == nil {
		found := false
		for i := range store.Profiles {
			if store.Profiles[i].ID != id {
				continue
			}
			if store.Profiles[i].Prefs != nil {
				store.Profiles[i].Prefs.MultihopEnabled = q.MultihopEnabled
				store.Profiles[i].Prefs.MultihopEntryID = q.MultihopEntryID
				store.Profiles[i].Prefs.MultihopExitID = q.MultihopExitID
			}
			found = true
			break
		}
		if !found {
			err = errors.New("connection profile disappeared before setup snapshot was finalized")
		}
	}
	if err == nil {
		err = persistConnectionProfileStore(a, store)
	}
	meta := cloneConnectionProfileSetupMetaStore(oldMeta)
	if meta.Entries == nil {
		meta.Entries = map[string]connectionProfileSetupMeta{}
	}
	if err == nil {
		meta.Entries[id] = connectionProfileSetupMeta{MultihopExitMode: q.MultihopExitMode}
		err = persistConnectionProfileSetupMeta(a, meta)
	}
	var rollbackErr error
	if err != nil {
		if restoreErr := persistConnectionProfileStore(a, oldProfiles); restoreErr != nil {
			rollbackErr = fmt.Errorf("restore profile store: %w", restoreErr)
		}
		if restoreMetaErr := persistConnectionProfileSetupMeta(a, oldMeta); restoreMetaErr != nil {
			if rollbackErr == nil {
				rollbackErr = fmt.Errorf("restore setup metadata: %w", restoreMetaErr)
			} else {
				rollbackErr = fmt.Errorf("%v; restore setup metadata: %w", rollbackErr, restoreMetaErr)
			}
		}
	}
	a.mu.Unlock()
	if err != nil {
		if rollbackErr != nil {
			http.Error(w, "connection setup snapshot failed and rollback was incomplete: "+err.Error()+"; "+rollbackErr.Error(), http.StatusInternalServerError)
			return
		}
		http.Error(w, "connection setup snapshot failed and was rolled back: "+err.Error(), http.StatusInternalServerError)
		return
	}

	base["multihop_enabled"] = q.MultihopEnabled
	base["multihop_entry_id"] = q.MultihopEntryID
	base["multihop_exit_id"] = q.MultihopExitID
	base["multihop_exit_mode"] = q.MultihopExitMode
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(base)
}

func (a *app) loadConnectionProfileSetup(w http.ResponseWriter, r *http.Request) {
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
	raw, err := readBoundedBody(r, 8<<10)
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var ref connectionProfileRefRequest
	if json.Unmarshal(raw, &ref) != nil || !validProfileID(strings.TrimSpace(ref.ID)) {
		http.Error(w, "load requires a valid connection profile id", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	meta, metaErr := loadConnectionProfileSetupMeta(a)
	a.mu.Unlock()
	if metaErr != nil {
		http.Error(w, metaErr.Error(), http.StatusInternalServerError)
		return
	}
	innerReq, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1/", bytes.NewReader(raw))
	innerReq.Header.Set("content-type", "application/json")
	innerReq = withInternalMutationContext(innerReq)
	recorder := httptest.NewRecorder()
	a.loadConnectionProfile(recorder, innerReq)
	if recorder.Code < 200 || recorder.Code >= 300 {
		writeCaptured(w, recorder)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		http.Error(w, "connection profile load returned invalid json", http.StatusInternalServerError)
		return
	}
	profileMap, _ := payload["profile"].(map[string]any)
	id, _ := profileMap["id"].(string)
	if item, ok := meta.Entries[id]; ok {
		payload["multihop_exit_mode"] = item.MultihopExitMode
	}
	if prefs, ok := profileMap["preferences"].(map[string]any); ok {
		payload["multihop_enabled"] = prefs["multihop_enabled"]
		payload["multihop_entry_id"] = prefs["multihop_entry_id"]
		payload["multihop_exit_id"] = prefs["multihop_exit_id"]
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}

func (a *app) deleteConnectionProfileSetup(w http.ResponseWriter, r *http.Request) {
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
	raw, err := readBoundedBody(r, 8<<10)
	if err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var ref connectionProfileRefRequest
	if json.Unmarshal(raw, &ref) != nil || !validProfileID(strings.TrimSpace(ref.ID)) {
		http.Error(w, "delete requires a valid connection profile id", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	oldProfiles, snapshotErr := loadConnectionProfileStore(a)
	oldMeta, metaSnapshotErr := loadConnectionProfileSetupMeta(a)
	oldMeta = cloneConnectionProfileSetupMetaStore(oldMeta)
	a.mu.Unlock()
	if snapshotErr != nil {
		http.Error(w, snapshotErr.Error(), http.StatusInternalServerError)
		return
	}
	if metaSnapshotErr != nil {
		http.Error(w, metaSnapshotErr.Error(), http.StatusInternalServerError)
		return
	}
	innerReq, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1/", bytes.NewReader(raw))
	innerReq.Header.Set("content-type", "application/json")
	innerReq = withInternalMutationContext(innerReq)
	recorder := httptest.NewRecorder()
	a.deleteConnectionProfile(recorder, innerReq)
	if recorder.Code < 200 || recorder.Code >= 300 {
		writeCaptured(w, recorder)
		return
	}
	a.mu.Lock()
	meta := cloneConnectionProfileSetupMetaStore(oldMeta)
	delete(meta.Entries, strings.TrimSpace(ref.ID))
	metaErr := persistConnectionProfileSetupMeta(a, meta)
	var rollbackErr error
	if metaErr != nil {
		rollbackErr = persistConnectionProfileStore(a, oldProfiles)
		if restoreMetaErr := persistConnectionProfileSetupMeta(a, oldMeta); restoreMetaErr != nil && rollbackErr == nil {
			rollbackErr = restoreMetaErr
		}
	}
	a.mu.Unlock()
	if metaErr != nil {
		if rollbackErr != nil {
			http.Error(w, "connection profile delete failed and rollback was incomplete: "+metaErr.Error()+"; "+rollbackErr.Error(), http.StatusInternalServerError)
			return
		}
		http.Error(w, "connection profile delete failed and was rolled back: "+metaErr.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func readBoundedBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, errors.New("empty body")
	}
	var body struct{ Raw json.RawMessage }
	_ = body
	reader := http.MaxBytesReader(nil, r.Body, limit)
	defer reader.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(reader); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
