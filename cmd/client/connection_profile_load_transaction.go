package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"

	"router-vpn/internal/common"
	"router-vpn/internal/desktopnetwork"
)

const profileLoadStoreField = "_connection_profile_load"
const profileLoadSnapshotLimit = 1 << 20

var errProfileLoadPending = errors.New("a connection profile Load needs recovery before connecting or changing saved choices")

// This non-secret owner is stored in the same atomic private-file publication
// as the selected Router profiles. It never copies node credentials. A terminal
// receipt stays reserved until the UI has durably completed its own journal.
type connectionProfileLoadTransaction struct {
	Version                int             `json:"version"`
	Revision               uint64          `json:"revision"`
	OperationID            string          `json:"operation_id"`
	Generation             string          `json:"generation"`
	State                  string          `json:"state"`
	ReceiptSHA256          string          `json:"receipt_sha256"`
	Finished               bool            `json:"finished"`
	SourceSHA256           string          `json:"source_sha256"`
	RequestSHA256          string          `json:"request_sha256"`
	Request                json.RawMessage `json:"request"`
	Snapshot               json.RawMessage `json:"snapshot"`
	CancelledBeforePrepare bool            `json:"cancelled_before_prepare,omitempty"`
}

type profileLoadTransactionReceipt struct {
	OperationID   string `json:"operation_id"`
	Generation    string `json:"generation,omitempty"`
	State         string `json:"state"`
	ReceiptSHA256 string `json:"receipt_sha256,omitempty"`
	Finished      bool   `json:"finished"`
}

type profileLoadTransactionResponse struct {
	OK          bool                          `json:"ok"`
	Revision    string                        `json:"revision"`
	Transaction profileLoadTransactionReceipt `json:"transaction"`
	Snapshot    json.RawMessage               `json:"snapshot"`
}

type profileLoadOwnerRequest struct {
	OperationID      string `json:"operation_id"`
	Generation       string `json:"generation,omitempty"`
	ReceiptSHA256    string `json:"receipt_sha256,omitempty"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
}

type profileLoadPreviewContextKey struct{}
type profileLoadPermitContextKey struct{}
type profileLoadWriteContextKey struct{}

// The prepared owner stays globally visible until the selected profiles and
// committed receipt are published together under app.mu. Other private writers
// must never observe a committed receipt paired with the old selection.
type profileLoadPublication struct {
	capture   *profileLoadFileCapture
	prepared  *connectionProfileLoadTransaction
	committed *connectionProfileLoadTransaction
	published bool
}

type profileLoadFileCapture struct {
	path   string
	info   os.FileInfo
	raw    []byte
	inputs []*profileLoadFileCapture
}

func profileLoadRevision(value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value {
		return 0, errors.New("profile Load revision must be a canonical decimal string")
	}
	return n, nil
}

func profileLoadCancelDigest(operation, generation, previous string) string {
	raw, _ := json.Marshal([]string{"routervpn-profile-load-cancel-v1", operation, generation, previous})
	return profileLoadDigest(raw)
}

func profileLoadCanonical(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if _, err := externalConnectJSONObject(raw); err != nil {
		return nil, err
	}
	// RawMessage only sorts the outer map. Reordered nested token maps must
	// retain one request identity across retries and an indented disk read.
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func profileLoadDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func profileLoadID(value string) bool {
	if len(value) != 32 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func newProfileLoadGeneration() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func validateProfileLoadTransaction(value *connectionProfileLoadTransaction) error {
	if value == nil {
		return nil
	}
	if value.Version != 1 || value.Revision == 0 || !profileLoadID(value.OperationID) || !profileLoadID(value.Generation) ||
		(value.State != "prepared" && value.State != "committed" && value.State != "aborted") ||
		(value.State == "prepared" && value.Finished) || !validExternalProfileExpectationToken(value.SourceSHA256) ||
		len(value.Request) == 0 || len(value.Request) > 16<<10 || profileLoadDigest(value.Request) != value.RequestSHA256 ||
		len(value.Snapshot) > profileLoadSnapshotLimit {
		return errors.New("saved connection profile Load owner is invalid")
	}
	fields, err := externalConnectJSONObject(value.Request)
	if err != nil {
		return err
	}
	var operation string
	if json.Unmarshal(fields["operation_id"], &operation) != nil || operation != value.OperationID {
		return errors.New("saved profile Load request changed its operation")
	}
	var previous string
	if json.Unmarshal(fields["expected_revision"], &previous) != nil {
		return errors.New("saved profile Load omitted its prior revision")
	}
	revision, err := profileLoadRevision(previous)
	if err != nil || revision != value.Revision-1 {
		return errors.New("saved profile Load revision does not follow its request")
	}
	if value.CancelledBeforePrepare {
		if value.State != "aborted" || len(value.Snapshot) != 0 || value.ReceiptSHA256 != profileLoadCancelDigest(value.OperationID, value.Generation, previous) {
			return errors.New("saved profile Load cancellation receipt is invalid")
		}
		return nil
	}
	if len(value.Snapshot) == 0 || profileLoadDigest(value.Snapshot) != value.ReceiptSHA256 {
		return errors.New("saved profile Load snapshot changed")
	}
	if _, err = externalConnectJSONObject(value.Snapshot); err != nil {
		return errors.New("saved profile Load snapshot is invalid")
	}
	return nil
}

func decodePrivateProfileLoad(raw []byte) (*connectionProfileLoadTransaction, error) {
	fields, err := externalConnectJSONObject(raw)
	if err != nil {
		return nil, err
	}
	for name := range fields {
		if name != profileLoadStoreField && strings.EqualFold(name, profileLoadStoreField) {
			return nil, errors.New("profile Load owner must use its canonical private field")
		}
	}
	encoded, exists := fields[profileLoadStoreField]
	if !exists {
		return nil, nil
	}
	var value *connectionProfileLoadTransaction
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, errors.New("saved profile Load owner is unreadable")
	}
	// JSON indentation of the outer private file is not part of a receipt.
	if value.Request, err = profileLoadCanonical(value.Request); err != nil {
		return nil, err
	}
	if value.Snapshot, err = profileLoadCanonical(value.Snapshot); err != nil {
		return nil, err
	}
	if err := validateProfileLoadTransaction(value); err != nil {
		return nil, err
	}
	return value, nil
}

// Every shipping reader of routers.json understands the same validated private
// extension. Keeping the owner in this file preserves one atomic publication;
// it must neither lower the existing file bound nor be discarded by a writer.
func decodePrivateProfiles(raw []byte) (common.RouterProfileStore, *connectionProfileLoadTransaction, error) {
	var store common.RouterProfileStore
	// RouterProfileStore historically accepts future top-level extensions and
	// portable upgrades retain them. Keep startup compatible with those files;
	// staged writes separately refuse fields they cannot faithfully preserve.
	if err := decodeExactJSONObjectBounded(raw, &store, maxPrivateStoreBytes); err != nil {
		return common.RouterProfileStore{}, nil, err
	}
	load, err := decodePrivateProfileLoad(raw)
	if err != nil {
		return common.RouterProfileStore{}, nil, err
	}
	return store, load, nil
}

func marshalPrivateProfiles(profiles common.RouterProfileStore, load *connectionProfileLoadTransaction) ([]byte, error) {
	if load == nil {
		return json.MarshalIndent(profiles, "", "  ")
	}
	if err := validateProfileLoadTransaction(load); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(profiles)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	fields[profileLoadStoreField], err = json.Marshal(load)
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(fields, "", "  ")
	if err == nil && len(encoded)+1 > maxPrivateStoreBytes {
		return nil, errors.New("private profiles and Load recovery owner exceed their storage limit")
	}
	return encoded, err
}

func (a *app) marshalPrivateProfilesLocked() ([]byte, error) {
	return marshalPrivateProfiles(a.profiles, a.profileLoad)
}

func (capture *profileLoadFileCapture) current(ctx context.Context) error {
	if capture == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("profile Load lost its original live publication")
	}
	info, err := os.Lstat(capture.path)
	if capture.info == nil {
		if os.IsNotExist(err) {
			return ctx.Err()
		}
		return errors.New("a previously absent profile Load input was created")
	}
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, capture.info) || info.Size() != capture.info.Size() || !info.ModTime().Equal(capture.info.ModTime()) {
		return errors.New("private profile store was replaced during Load")
	}
	raw, err := readPrivateRegular(capture.path, maxPrivateStoreBytes)
	if err != nil || !bytes.Equal(raw, capture.raw) {
		return errors.New("private profile store changed during Load")
	}
	for _, input := range capture.inputs {
		if err := input.current(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (a *app) captureProfileLoadFileLocked(includeInputs bool) (*profileLoadFileCapture, error) {
	info, err := os.Lstat(a.cfg.ProfilesFile)
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, info) {
		return nil, errors.New("profile Load requires its original private profile store")
	}
	raw, err := readPrivateRegular(a.cfg.ProfilesFile, maxPrivateStoreBytes)
	if err != nil {
		return nil, err
	}
	fields, err := externalConnectJSONObject(raw)
	if err != nil {
		return nil, err
	}
	for field := range fields {
		if field != "schema_version" && field != "selected_id" && field != "profiles" && field != profileLoadStoreField {
			return nil, errors.New("private profile store contains a newer field; staged Load retained the original file")
		}
	}
	savedLoad, err := decodePrivateProfileLoad(raw)
	if err != nil {
		return nil, err
	}
	want, _ := json.Marshal(a.profileLoad)
	got, _ := json.Marshal(savedLoad)
	if !bytes.Equal(want, got) {
		return nil, errors.New("private profile Load owner differs from the controller generation")
	}
	profiles, _, err := decodePrivateProfiles(raw)
	if err != nil {
		return nil, err
	}
	for i := range profiles.Profiles {
		applyProfileDefaults(&profiles.Profiles[i])
	}
	if profiles.SelectedID == "" && len(profiles.Profiles) > 0 {
		profiles.SelectedID = profiles.Profiles[0].ID
	}
	wantProfiles, err := json.Marshal(a.profiles)
	if err != nil {
		return nil, err
	}
	gotProfiles, err := json.Marshal(profiles)
	if err != nil || !bytes.Equal(wantProfiles, gotProfiles) {
		return nil, errors.New("private profiles changed outside the controller; newer saved state was retained")
	}
	// A legacy permission hardening during the read belongs to this same file.
	after, err := os.Lstat(a.cfg.ProfilesFile)
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("private profile store changed during its capture")
	}
	capture := &profileLoadFileCapture{path: a.cfg.ProfilesFile, info: after, raw: raw}
	// Recovery must remain possible when a named setup was removed or damaged
	// after preparation. Only prepare/commit consume those separate inputs.
	if !includeInputs {
		return capture, nil
	}
	for _, path := range []string{connectionProfileStorePath(a), connectionProfileSetupMetaPath(a)} {
		before, err := os.Lstat(path)
		if os.IsNotExist(err) {
			capture.inputs = append(capture.inputs, &profileLoadFileCapture{path: path})
			continue
		}
		if err != nil || !before.Mode().IsRegular() || !os.SameFile(before, before) {
			return nil, errors.New("profile Load input is not an original regular file")
		}
		body, err := readPrivateRegular(path, maxPrivateStoreBytes)
		if err != nil {
			return nil, err
		}
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return nil, errors.New("profile Load input changed during capture")
		}
		capture.inputs = append(capture.inputs, &profileLoadFileCapture{path: path, info: after, raw: body})
	}
	return capture, nil
}

func profileLoadSourceDigest(profiles common.RouterProfileStore) (string, error) {
	// The catalog digest excludes observation history and does not depend on an
	// in-memory epoch which restarts with the controller process.
	copy := &app{profiles: profiles}
	if _, err := copy.candidateCatalogRevisionLocked(); err != nil {
		return "", err
	}
	return copy.profileCatalogDigest, nil
}

func (a *app) persistProfileLoadLocked(ctx context.Context, capture *profileLoadFileCapture) error {
	body, err := a.marshalPrivateProfilesLocked()
	if err != nil {
		return err
	}
	_, err = atomicWritePrivateChecked(a.cfg.ProfilesFile, append(body, '\n'), func() error { return capture.current(ctx) })
	return err
}

func (a *app) guardProfileLoadPendingContext(ctx context.Context) error {
	if err := desktopnetwork.LockContext(ctx, &a.mu); err != nil {
		return err
	}
	defer a.mu.Unlock()
	if a.profileLoad == nil || a.profileLoad.Finished {
		return nil
	}
	permit, _ := ctx.Value(profileLoadPermitContextKey{}).(*connectionProfileLoadTransaction)
	if permit == a.profileLoad {
		return nil
	}
	return errProfileLoadPending
}

func registerConnectionProfileLoadTransactionRoutes(h *http.ServeMux, a *app) {
	for _, phase := range []string{"prepare", "status", "commit", "abort", "finish", "cancel"} {
		h.HandleFunc("/api/connection-profile/setup/load/"+phase, a.connectionProfileLoadTransaction)
	}
}

func profileLoadReply(w http.ResponseWriter, operation string, owner *connectionProfileLoadTransaction, revision uint64) {
	response := profileLoadTransactionResponse{OK: true, Revision: strconv.FormatUint(revision, 10), Transaction: profileLoadTransactionReceipt{OperationID: operation, State: "absent"}}
	if owner != nil {
		response.Transaction = profileLoadTransactionReceipt{OperationID: owner.OperationID, Generation: owner.Generation, State: owner.State, ReceiptSHA256: owner.ReceiptSHA256, Finished: owner.Finished}
		response.Snapshot = append(json.RawMessage(nil), owner.Snapshot...)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
}

func (a *app) profileLoadPreview(ctx context.Context, raw []byte, owner *connectionProfileLoadTransaction) ([]byte, int, error) {
	ctx = context.WithValue(ctx, profileLoadPreviewContextKey{}, true)
	if owner != nil {
		ctx = context.WithValue(ctx, profileLoadPermitContextKey{}, owner)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/connection-profile/setup/load", bytes.NewReader(raw)).WithContext(ctx)
	response := httptest.NewRecorder()
	a.loadConnectionProfileSetup(response, withInternalMutationContext(request))
	if response.Code != http.StatusOK {
		return nil, response.Code, errors.New(strings.TrimSpace(response.Body.String()))
	}
	fields, err := externalConnectJSONObject(response.Body.Bytes())
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defaults := map[string]json.RawMessage{"multihop_enabled": json.RawMessage("false"), "multihop_execution": json.RawMessage(`"local"`), "multihop_nodes": json.RawMessage("null")}
	for _, field := range []string{"multihop_entry_id", "multihop_exit_id", "multihop_entry_mode", "multihop_exit_mode"} {
		defaults[field] = json.RawMessage(`""`)
	}
	for field, value := range defaults {
		if old, exists := fields[field]; !exists || bytes.Equal(old, []byte("null")) {
			fields[field] = value
		}
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	canonical, err := profileLoadCanonical(encoded)
	if err != nil || len(canonical) > profileLoadSnapshotLimit {
		return nil, http.StatusInternalServerError, errors.New("prepared profile Load result exceeds its bound")
	}
	return canonical, http.StatusOK, nil
}

func profileLoadPrepareInput(raw []byte) (string, []byte, []byte, error) {
	fields, err := externalConnectJSONObject(raw)
	if err != nil {
		return "", nil, nil, err
	}
	allowed := map[string]bool{"operation_id": true, "expected_revision": true, "id": true, "expected_mode": true, "expected_selected_node_id": true, "expected_profile_tokens": true}
	for name := range fields {
		if !allowed[name] {
			return "", nil, nil, errors.New("profile Load prepare contains an unknown field")
		}
	}
	var operation, id, mode string
	if json.Unmarshal(fields["operation_id"], &operation) != nil || !profileLoadID(operation) || json.Unmarshal(fields["id"], &id) != nil || !validProfileID(id) ||
		json.Unmarshal(fields["expected_mode"], &mode) != nil || mode == "" {
		return "", nil, nil, errors.New("profile Load prepare requires its operation, saved profile and exact displayed mode")
	}
	expected, err := decodeDesktopProfileExpectations(fields)
	if err != nil {
		return "", nil, nil, err
	}
	if !expected.present() {
		return "", nil, nil, errors.New("profile Load prepare requires the displayed selection and node revisions")
	}
	var revision string
	if json.Unmarshal(fields["expected_revision"], &revision) != nil {
		return "", nil, nil, errors.New("profile Load prepare omitted its captured revision")
	}
	if _, err = profileLoadRevision(revision); err != nil {
		return "", nil, nil, err
	}
	canonical, err := profileLoadCanonical(raw)
	if err != nil {
		return "", nil, nil, err
	}
	delete(fields, "operation_id")
	delete(fields, "expected_revision")
	legacy, err := json.Marshal(fields)
	return operation, canonical, legacy, err
}

func (a *app) connectionProfileLoadTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	phase := strings.TrimPrefix(r.URL.Path, "/api/connection-profile/setup/load/")
	if phase != "prepare" && phase != "status" && phase != "commit" && phase != "abort" && phase != "finish" && phase != "cancel" {
		http.Error(w, "unknown profile Load phase", http.StatusNotFound)
		return
	}
	raw, err := readBoundedBody(r, 16<<10)
	if err != nil {
		http.Error(w, "invalid profile Load request", http.StatusBadRequest)
		return
	}
	var request profileLoadOwnerRequest
	var canonical, legacy []byte
	if phase == "prepare" {
		request.OperationID, canonical, legacy, err = profileLoadPrepareInput(raw)
		if err == nil {
			var fields map[string]json.RawMessage
			fields, _ = externalConnectJSONObject(canonical)
			_ = json.Unmarshal(fields["expected_revision"], &request.ExpectedRevision)
		}
	} else {
		var fields map[string]json.RawMessage
		fields, err = externalConnectJSONObject(raw)
		if err == nil {
			for field := range fields {
				if field != "operation_id" && field != "generation" && field != "receipt_sha256" && !(phase == "cancel" && field == "expected_revision") {
					err = errors.New("unknown profile Load owner field")
				}
			}
		}
		if err == nil {
			err = json.Unmarshal(raw, &request)
		}
		if err == nil && (!profileLoadID(request.OperationID) ||
			(phase != "status" && phase != "cancel" || request.Generation != "" || request.ReceiptSHA256 != "") &&
				(!profileLoadID(request.Generation) || !validExternalProfileExpectationToken(request.ReceiptSHA256))) {
			err = errors.New("profile Load requires its exact operation, generation and receipt")
		}
		if err == nil && phase == "cancel" {
			_, err = profileLoadRevision(request.ExpectedRevision)
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !a.operationMu.TryLock() {
		http.Error(w, "another Router VPN transaction is in progress; retry the same Load operation", http.StatusConflict)
		return
	}
	defer a.operationMu.Unlock()
	if err := desktopnetwork.LockContext(r.Context(), &a.mu); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if a.controllerClosingLocked() {
		a.mu.Unlock()
		http.Error(w, errControllerClosing.Error(), http.StatusConflict)
		return
	}
	owner := a.profileLoad
	includeInputs := phase == "prepare" && (owner == nil || owner.OperationID != request.OperationID) ||
		phase == "commit" && owner != nil && owner.State == "prepared"
	capture, err := a.captureProfileLoadFileLocked(includeInputs)
	revision := uint64(0)
	if owner != nil {
		revision = owner.Revision
	}
	busy := profileSettingsBusy(a.state.Connected, a.state.Phase)
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if phase == "status" {
		if owner == nil || owner.OperationID != request.OperationID {
			profileLoadReply(w, request.OperationID, nil, revision)
			return
		}
		if request.Generation != "" && (request.Generation != owner.Generation || request.ReceiptSHA256 != owner.ReceiptSHA256) {
			http.Error(w, "profile Load status belongs to a different generation", http.StatusConflict)
			return
		}
		profileLoadReply(w, request.OperationID, owner, revision)
		return
	}
	needsIdle := phase == "prepare" && (owner == nil || owner.OperationID != request.OperationID) ||
		phase == "commit" && owner != nil && owner.State == "prepared"
	if busy && needsIdle {
		http.Error(w, "disconnect before completing a profile Load", http.StatusConflict)
		return
	}
	if phase == "cancel" {
		expected, _ := profileLoadRevision(request.ExpectedRevision)
		if owner != nil && owner.OperationID == request.OperationID {
			if expected != owner.Revision-1 {
				http.Error(w, "profile Load cancellation reused another revision", http.StatusConflict)
				return
			}
			profileLoadReply(w, request.OperationID, owner, revision)
			return
		}
		if expected != revision {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(profileLoadTransactionResponse{OK: true, Revision: strconv.FormatUint(revision, 10), Transaction: profileLoadTransactionReceipt{OperationID: request.OperationID, State: "superseded", Finished: true}})
			return
		}
		if owner != nil && !owner.Finished {
			http.Error(w, errProfileLoadPending.Error(), http.StatusConflict)
			return
		}
		if revision == ^uint64(0) {
			http.Error(w, "profile Load revisions exhausted", http.StatusConflict)
			return
		}
		generation, err := newProfileLoadGeneration()
		if err != nil {
			http.Error(w, "could not allocate cancellation owner", http.StatusInternalServerError)
			return
		}
		cancelRequest, _ := json.Marshal(map[string]string{"operation_id": request.OperationID, "expected_revision": request.ExpectedRevision})
		a.mu.Lock()
		source, err := profileLoadSourceDigest(a.profiles)
		cancelled := &connectionProfileLoadTransaction{Version: 1, Revision: revision + 1, OperationID: request.OperationID, Generation: generation, State: "aborted", ReceiptSHA256: profileLoadCancelDigest(request.OperationID, generation, request.ExpectedRevision), SourceSHA256: source, RequestSHA256: profileLoadDigest(cancelRequest), Request: cancelRequest, CancelledBeforePrepare: true}
		if err == nil {
			a.profileLoad = cancelled
			err = a.persistProfileLoadLocked(r.Context(), capture)
		}
		if err != nil {
			a.profileLoad = owner
		}
		a.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		profileLoadReply(w, request.OperationID, cancelled, cancelled.Revision)
		return
	}
	if phase == "prepare" {
		if owner != nil && owner.OperationID == request.OperationID {
			if !owner.CancelledBeforePrepare && owner.RequestSHA256 != profileLoadDigest(canonical) {
				http.Error(w, "profile Load operation was reused for another request", http.StatusConflict)
				return
			}
			profileLoadReply(w, request.OperationID, owner, revision)
			return
		}
		if owner != nil && !owner.Finished {
			http.Error(w, errProfileLoadPending.Error(), http.StatusConflict)
			return
		}
		expected, _ := profileLoadRevision(request.ExpectedRevision)
		if expected != revision || revision == ^uint64(0) {
			http.Error(w, "profile Load revision changed; cancel the original intent before retrying", http.StatusConflict)
			return
		}
		if err := a.guardSessionDNSStopPending(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err := a.guardDesktopProtectionOffPending(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err := guardViaEntryDecisionContext(r.Context(), a); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		snapshot, status, err := a.profileLoadPreview(r.Context(), legacy, nil)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		generation, err := newProfileLoadGeneration()
		if err != nil {
			http.Error(w, "could not allocate a profile Load generation", http.StatusInternalServerError)
			return
		}
		a.mu.Lock()
		source, err := profileLoadSourceDigest(a.profiles)
		if err == nil {
			a.profileLoad = &connectionProfileLoadTransaction{Version: 1, Revision: revision + 1, OperationID: request.OperationID, Generation: generation, State: "prepared", ReceiptSHA256: profileLoadDigest(snapshot), SourceSHA256: source, RequestSHA256: profileLoadDigest(canonical), Request: canonical, Snapshot: snapshot}
			err = a.persistProfileLoadLocked(r.Context(), capture)
		}
		if err != nil {
			a.profileLoad = owner
		}
		prepared := a.profileLoad
		a.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// An accepted manual Load supersedes the older delayed startup intent.
		// Releasing recovery later must not revive that earlier mode choice.
		cancelPendingStartupPolicy(a)
		profileLoadReply(w, request.OperationID, prepared, prepared.Revision)
		return
	}
	if owner == nil || request.OperationID != owner.OperationID || request.Generation != owner.Generation || request.ReceiptSHA256 != owner.ReceiptSHA256 {
		http.Error(w, "profile Load belongs to another or absent recovery owner", http.StatusConflict)
		return
	}
	if phase == "commit" && owner.State == "aborted" || phase == "abort" && owner.State == "committed" || phase == "finish" && owner.State == "prepared" {
		http.Error(w, "profile Load phase contradicts its durable outcome", http.StatusConflict)
		return
	}
	if owner.Finished || phase == "commit" && owner.State == "committed" || phase == "abort" && owner.State == "aborted" {
		profileLoadReply(w, request.OperationID, owner, revision)
		return
	}
	if phase == "commit" {
		_, _, legacy, err = profileLoadPrepareInput(owner.Request)
		if err != nil {
			http.Error(w, "saved profile Load request is invalid", http.StatusConflict)
			return
		}
		a.mu.Lock()
		source, sourceErr := profileLoadSourceDigest(a.profiles)
		a.mu.Unlock()
		if sourceErr != nil || source != owner.SourceSHA256 {
			http.Error(w, "original profile Load source changed; restore the local journal and abort", http.StatusConflict)
			return
		}
		snapshot, status, err := a.profileLoadPreview(r.Context(), legacy, owner)
		if err != nil || profileLoadDigest(snapshot) != owner.ReceiptSHA256 {
			if err == nil {
				err, status = errors.New("prepared profile Load snapshot changed; restore the local journal and abort"), http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}
		committed := *owner
		committed.State = "committed"
		publication := &profileLoadPublication{capture: capture, prepared: owner, committed: &committed}
		ctx := context.WithValue(r.Context(), profileLoadPermitContextKey{}, owner)
		ctx = context.WithValue(ctx, profileLoadWriteContextKey{}, publication)
		inner := httptest.NewRequest(http.MethodPost, "/api/connection-profile/setup/load", bytes.NewReader(legacy)).WithContext(ctx)
		response := httptest.NewRecorder()
		a.loadConnectionProfileSetup(response, withInternalMutationContext(inner))
		if !publication.published {
			writeCaptured(w, response)
			return
		}
		// The durable publication is authoritative even if later response
		// projection fails. Never tell the UI to roll back a committed Load.
		profileLoadReply(w, request.OperationID, &committed, revision)
		return
	}
	updated := *owner
	if phase == "abort" {
		updated.State = "aborted"
	} else {
		updated.Finished = true
	}
	a.mu.Lock()
	a.profileLoad = &updated
	err = a.persistProfileLoadLocked(r.Context(), capture)
	if err != nil {
		a.profileLoad = owner
	}
	a.mu.Unlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("profile Load %s was not committed: %v", phase, err), http.StatusInternalServerError)
		return
	}
	profileLoadReply(w, request.OperationID, &updated, revision)
}
