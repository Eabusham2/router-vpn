package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

type setupExpectationResponse struct {
	Profile  connectionProfileRecord `json:"profile"`
	Selected string                  `json:"selected_node_id"`
	Tokens   map[string]string       `json:"profile_tokens"`
}

func setupExpectationTokens(t *testing.T, a *app, ids []string) map[string]string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	result := map[string]string{}
	for _, id := range ids {
		profile, ok := a.profileByIDLocked(id)
		if !ok {
			t.Fatal("fixture lost an original node")
		}
		result[id] = publicProfileToken(profile)
	}
	return result
}

func setupExpectationBody(t *testing.T, a *app, nodes []common.MultihopNodeSelection) map[string]any {
	t.Helper()
	ids := make([]string, len(nodes))
	for i, node := range nodes {
		ids[i] = node.ID
	}
	return map[string]any{"name": "Captured ordered choice", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": "local", "multihop_nodes": nodes,
		"expected_selected_node_id": a.profiles.SelectedID, "expected_profile_tokens": setupExpectationTokens(t, a, ids)}
}

func setupExpectationResult(t *testing.T, response *httptest.ResponseRecorder) setupExpectationResponse {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("setup status=%d: %s", response.Code, response.Body.String())
	}
	var result setupExpectationResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !validProfileID(result.Profile.ID) || !validProfileID(result.Selected) || len(result.Tokens) == 0 {
		t.Fatal("setup omitted its finalized selected graph receipt")
	}
	return result
}

type setupExpectationSnapshot struct {
	profiles common.RouterProfileStore
	state    state
	files    map[string][]byte
}

func snapshotSetupExpectation(t *testing.T, a *app) setupExpectationSnapshot {
	t.Helper()
	a.mu.Lock()
	result := setupExpectationSnapshot{profiles: cloneRouterProfileStore(a.profiles), state: a.state, files: map[string][]byte{}}
	a.mu.Unlock()
	err := filepath.WalkDir(filepath.Dir(a.cfg.ProfilesFile), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err == nil {
			result.files[path] = raw
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (before setupExpectationSnapshot) unchanged(t *testing.T, a *app) {
	t.Helper()
	after := snapshotSetupExpectation(t, a)
	if !reflect.DeepEqual(before.profiles, after.profiles) || !reflect.DeepEqual(before.state, after.state) || !reflect.DeepEqual(before.files, after.files) {
		t.Fatal("refused setup mutated original selection, sources or saved profile files")
	}
}

func setupExpectationPostRaw(a *app, path string, raw []byte) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	registerConnectionProfileSetupRoutes(mux, a)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	return response
}

func TestConnectionProfileSetupExpectationsRoundtripAndLegacy(t *testing.T) {
	for _, count := range []int{2, 3, 4, 8} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			a, nodes := savedNodeChainFixture(t, count)
			modes := make([]string, count)
			for i := range modes {
				modes[i] = []string{"awg2-fast", "wg", "awg2-strong"}[i%3]
			}
			modes[count-1] = "shadowsocks"
			installOrderedAWGAssets(t, a, nodes, modes, "")
			body := setupExpectationBody(t, a, nodes)
			original := cloneRouterProfileStore(a.profiles)
			saved := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/save", body))
			if saved.Selected != a.profiles.SelectedID || !reflect.DeepEqual(saved.Tokens, body["expected_profile_tokens"]) || !reflect.DeepEqual(saved.Profile.Prefs.MultihopNodes, nodes) {
				t.Fatal("Save receipt did not match its complete finalized graph")
			}
			body["id"], body["name"] = saved.Profile.ID, "Updated captured choice"
			updated := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/update", body))
			if updated.Selected != saved.Selected || !reflect.DeepEqual(updated.Tokens, saved.Tokens) || updated.Profile.Name != "Updated captured choice" || !reflect.DeepEqual(a.profiles, original) {
				t.Fatal("Update changed live preferences or returned another source snapshot")
			}
			a.mu.Lock()
			a.profiles.SelectedID = nodes[0].ID
			a.state.RouterID = nodes[0].ID
			a.mu.Unlock()
			caller := setupExpectationTokens(t, a, []string{nodes[0].ID})
			loaded := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.Profile.ID, "expected_selected_node_id": nodes[0].ID, "expected_profile_tokens": caller}))
			ids := make([]string, count)
			for i, node := range nodes {
				ids[i] = node.ID
			}
			if loaded.Selected != saved.Selected || len(loaded.Tokens) != count || !reflect.DeepEqual(loaded.Tokens, setupExpectationTokens(t, a, ids)) {
				t.Fatal("Load confused caller current selection with saved target source inventory")
			}
			delete(body, "expected_selected_node_id")
			delete(body, "expected_profile_tokens")
			setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/update", body))
			setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": saved.Profile.ID}))
		})
	}
}

func TestConnectionProfileSetupExpectationsRejectMalformedRequestsBeforeMutation(t *testing.T) {
	for _, action := range []string{"save", "update", "load"} {
		t.Run(action, func(t *testing.T) {
			a, nodes := savedNodeChainFixture(t, 3)
			body := setupExpectationBody(t, a, nodes)
			saved := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/save", body))
			if action == "update" {
				body["id"] = saved.Profile.ID
			}
			if action == "load" {
				body = map[string]any{"id": saved.Profile.ID, "expected_selected_node_id": a.profiles.SelectedID, "expected_profile_tokens": body["expected_profile_tokens"]}
			}
			raw, _ := json.Marshal(body)
			text := string(raw)
			token := body["expected_profile_tokens"].(map[string]string)[nodes[0].ID]
			for _, fault := range []string{"partial-selected", "partial-tokens", "null-selected", "null-tokens", "number-selected", "array-tokens", "case-selected", "case-tokens", "duplicate-selected", "duplicate-token", "null-token", "upper-token", "bad-token", "trailing"} {
				t.Run(fault, func(t *testing.T) {
					var changed map[string]json.RawMessage
					_ = json.Unmarshal(raw, &changed)
					modified := ""
					switch fault {
					case "partial-selected":
						delete(changed, "expected_profile_tokens")
					case "partial-tokens":
						delete(changed, "expected_selected_node_id")
					case "null-selected":
						changed["expected_selected_node_id"] = json.RawMessage("null")
					case "null-tokens":
						changed["expected_profile_tokens"] = json.RawMessage("null")
					case "number-selected":
						changed["expected_selected_node_id"] = json.RawMessage("1")
					case "array-tokens":
						changed["expected_profile_tokens"] = json.RawMessage("[]")
					case "case-selected":
						modified = strings.Replace(text, "expected_selected_node_id", "Expected_Selected_Node_ID", 1)
					case "case-tokens":
						modified = strings.Replace(text, "expected_profile_tokens", "EXPECTED_PROFILE_TOKENS", 1)
					case "duplicate-selected":
						modified = strings.TrimSuffix(text, "}") + `,"expected_selected_node_id":"` + a.profiles.SelectedID + `"}`
					case "duplicate-token":
						modified = strings.Replace(text, `"expected_profile_tokens":{`, `"expected_profile_tokens":{"`+nodes[0].ID+`":"`+token+`",`, 1)
					case "null-token":
						modified = strings.Replace(text, `"`+token+`"`, "null", 1)
					case "upper-token":
						modified = strings.Replace(text, token, strings.ToUpper(token), 1)
					case "bad-token":
						modified = strings.Replace(text, token, "not-a-token", 1)
					case "trailing":
						modified = text + " {}"
					}
					if modified == "" {
						encoded, _ := json.Marshal(changed)
						modified = string(encoded)
					}
					before := snapshotSetupExpectation(t, a)
					response := setupExpectationPostRaw(a, "/api/connection-profile/setup/"+action, []byte(modified))
					if response.Code != http.StatusBadRequest {
						t.Fatalf("ambiguous %s request status=%d", fault, response.Code)
					}
					before.unchanged(t, a)
				})
			}
		})
	}
}

func TestConnectionProfileSetupExpectationsRejectStaleSelectionAndMemberInventory(t *testing.T) {
	for _, action := range []string{"save", "update", "load"} {
		for _, fault := range []string{"selection", "selected-source", "middle-source", "missing-token", "extra-token"} {
			t.Run(action+"/"+fault, func(t *testing.T) {
				a, nodes := savedNodeChainFixture(t, 4)
				body := setupExpectationBody(t, a, nodes)
				saved := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/save", body))
				if action == "update" {
					body["id"] = saved.Profile.ID
				}
				if action == "load" {
					body = map[string]any{"id": saved.Profile.ID, "expected_selected_node_id": a.profiles.SelectedID, "expected_profile_tokens": body["expected_profile_tokens"]}
				}
				switch fault {
				case "selection":
					a.profiles.SelectedID = nodes[0].ID
				case "selected-source":
					a.profiles.Profiles[3].APIToken = "replacement-selected-secret"
				case "middle-source":
					a.profiles.Profiles[1].APIToken = "replacement-middle-secret"
				case "missing-token":
					delete(body["expected_profile_tokens"].(map[string]string), nodes[1].ID)
				case "extra-token":
					body["expected_profile_tokens"].(map[string]string)["unrelated"] = strings.Repeat("a", 64)
				}
				before := snapshotSetupExpectation(t, a)
				response := postSetup(t, a, "/api/connection-profile/setup/"+action, body)
				if response.Code != http.StatusConflict {
					t.Fatalf("stale %s status=%d: %s", fault, response.Code, response.Body.String())
				}
				before.unchanged(t, a)
			})
		}
	}
}

func TestConnectionProfileSetupExpectationLoadRetainsStoredTargetValidation(t *testing.T) {
	a, nodes := savedNodeChainFixture(t, 3)
	body := setupExpectationBody(t, a, nodes)
	saved := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/save", body))
	a.profiles.SelectedID = nodes[0].ID
	a.state.RouterID = nodes[0].ID
	request := map[string]any{"id": saved.Profile.ID, "expected_selected_node_id": nodes[0].ID, "expected_profile_tokens": setupExpectationTokens(t, a, []string{nodes[0].ID})}
	path := filepath.Join(clientRoot(a), "generated", nodes[1].ID, "wg", "wg.conf")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(raw, []byte("\n# changed saved target source\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	before := snapshotSetupExpectation(t, a)
	response := postSetup(t, a, "/api/connection-profile/setup/load", request)
	if response.Code != http.StatusConflict {
		t.Fatal("current UI expectation replaced saved target's original source validation")
	}
	before.unchanged(t, a)
}

func TestConnectionProfileSetupExpectationLoadCapturesNoCurrentSelection(t *testing.T) {
	a, nodes := savedNodeChainFixture(t, 2)
	saved := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/save", setupExpectationBody(t, a, nodes)))
	a.profiles.SelectedID = ""
	a.state.RouterID = ""
	request := map[string]any{"id": saved.Profile.ID, "expected_selected_node_id": "", "expected_profile_tokens": map[string]string{}}
	loaded := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/load", request))
	if loaded.Selected != nodes[1].ID {
		t.Fatal("Load did not preserve its explicitly captured empty prior selection")
	}
	before := snapshotSetupExpectation(t, a)
	response := postSetup(t, a, "/api/connection-profile/setup/load", request)
	if response.Code != http.StatusConflict {
		t.Fatal("old empty selection capture overrode a newer selected graph")
	}
	before.unchanged(t, a)
}

func TestConnectionProfileSetupExpectationFinalizationFailureRollsBack(t *testing.T) {
	for _, action := range []string{"save", "update"} {
		t.Run(action, func(t *testing.T) {
			a, nodes := savedNodeChainFixture(t, 3)
			control := &a.profiles.Profiles[2]
			control.MultihopEnabled = false
			control.MultihopNodes = nil
			control.MultihopExecution = ""
			initial := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Original direct choice", "mode": "shadowsocks", "multihop_enabled": false}))
			body := setupExpectationBody(t, a, nodes)
			if action == "update" {
				body["id"] = initial.Profile.ID
			}
			if err := os.Remove(filepath.Join(clientRoot(a), "generated", nodes[1].ID, "wg", "wg.conf")); err != nil {
				t.Fatal(err)
			}
			before := snapshotSetupExpectation(t, a)
			response := postSetup(t, a, "/api/connection-profile/setup/"+action, body)
			if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "rolled back") {
				t.Fatalf("finalization failure status=%d: %s", response.Code, response.Body.String())
			}
			before.unchanged(t, a)
		})
	}
}

type setupExpectationReadBarrier struct {
	reader           io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (r *setupExpectationReadBarrier) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.reader.Read(p)
}

func TestConnectionProfileSetupExpectationAdmissionOwnsOperationAndCurrentSources(t *testing.T) {
	a, nodes := savedNodeChainFixture(t, 3)
	body := setupExpectationBody(t, a, nodes)
	raw, _ := json.Marshal(body)
	reader := &setupExpectationReadBarrier{reader: bytes.NewReader(raw), entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(reader.release) })
	request := httptest.NewRequest(http.MethodPost, "/api/connection-profile/setup/save", reader)
	response := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() { a.saveConnectionProfileSetup(response, request); close(finished) }()
	select {
	case <-reader.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("setup did not reach bounded request admission")
	}
	other := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{"name": "Competing selection", "mode": "shadowsocks", "multihop_enabled": false})
	if other.Code != http.StatusConflict {
		t.Fatal("setup source capture did not retain the original mutation operation")
	}
	a.mu.Lock()
	a.profiles.Profiles[1].APIToken = "replacement-before-setup-admission"
	a.mu.Unlock()
	before := snapshotSetupExpectation(t, a)
	release.Do(func() { close(reader.release) })
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("captured setup admission did not complete")
	}
	if response.Code != http.StatusConflict {
		t.Fatal("setup used source tokens from before its actual admission")
	}
	before.unchanged(t, a)
}

type setupExpectationResponseBoundary struct {
	*httptest.ResponseRecorder
	beforeWrite func()
	once        sync.Once
}

func (w *setupExpectationResponseBoundary) Write(data []byte) (int, error) {
	w.once.Do(w.beforeWrite)
	return w.ResponseRecorder.Write(data)
}

func TestConnectionProfileSetupExpectationResponseKeepsFinalizedSnapshot(t *testing.T) {
	for _, action := range []string{"save", "update"} {
		t.Run(action, func(t *testing.T) {
			a, nodes := savedNodeChainFixture(t, 3)
			body := setupExpectationBody(t, a, nodes)
			if action == "update" {
				saved := setupExpectationResult(t, postSetup(t, a, "/api/connection-profile/setup/save", body))
				body["id"] = saved.Profile.ID
			}
			selected := a.profiles.SelectedID
			expected := body["expected_profile_tokens"].(map[string]string)
			raw, _ := json.Marshal(body)
			mux := http.NewServeMux()
			registerConnectionProfileSetupRoutes(mux, a)
			response := &setupExpectationResponseBoundary{ResponseRecorder: httptest.NewRecorder(), beforeWrite: func() {
				a.mu.Lock()
				a.profiles.SelectedID = nodes[0].ID
				a.profiles.Profiles[1].APIToken = "newer-after-finalized-snapshot"
				a.mu.Unlock()
			}}
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/connection-profile/setup/"+action, bytes.NewReader(raw)))
			result := setupExpectationResult(t, response.ResponseRecorder)
			if result.Selected != selected || !reflect.DeepEqual(result.Tokens, expected) || a.profiles.SelectedID == selected {
				t.Fatal("setup response borrowed a newer selection after its finalized snapshot")
			}
			if strings.Contains(response.Body.String(), "private-api-") || strings.Contains(response.Body.String(), "newer-after-finalized-snapshot") {
				t.Fatal("public setup source receipt copied private credentials")
			}
		})
	}
}
