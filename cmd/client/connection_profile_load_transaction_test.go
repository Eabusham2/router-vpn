package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

// These fixtures use the real save/load handlers, private files and admission
// locks. No connection engine, native route or user's catalog is substituted.
func profileLoadTestApp(t *testing.T) (*app, map[string]any) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOMEVPN_ROOT", root)
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}, state: state{Mode: "off", Phase: "off"}}
	a.profiles = common.RouterProfileStore{SelectedID: "home", Profiles: []common.RouterProfile{
		{ID: "home", Name: "Home", NodeKind: "router-vpn", Endpoint: "203.0.113.10", RouterAPI: "http://10.77.0.1:8787", APIToken: "fixture-private-home-key", IPv6Mode: "on", MTUPolicy: "auto", DNSMode: "home", KillSwitchPolicy: "off"},
		{ID: "other", Name: "Other", NodeKind: "router-vpn", Endpoint: "203.0.113.11", RouterAPI: "http://10.77.0.1:8787", APIToken: "fixture-private-other-key", IPv6Mode: "on", MTUPolicy: "auto", DNSMode: "home", KillSwitchPolicy: "off"},
	}}
	for i := range a.profiles.Profiles {
		applyProfileDefaults(&a.profiles.Profiles[i])
	}
	if err := a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	// Production startup normalizes the private schema before exposing catalog
	// tokens. Exercise that real reader instead of an unnormalized struct seed.
	if err := a.loadProfiles(); err != nil {
		t.Fatal(err)
	}
	saved := profileLoadTestRequest(t, a.saveConnectionProfileSetup, "/api/connection-profile/setup/save", map[string]any{
		"name": "Original setup", "mode": "custom:Exact Name", "custom_layers": []string{"wireguard", "reality"}, "multihop_enabled": false,
	})
	if saved.Code != http.StatusOK {
		t.Fatalf("save fixture: %d %s", saved.Code, saved.Body.String())
	}
	var savedBody struct {
		Profile connectionProfileRecord `json:"profile"`
	}
	if err := json.Unmarshal(saved.Body.Bytes(), &savedBody); err != nil || savedBody.Profile.ID == "" {
		t.Fatalf("saved fixture response: %v", err)
	}
	a.profiles.SelectedID = "other"
	a.state.RouterID = "other"
	if err := a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	return a, map[string]any{"operation_id": strings.Repeat("a", 32), "expected_revision": "0", "id": savedBody.Profile.ID,
		"expected_mode": "custom:Exact Name", "expected_selected_node_id": "other", "expected_profile_tokens": map[string]string{"other": publicProfileToken(a.profiles.Profiles[1])}}
}

func profileLoadTestRequest(t *testing.T, handler http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func profileLoadTestPhase(t *testing.T, a *app, phase string, body any, status int) profileLoadTransactionResponse {
	t.Helper()
	w := profileLoadTestRequest(t, a.connectionProfileLoadTransaction, "/api/connection-profile/setup/load/"+phase, body)
	if w.Code != status {
		t.Fatalf("%s: status %d want %d: %s", phase, w.Code, status, w.Body.String())
	}
	var response profileLoadTransactionResponse
	if status == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || !response.OK {
			t.Fatalf("%s response: %v", phase, err)
		}
	}
	return response
}

func profileLoadTestNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func profileLoadTestOwner(response profileLoadTransactionResponse) profileLoadOwnerRequest {
	return profileLoadOwnerRequest{OperationID: response.Transaction.OperationID, Generation: response.Transaction.Generation, ReceiptSHA256: response.Transaction.ReceiptSHA256}
}

func profileLoadTestRestart(t *testing.T, prior *app) *app {
	t.Helper()
	a := &app{cfg: prior.cfg, state: state{Mode: "off", Phase: "off"}}
	if err := a.loadProfiles(); err != nil {
		t.Fatal(err)
	}
	a.state.RouterID = a.profiles.SelectedID
	return a
}

func profileLoadTestProfiles(t *testing.T, a *app) []byte {
	t.Helper()
	raw, err := json.Marshal(a.profiles)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProfileLoadTransactionCommitRestartAndAdmission(t *testing.T) {
	a, request := profileLoadTestApp(t)
	before, stateBefore := profileLoadTestProfiles(t, a), a.state
	startup, cancelStartup := context.WithCancel(context.Background())
	defer cancelStartup()
	startupPolicyCancels.Store(a, context.CancelFunc(cancelStartup))
	t.Cleanup(func() { startupPolicyCancels.Delete(a) })
	initial := profileLoadTestPhase(t, a, "status", map[string]string{"operation_id": request["operation_id"].(string)}, http.StatusOK)
	if initial.Revision != "0" || initial.Transaction.State != "absent" || !profileLoadTestNull(initial.Snapshot) {
		t.Fatal("first status did not report absent revision zero")
	}
	prepared := profileLoadTestPhase(t, a, "prepare", request, http.StatusOK)
	if startup.Err() == nil {
		t.Fatal("accepted manual Load retained an older delayed startup intent")
	}
	if prepared.Revision != "1" || prepared.Transaction.State != "prepared" || prepared.Transaction.Finished || !bytes.Equal(before, profileLoadTestProfiles(t, a)) || a.state != stateBefore {
		t.Fatal("prepare changed active choices or omitted its unfinished receipt")
	}
	var snapshot map[string]json.RawMessage
	if json.Unmarshal(prepared.Snapshot, &snapshot) != nil || string(snapshot["multihop_nodes"]) != "null" || string(snapshot["mode"]) != `"custom:Exact Name"` {
		t.Fatal("prepare lost exact mode or canonical ordinary-path wire shape")
	}
	ownerBytes, _ := json.Marshal(a.profileLoad)
	if bytes.Contains(ownerBytes, []byte("fixture-private")) || bytes.Contains(ownerBytes, []byte("api_token")) {
		t.Fatal("non-secret recovery owner captured credentials")
	}
	for _, candidate := range []*app{a, profileLoadTestRestart(t, a)} {
		status, err := candidate.controllerStatusContext(context.Background())
		if err != nil || !status.ProfileLoadPending || status.Connected || status.Phase != "off" {
			t.Fatalf("recovered owner altered VPN phase: %+v %v", status, err)
		}
		if release, err := candidate.beginNodeBoundOperation(); !errors.Is(err, errProfileLoadPending) {
			if release != nil {
				release()
			}
			t.Fatalf("node admission ignored pending load: %v", err)
		}
		if _, release, err := candidate.beginConnectionTransactionContext(context.Background()); !errors.Is(err, errProfileLoadPending) {
			if release != nil {
				release()
			}
			t.Fatalf("Connect/startup ignored pending load: %v", err)
		}
		for _, internal := range []bool{false, true} {
			r := httptest.NewRequest(http.MethodPost, "/api/profile/select", nil)
			if internal {
				r = withInternalMutationContext(r)
			}
			if release, err := candidate.beginMutationOperation(r); !errors.Is(err, errProfileLoadPending) {
				if release != nil {
					release()
				}
				t.Fatalf("mutation bypassed pending load, internal=%v: %v", internal, err)
			}
		}
	}
	a = profileLoadTestRestart(t, a)
	owner := profileLoadTestOwner(prepared)
	committed := profileLoadTestPhase(t, a, "commit", owner, http.StatusOK)
	if committed.Transaction.State != "committed" || committed.Transaction.Finished || a.profiles.SelectedID != "home" || !bytes.Equal(committed.Snapshot, prepared.Snapshot) {
		t.Fatal("commit did not publish exact prepared choices with its receipt")
	}
	a = profileLoadTestRestart(t, a)
	if a.profileLoad == nil || a.profileLoad.State != "committed" || a.profiles.SelectedID != "home" {
		t.Fatal("committed receipt and selected profiles did not survive together")
	}
	// An idempotent commit no longer consumes a named source that could have
	// disappeared after the original publication.
	if err := os.Remove(connectionProfileStorePath(a)); err != nil {
		t.Fatal(err)
	}
	profileLoadTestPhase(t, a, "commit", owner, http.StatusOK)
	profileLoadTestPhase(t, a, "abort", owner, http.StatusConflict)
	if _, release, err := a.beginConnectionTransaction(); !errors.Is(err, errProfileLoadPending) {
		if release != nil {
			release()
		}
		t.Fatalf("committed local recovery was not fenced: %v", err)
	}
	finished := profileLoadTestPhase(t, a, "finish", owner, http.StatusOK)
	if !finished.Transaction.Finished || finished.Revision != "1" {
		t.Fatal("finish discarded the monotonic receipt")
	}
	profileLoadTestPhase(t, a, "finish", owner, http.StatusOK)
	a = profileLoadTestRestart(t, a)
	if err := a.guardProfileLoadPendingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if release, err := a.beginNodeBoundOperation(); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
}

func TestProfileLoadTransactionAbortAndOriginalOwner(t *testing.T) {
	a, request := profileLoadTestApp(t)
	before := profileLoadTestProfiles(t, a)
	prepared := profileLoadTestPhase(t, a, "prepare", request, http.StatusOK)
	owner := profileLoadTestOwner(prepared)
	wrong := owner
	wrong.Generation = strings.Repeat("b", 32)
	for _, phase := range []string{"commit", "abort", "finish", "status"} {
		profileLoadTestPhase(t, a, phase, wrong, http.StatusConflict)
	}
	profileLoadTestPhase(t, a, "finish", owner, http.StatusConflict)
	aborted := profileLoadTestPhase(t, a, "abort", owner, http.StatusOK)
	if aborted.Transaction.State != "aborted" || aborted.Transaction.Finished || !bytes.Equal(before, profileLoadTestProfiles(t, a)) {
		t.Fatal("abort changed prior choices or released unfinished local recovery")
	}
	profileLoadTestPhase(t, a, "commit", owner, http.StatusConflict)
	profileLoadTestPhase(t, a, "abort", owner, http.StatusOK)
	profileLoadTestPhase(t, a, "finish", owner, http.StatusOK)
	a = profileLoadTestRestart(t, a)
	if !bytes.Equal(before, profileLoadTestProfiles(t, a)) || a.profileLoad.State != "aborted" || !a.profileLoad.Finished {
		t.Fatal("aborted choices and finished receipt did not survive restart")
	}
}

func TestProfileLoadTransactionCancelFencesDelayedPrepare(t *testing.T) {
	a, request := profileLoadTestApp(t)
	before := profileLoadTestProfiles(t, a)
	operation := request["operation_id"].(string)
	cancelled := profileLoadTestPhase(t, a, "cancel", map[string]string{"operation_id": operation, "expected_revision": "0"}, http.StatusOK)
	if cancelled.Revision != "1" || cancelled.Transaction.State != "aborted" || cancelled.Transaction.Finished || !profileLoadTestNull(cancelled.Snapshot) || !bytes.Equal(before, profileLoadTestProfiles(t, a)) {
		t.Fatal("lost-prepare cancellation did not publish an untouched tombstone")
	}
	late := profileLoadTestPhase(t, a, "prepare", request, http.StatusOK)
	if late.Transaction != cancelled.Transaction || !profileLoadTestNull(late.Snapshot) {
		t.Fatal("delayed prepare escaped its tombstone")
	}
	profileLoadTestPhase(t, a, "finish", profileLoadTestOwner(cancelled), http.StatusOK)
	a = profileLoadTestRestart(t, a)
	newRequest := map[string]any{}
	for k, v := range request {
		newRequest[k] = v
	}
	newRequest["operation_id"], newRequest["expected_revision"] = strings.Repeat("b", 32), "1"
	newPrepared := profileLoadTestPhase(t, a, "prepare", newRequest, http.StatusOK)
	if newPrepared.Revision != "2" {
		t.Fatal("next owner reused a revision")
	}
	profileLoadTestPhase(t, a, "prepare", request, http.StatusConflict)
	oldCancel := profileLoadTestPhase(t, a, "cancel", map[string]string{"operation_id": operation, "expected_revision": "0"}, http.StatusOK)
	if oldCancel.Transaction.State != "superseded" || !oldCancel.Transaction.Finished || oldCancel.Transaction.Generation != "" || oldCancel.Transaction.ReceiptSHA256 != "" || !profileLoadTestNull(oldCancel.Snapshot) || oldCancel.Revision != "2" {
		t.Fatal("superseded cancellation claimed another owner's snapshot")
	}
	sameCancel := profileLoadTestPhase(t, a, "cancel", map[string]string{"operation_id": newRequest["operation_id"].(string), "expected_revision": "1"}, http.StatusOK)
	if sameCancel.Transaction != newPrepared.Transaction {
		t.Fatal("cancellation lost an already prepared owner")
	}
	profileLoadTestPhase(t, a, "abort", profileLoadTestOwner(newPrepared), http.StatusOK)
	profileLoadTestPhase(t, a, "finish", profileLoadTestOwner(newPrepared), http.StatusOK)
}

func TestProfileLoadTransactionRejectedSourceAndCancelledCallerDoNotPublish(t *testing.T) {
	t.Run("source changed after prepare", func(t *testing.T) {
		a, request := profileLoadTestApp(t)
		prepared := profileLoadTestPhase(t, a, "prepare", request, http.StatusOK)
		a.profiles.Profiles[0].Endpoint = "203.0.113.99"
		if err := a.persistProfiles(); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(a.cfg.ProfilesFile)
		profileLoadTestPhase(t, a, "commit", profileLoadTestOwner(prepared), http.StatusConflict)
		after, _ := os.ReadFile(a.cfg.ProfilesFile)
		if !bytes.Equal(before, after) || a.profileLoad.State != "prepared" || a.profiles.SelectedID != "other" {
			t.Fatal("failed commit overwrote the newer source")
		}
		profileLoadTestPhase(t, a, "abort", profileLoadTestOwner(prepared), http.StatusOK)
		profileLoadTestPhase(t, a, "finish", profileLoadTestOwner(prepared), http.StatusOK)
	})
	t.Run("caller cancellation", func(t *testing.T) {
		a, request := profileLoadTestApp(t)
		before, _ := os.ReadFile(a.cfg.ProfilesFile)
		raw, _ := json.Marshal(request)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := httptest.NewRequest(http.MethodPost, "/api/connection-profile/setup/load/prepare", bytes.NewReader(raw)).WithContext(ctx)
		w := httptest.NewRecorder()
		a.connectionProfileLoadTransaction(w, r)
		after, _ := os.ReadFile(a.cfg.ProfilesFile)
		if w.Code == http.StatusOK || !bytes.Equal(before, after) || a.profileLoad != nil {
			t.Fatal("cancelled caller published a load owner")
		}
	})
}

func TestProfileLoadRecoveryKeepsPublicStopAvailable(t *testing.T) {
	for _, phase := range []string{"prepared", "committed", "aborted"} {
		t.Run(phase, func(t *testing.T) {
			a, request := profileLoadTestApp(t)
			prepared := profileLoadTestPhase(t, a, "prepare", request, http.StatusOK)
			owner := profileLoadTestOwner(prepared)
			if phase == "committed" {
				profileLoadTestPhase(t, a, "commit", owner, http.StatusOK)
			}
			if phase == "aborted" {
				profileLoadTestPhase(t, a, "abort", owner, http.StatusOK)
			}
			for _, reason := range []string{"", "emergency-stop"} {
				receipt, err := a.capturePublicStopContext(context.Background(), reason)
				if err != nil {
					t.Fatalf("public Stop capture blocked by %s Load: %v", phase, err)
				}
				release, err := a.beginCapturedPublicStopContext(context.Background(), receipt)
				if err != nil {
					t.Fatalf("public Stop admission blocked by %s Load: %v", phase, err)
				}
				release()
			}
		})
	}
}

func TestProfileLoadTerminalRecoveryDoesNotNeedAnIdleDataplane(t *testing.T) {
	a, request := profileLoadTestApp(t)
	a.state.Connected, a.state.Phase = true, "connected"
	before, _ := os.ReadFile(a.cfg.ProfilesFile)
	profileLoadTestPhase(t, a, "prepare", request, http.StatusConflict)
	after, _ := os.ReadFile(a.cfg.ProfilesFile)
	if !bytes.Equal(before, after) {
		t.Fatal("busy prepare changed private choices")
	}
	// Cancel/finish only fence the original delayed request; neither applies a
	// connection choice or interferes with an independently retained runtime.
	cancelled := profileLoadTestPhase(t, a, "cancel", map[string]string{"operation_id": request["operation_id"].(string), "expected_revision": "0"}, http.StatusOK)
	profileLoadTestPhase(t, a, "finish", profileLoadTestOwner(cancelled), http.StatusOK)
	if !a.state.Connected || a.state.Phase != "connected" || a.profiles.SelectedID != "other" {
		t.Fatal("terminal recovery changed the dataplane")
	}
}

func TestProfileLoadPublicationRejectsLatePrivateReplacement(t *testing.T) {
	a, request := profileLoadTestApp(t)
	prepared := profileLoadTestPhase(t, a, "prepare", request, http.StatusOK)
	before := profileLoadTestProfiles(t, a)
	a.mu.Lock()
	capture, err := a.captureProfileLoadFileLocked(true)
	original := a.profileLoad
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	// A different writer publishes even identical bytes at a new inode after
	// admission. The original Load must not borrow that replacement's authority.
	if err := atomicWritePrivate(a.cfg.ProfilesFile, raw); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.Stat(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	committed := *original
	committed.State = "committed"
	publication := &profileLoadPublication{capture: capture, prepared: original, committed: &committed}
	_, _, legacy, err := profileLoadPrepareInput(original.Request)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), profileLoadPermitContextKey{}, original)
	ctx = context.WithValue(ctx, profileLoadWriteContextKey{}, publication)
	r := httptest.NewRequest(http.MethodPost, "/api/connection-profile/setup/load", bytes.NewReader(legacy)).WithContext(ctx)
	w := httptest.NewRecorder()
	a.loadConnectionProfileSetup(w, withInternalMutationContext(r))
	if w.Code == http.StatusOK || publication.published || a.profileLoad != original || a.profileLoad.State != "prepared" || !bytes.Equal(before, profileLoadTestProfiles(t, a)) {
		t.Fatal("failed atomic publication leaked a committed owner or staged choices")
	}
	after, _ := os.Stat(a.cfg.ProfilesFile)
	retained, _ := os.ReadFile(a.cfg.ProfilesFile)
	if !os.SameFile(foreign, after) || !bytes.Equal(raw, retained) {
		t.Fatal("Load overwrote another writer's replacement")
	}
	// Authenticated recovery can capture the still-prepared replacement afresh.
	profileLoadTestPhase(t, a, "abort", profileLoadTestOwner(prepared), http.StatusOK)
	profileLoadTestPhase(t, a, "finish", profileLoadTestOwner(prepared), http.StatusOK)
}

func TestProfileLoadRestartDoesNotScheduleOldAutomaticChoice(t *testing.T) {
	a, request := profileLoadTestApp(t)
	a.profiles.Profiles[1].AutoConnect, a.profiles.Profiles[1].StartupMode = true, "smart-auto"
	if err := a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	request["expected_profile_tokens"] = map[string]string{"other": publicProfileToken(a.profiles.Profiles[1])}
	if capture, err := a.captureStartupPolicy(); err != nil || capture == nil {
		t.Fatalf("positive automatic startup capture: %v", err)
	}
	prepared := profileLoadTestPhase(t, a, "prepare", request, http.StatusOK)
	a = profileLoadTestRestart(t, a)
	if capture, err := a.captureStartupPolicy(); err != nil || capture != nil {
		t.Fatalf("pending recovery scheduled an old automatic choice: %v", err)
	}
	profileLoadTestPhase(t, a, "abort", profileLoadTestOwner(prepared), http.StatusOK)
	profileLoadTestPhase(t, a, "finish", profileLoadTestOwner(prepared), http.StatusOK)
	if capture, err := a.captureStartupPolicy(); err != nil || capture == nil {
		t.Fatalf("resolved recovery changed saved automatic preference: %v", err)
	}
}

func TestProfileLoadDNSPathsAndCatalogTokensSurviveReload(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp", "tls", "https", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			a, _ := profileLoadTestApp(t)
			p := a.profiles.Profiles[0]
			request := dnsPolicyRequest{Mode: "home", Protocol: protocol, Host: p.AdGuardIPv4, ServerName: "resolver.example"}
			updated, err := applyRouterHomeDNSPolicy(p, request)
			if err != nil {
				t.Fatal(err)
			}
			a.profiles.Profiles[0] = updated
			before := publicProfileToken(updated)
			if err := a.persistProfiles(); err != nil {
				t.Fatal(err)
			}
			a = profileLoadTestRestart(t, a)
			p = a.profiles.Profiles[0]
			wantPath := ""
			if protocol == "https" || protocol == "h3" {
				wantPath = "/dns-query"
			}
			if p.DNSPath != wantPath || publicProfileToken(p) != before {
				t.Fatalf("%s changed its path or revision on reload", protocol)
			}
		})
	}
}

func TestProfileLoadAcceptsCompleteNinetySixNodeExpectationBody(t *testing.T) {
	a, request := profileLoadTestApp(t)
	nodes := []common.MultihopNodeSelection{{ID: "home", Mode: "wg"}}
	for i := 0; i < 94; i++ {
		p := cloneRouterProfile(a.profiles.Profiles[0])
		p.ID = fmt.Sprintf("node-%02d-%s", i, strings.Repeat("x", 56))
		p.Name, p.Endpoint = p.ID, fmt.Sprintf("198.51.100.%d", i+1)
		a.profiles.Profiles = append(a.profiles.Profiles, p)
		nodes = append(nodes, common.MultihopNodeSelection{ID: p.ID, Mode: "shadowsocks"})
	}
	nodes = append(nodes, common.MultihopNodeSelection{ID: "other", Mode: "shadowsocks"})
	a.profiles.Profiles[1].MultihopEnabled = true
	a.profiles.Profiles[1].MultihopNodes, a.profiles.Profiles[1].MultihopExecution = nodes, "local"
	if err := a.persistProfiles(); err != nil {
		t.Fatal(err)
	}
	if err := a.loadProfiles(); err != nil {
		t.Fatal(err)
	}
	tokens, err := a.connectionProfileTokensLocked(a.profiles.Profiles[1])
	if err != nil || len(tokens) != 96 {
		t.Fatalf("complete selected-path inventory: %v", err)
	}
	request["expected_profile_tokens"] = tokens
	raw, err := json.Marshal(request)
	if err != nil || len(raw) <= 8<<10 || len(raw) > 16<<10 {
		t.Fatalf("request did not exercise the real extended bound: %d %v", len(raw), err)
	}
	prepared := profileLoadTestPhase(t, a, "prepare", request, http.StatusOK)
	profileLoadTestPhase(t, a, "abort", profileLoadTestOwner(prepared), http.StatusOK)
	profileLoadTestPhase(t, a, "finish", profileLoadTestOwner(prepared), http.StatusOK)
	request["operation_id"], request["expected_revision"] = strings.Repeat("b", 32), "1"
	tokens["one-too-many"] = strings.Repeat("f", 64)
	profileLoadTestPhase(t, a, "prepare", request, http.StatusBadRequest)
}
