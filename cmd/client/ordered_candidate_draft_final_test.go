//go:build linux || windows || (darwin && (amd64 || arm64))

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
)

// Exercise the actual source capture, profile compiler, HTTP transaction and
// private store. The drained measurement worker and physical observer are
// modeled here. The encrypted peer suite independently verifies the response.
func TestOrderedCandidateDraftNamedFinalProfile(t *testing.T) {
	for _, count := range []int{3, 9, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) { testOrderedCandidateDraftNamedFinal(t, count) })
	}
}
func testOrderedCandidateDraftNamedFinal(t *testing.T, count int) {
	ctx := t.Context()
	a, inventory := desktopNodeChainCaptureFixture(t, count+1)
	final, selected := count-1, count-2
	rows := append([]common.MultihopNodeSelection(nil), inventory[:count]...)
	rows[final].Mode = "shadowsocks"
	if count == 3 {
		installDesktopOrderedImported(t, a, rows)
	} else {
		positions := make([]int, count-2)
		for i := range positions {
			positions[i] = i + 1
		}
		installDesktopIndependentImports(t, a, rows, positions)
	}
	home, candidate := rows[final].ID, inventory[count].ID
	// The candidate owns an independent cipher, private token, router ID and
	// endpoint. Replacing just its public ID cannot reconstruct its transport.
	file := filepath.Join(clientRoot(a), "generated", candidate, "shadowsocks", "sing-box.json")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	newKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	if strings.Count(string(raw), oldKey) != 1 {
		t.Fatal("ambiguous paired candidate fixture key")
	}
	if err := os.WriteFile(file, []byte(strings.Replace(string(raw), oldKey, newKey, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	a.profiles.Profiles[final].MultihopEnabled, a.profiles.Profiles[final].MultihopExecution = true, "local"
	a.profiles.Profiles[count].MultihopNodes = nil
	a.profiles.Profiles[count].MultihopEnabled, a.profiles.Profiles[count].MultihopExecution = false, ""
	a.profiles.SelectedID, a.state.RouterID = home, home
	a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
	}
	tokens := map[string]string{}
	for _, row := range rows {
		p, _ := a.profileByIDLocked(row.ID)
		tokens[row.ID] = publicProfileToken(p)
	}
	initial := cloneRouterProfileStore(a.profiles)
	draft := &multihopConnectRequest{Execution: "local", Nodes: rows, desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &home, ExpectedProfileTokens: tokens}}
	request := orderedCandidatePreparationRequest{RequestID: strings.Repeat("a", 32), Samples: 50, Scope: orderedCandidateSavedPrefixScope, Position: selected, CandidateIDs: []string{candidate}, draft: draft}
	observe := func(ctx context.Context) (string, error) { return "original physical network", ctx.Err() }
	view, err := captureOrderedCandidatePreparedSelection(ctx, a, selected, request.Scope, draft, observe)
	if err != nil {
		t.Fatal("original draft catalog:", err)
	}
	if candidateViewMetric(view.prefixes, selected) != hopmeasure.CandidatePrivateResponseMeasurement {
		t.Fatal("selected metric", view.prefixes)
	}
	expected := append([]common.MultihopNodeSelection(nil), rows...)
	expected[final].ID = candidate
	var choice orderedCandidateChoice
	for _, c := range view.candidates {
		if c.ID == candidate {
			choice = c
		}
	}
	if choice.ProposalAction != "save-final-profile" || choice.SaveReason != "" || !reflect.DeepEqual(choice.Proposal, expected) {
		t.Fatal("candidate proposal", choice, expected)
	}
	control := viaEntryControlFor(a)
	if err := reserveOrderedCandidatePreparedAdmissionLocked(control, request.RequestID, view); err != nil {
		t.Fatal(err)
	}
	p, err := beginOrderedCandidatePreparationWithNetwork(ctx, a, request, observe)
	if err != nil {
		t.Fatal(err)
	}
	defer p.finish()
	result := desktopCandidateDescriptionStatusFixture(t, p.prefixPreparation, candidate)
	result.Measurement, result.Results[0].Kind, result.Results[0].Benchmark.Measurement = hopmeasure.CandidatePrivateResponseMeasurement, "private-agent-response", hopmeasure.CandidatePrivateResponseMeasurement
	if err := validateOrderedCandidatePreparedStatus(p, candidate, result, time.Now()); err != nil {
		t.Fatal(err)
	}
	observer := &selectedDraftNetworkFixture{phase: 5}
	done := make(chan struct{})
	close(done)
	p.workerDone = done
	if err := p.retireNative(ctx); err != nil {
		t.Fatal("original DOWN", err)
	}
	p.runtime = &orderedCandidatePreparedRuntime{preparation: p, catalog: p.inventory, cohort: observer}
	job := &orderedCandidatePreparedJob{preparation: p, view: view, accepted: true, nativeDown: true, expires: time.Now().Add(time.Minute), results: []hopmeasure.CandidateStatus{result}}
	owner := p.owner
	owner.prepared = job
	// Complete only the modeled worker lifetime. Physical currency, current
	// sources, the compiled path and the store transaction remain live checks.
	p.finishOnce.Do(func() { owner.running = false; close(owner.done); a.operationMu.Unlock() })
	payload := map[string]any{"request_id": request.RequestID, "view_token": view.token, "candidate_id": candidate, "proposed_path": expected, "scope": request.Scope}
	choose := orderedCandidateHTTP(t, a, "/api/multihop/draft-candidates/choose", payload)
	if choose.Code != 409 || !strings.Contains(choose.Body.String(), "Action differs") {
		t.Fatal("editor chose a named final", choose.Code, choose.Body.String())
	}
	payload["name"] = "Measured new final"
	payload["proposed_path"] = rows
	path := "/api/multihop/draft-candidates/save-profile"
	if r := orderedCandidateHTTP(t, a, path, payload); r.Code != 409 {
		t.Fatal("substituted original final", r.Code)
	}
	payload["proposed_path"] = expected
	var id string
	for i := 0; i < 2; i++ {
		r := orderedCandidateHTTP(t, a, path, payload)
		if r.Code != 200 {
			t.Fatal("named save or retry", i, r.Code, r.Body.String())
		}
		var v struct {
			Saved     bool
			ID        string                         `json:"saved_profile_id"`
			Candidate string                         `json:"candidate_id"`
			Action    string                         `json:"proposal_action"`
			Path      []common.MultihopNodeSelection `json:"proposed_path"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &v); err != nil || !v.Saved || v.ID == "" || v.Candidate != candidate || v.Action != "save-final-profile" || !reflect.DeepEqual(v.Path, expected) || (i > 0 && id != v.ID) {
			t.Fatal("saved result lost original identity", v, err)
		}
		id = v.ID
	}
	w := httptest.NewRecorder()
	a.orderedCandidatePreparedStatus(w, httptest.NewRequest(http.MethodGet, "/api/multihop/draft-candidates?request_id="+request.RequestID, nil))
	cancelled := orderedCandidateHTTP(t, a, "/api/multihop/draft-candidates/cancel", map[string]any{"request_id": request.RequestID, "view_token": view.token, "scope": request.Scope})
	for _, r := range []*httptest.ResponseRecorder{w, cancelled} {
		var v map[string]any
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v["saved_profile_id"] != id || v["candidate_id"] != candidate || v["proposal_action"] != "save-final-profile" || v["active_path_changed"] != false || v["measurement"] != hopmeasure.CandidatePrivateResponseMeasurement {
			t.Fatal("lost saved status/late cancel identity", r.Code, r.Body.String())
		}
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil || len(store.Profiles) != 1 || store.Profiles[0].ID != id || store.Profiles[0].Name != payload["name"] || store.Profiles[0].NodeID != candidate || store.Profiles[0].Prefs == nil || !reflect.DeepEqual(store.Profiles[0].Prefs.MultihopNodes, expected) || !reflect.DeepEqual(initial, a.profiles) || a.state.Connected {
		t.Fatal("named Save changed Home or appended twice", err, len(store.Profiles))
	}
}
