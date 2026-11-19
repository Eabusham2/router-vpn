package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestDraftCandidateViewAndAdmissionKeepSavedPathUntouched(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	selected := a.profiles.SelectedID
	ref := func(id string) *common.RouterProfile {
		for i := range a.profiles.Profiles {
			if a.profiles.Profiles[i].ID == id {
				return &a.profiles.Profiles[i]
			}
		}
		t.Fatalf("missing fixture member %q", id)
		return nil
	}
	control := ref(selected)
	rows := []common.MultihopNodeSelection{control.MultihopNodes[0], control.MultihopNodes[len(control.MultihopNodes)-1]}
	control.MultihopNodes = nil
	control.MultihopEnabled = false
	control.MultihopExecution = ""
	initial := cloneRouterProfileStore(a.profiles)
	draft := &multihopConnectRequest{Execution: "local", Nodes: rows, desktopProfileExpectations: desktopProfileExpectations{
		ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: map[string]string{}}}
	for _, node := range rows {
		draft.ExpectedProfileTokens[node.ID] = publicProfileToken(*ref(node.ID))
	}
	observe := func(ctx context.Context) (string, error) { return "fixture-network", ctx.Err() }
	ctx := context.Background()
	view, err := captureOrderedCandidatePreparedSelection(ctx, a, 0, orderedCandidateSavedPrefixScope, draft, observe)
	if err != nil {
		t.Fatal(err)
	}
	if view.selection.Entry.ID != rows[0].ID || view.selection.Exit.ID != selected || len(view.selection.Nodes) != 2 || view.catalog.prefixPreparation == nil || a.candidatePreparation != nil {
		t.Fatal("draft capture lost its exact closed prefix")
	}
	var proposed []common.MultihopNodeSelection
	for _, choice := range view.candidates {
		if choice.ID == q.CandidateIDs[0] {
			proposed = choice.Proposal
		}
	}
	if len(proposed) != 3 || proposed[0] != rows[0] || proposed[2] != rows[1] || proposed[1].ID != q.CandidateIDs[0] {
		t.Fatalf("proposal did not preserve both original draft members: %v", proposed)
	}
	q.draft, q.Scope = draft, orderedCandidateSavedPrefixScope
	p, err := beginOrderedCandidatePreparationWithNetwork(ctx, a, q, observe)
	if err != nil {
		t.Fatal(err)
	}
	if !view.matchesPreparation(p, time.Now()) || p.prefixPreparation == nil || !reflect.DeepEqual(a.profiles, initial) {
		t.Fatal("draft admission replaced a source, lost its native purpose, or changed the saved store")
	}
	if err := p.finish(); err != nil {
		t.Fatal(err)
	}
	draft.ExpectedProfileTokens[rows[0].ID] = strings.Repeat("0", 64)
	if _, err := captureOrderedCandidatePreparedSelection(ctx, a, 0, q.Scope, draft, observe); err == nil {
		t.Fatal("draft accepted a replaced original source token")
	}
	if !reflect.DeepEqual(a.profiles, initial) {
		t.Fatal("draft testing modified a saved profile")
	}
}

func TestDraftCandidateCatalogRejectsArbitraryEndpoints(t *testing.T) {
	a, _ := orderedPreparationFixture(t, "wg")
	mux := http.NewServeMux()
	registerOrderedCandidatePreparedRoutes(mux, a)
	for _, raw := range []string{
		`{"endpoint":"192.0.2.1:8080"}`,
		`{"nodes":[{"id":"a","mode":"wg"},{"id":"b","mode":"shadowsocks"}],"execution":"local","expected_selected_node_id":"b","expected_profile_tokens":{"a":"bad","b":"bad"},"target":"other"}`,
		`{"entry_id":"x","exit_id":"y","execution":"local"}`,
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/multihop/draft-candidates/catalog?scope=saved-prefix-local&prefix_position=0", strings.NewReader(raw))
		mux.ServeHTTP(w, r)
		if w.Code < 400 || a.candidatePreparation != nil {
			t.Fatal("non-draft request reached the native worker", w.Code)
		}
	}
}

func TestDraftCandidateChooseRequiresOriginalDownReview(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	control := viaEntryControlFor(a)
	view := &orderedCandidatePreparedView{token: strings.Repeat("d", 64), scope: orderedCandidateSavedPrefixScope, draft: &multihopConnectRequest{}}
	owner := &viaEntryOwner{id: q.RequestID, prepared: &orderedCandidatePreparedJob{view: view, accepted: true, expires: time.Now().Add(time.Minute)}}
	control.owner = owner
	initial := cloneRouterProfileStore(a.profiles)
	request := map[string]any{"scope": view.scope, "request_id": q.RequestID, "view_token": view.token, "candidate_id": q.CandidateIDs[0], "proposed_path": []any{}}
	for _, state := range []struct{ running, down, cancelled, drained bool }{
		{true, false, false, false}, {false, false, false, false}, {false, true, true, false}, {false, true, false, true},
	} {
		owner.running, owner.prepared.nativeDown, owner.cancelled, owner.drained = state.running, state.down, state.cancelled, state.drained
		reply := orderedCandidateHTTP(t, a, "/api/multihop/draft-candidates/choose", request)
		if reply.Code != 409 || !strings.Contains(reply.Body.String(), "original DOWN review") {
			t.Fatal("choice bypassed original native owner", state, reply.Code, reply.Body.String())
		}
	}
	request["name"] = "Other surface"
	reply := orderedCandidateHTTP(t, a, "/api/multihop/saved-candidates/save-profile", request)
	if reply.Code != 409 || !strings.Contains(reply.Body.String(), "original temporary candidate result is unavailable") || !reflect.DeepEqual(a.profiles, initial) {
		t.Fatal("draft result was allowed to save a profile", reply.Code, reply.Body.String())
	}
	control.owner = nil
	if err := rememberOrderedCandidatePreparedViewLocked(control, view); err != nil {
		t.Fatal(err)
	}
	cancel := map[string]any{"scope": view.scope, "request_id": q.RequestID, "view_token": view.token}
	for _, target := range []struct {
		path   string
		status int
	}{
		{"/api/multihop/saved-candidates/cancel", 409}, {"/api/multihop/draft-candidates/cancel", 200},
	} {
		reply := orderedCandidateHTTP(t, a, target.path, cancel)
		if reply.Code != target.status || (reply.Code == 200 && !strings.Contains(reply.Body.String(), `"origin":"editor-draft"`)) {
			t.Fatal("cancel changed original source purpose", reply.Code, reply.Body.String())
		}
	}
}

func TestDraftCandidateDeliveryRetainsIdleReservationAndDetectsAwayBack(t *testing.T) {
	a, q := orderedPreparationFixture(t, "wg")
	q.Scope = orderedCandidateSavedPrefixScope
	p := beginOrderedPreparationFixture(t, a, q)
	if err := p.retireOriginal(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !p.draftDeliveryCurrentLocked() || orderedCandidatePreparationIdleLocked(a) {
		t.Fatal("cleanup lost the original idle publication reservation")
	}
	a.state.Phase = "starting"
	if p.draftDeliveryCurrentLocked() {
		t.Fatal("replacement Home operation could receive old choice")
	}
	a.state = p.state
	previous := a.profiles.SelectedID
	a.profiles.SelectedID = q.CandidateIDs[0]
	if _, err := a.candidateCatalogRevisionLocked(); err != nil {
		t.Fatal(err)
	}
	a.profiles.SelectedID = previous
	if p.draftDeliveryCurrentLocked() {
		t.Fatal("same public values after an observed catalog change revived the original selection")
	}
	a.candidatePreparation = nil
}
