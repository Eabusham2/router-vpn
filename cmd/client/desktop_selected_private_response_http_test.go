package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
)

var selectedResponseFinalLayouts = []struct {
	name                   string
	count, privatePosition int
}{
	{"private-penultimate/4", 4, 2},
	{"private-penultimate/9", 9, 7},
	{"private-penultimate/16", 16, 14},
	{"all-imported/4", 4, -1},
	{"all-imported/9", 9, -1},
	{"all-imported/16", 16, -1},
	{"earlier-private/5", 5, 2},
	{"earlier-private/9", 9, 2},
	{"earlier-private/16", 16, 2},
}

func desktopSelectedPrivateResponseParentFixture(t *testing.T, count int, winner string) (*desktopNodeChainOwnedFixture, []common.MultihopNodeSelection, string) {
	return desktopSelectedResponseParentFixture(t, count, count-2, winner)
}

func desktopSelectedResponseParentFixture(t *testing.T, count, privatePosition int, winner string) (*desktopNodeChainOwnedFixture, []common.MultihopNodeSelection, string) {
	t.Helper()
	return desktopSelectedResponseParentWithRequest(t, count, privatePosition, "auto", winner)
}

func desktopSelectedResponseParentWithRequest(t *testing.T, count, privatePosition int, requested, winner string) (*desktopNodeChainOwnedFixture, []common.MultihopNodeSelection, string) {
	t.Helper()
	a, nodes, id := selectedResponseAppFixture(t, count, privatePosition)
	for i := range a.profiles.Profiles {
		p := &a.profiles.Profiles[i]
		p.MultihopEnabled, p.MultihopExecution, p.MultihopNodes = false, "", nil
		p.MultihopEntryID, p.MultihopExitID, p.MultihopEntryMode = "", "", ""
		if p.ID == nodes[len(nodes)-1].ID {
			p.MultihopEnabled, p.MultihopExecution, p.MultihopNodes = true, requested, slices.Clone(nodes)
		}
	}
	f, session := prepareDesktopCapturedMultipleImportedExecutionModel(t, a, nodes, requested, winner)
	f, _ = finishDesktopMultipleImportedSelectedLatencyFixture(t, f, session, winner, count)
	identity, _, err := captureSpeedLabIdentityContext(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	// Retain the unrelated resolver at the same pending boundary used by the
	// original selected HTTP fixture; candidate ownership remains real.
	identity.Tracker.mu.Lock()
	if identity.Tracker.dnsProofRunning || identity.Tracker.dnsProofWork != nil {
		identity.Tracker.mu.Unlock()
		t.Fatal("private response fixture lost its idle resolver boundary")
	}
	identity.Tracker.dnsProofRunning = true
	identity.Tracker.mu.Unlock()
	return f, nodes, id
}

func privateResponseExpectedSource(nodes []common.MultihopNodeSelection) []orderedCandidateResponseSourceNode {
	return responseExpectedSourceAt(nodes, len(nodes)-2)
}

func responseExpectedSourceAt(nodes []common.MultihopNodeSelection, privatePosition int) []orderedCandidateResponseSourceNode {
	rows := make([]orderedCandidateResponseSourceNode, len(nodes))
	for i, node := range nodes {
		kind := "external"
		if i == 0 || i == len(nodes)-1 || i == privatePosition {
			kind = "router-vpn"
		}
		rows[i] = orderedCandidateResponseSourceNode{node.ID, node.Mode, kind}
	}
	return rows
}

func responseExpectedPositions(count, _ int) []int {
	positions := []int{0}
	if count < 96 {
		for i := 1; i < count-2; i++ {
			positions = append(positions, i)
		}
	}
	return append(positions, count-2)
}

func checkPrivateResponsePublicSource(t *testing.T, raw []byte, view desktopSelectedCandidateHTTPTestView) {
	t.Helper()
	var response desktopSelectedCandidateHTTPTestView
	if json.Unmarshal(raw, &response) != nil || response.Token != view.Token || response.Epoch != view.Epoch || response.Epoch == 0 ||
		response.Requested != "auto" || response.Required != "local" || response.Selected != "local" || !reflect.DeepEqual(response.ResponseNodes, view.ResponseNodes) {
		t.Fatal("HTTP reply lost its original connected source, Compare winner or epoch", string(raw))
	}
}

func checkPrivateResponseCancel(t *testing.T, raw []byte, view desktopSelectedCandidateHTTPTestView, request string, started bool) {
	t.Helper()
	checkPrivateResponsePublicSource(t, raw, view)
	var response struct {
		Request                                              string `json:"request_id"`
		Started                                              bool   `json:"started"`
		AdmissionCancelled                                   bool   `json:"admission_cancelled"`
		Drained, Running, Accepted, Reviewing, Cancelled, OK bool
		Results                                              []hopmeasure.CandidateStatus
		Saved                                                string `json:"saved_profile_id"`
	}
	if json.Unmarshal(raw, &response) != nil || response.Request != request || response.Started != started || response.AdmissionCancelled == started ||
		!response.Drained || response.Running || response.Accepted || response.Reviewing || !response.Cancelled || !response.OK || len(response.Results) != 0 || response.Saved != "" {
		t.Fatal("connected Cancel changed purpose, invented scores, or failed original cleanup", string(raw))
	}
}

func TestDesktopSelectedPrivateResponseHTTPPreservesCompleteSourceAndNamedProfile(t *testing.T) {
	for _, layout := range selectedResponseFinalLayouts {
		t.Run(layout.name, func(t *testing.T) {
			count := layout.count
			f, nodes, id := desktopSelectedResponseParentFixture(t, count, layout.privatePosition, "local")
			identity, _, err := captureSpeedLabIdentityContext(context.Background(), f.a)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := captureDesktopNodeChainCandidates(context.Background(), f.a, identity, count-2, []string{id})
			if err != nil || catalog.selectedPlan == nil {
				t.Fatal("private connected descriptor", err)
			}
			status := desktopCandidateDescriptionStatusFixture(t, catalog.selectedPlan.plan, id)
			if validateDesktopNodeChainCandidateStatus(catalog.selectedPlan.plan, id, status, time.Now()) == nil {
				t.Fatal("TCP handshake substituted for an authenticated private response")
			}
			status.Measurement, status.Results[0].Kind, status.Results[0].Benchmark.Measurement = hopmeasure.CandidatePrivateResponseMeasurement, "private-agent-response", hopmeasure.CandidatePrivateResponseMeasurement
			if err := validateDesktopNodeChainCandidateStatus(catalog.selectedPlan.plan, id, status, time.Now()); err != nil {
				t.Fatal("original private response description", err)
			}
			view, q := exerciseDesktopSelectedCandidateHTTP(t, f, catalog, id, "local", count-2, responseExpectedPositions(count, layout.privatePosition))
			if view.Requested != "auto" || view.Required != "local" || view.Selected != "local" || view.Epoch == 0 || !reflect.DeepEqual(view.ResponseNodes, responseExpectedSourceAt(nodes, layout.privatePosition)) {
				t.Fatal("connected catalog omitted or changed an original source role")
			}
			mux := http.NewServeMux()
			registerOrderedCandidateRoutes(mux, f.a)
			poll := httptest.NewRecorder()
			mux.ServeHTTP(poll, httptest.NewRequest("GET", "/api/multihop/prefix-candidates?request_id="+q.RequestID, nil))
			if poll.Code != 200 {
				t.Fatal("connected private status", poll.Code, poll.Body.String())
			}
			checkPrivateResponsePublicSource(t, poll.Body.Bytes(), view)
			before := cloneRouterProfileStore(f.a.profiles)
			proposed := slices.Clone(nodes)
			proposed[count-1] = common.MultihopNodeSelection{ID: id, Mode: "shadowsocks"}
			found := false
			for _, candidate := range view.Candidates {
				if candidate.SaveReason != "" || candidate.ProposalAction != "save-final-profile" || len(candidate.Proposal) != count || !reflect.DeepEqual(candidate.Proposal[:count-1], nodes[:count-1]) {
					t.Fatal("offered a private response candidate without its complete saveable prefix")
				}
				if candidate.ID == id {
					found = reflect.DeepEqual(candidate.Proposal, proposed)
				}
			}
			if !found {
				t.Fatal("measured final replacement was not offered")
			}
			save := orderedCandidateSaveRequest{RequestID: q.RequestID, ViewToken: q.ViewToken, CandidateID: id, Name: "Measured private final", ProposedPath: proposed}
			saved := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", save)
			store, err := loadConnectionProfileStore(f.a)
			if saved.Code != 200 || err != nil || len(store.Profiles) != 1 || len(store.Profiles[0].NodeChain) != count || store.Profiles[0].Prefs.MultihopExecution != "auto" || !reflect.DeepEqual(store.Profiles[0].Prefs.MultihopNodes, proposed) {
				t.Fatal("explicit private Save lost the complete Compare path", saved.Code, saved.Body.String(), err)
			}
			checkPrivateResponsePublicSource(t, saved.Body.Bytes(), view)
			var receipt struct {
				Request   string                         `json:"request_id"`
				Candidate string                         `json:"candidate_id"`
				Action    string                         `json:"proposal_action"`
				Proposal  []common.MultihopNodeSelection `json:"proposed_path"`
			}
			if json.Unmarshal(saved.Body.Bytes(), &receipt) != nil || receipt.Request != q.RequestID || receipt.Candidate != id || receipt.Action != "save-final-profile" || !reflect.DeepEqual(receipt.Proposal, proposed) {
				t.Fatal("Save acknowledgment lost the measured replacement")
			}
			if !reflect.DeepEqual(before, f.a.profiles) || f.starts != 1 || !f.a.state.Connected || mtuSuspended(f.a) {
				t.Fatal("named private Save altered the current connection or selected Home")
			}
			if repeated := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", save); repeated.Code != 409 {
				t.Fatal("same private receipt saved twice")
			}
			cold := &app{cfg: f.a.cfg, profiles: cloneRouterProfileStore(f.a.profiles)}
			loaded := postSetup(t, cold, "/api/connection-profile/setup/load", map[string]any{"id": store.Profiles[0].ID})
			selected, found := profileByID(cold.profiles.Profiles, cold.profiles.SelectedID)
			if loaded.Code != 200 || !found || selected.MultihopExecution != "auto" || !reflect.DeepEqual(selected.MultihopNodes, proposed) || cold.cmd != nil || cold.state.Connected {
				t.Fatal("cold public Load changed the measured Compare path", loaded.Code, loaded.Body.String())
			}
			cancel := map[string]string{"request_id": q.RequestID, "view_token": view.Token}
			for _, wrong := range []map[string]string{{"request_id": q.RequestID}, {"request_id": q.RequestID, "view_token": strings.Repeat("f", 64)}} {
				if reply := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/cancel", wrong); reply.Code != 409 {
					t.Fatal("connected cancellation borrowed another view", reply.Code, reply.Body.String())
				}
			}
			for retry := 0; retry < 2; retry++ {
				reply := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/cancel", cancel)
				if reply.Code != 200 {
					t.Fatal("original connected cancellation", reply.Code, reply.Body.String())
				}
				checkPrivateResponseCancel(t, reply.Body.Bytes(), view, q.RequestID, true)
			}
			// The HTTP cleanup has already joined the original child. Retire
			// its registry entry to exercise a retry after another owner takes
			// the slot; the public receipt must retain that completed boundary.
			control := viaEntryControlFor(f.a)
			control.mu.Lock()
			if control.owner == nil || !control.owner.drained {
				control.mu.Unlock()
				t.Fatal("connected owner was not joined before retirement")
			}
			control.owner = nil
			control.mu.Unlock()
			retried := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/cancel", cancel)
			if retried.Code != 200 {
				t.Fatal("retired connected owner lost its cancellation receipt", retried.Code, retried.Body.String())
			}
			checkPrivateResponseCancel(t, retried.Body.Bytes(), view, q.RequestID, true)
		})
	}
}

func TestDesktopSelectedPrivateResponseCancelBeforeStartRetainsIssuedSource(t *testing.T) {
	for _, layout := range selectedResponseFinalLayouts {
		if layout.count != 16 {
			continue
		}
		t.Run(layout.name, func(t *testing.T) { testSelectedResponseCancelBeforeStart(t, layout.privatePosition) })
	}
}

func testSelectedResponseCancelBeforeStart(t *testing.T, private int) {
	t.Helper()
	f, nodes, id := desktopSelectedResponseParentFixture(t, 16, private, "local")
	mux := http.NewServeMux()
	registerOrderedCandidateRoutes(mux, f.a)
	get := func() desktopSelectedCandidateHTTPTestView {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest("GET", "/api/multihop/prefix-candidates/catalog?prefix_position=14", nil))
		var view desktopSelectedCandidateHTTPTestView
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &view) != nil || !reflect.DeepEqual(view.ResponseNodes, responseExpectedSourceAt(nodes, private)) {
			t.Fatal("original cancellation catalog", response.Code, response.Body.String())
		}
		return view
	}
	original := get()
	other := get()
	request := strings.Repeat("e", 32)
	for retry := 0; retry < 2; retry++ {
		reply := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/cancel", map[string]string{"request_id": request, "view_token": original.Token})
		if reply.Code != 200 {
			t.Fatal("Cancel lost an issued view after another window refreshed", reply.Code, reply.Body.String())
		}
		checkPrivateResponseCancel(t, reply.Body.Bytes(), original, request, false)
	}
	if crossed := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/cancel", map[string]string{"request_id": request, "view_token": other.Token}); crossed.Code != 409 {
		t.Fatal("cancelled nonce rebound to a newer connected view")
	}
	if late := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates", orderedCandidateRequest{RequestID: request, ViewToken: other.Token, PrefixPosition: 14, CandidateIDs: []string{id}, Samples: 50}); late.Code != 409 {
		t.Fatal("delayed POST revived a cancelled connected request")
	}
	if viaEntryControlFor(f.a).owner != nil || f.starts != 1 || !f.a.state.Connected || mtuSuspended(f.a) {
		t.Fatal("prestart Cancel acquired a native child or changed the active VPN")
	}
}

func TestDesktopSelectedPrivateResponseConnectedServerWinnerHasNoPrivateOffer(t *testing.T) {
	for _, layout := range selectedResponseFinalLayouts {
		if layout.count != 16 {
			continue
		}
		t.Run(layout.name, func(t *testing.T) { testSelectedResponseServerWinner(t, layout.privatePosition) })
	}
}

func testSelectedResponseServerWinner(t *testing.T, private int) {
	t.Helper()
	f, _, _ := desktopSelectedResponseParentFixture(t, 16, private, "server")
	mux := http.NewServeMux()
	registerOrderedCandidateRoutes(mux, f.a)
	reply := httptest.NewRecorder()
	mux.ServeHTTP(reply, httptest.NewRequest("GET", "/api/multihop/prefix-candidates/catalog?prefix_position=14", nil))
	c := viaEntryControlFor(f.a)
	if reply.Code != 409 || c.orderedView != nil || len(c.orderedResponseViews) != 0 || c.owner != nil || f.starts != 1 || !f.a.state.Connected || mtuSuspended(f.a) {
		t.Fatal("Server winner published a Local private-response offer or changed the active VPN", reply.Code, reply.Body.String())
	}
}

func TestSelectedPrivateResponseDraftCancelBeforeStartRetainsSourceWithoutEpoch(t *testing.T) {
	for _, layout := range selectedResponseFinalLayouts {
		if layout.count != 16 {
			continue
		}
		t.Run(layout.name, func(t *testing.T) { testSelectedResponseDraftCancelBeforeStart(t, layout.privatePosition) })
	}
}

func testSelectedResponseDraftCancelBeforeStart(t *testing.T, private int) {
	t.Helper()
	a, nodes, id := selectedResponseAppFixture(t, 16, private)
	a, draft, q := selectedDraftSourceFixture(t, a, nodes, "auto", 14, id)
	view, err := captureOrderedCandidatePreparedSelection(context.Background(), a, 14, q.Scope, draft, func(context.Context) (string, error) { return "original-network", nil })
	if err != nil {
		t.Fatal(err)
	}
	c := viaEntryControlFor(a)
	c.mu.Lock()
	err = rememberOrderedCandidatePreparedViewLocked(c, view)
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"request_id": q.RequestID, "view_token": view.token, "scope": q.Scope})
	reply := httptest.NewRecorder()
	a.orderedCandidatePreparedCancel(reply, httptest.NewRequest("POST", "/api/multihop/draft-candidates/cancel", bytes.NewReader(payload)))
	var response struct {
		ResponseNodes              []orderedCandidateResponseSourceNode `json:"response_source_nodes"`
		Requested                  string                               `json:"requested_execution"`
		Required                   string                               `json:"required_selected_execution"`
		Selected                   *string                              `json:"selected_execution"`
		Epoch                      *uint64                              `json:"selection_epoch"`
		Started                    bool                                 `json:"started"`
		AdmissionCancelled         bool                                 `json:"admission_cancelled"`
		NativeDown                 bool                                 `json:"native_down"`
		Drained, Accepted, Running bool
	}
	if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &response) != nil || response.Requested != "auto" || response.Required != "local" || response.Selected != nil || response.Epoch != nil || response.Started || !response.AdmissionCancelled || response.NativeDown || !response.Drained || response.Accepted || response.Running || !reflect.DeepEqual(response.ResponseNodes, responseExpectedSourceAt(nodes, private)) {
		t.Fatal("prestart draft Cancel lost its exact source or invented a selection", reply.Code, reply.Body.String())
	}
}
