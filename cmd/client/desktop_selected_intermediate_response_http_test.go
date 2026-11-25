package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

var selectedIntermediateResponseLayouts = []struct{ count, position int }{{4, 1}, {9, 6}, {16, 8}, {16, 13}}

func checkIntermediateResponseFrame(t *testing.T, raw []byte, view desktopSelectedCandidateHTTPTestView, position int) {
	t.Helper()
	checkPrivateResponsePublicSource(t, raw, view)
	var frame struct {
		Position int `json:"prefix_position"`
	}
	if json.Unmarshal(raw, &frame) != nil || frame.Position != position {
		t.Fatal("intermediate response borrowed another eligible captured stop", string(raw))
	}
}

func TestDesktopSelectedIntermediateResponseHTTPPreservesOriginalSuffixAndNamedLoad(t *testing.T) {
	for _, layout := range selectedIntermediateResponseLayouts {
		t.Run(fmt.Sprintf("%d/%d", layout.count, layout.position), func(t *testing.T) {
			f, nodes, candidate := desktopSelectedResponseParentFixture(t, layout.count, -1, "local")
			before := cloneRouterProfileStore(f.a.profiles)
			identity, _, err := captureSpeedLabIdentityContext(context.Background(), f.a)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := captureDesktopNodeChainCandidates(context.Background(), f.a, identity, layout.position, []string{candidate})
			if err != nil {
				t.Fatal("captured intermediate plan", err)
			}
			view, request := exerciseDesktopSelectedCandidateHTTP(t, f, catalog, candidate, "local", layout.position, responseExpectedPositions(layout.count, -1))
			if !reflect.DeepEqual(view.ResponseNodes, responseExpectedSourceAt(nodes, -1)) {
				t.Fatal("intermediate offer changed the original source")
			}
			wanted := slices.Insert(slices.Clone(nodes), layout.position+1, common.MultihopNodeSelection{ID: candidate, Mode: "shadowsocks"})
			found := false
			for _, row := range view.Candidates {
				if row.SaveReason != "" || row.Kind != "router-vpn" || row.ProposalAction != "save-intermediate-profile" || len(row.Proposal) != layout.count+1 ||
					!slices.Equal(row.Proposal[:layout.position+1], nodes[:layout.position+1]) || !slices.Equal(row.Proposal[layout.position+2:], nodes[layout.position+1:]) ||
					row.Proposal[layout.position+1] != (common.MultihopNodeSelection{ID: row.ID, Mode: "shadowsocks"}) {
					t.Fatal("offered intermediate lost an original prefix or suffix")
				}
				for _, original := range nodes {
					if row.ID == original.ID {
						t.Fatal("offered an original suffix member")
					}
				}
				found = found || row.ID == candidate && slices.Equal(row.Proposal, wanted)
			}
			if !found {
				t.Fatal("missing complete intermediate proposal")
			}
			mux := http.NewServeMux()
			registerOrderedCandidateRoutes(mux, f.a)
			poll := httptest.NewRecorder()
			mux.ServeHTTP(poll, httptest.NewRequest("GET", "/api/multihop/prefix-candidates?request_id="+request.RequestID, nil))
			if poll.Code != 200 {
				t.Fatal(poll.Code, poll.Body.String())
			}
			checkIntermediateResponseFrame(t, poll.Body.Bytes(), view, layout.position)
			save := orderedCandidateSaveRequest{RequestID: request.RequestID, ViewToken: view.Token, CandidateID: candidate, Name: "Measured intermediate with original final", ProposedPath: slices.Clone(wanted)}
			// A candidate replacement, truncated suffix or another eligible stop
			// cannot stand in for the insertion originally measured at k.
			for _, wrong := range [][]common.MultihopNodeSelection{nodes, wanted[:len(wanted)-1], slices.Insert(slices.Clone(nodes), layout.position+2, common.MultihopNodeSelection{ID: candidate, Mode: "shadowsocks"})} {
				save.ProposedPath = wrong
				if r := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", save); r.Code != 409 {
					t.Fatal("crossed suffix or stop saved", r.Code, r.Body.String())
				}
			}
			save.ProposedPath = wanted
			result := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", save)
			if result.Code != 200 {
				t.Fatal("named intermediate Save", result.Code, result.Body.String())
			}
			checkIntermediateResponseFrame(t, result.Body.Bytes(), view, layout.position)
			var receipt struct {
				Action string                         `json:"proposal_action"`
				Path   []common.MultihopNodeSelection `json:"proposed_path"`
			}
			if json.Unmarshal(result.Body.Bytes(), &receipt) != nil || receipt.Action != "save-intermediate-profile" || !slices.Equal(receipt.Path, wanted) {
				t.Fatal("Save changed the captured intermediate action")
			}
			store, err := loadConnectionProfileStore(f.a)
			final := nodes[len(nodes)-1].ID
			if err != nil || len(store.Profiles) != 1 || store.Profiles[0].NodeID != final || len(store.Profiles[0].NodeChain) != len(wanted) ||
				store.Profiles[0].Prefs.MultihopExecution != "auto" || !slices.Equal(store.Profiles[0].Prefs.MultihopNodes, wanted) || !reflect.DeepEqual(before, f.a.profiles) ||
				f.starts != 1 || !f.a.state.Connected || mtuSuspended(f.a) {
				t.Fatal("intermediate Save changed Home, original final or current owner", err)
			}
			cold := &app{cfg: f.a.cfg, profiles: cloneRouterProfileStore(f.a.profiles)}
			loaded := postSetup(t, cold, "/api/connection-profile/setup/load", map[string]any{"id": store.Profiles[0].ID})
			profile, exists := profileByID(cold.profiles.Profiles, final)
			if loaded.Code != 200 || !exists || cold.profiles.SelectedID != final || profile.MultihopExecution != "auto" || !slices.Equal(profile.MultihopNodes, wanted) || cold.cmd != nil || cold.state.Connected {
				t.Fatal("explicit intermediate Load lost original suffix/final", loaded.Code, loaded.Body.String())
			}
			cancel := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/cancel", map[string]string{"request_id": request.RequestID, "view_token": view.Token})
			if cancel.Code != 200 {
				t.Fatal(cancel.Code, cancel.Body.String())
			}
			checkPrivateResponseCancel(t, cancel.Body.Bytes(), view, request.RequestID, true)
			checkIntermediateResponseFrame(t, cancel.Body.Bytes(), view, layout.position)
		})
	}
}

func TestDesktopSelectedIntermediateResponseRejectsChangedOriginalSuffixBeforeSave(t *testing.T) {
	f, nodes, candidate := desktopSelectedResponseParentFixture(t, 9, -1, "local")
	identity, _, err := captureSpeedLabIdentityContext(context.Background(), f.a)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := captureDesktopNodeChainCandidates(context.Background(), f.a, identity, 1, []string{candidate})
	if err != nil {
		t.Fatal(err)
	}
	view, request := exerciseDesktopSelectedCandidateHTTP(t, f, catalog, candidate, "local", 1, responseExpectedPositions(9, -1))
	wanted := slices.Insert(slices.Clone(nodes), 2, common.MultihopNodeSelection{ID: candidate, Mode: "shadowsocks"})
	f.a.mu.Lock()
	changed := false
	for i := range f.a.profiles.Profiles {
		profile := &f.a.profiles.Profiles[i]
		if profile.ID == nodes[6].ID {
			if profile.External == nil || profile.External.Shadowsocks == nil {
				t.Fatal("untouched suffix is not the original imported source")
			}
			profile.External.Shadowsocks.Server = "203.0.113.211"
			changed = true
		}
	}
	f.a.mu.Unlock()
	if !changed {
		t.Fatal("untouched suffix source missing")
	}
	r := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/save-profile", orderedCandidateSaveRequest{RequestID: request.RequestID, ViewToken: view.Token, CandidateID: candidate, Name: "Must not save changed suffix", ProposedPath: wanted})
	store, err := loadConnectionProfileStore(f.a)
	if r.Code != 409 || err != nil || len(store.Profiles) != 0 {
		t.Fatal("stale untouched suffix saved", r.Code, r.Body.String(), err)
	}
}

func TestDesktopSelectedIntermediateResponseDraftRetainsOriginalSuffixThroughDownSaveAndLoad(t *testing.T) {
	for _, layout := range selectedIntermediateResponseLayouts {
		t.Run(fmt.Sprintf("%d/%d", layout.count, layout.position), func(t *testing.T) {
			a, nodes, candidate := selectedResponseAppFixture(t, layout.count, -1)
			a, draft, request := selectedDraftSourceFixture(t, a, nodes, "auto", layout.position, candidate)
			testOriginalSelectedDraftLifecycle(t, a, draft, request, [3]string{"auto", "local", "private-intermediate"})
		})
	}
}

func TestDesktopSelectedIntermediateResponseDraftServerWinnerClosesWithoutScores(t *testing.T) {
	a, nodes, candidate := selectedResponseAppFixture(t, 16, -1)
	a, draft, request := selectedDraftSourceFixture(t, a, nodes, "auto", 8, candidate)
	testOriginalSelectedDraftLifecycle(t, a, draft, request, [3]string{"auto", "server", "private-server-refusal"})
}

func TestDesktopSelectedIntermediateResponseCancelCannotBorrowAnotherEligibleStop(t *testing.T) {
	f, nodes, candidate := desktopSelectedResponseParentFixture(t, 16, -1, "local")
	mux := http.NewServeMux()
	registerOrderedCandidateRoutes(mux, f.a)
	get := func(position int) desktopSelectedCandidateHTTPTestView {
		reply := httptest.NewRecorder()
		mux.ServeHTTP(reply, httptest.NewRequest("GET", fmt.Sprintf("/api/multihop/prefix-candidates/catalog?prefix_position=%d", position), nil))
		var view desktopSelectedCandidateHTTPTestView
		if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &view) != nil || !reflect.DeepEqual(view.ResponseNodes, responseExpectedSourceAt(nodes, -1)) {
			t.Fatal("original stop catalog", reply.Code, reply.Body.String())
		}
		return view
	}
	original, other := get(8), get(9)
	request := strings.Repeat("e", 32)
	for i := 0; i < 2; i++ {
		reply := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/cancel", map[string]string{"request_id": request, "view_token": original.Token})
		if reply.Code != 200 {
			t.Fatal(reply.Code, reply.Body.String())
		}
		checkPrivateResponseCancel(t, reply.Body.Bytes(), original, request, false)
		checkIntermediateResponseFrame(t, reply.Body.Bytes(), original, 8)
	}
	if crossed := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates/cancel", map[string]string{"request_id": request, "view_token": other.Token}); crossed.Code != 409 {
		t.Fatal("cancelled admission borrowed another eligible stop")
	}
	if late := orderedCandidateHTTP(t, f.a, "/api/multihop/prefix-candidates", orderedCandidateRequest{RequestID: request, ViewToken: other.Token, PrefixPosition: 9, CandidateIDs: []string{candidate}, Samples: 50}); late.Code != 409 {
		t.Fatal("delayed request revived under another eligible stop")
	}
	if viaEntryControlFor(f.a).owner != nil || f.starts != 1 || !f.a.state.Connected || mtuSuspended(f.a) {
		t.Fatal("prestart intermediate Cancel started a child or changed the original VPN")
	}
}

func TestDesktopSelectedIntermediateResponseDraftPrestartCancelRetainsExactStopWithoutEpoch(t *testing.T) {
	a, nodes, candidate := selectedResponseAppFixture(t, 16, -1)
	a, draft, request := selectedDraftSourceFixture(t, a, nodes, "auto", 8, candidate)
	observe := func(context.Context) (string, error) { return "original-intermediate-network", nil }
	control := viaEntryControlFor(a)
	var views []*orderedCandidatePreparedView
	for _, position := range []int{8, 9} {
		view, err := captureOrderedCandidatePreparedSelection(context.Background(), a, position, request.Scope, draft, observe)
		if err != nil {
			t.Fatal(err)
		}
		control.mu.Lock()
		err = rememberOrderedCandidatePreparedViewLocked(control, view)
		control.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		views = append(views, view)
	}
	for i := 0; i < 2; i++ {
		reply := orderedCandidateHTTP(t, a, "/api/multihop/draft-candidates/cancel", map[string]string{"request_id": request.RequestID, "view_token": views[0].token, "scope": request.Scope})
		var frame struct {
			Position                            int                                  `json:"prefix_position"`
			Source                              []orderedCandidateResponseSourceNode `json:"response_source_nodes"`
			Epoch                               *uint64                              `json:"selection_epoch"`
			Selected                            *string                              `json:"selected_execution"`
			NativeDown                          bool                                 `json:"native_down"`
			AdmissionCancelled                  bool                                 `json:"admission_cancelled"`
			Drained, Running, Started, Accepted bool
		}
		if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &frame) != nil || frame.Position != 8 || !reflect.DeepEqual(frame.Source, responseExpectedSourceAt(nodes, -1)) || frame.Epoch != nil || frame.Selected != nil || frame.NativeDown || !frame.AdmissionCancelled || !frame.Drained || frame.Running || frame.Started || frame.Accepted {
			t.Fatal("prestart draft Cancel changed its measured stop or invented a native epoch", reply.Code, reply.Body.String())
		}
	}
	if crossed := orderedCandidateHTTP(t, a, "/api/multihop/draft-candidates/cancel", map[string]string{"request_id": request.RequestID, "view_token": views[1].token, "scope": request.Scope}); crossed.Code != 409 {
		t.Fatal("draft nonce rebound to another eligible source stop", crossed.Code, crossed.Body.String())
	}
}
