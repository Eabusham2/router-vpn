package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

func TestSelectedPrivateResponseDraftUsePreservesUnsavedPath(t *testing.T) {
	for _, layout := range []struct{ count, position int }{{3, 1}, {4, 1}, {4, 2}, {9, 6}, {16, 8}, {16, 14}} {
		t.Run(fmt.Sprintf("%d/%d", layout.count, layout.position), func(t *testing.T) {
			a, nodes, candidate := selectedResponseAppFixture(t, layout.count, -1)
			a, draft, request := selectedDraftSourceFixture(t, a, nodes, "auto", layout.position, candidate)
			testOriginalSelectedDraftLifecycle(t, a, draft, request, [3]string{"auto", "local", "private-use"})
		})
	}
}

func TestSelectedPrivateResponseDraftUseStartsFreshMeasurement(t *testing.T) {
	a, nodes, candidate := selectedResponseAppFixtureWithCandidates(t, 3, -1, 2)
	a, draft, request := selectedDraftSourceFixture(t, a, nodes, "auto", 1, candidate)
	testOriginalSelectedDraftLifecycle(t, a, draft, request, [3]string{"auto", "local", "private-use-recursive"})
}

func TestSelectedPrivateResponseDraftUseRejectsChangedOwner(t *testing.T) {
	for _, mutation := range []string{"source", "network", "epoch", "cancelled", "expired", "file-candidate", "file-final"} {
		t.Run(mutation, func(t *testing.T) {
			a, nodes, candidate := selectedResponseAppFixture(t, 9, -1)
			a, draft, request := selectedDraftSourceFixture(t, a, nodes, "auto", 1, candidate)
			testOriginalSelectedDraftLifecycle(t, a, draft, request, [3]string{"auto", "local", "private-use-" + mutation})
		})
	}
}

// The controller's response is an in-memory editor transaction. Every native
// publication, sample receipt and DOWN transition preceding this helper comes
// from the same original selected-worker fixture used by the named Save tests.
func testOriginalSelectedResponseDraftUse(t *testing.T, ctx context.Context, p *orderedCandidatePreparation, view *orderedCandidatePreparedView,
	before common.RouterProfileStore, network *selectedDraftNetworkFixture, epoch uint64, behavior string) {
	t.Helper()
	a, q, job := p.app, p.request, p.owner.prepared
	draft := q.draft
	wanted := slices.Insert(slices.Clone(draft.Nodes), q.Position+1, common.MultihopNodeSelection{ID: q.CandidateIDs[0], Mode: "shadowsocks"})
	var offered *orderedCandidateChoice
	for i := range view.candidates {
		if view.candidates[i].ID == q.CandidateIDs[0] {
			offered = &view.candidates[i]
		}
	}
	if offered == nil || offered.DraftAction != orderedCandidateDraftInsertAction || !slices.Equal(offered.DraftProposal, wanted) {
		t.Fatal("original view did not compile its independent full draft insertion")
	}
	if q.Position == len(draft.Nodes)-2 && (offered.ProposalAction != "save-final-profile" || slices.Equal(offered.Proposal, offered.DraftProposal) || len(offered.Proposal) != len(draft.Nodes)) {
		t.Fatal("penultimate draft insertion replaced the separate named final offer")
	}
	payload := map[string]any{"request_id": q.RequestID, "view_token": view.token, "candidate_id": q.CandidateIDs[0], "proposed_path": wanted, "scope": q.Scope}
	const endpoint = "/api/multihop/draft-candidates/choose"
	for _, change := range []string{"old-path", "wrong-view", "wrong-scope", "name", "not-down", "different-epoch"} {
		oldEpoch := p.runtime.selectedReady.SelectionEpoch
		switch change {
		case "old-path":
			payload["proposed_path"] = draft.Nodes
		case "wrong-view":
			payload["view_token"] = strings.Repeat("0", 64)
		case "wrong-scope":
			payload["scope"] = orderedCandidateSavedCompleteScope
		case "name":
			payload["name"] = "An implicit profile must not be saved"
		case "not-down":
			job.nativeDown = false
		case "different-epoch":
			p.runtime.selectedReady.SelectionEpoch++
		}
		out := orderedCandidateHTTP(t, a, endpoint, payload)
		if out.Code < 400 || job.saved != nil || !reflect.DeepEqual(before, a.profiles) {
			t.Fatal("draft Use accepted foreign action or ownership", change, out.Code, out.Body.String())
		}
		payload["proposed_path"], payload["view_token"], payload["scope"] = wanted, view.token, q.Scope
		delete(payload, "name")
		job.nativeDown = true
		p.runtime.selectedReady.SelectionEpoch = oldEpoch
	}

	changed := behavior != "private-use" && behavior != "private-use-recursive"
	assetReplaced := false
	switch behavior {
	case "private-use-source":
		a.mu.Lock()
		for i := range a.profiles.Profiles {
			if a.profiles.Profiles[i].ID == draft.Nodes[len(draft.Nodes)-3].ID {
				a.profiles.Profiles[i].External.Shadowsocks.Server = "203.0.113.211"
			}
		}
		a.mu.Unlock()
	case "private-use-network":
		network.lost = true
	case "private-use-epoch":
		p.runtime.selectedReady.SelectionEpoch++
	case "private-use-cancelled":
		p.control.mu.Lock()
		p.owner.cancelled = true
		p.control.mu.Unlock()
	case "private-use-expired":
		job.expires = time.Now().Add(-time.Second)
	case "private-use-file-candidate", "private-use-file-final":
		id := q.CandidateIDs[0]
		if behavior == "private-use-file-final" {
			id = draft.Nodes[len(draft.Nodes)-1].ID
		}
		file := filepath.Join(clientRoot(a), "generated", id, "shadowsocks", "sing-box.json")
		observe := p.observeNetwork
		p.observeNetwork = func(ctx context.Context) (string, error) {
			physical, err := observe(ctx)
			if err != nil || !p.down || assetReplaced {
				return physical, err
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				return "", err
			}
			err = os.WriteFile(file, append(raw, '\n'), 0600)
			assetReplaced = err == nil
			return physical, err
		}
	}
	currentProfiles := cloneRouterProfileStore(a.profiles)
	out := orderedCandidateHTTP(t, a, endpoint, payload)
	if changed {
		if strings.HasPrefix(behavior, "private-use-file-") && !assetReplaced {
			t.Fatal("source replacement did not reach the original post-DOWN delivery boundary")
		}
		if out.Code != 409 || job.saved != nil || !reflect.DeepEqual(currentProfiles, a.profiles) {
			t.Fatal("changed source or owner delivered an unsaved draft choice", behavior, out.Code, out.Body.String())
		}
		cancelled := orderedCandidateHTTP(t, a, "/api/multihop/draft-candidates/cancel", map[string]any{"request_id": q.RequestID, "view_token": view.token, "scope": q.Scope})
		if cancelled.Code != 200 || !p.down || a.candidatePreparation != nil || network.phase != 6 {
			t.Fatal("refused choice did not join its original owner", cancelled.Code, cancelled.Body.String())
		}
		return
	}
	var chosen struct {
		Chosen, Drained, NativeDown, Saved, ActivePathChanged bool
		RequestID                                             string                               `json:"request_id"`
		ViewToken                                             string                               `json:"view_token"`
		CandidateID                                           string                               `json:"candidate_id"`
		Position                                              int                                  `json:"prefix_position"`
		DraftAction                                           string                               `json:"draft_action"`
		Requested                                             string                               `json:"requested_execution"`
		Selected                                              string                               `json:"selected_execution"`
		Required                                              string                               `json:"required_selected_execution"`
		Epoch                                                 uint64                               `json:"selection_epoch"`
		Measurement                                           string                               `json:"measurement"`
		Nodes                                                 []common.MultihopNodeSelection       `json:"proposed_path"`
		Source                                                []orderedCandidateResponseSourceNode `json:"response_source_nodes"`
		SelectedID                                            string                               `json:"expected_selected_node_id"`
		Tokens                                                map[string]string                    `json:"expected_profile_tokens"`
		SavedID                                               string                               `json:"saved_profile_id"`
		ProfileID                                             string                               `json:"profile_id"`
	}
	// Underscored booleans require their explicit wire names as well.
	var wire map[string]any
	if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &chosen) != nil || json.Unmarshal(out.Body.Bytes(), &wire) != nil ||
		!chosen.Chosen || !chosen.Drained || wire["native_down"] != true || wire["active_path_changed"] != false || chosen.Saved || chosen.SavedID != "" || chosen.ProfileID != "" ||
		chosen.RequestID != q.RequestID || chosen.ViewToken != view.token || chosen.CandidateID != q.CandidateIDs[0] || chosen.Position != q.Position ||
		chosen.DraftAction != orderedCandidateDraftInsertAction || chosen.Requested != "auto" || chosen.Selected != "local" || chosen.Required != "local" || chosen.Epoch != epoch ||
		chosen.Measurement != hopmeasure.CandidatePrivateResponseMeasurement || !slices.Equal(chosen.Nodes, wanted) || !reflect.DeepEqual(chosen.Source, view.responseNodes) ||
		chosen.SelectedID != before.SelectedID || len(chosen.Tokens) != len(wanted) || job.saved != nil || !p.down || !p.owner.drained || a.candidatePreparation != nil ||
		a.state.Connected || a.cmd != nil || network.phase != 6 || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("Use lost its original response proof or changed persistent/Home state", out.Code, out.Body.String())
	}
	for _, node := range wanted {
		profile, found := profileByID(before.Profiles, node.ID)
		if !found || chosen.Tokens[node.ID] != publicProfileToken(profile) {
			t.Fatal("Use returned credentials or tokens from another source")
		}
	}
	if replay := orderedCandidateHTTP(t, a, endpoint, payload); replay.Code != 409 {
		t.Fatal("consumed result authorized another draft choice", replay.Code)
	}
	payload["name"], payload["proposed_path"] = "Must not save a consumed result", offered.Proposal
	if replay := orderedCandidateHTTP(t, a, "/api/multihop/draft-candidates/save-profile", payload); replay.Code != 409 {
		t.Fatal("consumed draft result authorized a later persistent Save", replay.Code)
	}
	if behavior != "private-use-recursive" {
		return
	}
	var nextCandidate string
	for _, profile := range a.profiles.Profiles {
		if _, used := chosen.Tokens[profile.ID]; !used && profile.External == nil {
			nextCandidate = profile.ID
			break
		}
	}
	if nextCandidate == "" {
		t.Fatal("recursive fixture has no independent next candidate")
	}
	nextDraft := &multihopConnectRequest{Execution: "auto", Nodes: slices.Clone(chosen.Nodes), desktopProfileExpectations: desktopProfileExpectations{
		ExpectedSelectedNodeID: &chosen.SelectedID, ExpectedProfileTokens: chosen.Tokens}}
	next := orderedCandidatePreparationRequest{draft: nextDraft, Scope: q.Scope, RequestID: strings.Repeat("b", 32), Position: len(nextDraft.Nodes) - 2, CandidateIDs: []string{nextCandidate}, Samples: 50}
	nextView, err := captureOrderedCandidatePreparedSelection(ctx, a, next.Position, next.Scope, nextDraft, func(ctx context.Context) (string, error) { return "original-chain-physical-network", ctx.Err() })
	if err != nil || nextView.token == view.token || nextView.selection.Native.source == view.selection.Native.source ||
		!slices.Equal(nodeChainSelectedReferences(nextView.selection.Nodes), chosen.Nodes) || next.RequestID == q.RequestID {
		t.Fatal("recursive draft reused the old source or request", err)
	}
	testOriginalSelectedDraftLifecycle(t, a, nextDraft, next, [3]string{"auto", "local", "private-measure-only"})
}

func TestSelectedPrivateResponseDraftUseRejectsSecondPrivateAndCapacity(t *testing.T) {
	ctx := context.Background()
	a, nodes, candidate := selectedResponseAppFixture(t, 5, 2)
	a, draft, request := selectedDraftSourceFixture(t, a, nodes, "auto", 3, candidate)
	view, err := captureOrderedCandidatePreparedSelection(ctx, a, request.Position, request.Scope, draft, func(ctx context.Context) (string, error) { return "source-capacity-network", ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, offer := range view.candidates {
		if offer.ID == candidate {
			seen = true
			if len(offer.DraftProposal) != 0 || offer.DraftAction != "" || offer.ProposalAction != "save-final-profile" || len(offer.Proposal) != len(nodes) {
				t.Fatal("one-private source lost named Save or admitted two-private draft Use")
			}
		}
	}
	if !seen {
		t.Fatal("original penultimate named offer disappeared")
	}
	a, nodes, candidate = selectedResponseAppFixture(t, 4, -1)
	a, draft, request = selectedDraftSourceFixture(t, a, nodes, "auto", 2, candidate)
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "auto")
	if err != nil {
		t.Fatal(err)
	}
	member := selection.Nodes[1]
	members := append([]desktopNodeChainMember(nil), selection.Nodes[:1]...)
	for i := 1; i < mobilemultihop.NodeChainExtendedLocalMaximumNodes-1; i++ {
		copy := member
		copy.Profile = cloneRouterProfile(member.Profile)
		copy.Profile.ID = fmt.Sprintf("capacity-import-%d", i)
		members = append(members, copy)
	}
	members = append(members, selection.Nodes[len(selection.Nodes)-1])
	profile, _ := a.profileByIDLocked(candidate)
	position := len(members) - 2
	if !desktopCompareLocalResponseProposal(members, "auto", position, profile) {
		t.Fatal("96-member source shape did not retain its penultimate named grant")
	}
	if _, _, err := orderedResponseDraftProposal(ctx, clientRoot(a), "auto", members, position, profile, a.profiles.Profiles); err == nil || !strings.Contains(err.Error(), "cannot be inserted") {
		t.Fatal("draft Use exceeded the 96-member compiler capacity", err)
	}
}
