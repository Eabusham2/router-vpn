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
	"slices"
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
		t.Run(fmt.Sprint(count), func(t *testing.T) { testOrderedCandidateDraftNamedFinal(t, count, "wg", false) })
	}
}
func TestOrderedCandidateDraftNamedFinalPacketAndHostname(t *testing.T) {
	for _, spec := range []struct {
		count    int
		mode     string
		hostname bool
	}{{3, "awg2-fast", false}, {4, "wg", false}, {3, "wg", true}, {4, "awg2-strong", true}} {
		t.Run(fmt.Sprintf("%d-%s-hostname-%t", spec.count, spec.mode, spec.hostname), func(t *testing.T) { testOrderedCandidateDraftNamedFinal(t, spec.count, spec.mode, spec.hostname) })
	}
}

func TestOrderedCandidateDraftNamedIntermediateKeepsSuffix(t *testing.T) {
	testOrderedCandidateDraftNamed(t, 4, "wg", false, 1)
	testOrderedCandidateDraftNamed(t, 6, "wg", false, 2)
	testOrderedCandidateDraftNamed(t, 8, "wg", false, 5)
	testOrderedCandidateDraftNamed(t, 9, "wg", true, 1)
}

func testOrderedCandidateDraftNamedFinal(t *testing.T, count int, mode string, hostname bool) {
	t.Helper()
	testOrderedCandidateDraftNamed(t, count, mode, hostname, count-2)
}
func testOrderedCandidateDraftNamed(t *testing.T, count int, mode string, hostname bool, selected int) {
	ctx := t.Context()
	final := count - 1
	interior := selected < final-1
	inventorySize := count + 1
	if interior {
		inventorySize++ // A fresh private candidate for the reopened measured path.
	}
	a, inventory := desktopNodeChainCaptureFixture(t, inventorySize)
	if mode != "wg" {
		modes := make([]string, len(inventory))
		for i := range modes {
			modes[i] = "wg"
			if i < selected {
				modes[i] = mode
			}
		}
		modes[len(modes)-1] = "shadowsocks"
		installOrderedAWGAssets(t, a, inventory, modes, "off")
	}
	rows := append([]common.MultihopNodeSelection(nil), inventory[:count]...)
	rows[final].Mode = "shadowsocks"
	if hostname && !interior {
		installDesktopOrderedHostname(t, a, rows)
	} else if count <= 8 && !interior {
		installDesktopOrderedImported(t, a, rows)
	} else {
		positions := make([]int, count-2)
		for i := range positions {
			positions[i] = i + 1
		}
		installDesktopIndependentImports(t, a, rows, positions)
		if hostname {
			p := &a.profiles.Profiles[1]
			p.Endpoint, p.External.Shadowsocks.Server = "original.example.test", "original.example.test"
			p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "custom", "tcp", "10.81.0.53", 5353
			if err := common.NormalizeRouterProfile(p); err != nil {
				t.Fatal(err)
			}
		}
	}
	home, candidate := rows[final].ID, inventory[count].ID
	// The candidate owns an independent cipher, private token, router ID and
	// endpoint. Replacing just its public ID cannot reconstruct its transport.
	keyFor := func(id, keyByte string) {
		t.Helper()
		file := filepath.Join(clientRoot(a), "generated", id, "shadowsocks", "sing-box.json")
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		oldKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
		newKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(keyByte, 32)))
		if strings.Count(string(raw), oldKey) != 1 {
			t.Fatal("ambiguous paired candidate fixture key")
		}
		if err := os.WriteFile(file, []byte(strings.Replace(string(raw), oldKey, newKey, 1)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	keyFor(candidate, "x")
	if interior {
		keyFor(inventory[count+1].ID, "y")
	}
	a.profiles.Profiles[final].MultihopEnabled, a.profiles.Profiles[final].MultihopExecution = true, "local"
	for i := count; i < len(a.profiles.Profiles); i++ {
		a.profiles.Profiles[i].MultihopNodes = nil
		a.profiles.Profiles[i].MultihopEnabled, a.profiles.Profiles[i].MultihopExecution = false, ""
	}
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
	action, savedControl := "save-final-profile", candidate
	if interior {
		expected = slices.Insert(expected, selected+1, common.MultihopNodeSelection{ID: candidate, Mode: "shadowsocks"})
		action, savedControl = "save-intermediate-profile", home
	} else {
		expected[final].ID = candidate
	}
	var choice orderedCandidateChoice
	for _, c := range view.candidates {
		if c.ID == candidate {
			choice = c
		}
	}
	if choice.ProposalAction != action || choice.SaveReason != "" || !reflect.DeepEqual(choice.Proposal, expected) {
		t.Fatal("candidate proposal", choice, expected)
	}
	review := func(request orderedCandidatePreparationRequest, view *orderedCandidatePreparedView, candidate string) {
		t.Helper()
		control := viaEntryControlFor(a)
		if err := reserveOrderedCandidatePreparedAdmissionLocked(control, request.RequestID, view); err != nil {
			t.Fatal(err)
		}
		p, err := beginOrderedCandidatePreparationWithNetwork(ctx, a, request, observe)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.finish() })
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
	}
	review(request, view, candidate)
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
	if interior {
		shortened := slices.Clone(expected[:selected+2])
		payload["proposed_path"] = shortened
		if r := orderedCandidateHTTP(t, a, path, payload); r.Code != 409 {
			t.Fatal("truncated suffix admitted", r.Code)
		}
		forged := slices.Clone(expected)
		forged[len(forged)-2], forged[len(forged)-1] = forged[len(forged)-1], forged[len(forged)-2]
		payload["proposed_path"] = forged
		if r := orderedCandidateHTTP(t, a, path, payload); r.Code != 409 {
			t.Fatal("reordered suffix admitted", r.Code)
		}
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
		if err := json.Unmarshal(r.Body.Bytes(), &v); err != nil || !v.Saved || v.ID == "" || v.Candidate != candidate || v.Action != action || !reflect.DeepEqual(v.Path, expected) || (i > 0 && id != v.ID) {
			t.Fatal("saved result lost original identity", v, err)
		}
		id = v.ID
	}
	w := httptest.NewRecorder()
	a.orderedCandidatePreparedStatus(w, httptest.NewRequest(http.MethodGet, "/api/multihop/draft-candidates?request_id="+request.RequestID, nil))
	cancelled := orderedCandidateHTTP(t, a, "/api/multihop/draft-candidates/cancel", map[string]any{"request_id": request.RequestID, "view_token": view.token, "scope": request.Scope})
	for _, r := range []*httptest.ResponseRecorder{w, cancelled} {
		var v map[string]any
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v["saved_profile_id"] != id || v["candidate_id"] != candidate || v["proposal_action"] != action || v["active_path_changed"] != false || v["measurement"] != hopmeasure.CandidatePrivateResponseMeasurement {
			t.Fatal("lost saved status/late cancel identity", r.Code, r.Body.String())
		}
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil || len(store.Profiles) != 1 || store.Profiles[0].ID != id || store.Profiles[0].Name != payload["name"] || store.Profiles[0].NodeID != savedControl || store.Profiles[0].Prefs == nil || !reflect.DeepEqual(store.Profiles[0].Prefs.MultihopNodes, expected) || !reflect.DeepEqual(initial, a.profiles) || a.state.Connected {
		t.Fatal("named Save changed Home or appended twice", err, len(store.Profiles))
	}
	if interior {
		loaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
		if loaded.Code != http.StatusOK {
			t.Fatal("load saved intermediate", loaded.Code, loaded.Body.String())
		}
		current, found := a.profileByIDLocked(home)
		if !found || !reflect.DeepEqual(current.MultihopNodes, expected) || current.MultihopExecution != "local" || a.state.Connected {
			t.Fatal("loaded path lost original suffix, selection or Local execution")
		}
		loadedTokens := map[string]string{}
		for _, row := range expected {
			p, _ := a.profileByIDLocked(row.ID)
			loadedTokens[row.ID] = publicProfileToken(p)
		}
		reopened := &multihopConnectRequest{Execution: "local", Nodes: expected, desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &home, ExpectedProfileTokens: loadedTokens}}
		second := inventory[count+1].ID
		recursive := slices.Insert(slices.Clone(expected), selected+2, common.MultihopNodeSelection{ID: second, Mode: "shadowsocks"})
		for _, position := range []int{selected + 2, selected + 1} {
			next, err := captureOrderedCandidatePreparedSelection(ctx, a, position, request.Scope, reopened, observe)
			if err != nil || candidateViewMetric(next.prefixes, position) != hopmeasure.CandidatePrivateResponseMeasurement {
				t.Fatal("reopened recursive position lost its private response path", position, err)
			}
			found := false
			for _, choice := range next.candidates {
				if choice.ID == inventory[count+1].ID {
					found = choice.Kind == "router-vpn"
					if position == selected+1 && (choice.ProposalAction != "save-intermediate-profile" || choice.SaveReason != "" || !slices.Equal(choice.Proposal, recursive)) {
						t.Fatal("recursive insertion lost the original suffix", choice.SaveReason)
					}
				}
			}
			if !found || next.catalog.prefixPreparation == nil || next.catalog.prefixPreparation.PrefixPosition() != position {
				t.Fatal("fresh candidate lost its original closed-prefix source", position)
			}
			if position == selected+1 {
				request := orderedCandidatePreparationRequest{RequestID: strings.Repeat("b", 32), Samples: 50, Scope: orderedCandidateSavedPrefixScope, Position: position, CandidateIDs: []string{second}, draft: reopened}
				savedView, err := captureOrderedCandidatePreparedSelection(ctx, a, position, request.Scope, nil, observe)
				if err != nil {
					t.Fatal("saved performance recursive catalog", err)
				}
				matched := false
				for _, c := range savedView.candidates {
					if c.ID == second && c.SaveReason == "" && slices.Equal(c.Proposal, recursive) {
						matched = true
					}
				}
				if !matched {
					t.Fatal("saved performance proposal replaced an original member")
				}
				review(request, next, second)
				body := map[string]any{"request_id": request.RequestID, "view_token": next.token, "candidate_id": second, "proposed_path": recursive, "scope": request.Scope, "name": "Recursive measured profile"}
				w := orderedCandidateHTTP(t, a, path, body)
				var response struct {
					ID string `json:"saved_profile_id"`
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.ID == "" || response.ID == id {
					t.Fatal("recursive named save", w.Code, w.Body.String())
				}
				reloaded := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": response.ID})
				profile, ok := a.profileByIDLocked(home)
				if reloaded.Code != 200 || !ok || !slices.Equal(profile.MultihopNodes, recursive) {
					t.Fatal("recursive Load changed source order", reloaded.Code, reloaded.Body.String())
				}
				members, err := resolveDesktopNodeChainMembers(profile, a.profiles.Profiles, recursive, "local")
				if err != nil {
					t.Fatal(err)
				}
				members[position].Profile.NodeKind = "foreign"
				if _, err := desktopNodeChainSourceSchema(members); err == nil {
					t.Fatal("foreign source kind borrowed a paired stream identity")
				}
				t.Setenv("HOMEVPN_PORTABLE", "0")
				manifest := filepath.Join(clientRoot(a), "runtime", "native", "NATIVE-RUNTIME.json")
				if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifest, []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if nativeNodeChainPlatformSupported() {
					capture, err := captureStartupNodeChain(a, profile, a.profiles.Profiles, nil)
					if err != nil {
						t.Fatal("recursive startup source", err)
					}
					last := startupOrderedReceipt(t, &startupPolicyCapture{nodeChain: capture})
					reopened, err := captureStartupNodeChain(a, profile, a.profiles.Profiles, &last)
					if err != nil || !reflect.DeepEqual(reopened.receipt(), last.NodeChain) {
						t.Fatal("recursive Last lost a source or private interior", err)
					}
				}
			}
		}
	}
}
