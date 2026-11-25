//go:build linux || windows || (darwin && (amd64 || arm64))

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
)

func publicCandidateFixtureImport(t *testing.T, index int) common.RouterProfile {
	t.Helper()
	q := createRequestFor("shadowsocks")
	q.Name = fmt.Sprintf("Original external %d", index)
	q.Server, q.Port, q.ExpectedPublicIP = fmt.Sprintf("192.0.2.%d", index), 32000+index, fmt.Sprintf("198.51.100.%d", index)
	key := sha256.Sum256([]byte("public candidate fixture " + strconv.Itoa(index)))
	q.Method, q.Secret = "2022-blake3-aes-256-gcm", base64.StdEncoding.EncodeToString(key[:])
	p, err := externalProfileFromCreateRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	p.ID, p.StartLayer = fmt.Sprintf("public-candidate-%d", index), "off"
	p.KillSwitch, p.KillSwitchPolicy = true, "on-connect"
	if err = common.NormalizeRouterProfile(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func publicCandidateApp(t *testing.T, count int) (*app, []common.MultihopNodeSelection, []string) {
	t.Helper()
	a, nodes := desktopExternalFinalFixture(t, min(count, 9), "home")
	for index := len(nodes); index < count; index++ {
		p := publicCandidateFixtureImport(t, index)
		a.profiles.Profiles = append(a.profiles.Profiles, p)
		nodes = slices.Insert(nodes, len(nodes)-1, common.MultihopNodeSelection{ID: p.ID, Mode: "shadowsocks"})
	}
	a.profiles.Profiles[0].MultihopNodes = slices.Clone(nodes)
	first, second := publicCandidateFixtureImport(t, 170), publicCandidateFixtureImport(t, 171)
	ambiguous := publicCandidateFixtureImport(t, 175)
	ambiguousCopy := cloneRouterProfile(ambiguous)
	ambiguousCopy.ID = "candidate-alias-of-175"
	suffix, _ := a.profileByIDLocked(nodes[len(nodes)-1].ID)
	suffixAlias := cloneRouterProfile(suffix)
	suffixAlias.ID = "candidate-alias-of-original-final"
	a.profiles.Profiles = append(a.profiles.Profiles, ambiguous, first, ambiguousCopy, suffixAlias, second)
	a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
	t.Setenv("HOMEVPN_ROOT", clientRoot(a))
	desktopCONNECTSelectPublicHandler(t, a)
	return a, nodes, []string{first.ID, second.ID}
}

func publicCandidateEditorDraft(t *testing.T, a *app, nodes []common.MultihopNodeSelection) *multihopConnectRequest {
	t.Helper()
	selected := a.profiles.SelectedID
	tokens := map[string]string{}
	for _, n := range nodes {
		p, ok := a.profileByIDLocked(n.ID)
		if !ok {
			t.Fatal("missing linked source", n.ID)
		}
		tokens[n.ID] = publicProfileToken(p)
	}
	return &multihopConnectRequest{Execution: "local", ExternalFinal: true, Nodes: slices.Clone(nodes), desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: tokens}}
}

func originalPublicCandidateNetwork(ctx context.Context) (string, error) {
	return "original-public-candidate-network", ctx.Err()
}

func publicCandidateCatalog(t *testing.T, a *app, draft *multihopConnectRequest, pos int, wantIDs []string) *orderedCandidatePreparedView {
	t.Helper()
	path, method := "/api/multihop/saved-candidates/catalog", http.MethodGet
	var raw []byte
	if draft != nil {
		path, method = "/api/multihop/draft-candidates/catalog", http.MethodPost
		var err error
		raw, err = json.Marshal(draft)
		if err != nil {
			t.Fatal(err)
		}
	}
	url := path + "?scope=" + orderedCandidateSavedPrefixScope + "&prefix_position=" + strconv.Itoa(pos)
	reply := httptest.NewRecorder()
	a.orderedCandidatePreparedCatalogWithNetwork(reply, httptest.NewRequest(method, url, bytes.NewReader(raw)), originalPublicCandidateNetwork)
	var body struct {
		Metric     string                               `json:"measurement"`
		Token      string                               `json:"view_token"`
		Execution  string                               `json:"requested_execution"`
		Public     bool                                 `json:"external_final"`
		Nodes      []orderedCandidateResponseSourceNode `json:"public_response_source_nodes"`
		Candidates []orderedCandidateChoice             `json:"candidates"`
	}
	if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &body) != nil || body.Token == "" || !body.Public || body.Execution != "local" || body.Metric != hopmeasure.CandidatePublicResponseMeasurement {
		t.Fatalf("original public catalog at %d: %d %s", pos, reply.Code, reply.Body.String())
	}
	view := viaEntryControlFor(a).preparedView
	if view == nil || view.token != body.Token || !reflect.DeepEqual(body.Nodes, originalCandidateResponseNodes(view.selection)) || len(body.Candidates) != len(wantIDs) {
		t.Fatal("catalog lost original source map or independent rows", body.Candidates)
	}
	for i, c := range body.Candidates {
		if c.ID != wantIDs[i] || c.Kind != "external" {
			t.Fatal("ambiguous import accepted or independent source reordered", body.Candidates)
		}
	}
	return view
}

func publicCandidateReceipt(t *testing.T, description desktopCandidateDescription, id string) hopmeasure.CandidateStatus {
	t.Helper()
	result := desktopCandidateDescriptionStatusFixture(t, description, id)
	result.Measurement = hopmeasure.CandidatePublicResponseMeasurement
	r := &result.Results[0]
	r.Kind = "public-exit-response"
	r.Benchmark.Measurement, r.Benchmark.Endpoint = result.Measurement, hopmeasure.CandidatePublicResponseEndpoint
	return result
}

func checkPublicCandidateReceipt(t *testing.T, result hopmeasure.CandidateStatus, validate func(hopmeasure.CandidateStatus) error) {
	t.Helper()
	if err := validate(result); err != nil {
		t.Fatal("valid original 50-sample public receipt", err)
	}
	for _, fault := range []string{"endpoint", "kind", "metric", "not-registered", "short", "prefix", "source"} {
		bad := result
		bad.Results = slices.Clone(result.Results)
		row := &bad.Results[0]
		bench := *row.Benchmark
		row.Benchmark = &bench
		switch fault {
		case "endpoint":
			bench.Endpoint = "https://1.0.0.1/cdn-cgi/trace"
		case "kind":
			row.Kind = "private-agent-response"
		case "metric":
			bench.Measurement = hopmeasure.CandidatePrivateResponseMeasurement
		case "not-registered":
			row.CandidateDisposition = hopmeasure.CandidateNotRegistered
		case "short":
			bench.Attempts--
		case "prefix":
			bad.PrefixPosition--
		case "source":
			bad.CandidateSourceSHA256 = strings.Repeat("0", 64)
		}
		if validate(bad) == nil {
			t.Fatal("substituted terminal public receipt accepted", fault)
		}
	}
}

func TestDesktopPublicCandidateOriginalCatalogAndAdoption(t *testing.T) {
	for _, tc := range []struct {
		count, pos    int
		draft, choose bool
	}{
		{3, 1, true, false}, {4, 1, true, true}, {4, 2, false, false}, {9, 7, true, true}, {9, 1, false, false},
	} {
		t.Run(fmt.Sprintf("%d/position-%d/draft-%t/use-%t", tc.count, tc.pos, tc.draft, tc.choose), func(t *testing.T) {
			a, nodes, ids := publicCandidateApp(t, tc.count)
			var draft *multihopConnectRequest
			if tc.draft {
				draft = publicCandidateEditorDraft(t, a, nodes)
			}
			before := cloneRouterProfileStore(a.profiles)
			view := publicCandidateCatalog(t, a, draft, tc.pos, ids)
			inserted := slices.Insert(slices.Clone(nodes), tc.pos+1, common.MultihopNodeSelection{ID: ids[0], Mode: "shadowsocks"})
			choice := view.candidates[0]
			if choice.SaveReason != "" || choice.ProposalAction != "save-intermediate-profile" || !slices.Equal(choice.Proposal, inserted) || tc.draft && (choice.DraftAction != orderedCandidateDraftInsertAction || !slices.Equal(choice.DraftProposal, inserted)) {
				t.Fatal("public exit or retained suffix changed in original Save/Use offer", choice)
			}
			q := orderedCandidatePreparationRequest{RequestID: strings.Repeat("d", 32), Samples: 50, Scope: orderedCandidateSavedPrefixScope, Position: tc.pos, CandidateIDs: []string{ids[0]}, draft: draft}
			control := viaEntryControlFor(a)
			if err := reserveOrderedCandidatePreparedAdmissionLocked(control, q.RequestID, view); err != nil {
				t.Fatal(err)
			}
			p, err := beginOrderedCandidatePreparationWithNetwork(t.Context(), a, q, originalPublicCandidateNetwork)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.finish() })
			if p.selection.Control.ID != nodes[0].ID || p.selection.Exit.ID != nodes[len(nodes)-1].ID || p.prefixPreparation.PrefixPosition() != tc.pos {
				t.Fatal("original control or selected prefix changed")
			}
			// The native worker has its own encrypted-path gate. Model its exact
			// receipt here to exercise the real parent validator and transactions.
			result := publicCandidateReceipt(t, p.prefixPreparation, ids[0])
			checkPublicCandidateReceipt(t, result, func(st hopmeasure.CandidateStatus) error {
				return validateOrderedCandidatePreparedStatus(p, ids[0], st, time.Now())
			})
			full, err := p.selection.Native.chain.chain.NewCandidatePlan(tc.pos, p.inventory.inventory)
			if err != nil {
				t.Fatal(err)
			}
			fullResult := publicCandidateReceipt(t, full, ids[0])
			checkPublicCandidateReceipt(t, fullResult, func(st hopmeasure.CandidateStatus) error {
				return validateDesktopNodeChainCandidateStatus(full, ids[0], st, time.Now())
			})
			request := map[string]any{"request_id": q.RequestID, "view_token": view.token, "scope": q.Scope, "candidate_id": ids[0], "proposed_path": inserted}
			path := "/api/multihop/saved-candidates/save-profile"
			if tc.draft {
				path = "/api/multihop/draft-candidates/save-profile"
			}
			if tc.choose {
				path = "/api/multihop/draft-candidates/choose"
			} else {
				request["name"] = "Measured public exit candidate"
			}
			if out := orderedCandidateHTTP(t, a, path, request); out.Code != 409 {
				t.Fatal("unjoined trial adopted", out.Code, out.Body.String())
			}
			done := make(chan struct{})
			close(done)
			p.workerDone = done
			if err := p.retireNative(t.Context()); err != nil {
				t.Fatal(err)
			}
			p.runtime = &orderedCandidatePreparedRuntime{preparation: p, catalog: p.inventory, cohort: &selectedDraftNetworkFixture{phase: 5}}
			now := time.Now()
			job := &orderedCandidatePreparedJob{preparation: p, view: view, accepted: true, nativeDown: true, expires: now.Add(time.Minute), results: []hopmeasure.CandidateStatus{result}}
			p.owner.prepared = job
			p.finishOnce.Do(func() { p.owner.running = false; close(p.owner.done); a.operationMu.Unlock() })
			request["proposed_path"] = nodes
			if out := orderedCandidateHTTP(t, a, path, request); out.Code != 409 {
				t.Fatal("unmodified or truncated route accepted", out.Code, out.Body.String())
			}
			request["proposed_path"] = inserted
			out := orderedCandidateHTTP(t, a, path, request)
			if out.Code != 200 {
				t.Fatal("original public choice", out.Code, out.Body.String())
			}
			if !reflect.DeepEqual(before, a.profiles) || a.state.Connected {
				t.Fatal("temporary operation changed original Home")
			}
			store, err := loadConnectionProfileStore(a)
			if err != nil {
				t.Fatal(err)
			}
			if tc.choose {
				var reply struct {
					Chosen bool                           `json:"chosen"`
					Path   []common.MultihopNodeSelection `json:"proposed_path"`
					Tokens map[string]string              `json:"expected_profile_tokens"`
				}
				if json.Unmarshal(out.Body.Bytes(), &reply) != nil || !reply.Chosen || !slices.Equal(reply.Path, inserted) || len(store.Profiles) != 0 {
					t.Fatal("Use changed persistent profile or dropped public final", out.Body.String())
				}
				next := publicCandidateEditorDraft(t, a, inserted)
				if !reflect.DeepEqual(reply.Tokens, next.ExpectedProfileTokens) {
					t.Fatal("Use lost original linked source tokens", out.Body.String())
				}
				again := publicCandidateCatalog(t, a, next, tc.pos+1, []string{ids[1]})
				if again.token == view.token || again.catalog.prefixPreparation.CaptureSHA256() == p.prefixPreparation.CaptureSHA256() || again.selection.Nodes[tc.pos+1].Profile.ID != ids[0] || again.selection.Exit.ID != nodes[len(nodes)-1].ID {
					t.Fatal("new selected prefix reused prior measurement or final")
				}
			} else {
				if len(store.Profiles) != 1 || store.Profiles[0].NodeID != nodes[0].ID || store.Profiles[0].Prefs == nil || !slices.Equal(store.Profiles[0].Prefs.MultihopNodes, inserted) || len(store.Profiles[0].NodeChain) != len(inserted) || store.Profiles[0].NodeChain[len(inserted)-1].ID != inserted[len(inserted)-1].ID {
					t.Fatal("named profile lost paired control, intermediate insertion or public final", store.Profiles)
				}
				pollPath := strings.TrimSuffix(path, "/save-profile") + "?request_id=" + q.RequestID
				poll := httptest.NewRecorder()
				a.orderedCandidatePreparedStatus(poll, httptest.NewRequest(http.MethodGet, pollPath, nil))
				if poll.Code != http.StatusOK {
					t.Fatal("committed original Save status", poll.Code, poll.Body.String())
				}
				for _, delivered := range [][]byte{out.Body.Bytes(), poll.Body.Bytes()} {
					var saved struct {
						Request  string                         `json:"request_id"`
						Token    string                         `json:"view_token"`
						Metric   string                         `json:"measurement"`
						Position int                            `json:"prefix_position"`
						Action   string                         `json:"proposal_action"`
						ID       string                         `json:"candidate_id"`
						Path     []common.MultihopNodeSelection `json:"proposed_path"`
					}
					if json.Unmarshal(delivered, &saved) != nil || saved.Request != q.RequestID || saved.Token != view.token ||
						saved.Metric != hopmeasure.CandidatePublicResponseMeasurement || saved.Position != tc.pos || saved.Action != "save-intermediate-profile" ||
						saved.ID != ids[0] || !slices.Equal(saved.Path, inserted) {
						t.Fatal("committed public Save confirmation lost original request, source or selection", string(delivered))
					}
				}
			}
		})
	}
}

func TestDesktopPublicCandidateCatalogAtCapacity(t *testing.T) {
	a, nodes, ids := publicCandidateApp(t, 96)
	view := publicCandidateCatalog(t, a, publicCandidateEditorDraft(t, a, nodes), 94, ids)
	if len(view.selection.Nodes) != 96 || view.catalog.prefixPreparation.ExtendedCandidateDepth() != 96 {
		t.Fatal("full source lost measurement capability")
	}
	for _, choice := range view.candidates {
		if choice.SaveReason == "" || len(choice.Proposal) != 0 || len(choice.DraftProposal) != 0 || choice.DraftAction != "" || choice.ProposalAction != "" {
			t.Fatal("full public source offered a 97th member or replacement", choice)
		}
	}
}
