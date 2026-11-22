package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"router-vpn/internal/desktopnetwork"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func selectedDraftFixture(t *testing.T, sparse bool, requested string) (*app, *multihopConnectRequest, orderedCandidatePreparationRequest) {
	t.Helper()
	var a *app
	var nodes []common.MultihopNodeSelection
	position := 1
	if sparse {
		a, nodes = desktopIndependentImportedFixture(t, desktopIndependentImportedLayouts[2], "wg", "off")
		position = 2
	} else {
		a, nodes = desktopNodeChainCaptureFixture(t, 3)
	}
	return selectedDraftSourceFixture(t, a, nodes, requested, position, desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm"))
}

func selectedDraftSourceFixture(t *testing.T, a *app, nodes []common.MultihopNodeSelection, requested string, position int, id string) (*app, *multihopConnectRequest, orderedCandidatePreparationRequest) {
	t.Helper()
	desktopCONNECTSelectPublicHandler(t, a)
	a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
	selected := a.profiles.SelectedID
	tokens := map[string]string{}
	for i := range a.profiles.Profiles {
		node := &a.profiles.Profiles[i]
		if node.ID == selected {
			node.MultihopNodes = nil
			node.MultihopEnabled = false
			node.MultihopExecution = ""
		}
		tokens[node.ID] = publicProfileToken(*node)
	}
	exact := map[string]string{}
	for _, node := range nodes {
		exact[node.ID] = tokens[node.ID]
	}
	draft := &multihopConnectRequest{Execution: requested, Nodes: nodes, desktopProfileExpectations: desktopProfileExpectations{ExpectedSelectedNodeID: &selected, ExpectedProfileTokens: exact}}
	return a, draft, orderedCandidatePreparationRequest{draft: draft, Scope: orderedCandidateSelectedDraftScope, RequestID: strings.Repeat("a", 32), Position: position, CandidateIDs: []string{id}, Samples: 50}
}

func TestDesktopSelectedDraftCapturesFullUnsavedPacketSource(t *testing.T) {
	observe := func(ctx context.Context) (string, error) { return "original-draft-network", ctx.Err() }
	ctx := context.Background()
	for _, family := range []string{"paired", "sparse"} {
		for _, requested := range []string{"server", "auto"} {
			t.Run(family+"/"+requested, func(t *testing.T) {
				a, draft, q := selectedDraftFixture(t, family == "sparse", requested)
				before := cloneRouterProfileStore(a.profiles)
				view, err := captureOrderedCandidatePreparedSelection(ctx, a, q.Position, q.Scope, draft, observe)
				if err != nil {
					t.Fatal("complete draft catalog", err)
				}
				if view.catalog.plan == nil || view.catalog.selectedPlan != nil || view.catalog.prefixPreparation != nil || view.catalog.launch.command != nil ||
					view.catalog.launch.chain.execution.preparation.Execution() != requested || !reflect.DeepEqual(nodeChainSelectedReferences(view.selection.Nodes), draft.Nodes) ||
					a.cmd != nil || a.connectionContext != nil || a.candidatePreparation != nil {
					t.Fatal("source-only catalog adopted a live or incomplete draft")
				}
				p, err := beginOrderedCandidatePreparationWithNetwork(ctx, a, q, observe)
				if err != nil {
					t.Fatal("original selected draft admission", err)
				}
				t.Cleanup(func() {
					if err := p.finish(); err != nil {
						t.Error(err)
					}
				})
				if !view.matchesPreparation(p, time.Now()) || p.inventory.plan == nil || p.inventory.selectedPlan != nil || p.prefixPreparation != nil || a.state.Connected || a.cmd != nil || !reflect.DeepEqual(a.profiles, before) {
					t.Fatal("draft preparation lost its exact source-only reservation")
				}
				candidate, _ := a.profileByIDLocked(q.CandidateIDs[0])
				control, rows, err := orderedDraftProposal(requested, p.selection.Nodes, q.Position, candidate, a.profiles.Profiles)
				if err != nil || control.MultihopExecution != requested || len(rows) != len(draft.Nodes)+1 || rows[q.Position+1].ID != candidate.ID ||
					!reflect.DeepEqual(rows[:q.Position+1], draft.Nodes[:q.Position+1]) || !reflect.DeepEqual(rows[q.Position+2:], draft.Nodes[q.Position+1:]) {
					t.Fatal("selected proposal lost requested path or a suffix member", err)
				}
				if err := p.finish(); err != nil || a.connectionContext != nil || a.candidatePreparation != nil || a.cmd != nil || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("draft source-only teardown did not return original DOWN", err)
				}
				originalID := strings.Repeat("e", 32)
				if err := rememberOrderedCandidatePreparedViewLocked(p.control, view); err != nil {
					t.Fatal(err)
				}
				if requested == "auto" {
					if err := reserveOrderedCandidatePreparedAdmissionLocked(p.control, originalID, view); err != nil {
						t.Fatal(err)
					}
				}
				payload, _ := json.Marshal(map[string]string{"request_id": originalID, "view_token": view.token, "scope": q.Scope})
				reply := httptest.NewRecorder()
				a.orderedCandidatePreparedCancel(reply, httptest.NewRequest("POST", "/api/multihop/draft-candidates/cancel", bytes.NewReader(payload)))
				var cancelled map[string]any
				if reply.Code != 200 || json.Unmarshal(reply.Body.Bytes(), &cancelled) != nil || cancelled["requested_execution"] != requested || cancelled["scope"] != q.Scope || cancelled["origin"] != "editor-draft" || cancelled["admission_cancelled"] != true || cancelled["started"] != false || cancelled["native_down"] != false || cancelled["selected_execution"] != nil || cancelled["selection_epoch"] != nil {
					t.Fatal("prestart cancellation lost original execution or invented an epoch", reply.Code, reply.Body.String())
				}

			})
		}
	}
}

func TestDesktopSelectedDraftRejectsMismatchedSourceAndPurpose(t *testing.T) {
	observe := func(ctx context.Context) (string, error) { return "original-draft-network", ctx.Err() }
	for _, fault := range []string{"closed-prefix", "saved-endpoint", "no-execution", "wrong-selected", "missing-token", "changed-token", "stream-interior", "final", "truncated-suffix"} {
		t.Run(fault, func(t *testing.T) {
			a, draft, q := selectedDraftFixture(t, true, "server")
			switch fault {
			case "closed-prefix":
				q.Scope = orderedCandidateSavedPrefixScope
			case "saved-endpoint":
				draft = nil
			case "no-execution":
				draft.Execution = ""
			case "wrong-selected":
				wrong := draft.Nodes[0].ID
				draft.ExpectedSelectedNodeID = &wrong
			case "missing-token":
				delete(draft.ExpectedProfileTokens, draft.Nodes[3].ID)
			case "changed-token":
				draft.ExpectedProfileTokens[draft.Nodes[1].ID] = strings.Repeat("a", 64)
			case "stream-interior":
				q.Position = 1
			case "final":
				q.Position = len(draft.Nodes) - 1
			case "truncated-suffix":
				draft.Nodes = draft.Nodes[:3]
			}
			q.draft = draft
			_, viewErr := captureOrderedCandidatePreparedSelection(context.Background(), a, q.Position, q.Scope, draft, observe)
			p, runErr := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, observe)
			if p != nil {
				_ = p.finish()
			}
			if viewErr == nil || runErr == nil || a.cmd != nil || a.connectionContext != nil || a.state.Connected {
				t.Fatal("foreign draft reached view or operation", fault, viewErr, runErr)
			}
		})
	}
}

// The physical observer and privileged child are modeled together. The same
// production controller that checks the cohort, stages the selected graph and
// reads the private mailboxes must join the worker and original protection.
type selectedDraftNetworkFixture struct {
	lost    bool
	phase   int
	receipt desktopnetwork.DesktopNetworkReceipt
}

func (m *selectedDraftNetworkFixture) Begin(ctx context.Context, r *desktopnetwork.DesktopNetworkReceipt) error {
	if m.phase == 0 && r == nil {
		m.phase = 1
		return ctx.Err()
	}
	if m.phase == 3 && reflect.DeepEqual(r, &m.receipt) {
		m.phase = 4
		return ctx.Err()
	}
	return errors.New("wrong original modeled network transition")
}
func (m *selectedDraftNetworkFixture) RecordContext(ctx context.Context, r desktopnetwork.DesktopNetworkReceipt) error {
	if m.phase != 1 || !reflect.DeepEqual(r, m.receipt) || r.Validate() != nil {
		return errors.New("foreign modeled network receipt")
	}
	m.phase = 2
	return ctx.Err()
}
func (m *selectedDraftNetworkFixture) End(ctx context.Context, r *desktopnetwork.DesktopNetworkReceipt) error {
	if m.phase == 2 && reflect.DeepEqual(r, &m.receipt) {
		m.phase = 3
		return ctx.Err()
	}
	if m.phase == 4 && r == nil {
		m.phase = 5
		return ctx.Err()
	}
	return errors.New("modeled network did not join original transition")
}
func (m *selectedDraftNetworkFixture) CurrentContext(ctx context.Context) error {
	if m.lost || m.phase != 3 && m.phase != 5 {
		return errors.New("modeled network has no current original observation")
	}
	return ctx.Err()
}
func (m *selectedDraftNetworkFixture) Close() error {
	if m.phase == 5 {
		m.phase = 6
		return nil
	}
	return errors.New("modeled network close before original DOWN")
}

func TestDesktopSelectedDraftRetainsWinnerThroughOriginalDownAndChoose(t *testing.T) {
	for _, choice := range [][3]string{{"server", "server", "server/server"}, {"auto", "local", "auto/local"}, {"auto", "server", "auto/server"}, {"auto", "server", "held-native-down"}, {"auto", "local", "changed-review-network"}} {
		t.Run(choice[2], func(t *testing.T) {
			a, draft, q := selectedDraftFixture(t, true, choice[0])
			testOriginalSelectedDraftLifecycle(t, a, draft, q, choice)
		})
	}
}

func testOriginalSelectedDraftLifecycle(t *testing.T, a *app, draft *multihopConnectRequest, q orderedCandidatePreparationRequest, choice [3]string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	before := cloneRouterProfileStore(a.profiles)
	storePath := connectionProfileStorePath(a)
	storeBytes, storeErr := os.ReadFile(storePath)
	if storeErr != nil && !errors.Is(storeErr, os.ErrNotExist) {
		t.Fatal(storeErr)
	}
	t.Cleanup(func() {
		after, err := os.ReadFile(storePath)
		if !bytes.Equal(storeBytes, after) || errors.Is(storeErr, os.ErrNotExist) != errors.Is(err, os.ErrNotExist) {
			t.Error("temporary trial modified the durable connection profile store")
		}
	})

	observed := func(ctx context.Context) (string, error) { return "original-chain-physical-network", ctx.Err() }
	view, err := captureOrderedCandidatePreparedSelection(ctx, a, q.Position, q.Scope, draft, observed)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the modeled controller lifetime independent of this one finite operation.
	f := newDesktopNodeChainOwnedFixtureWith(t, a, view.selection)
	a.connectionContext, a.connectionCancel = nil, nil
	p, err := beginOrderedCandidatePreparationWithNetwork(ctx, a, q, f.readNetwork)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.finish() })
	f.operation, f.selection = p.operation, p.selection
	f.capture, err = captureDesktopNodeChainHostContextWith(ctx, a, p.selection, f.readNetwork)
	if err != nil {
		t.Fatal(err)
	}
	qHost := &desktopNodeChainExecutionRequest{capture: f.capture, native: p.selection.Native, requested: choice[0], draftPurpose: p}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(ctx, f.capture, p.selection, nil, qHost)
	if err != nil {
		t.Fatal("selected draft physical preparation", err)
	}
	f.launch = launch
	if err := p.holdLease(ctx); err != nil {
		t.Fatal(err)
	}
	net := &selectedDraftNetworkFixture{}
	r := &orderedCandidatePreparedRuntime{preparation: p, cohort: net}
	p.runtime = r
	job := &orderedCandidatePreparedJob{view: view, preparation: p}
	p.owner.prepared = job
	f.executionModel = &desktopExecutionOwnedModel{winner: choice[1], draftPublication: func(launch *desktopNodeLaunch, prep *mobilemultihop.NodeChainExecutionPreparation, projection *mobilemultihop.NodeChainExecutionProjection, ready mobilemultihop.DesktopNodeChainExecutionReadyRecord) string {
		publishDesktopSelectedDraftCapture(t, launch, prep, projection, ready, choice[1])
		net.receipt = desktopnetwork.DesktopNetworkReceipt{Schema: 1, TargetOS: runtime.GOOS, Incarnation: strings.Repeat("ab", 16), Name: ready.InterfaceName, Index: ready.InterfaceIndex, MTU: ready.MTU, Addresses: []string{"172.31.99.1/32"}}
		if runtime.GOOS == "windows" {
			net.receipt.LUID = 1234
		}
		raw, err := desktopnetwork.CanonicalDesktopNetworkReceipt(net.receipt)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}}
	if _, err := p.startFullRuntime(ctx, r, launch); err != nil {
		t.Fatal("original selected draft startup", err)
	}
	if _, registered := desktopOrderedExecutionOwners.Load(a); registered || a.state.Connected || a.state.Phase != "candidate:testing" || !mtuSuspended(a) || f.starts != 1 || r.selectedReady == nil || r.selectedReady.Progress.Execution != choice[1] || r.selectedReady.SelectionEpoch == 0 || net.phase != 3 || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("selected draft adopted an ordinary connection or lost its original proof")
	}
	if _, _, _, _, err := readDesktopSelectedLatencyCapture(ctx, launch); err == nil {
		t.Fatal("ordinary connected reader accepted a draft")
	}
	if _, err := captureDesktopSelectedCandidateDescriptor(launch, q.Position, p.inventory.inventory); err == nil {
		t.Fatal("ordinary candidate descriptor accepted a draft")
	}
	if _, err := launch.chain.execution.captureRestoreContext(ctx, a, launch); err == nil {
		t.Fatal("temporary draft created a resumable Last connection")
	}
	if _, err := captureDesktopSelectedCandidateDescriptorForPurpose(launch, q.Position, p.inventory.inventory, &orderedCandidatePreparation{}); err == nil {
		t.Fatal("foreign preparation borrowed the draft")
	}
	owned := r.selectedReady.SelectionEpoch
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		err := p.measureRuntime(ctx, r, func(_ string, status hopmeasure.CandidateStatus, failure error) {
			if failure != nil {
				rec.WriteHeader(409)
				rec.WriteString(failure.Error())
				return
			}
			job.results = append(job.results, status)
		})
		if err != nil {
			rec.WriteHeader(409)
			rec.WriteString(err.Error())
		}
		done <- rec
	}()
	var req desktopSelectedCandidateRequest
	if raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateRequestFile, done); json.Unmarshal(raw, &req) != nil || req.Capture.SelectionEpoch != owned || req.Capture.Progress.Execution != choice[1] || req.Position != q.Position || req.Candidate != q.CandidateIDs[0] {
		t.Fatal("temporary candidate prepare changed the original position or selected trial")
	}
	metadata := desktopSelectedCandidateMetadataFixture(t, r.catalog, req)
	if err := writeDesktopRuntimeFile(launch, desktopSelectedCandidateMetadataFile, metadata, false); err != nil {
		t.Fatal(err)
	}
	waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateStartFile, done)
	waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedCandidateLiveFile, done)
	status := desktopSelectedCandidateStatusFixture(t, r.catalog, req)
	publishDesktopSelectedCandidateParentResult(t, f, req, metadata, status)
	select {
	case out := <-done:
		if out.Code != 200 {
			t.Fatal("original selected receipt", out.Body.String())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(job.results) != 1 || !job.results[0].Drained || job.results[0].Results[0].Benchmark.Attempts != 50 || !mtuSuspended(a) {
		t.Fatal("temporary draft returned without all original samples and retained lease")
	}
	if choice[2] == "held-native-down" {
		original := f.processes[0]
		original.mu.Lock()
		original.closeErr = errors.New("original native join pending")
		original.mu.Unlock()
		retireErr := p.finishForReview(job)
		if retireErr == nil || job.accepted || p.nativeDown || !mtuSuspended(a) || a.candidatePreparation != p || p.workspaceDown || net.phase != 4 {
			t.Fatal("failed native retirement released draft choice, lease, workspace or original reservation", retireErr)
		}
		original.mu.Lock()
		original.closeErr = nil
		original.mu.Unlock()
		if err := p.finish(); err != nil || !p.down || !p.workspaceDown || a.candidatePreparation != nil || mtuSuspended(a) || net.phase != 6 || !reflect.DeepEqual(before, a.profiles) {
			t.Fatal("retry did not join only the originally held temporary native owner", err)
		}
		return
	}
	if err := p.finishForReview(job); err != nil {
		t.Fatal("original native DOWN review", err)
	}
	current := orderedCandidatePreparedResponseLocked(p.owner, time.Now())
	if !p.nativeDown || !p.workspaceDown || !job.accepted || current["requested_execution"] != choice[0] || current["selected_execution"] != choice[1] || current["selection_epoch"] != owned || !orderedCandidatePreparationDownLocked(a) || net.phase != 5 || mtuSuspended(a) || a.candidatePreparation != p || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("review failed original DOWN or changed its selected trial")
	}
	candidate, _ := a.profileByIDLocked(q.CandidateIDs[0])
	_, proposal, err := orderedDraftProposal(choice[0], p.selection.Nodes, q.Position, candidate, a.profiles.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"request_id": q.RequestID, "view_token": view.token, "candidate_id": candidate.ID, "proposed_path": proposal, "scope": q.Scope})
	rec := httptest.NewRecorder()
	net.lost = choice[2] == "changed-review-network"
	a.saveOrderedCandidatePreparedProfile(rec, httptest.NewRequest("POST", "/api/multihop/draft-candidates/choose", bytes.NewReader(payload)).WithContext(ctx))
	if choice[2] == "changed-review-network" {
		if rec.Code != 409 || !p.invalidated.Load() || a.candidatePreparation != p || !reflect.DeepEqual(before, a.profiles) {
			t.Fatal("changed DOWN observer released a stale draft choice", rec.Code, rec.Body.String())
		}
		if err := cleanupViaEntryOwner(p.control, p.owner); err != nil || !p.down || net.phase != 6 || a.candidatePreparation != nil {
			t.Fatal("changed DOWN observer did not join its original reservation", err)
		}
		return
	}
	var picked struct {
		Chosen    bool
		Requested string                         `json:"requested_execution"`
		Selected  string                         `json:"selected_execution"`
		Epoch     uint64                         `json:"selection_epoch"`
		Nodes     []common.MultihopNodeSelection `json:"proposed_path"`
		Tokens    map[string]string              `json:"expected_profile_tokens"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &picked) != nil || !picked.Chosen || picked.Requested != choice[0] || picked.Selected != choice[1] || picked.Epoch != owned || !reflect.DeepEqual(picked.Nodes, proposal) || len(picked.Tokens) != len(proposal) || !reflect.DeepEqual(proposal[q.Position+2:], draft.Nodes[q.Position+1:]) || net.phase != 6 || a.candidatePreparation != nil || !p.down || !reflect.DeepEqual(before, a.profiles) || f.starts != 1 {
		t.Fatal("Choose lost the original graph, retained reservation, or changed a saved profile", rec.Code, rec.Body.String())
	}
}

func publishDesktopSelectedDraftCapture(t *testing.T, launch *desktopNodeLaunch, prep *mobilemultihop.NodeChainExecutionPreparation, projection *mobilemultihop.NodeChainExecutionProjection, ready mobilemultihop.DesktopNodeChainExecutionReadyRecord, winner string) {
	t.Helper()
	if launch.chain.execution.multiplePhysical != nil {
		publishDesktopMultipleImportedSelectedLatencyFixture(t, launch, prep, projection, ready, winner)
		return
	}
	selected := desktopSelectedLatencyCapture{Schema: 1, SourceSHA256: projection.SourceSHA256(), ConfigSHA256: projection.ConfigSHA256(), GenerationSHA256: strings.Repeat("e", 64), Execution: winner}
	proofs, err := projection.ProofInventory(winner)
	if err != nil {
		t.Fatal(err)
	}
	for pos, p := range proofs {
		kind := p.Kind
		if kind == "" {
			kind = "private-node"
		}
		role, _, _, _, _ := desktopSelectedLatencyMeaningFamily(pos, len(proofs), kind, winner, false)
		selected.Nodes = append(selected.Nodes, desktopSelectedLatencyNode{NodeID: p.ProfileID, Position: pos, Role: role, Kind: kind})
	}
	raw, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := json.Marshal(desktopSelectedLatencyPublication{Schema: 1, Kind: "routervpn-node-chain-execution-latency-capture-v1", Capture: mustMarshalSelectedDraftReady(t, ready), Selected: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(launch, "node-chain-execution-latency-capture.json", publication, false); err != nil {
		t.Fatal(err)
	}
}
