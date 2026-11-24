package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func TestDesktopExtendedThroughputPublicController(t *testing.T) {
	for _, count := range []int{9, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			positions := make([]int, count-2)
			for i := range positions {
				positions[i] = i + 1
			}
			a, selection := desktopOrderedIndependentSelection(t, desktopIndependentImportedLayout{"extended", count, positions})
			status := hopmeasure.Status{Stage: "complete", Complete: true, Drained: true}
			for i, n := range selection.Nodes {
				role, kind := "intermediate", "public-path"
				if i == 0 {
					role, kind = "entry", "private-node"
				} else if i == count-1 {
					role, kind = "exit", "private-node"
				}
				duration := float64(i + 1)
				tr := hopmeasure.Transfer{Bytes: 8 << 20, Seconds: duration, Mbps: float64(8<<20) * 8 / duration / 1e6}
				status.Results = append(status.Results, hopmeasure.Result{ID: n.Profile.ID, Role: role, Kind: kind, Ready: true,
					Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}, Download: &tr, Upload: &tr})
			}
			desktopExtendedThroughputPublicReplay(t, a, selection, status)
		})
	}
}

// The native child is represented by its authenticated mailbox response. The
// real HTTP handlers retain their ordinary source, original session and MTU ownership.
func desktopExtendedThroughputPublicReplay(t *testing.T, a *app, selection multihopSelection, status hopmeasure.Status) ([]byte, []byte) {
	t.Helper()
	f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
	f.stagePublish(t)
	if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, a, f.launch); err != nil {
		t.Fatal(err)
	}
	if err := proveDesktopNodeChainContext(f.operation, a, selection, f.launch.command); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.state.Connected, a.state.Phase = true, "connected"
	a.mu.Unlock()
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{ID: "original-extended-throughput-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: selection.Control.ID}})
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	if selection.Native.chain.chain.HasPairedStreamInterior() {
		_, latency, err := captureDesktopOrderedLatency(ctx, a)
		if err != nil || latency.Capture.LocalRolesJSON != selection.Native.chain.chain.ExtendedLocalRolesJSON() || latency.Capture.ExtendedLocalNodes != len(selection.Nodes) || latency.Capture.PairedPrefixNodes != 0 || latency.Capture.SelectedCaptureJSON != "" {
			t.Fatal("live ordered latency capture lost its original private stream roles", err)
		}
	}
	w := httptest.NewRecorder()
	a.nativeMultihopStatus(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/multihop/status", nil))
	var view struct {
		Capture string                           `json:"ordered_capture"`
		Source  *desktopOrderedPerformanceSource `json:"ordered_local_source"`
		Count   int                              `json:"ordered_nodes"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || view.Count != len(selection.Nodes) || len(view.Capture) != 64 || view.Source == nil ||
		view.Source.SourceSHA256 != selection.Native.source || view.Source.ConfigSHA256 != f.launch.configSHA256 || len(view.Source.NodeIDs) != len(selection.Nodes) {
		t.Fatal("unqualified public GET", w.Code, w.Body)
	}
	for i, n := range selection.Nodes {
		if view.Source.NodeIDs[i] != n.Profile.ID {
			t.Fatal("changed public preflight order", i)
		}
	}
	if rejected := <-selectedThroughputParentRequest(t, f, ctx, strings.Repeat("0", 64)); rejected.Code != http.StatusConflict {
		t.Fatal("accepted foreign full preflight", rejected.Code)
	}
	// This changes an actual original credential while leaving the visible
	// ordered IDs, route and requested capture untouched.
	a.mu.Lock()
	active := -1
	for i := range a.profiles.Profiles {
		if a.profiles.Profiles[i].ID == selection.Exit.ID {
			active = i
			break
		}
	}
	if active < 0 {
		a.mu.Unlock()
		t.Fatal("missing original protected exit")
	}
	credential := a.profiles.Profiles[active].APIToken
	a.profiles.Profiles[active].APIToken += "changed"
	a.mu.Unlock()
	credentialResponse := <-selectedThroughputParentRequest(t, f, ctx, view.Capture)
	a.mu.Lock()
	a.profiles.Profiles[active].APIToken = credential
	a.mu.Unlock()
	if credentialResponse.Code != http.StatusConflict {
		t.Fatal("accepted changed actual exit credential", credentialResponse.Code)
	}
	sizeRequest := routedSpeedRequest{EntryID: selection.Entry.ID, ExitID: selection.Exit.ID, OrderedCapture: view.Capture, Bytes: 65536}
	sizeBody, _ := json.Marshal(sizeRequest)
	rejected := httptest.NewRecorder()
	a.multihopSpeedTest(rejected, httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/multihop/speed-test", bytes.NewReader(sizeBody)))
	if rejected.Code != http.StatusConflict {
		t.Fatal("accepted changed transfer size", rejected.Code)
	}

	done := selectedThroughputParentRequest(t, f, ctx, view.Capture)
	raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, "node-chain-measure-request.json", done)
	var request desktopNodeChainMeasurementRequest
	if json.Unmarshal(raw, &request) != nil || request.Schema != 1 || request.Bytes != 8<<20 || !mtuSuspended(a) || request.Capture.Identity.SourceSHA256 != view.Source.SourceSHA256 || request.Capture.Identity.ConfigSHA256 != view.Source.ConfigSHA256 {
		t.Fatal("unbound native throughput mailbox")
	}
	status.Request = request.Request
	reply := desktopNodeChainMeasurementResult{desktopNodeChainMeasurementRequest: request, CompletedAt: time.Now().UnixMilli(), Status: status}
	content, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDesktopRuntimeFile(f.launch, "node-chain-measure-result.json", content, false); err != nil {
		t.Fatal(err)
	}
	if err := f.launch.directoryRoot.Remove("node-chain-measure-request.json"); err != nil {
		t.Fatal(err)
	}
	post := <-done
	var result struct {
		Capture string                           `json:"ordered_capture"`
		Source  *desktopOrderedPerformanceSource `json:"ordered_local_source"`
		Rows    []speedLabHopMeasurement         `json:"hops"`
	}
	if post.Code != 200 || json.Unmarshal(post.Body.Bytes(), &result) != nil || result.Capture != view.Capture || !reflect.DeepEqual(result.Source, view.Source) || len(result.Rows) != len(status.Results) || mtuSuspended(a) {
		t.Fatal("public POST lost original source, capture, rows or retirement", post.Code, post.Body)
	}
	for i, row := range result.Rows {
		native := status.Results[i]
		if row.RouterID != view.Source.NodeIDs[i] || row.Role != native.Role || row.Speed == nil || row.Speed.Bytes != 8<<20 || row.Speed.DownloadMs != 1000*native.Download.Seconds || row.Speed.UploadMs != 1000*native.Upload.Seconds {
			t.Fatal("public throughput changed original transfer or position", i)
		}
	}
	return w.Body.Bytes(), post.Body.Bytes()
}
