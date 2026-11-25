package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/mobilemultihop"
)

// The native process and kernel remain component boundaries. The actual parent
// captures the typed selected projection, exchanges its private request files,
// holds the original MTU lease and commits each independent hop's history.
func desktopMultipleImportedSelectedLatencyFixture(t *testing.T, layout desktopIndependentImportedLayout, requested, winner string) (*desktopNodeChainOwnedFixture, desktopOrderedLatencyView) {
	t.Helper()
	return desktopMultipleImportedSelectedLatencyFixtureForEntry(t, layout, "wg", requested, winner)
}

func desktopMultipleImportedSelectedLatencyFixtureForEntry(t *testing.T, layout desktopIndependentImportedLayout, entryMode, requested, winner string) (*desktopNodeChainOwnedFixture, desktopOrderedLatencyView) {
	t.Helper()
	f, session := prepareDesktopMultipleImportedExecutionModelForEntry(t, layout, entryMode, requested, winner)
	return finishDesktopMultipleImportedSelectedLatencyFixture(t, f, session, winner, layout.count)
}

func finishDesktopMultipleImportedSelectedLatencyFixture(t *testing.T, f *desktopNodeChainOwnedFixture, session *desktopNodeChainExecutionSession, winner string, count int) (*desktopNodeChainOwnedFixture, desktopOrderedLatencyView) {
	t.Helper()
	if err := session.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := retireDesktopOrderedLatencyFixture(ctx, f.a, f.launch.command); err != nil {
			t.Error("multiple imported selected parent left original workers", err)
		}
	})
	f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "selected-multiple-fifty-state.json")
	f.a.mu.Lock()
	f.a.state.Connected, f.a.state.Phase = true, "connected"
	f.a.mu.Unlock()
	sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "session-1-1", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
	e := session.execution
	e.mu.Lock()
	ready, projection := *e.ready, e.projection
	e.mu.Unlock()
	selectedBytes := publishDesktopMultipleImportedSelectedLatencyFixture(t, f.launch, e.preparation, projection, ready, winner)
	response := desktopOrderedHTTP(t, f.a, "GET", "/api/speed-lab/ordered-latency", nil)
	var view desktopOrderedLatencyView
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &view) != nil || view.Capture.SelectedCaptureJSON != string(selectedBytes) || len(view.Nodes) != count {
		t.Fatal("parent lost complete multiple imported selected capture", response.Code, response.Body.String())
	}
	return f, view
}
func mustMarshalSelectedDraftReady(t *testing.T, ready mobilemultihop.DesktopNodeChainExecutionReadyRecord) []byte {
	t.Helper()
	raw, err := json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func publishDesktopMultipleImportedSelectedLatencyFixture(t *testing.T, launch *desktopNodeLaunch, prep *mobilemultihop.NodeChainExecutionPreparation, projection *mobilemultihop.NodeChainExecutionProjection, ready mobilemultihop.DesktopNodeChainExecutionReadyRecord, winner string) []byte {
	t.Helper()
	original, err := prep.OriginalMultipleImportedSource()
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := projection.ImportedPublicMeasurementCaptures(winner)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := projection.ProofInventory(winner)
	if err != nil {
		t.Fatal(err)
	}
	selected := desktopSelectedLatencyCapture{Schema: 1, SourceSHA256: projection.SourceSHA256(), ConfigSHA256: projection.ConfigSHA256(),
		GenerationSHA256: strings.Repeat("e", 64), Execution: winner, Nodes: []desktopSelectedLatencyNode{},
		MultipleImported: &desktopSelectedLatencyMultipleImported{Schema: 6, OriginalSourceSHA256: original.SourceSHA256(), Public: []desktopSelectedLatencyPublic{}}}
	for _, row := range public {
		selected.MultipleImported.Public = append(selected.MultipleImported.Public, desktopSelectedLatencyPublic{Position: row.Position, Tag: row.Tag, SourceSHA256: row.SourceSHA256})
	}
	for position, proof := range proofs {
		kind := proof.Kind
		if kind == "" {
			kind = "private-node"
		}
		role := "intermediate"
		if position == 0 {
			role = "entry"
		} else if position == len(proofs)-1 {
			role = "exit"
		}
		selected.Nodes = append(selected.Nodes, desktopSelectedLatencyNode{NodeID: proof.ProfileID, Position: position, Role: role, Kind: kind})
	}
	selectedBytes, err := json.Marshal(selected)
	if err != nil || original.ValidateMultipleImportedLatencyCapture(string(selectedBytes)) != nil {
		t.Fatal("parent fixture differs from shared native capture format", err)
	}
	publication := desktopSelectedLatencyPublication{Schema: 1, Kind: "routervpn-node-chain-execution-latency-capture-v1", Capture: mustMarshalSelectedDraftReady(t, ready), Selected: string(selectedBytes)}
	raw, _ := json.Marshal(publication)
	if err := writeDesktopRuntimeFile(launch, "node-chain-execution-latency-capture.json", raw, false); err != nil {
		t.Fatal(err)
	}
	return selectedBytes
}

func TestDesktopMultipleImportedSelectedLatencyPerPositionHistory(t *testing.T) {
	for _, layout := range desktopIndependentSelectedLayouts() {
		for _, choice := range [][2]string{{"server", "server"}, {"auto", "local"}, {"auto", "server"}} {
			t.Run(fmt.Sprintf("%s/%s/%s", layout.name, choice[0], choice[1]), func(t *testing.T) {
				f, view := desktopMultipleImportedSelectedLatencyFixture(t, layout, choice[0], choice[1])
				for index, position := range layout.positions {
					node := view.Nodes[position]
					request := desktopOrderedLatencyRequest{Capture: view.Capture, NodeID: node.NodeID, Position: position, Request: fmt.Sprintf("%032x", index+1)}
					if node.Kind != "public-path" || !strings.Contains(node.Label, "Cumulative "+choice[1]+" path through custom node") || node.Measurement != "routed-https-response-after-tls" {
						t.Fatal("independent imported node lost selected meaning", node)
					}
					if r := desktopOrderedHTTP(t, f.a, "POST", "/api/speed-lab/ordered-latency", request); r.Code != 202 {
						t.Fatal("selected imported request not admitted", position, r.Code, r.Body.String())
					}
					slot := f.a.desktopOrderedLatencyFor()
					slot.mu.Lock()
					op := slot.current
					slot.mu.Unlock()
					ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
					defer cancel()
					mailbox, _ := waitDesktopSelectedLatencyFixtureRequest(t, f, op, ctx, desktopSelectedLatencyRequestFile)
					if mailbox.Selected != view.Capture.SelectedCaptureJSON || mailbox.Position != position || mailbox.NodeID != node.NodeID || mailbox.Capture.Progress.Execution != choice[1] || !mtuSuspended(f.a) {
						t.Fatal("measurement borrowed another imported node or selected owner")
					}
					saved := desktopSelectedLatencyReceiptFixture(view.Capture, node)
					saved.Request = request.Request
					result := desktopSelectedLatencyResult{desktopSelectedLatencyRequest: mailbox, Saved: &saved, CompletedAt: time.Now().UnixMilli(),
						Status: hopmeasure.Status{Request: request.Request, Complete: true, Drained: true, Stage: "complete", Results: []hopmeasure.Result{saved.Result}}}
					raw, _ := json.Marshal(result)
					if err := writeDesktopRuntimeFile(f.launch, desktopSelectedLatencyResultFile, raw, false); err != nil {
						t.Fatal(err)
					}
					if err := f.launch.directoryRoot.Remove(desktopSelectedLatencyRequestFile); err != nil {
						t.Fatal(err)
					}
					select {
					case <-op.done:
					case <-ctx.Done():
						t.Fatal("selected imported measurement did not join", ctx.Err(), op.view())
					}
					completed := op.view()
					history, err := readDesktopSelectedLatencyHistory(&app{cfg: f.a.cfg})
					if err != nil || completed.Receipt == nil || completed.Status.Failure != "" || !completed.Status.Drained || len(history.Records) != index+1 || !reflect.DeepEqual(*completed.Receipt, saved) {
						t.Fatal("selected per-position history did not commit", err, completed)
					}
					if f.starts != 1 || f.executionModel.winner != choice[1] || mtuSuspended(f.a) {
						t.Fatal("selected imported measurement repeated selection or retained MTU hold")
					}
					// The modeled native producer retires its completed response
					// before publishing the next independently identified request.
					if err := f.launch.directoryRoot.Remove(desktopSelectedLatencyResultFile); err != nil {
						t.Fatal(err)
					}
					if index+1 < len(layout.positions) {
						// The completed measurement has legitimately resumed Auto.
						// Its original source/DNS adoption has a separate join from
						// the fifty-response operation; retain this exact session.
						if err := op.current(ctx, f.a); err != nil {
							t.Fatal("selected source changed before resumed work joined", err)
						}
						if err := joinDesktopOrderedLatencyFixtureAutomatic(ctx, f.a, op.identity.Command, op.identity.Tracker, op.identity.SessionID); err != nil {
							t.Fatal("original resumed Auto/DNS work did not join", err)
						}
						if err := op.current(ctx, f.a); err != nil {
							t.Fatal("selected source changed while resumed work joined", err)
						}
					}
				}
				history, err := readDesktopOrderedLatencyViewHistory(&app{cfg: f.a.cfg}, view)
				if err != nil || len(history) != len(layout.positions) {
					t.Fatal("complete independent selected history did not reopen", err)
				}
			})
		}
	}
}

func TestDesktopMultipleImportedSelectedLatencyRefusesForeignInventory(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, _ := desktopMultipleImportedSelectedLatencyFixture(t, desktopIndependentImportedLayouts[2], "auto", winner)
			original, _, _, _, err := readDesktopSelectedLatencyCapture(f.operation, f.launch)
			if err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"missing-extension", "wrong-schema", "original-source", "missing-member", "duplicate-position", "reordered", "foreign-tag", "foreign-source", "public-entry", "public-exit", "private-import", "wrong-choice"} {
				t.Run(fault, func(t *testing.T) {
					publication := original
					var capture desktopSelectedLatencyCapture
					if json.Unmarshal([]byte(original.Selected), &capture) != nil {
						t.Fatal("fixture capture")
					}
					rows := capture.MultipleImported.Public
					switch fault {
					case "missing-extension":
						capture.MultipleImported = nil
					case "wrong-schema":
						capture.MultipleImported.Schema = 2
					case "original-source":
						capture.MultipleImported.OriginalSourceSHA256 = strings.Repeat("f", 64)
					case "missing-member":
						capture.MultipleImported.Public = rows[:1]
					case "duplicate-position":
						rows[1].Position = rows[0].Position
					case "reordered":
						rows[0], rows[1] = rows[1], rows[0]
					case "foreign-tag":
						rows[0].Tag += "a"
					case "foreign-source":
						rows[0].SourceSHA256 = strings.Repeat("f", 64)
					case "public-entry":
						capture.Nodes[0].Kind = "public-path"
					case "public-exit":
						capture.Nodes[len(capture.Nodes)-1].Kind = "public-path"
					case "private-import":
						capture.Nodes[rows[0].Position].Kind = "private-node"
					case "wrong-choice":
						capture.Execution = "local"
						if winner == "local" {
							capture.Execution = "server"
						}
					}
					selected, _ := json.Marshal(capture)
					publication.Selected = string(selected)
					raw, _ := json.Marshal(publication)
					if err := f.launch.directoryRoot.Remove("node-chain-execution-latency-capture.json"); err != nil {
						t.Fatal(err)
					}
					if err := writeDesktopRuntimeFile(f.launch, "node-chain-execution-latency-capture.json", raw, false); err != nil {
						t.Fatal(err)
					}
					if _, _, _, _, err := readDesktopSelectedLatencyCapture(f.operation, f.launch); err == nil {
						t.Fatal("foreign imported inventory borrowed selected native ownership")
					}
				})
			}
		})
	}
}
