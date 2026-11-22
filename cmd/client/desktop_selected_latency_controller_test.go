package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

// This fixture models only the native producer and its kernel/transport. The
// shipping parent executes its actual typed adoption, HTTP API, private-file
// exchange, source/reader ownership, MTU hold and durable history transaction.
// Actual shared HTTP50 facade execution belongs to the separate native gate.
func desktopSelectedLatencyControllerFixture(t *testing.T, execution string, count int) (*desktopNodeChainOwnedFixture, desktopOrderedLatencyView) {
	t.Helper()
	return desktopSelectedMeasurementControllerFixture(t, "auto", execution, count)
}

func desktopSelectedMeasurementControllerFixture(t *testing.T, requested, execution string, count int) (*desktopNodeChainOwnedFixture, desktopOrderedLatencyView) {
	t.Helper()
	f := newDesktopNodeChainOwnedFixture(t, count)
	f.executionModel = &desktopExecutionOwnedModel{winner: execution}
	request := &desktopNodeChainExecutionRequest{capture: f.capture, native: f.selection.Native, requested: requested}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, f.selection, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	f.launch = launch
	session := &desktopNodeChainExecutionSession{app: f.a, launch: launch, execution: launch.chain.execution, selection: f.selection}
	if err := session.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := retireDesktopOrderedLatencyFixture(ctx, f.a, f.launch.command); err != nil {
			t.Error("selected parent fixture left original workers", err)
		}
	})
	f.a.cfg.StateFile = filepath.Join(clientRoot(f.a), "selected-fifty-state.json")
	f.a.mu.Lock()
	f.a.state.Connected, f.a.state.Phase = true, "connected"
	f.a.mu.Unlock()
	sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "session-1-1", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
	e := f.launch.chain.execution
	e.mu.Lock()
	readyBytes, _ := json.Marshal(e.ready)
	projection := e.projection
	e.mu.Unlock()
	selected := desktopSelectedLatencyCapture{Schema: 1, SourceSHA256: projection.SourceSHA256(), ConfigSHA256: projection.ConfigSHA256(),
		GenerationSHA256: strings.Repeat("e", 64), Execution: execution, Nodes: []desktopSelectedLatencyNode{}}
	for position, member := range f.selection.Nodes {
		role, kind, _, _, _ := desktopSelectedLatencyMeaning(position, len(f.selection.Nodes), "private-node", execution)
		selected.Nodes = append(selected.Nodes, desktopSelectedLatencyNode{NodeID: member.Profile.ID, Position: position, Role: role, Kind: kind})
	}
	selectedBytes, _ := json.Marshal(selected)
	publication := desktopSelectedLatencyPublication{Schema: 1, Kind: "routervpn-node-chain-execution-latency-capture-v1", Capture: readyBytes, Selected: string(selectedBytes)}
	raw, _ := json.Marshal(publication)
	if err := writeDesktopRuntimeFile(f.launch, "node-chain-execution-latency-capture.json", raw, false); err != nil {
		t.Fatal(err)
	}
	response := desktopOrderedHTTP(t, f.a, "GET", "/api/speed-lab/ordered-latency", nil)
	var view desktopOrderedLatencyView
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &view) != nil ||
		view.Capture.SelectedCaptureJSON != string(selectedBytes) || len(view.Nodes) != len(f.selection.Nodes) {
		t.Fatal("selected parent did not capture original typed native record", response.Code, response.Body.String())
	}
	return f, view
}

func waitDesktopSelectedLatencyFixtureRequest(t *testing.T, f *desktopNodeChainOwnedFixture, op *desktopOrderedLatencyOperation, ctx context.Context, filename string) (desktopSelectedLatencyRequest, []byte) {
	t.Helper()
	for {
		raw, err := readDesktopRuntimeFileContext(ctx, f.launch, filename, 16384)
		if err == nil {
			var request desktopSelectedLatencyRequest
			if decodePrivateControlJSONBounded(raw, &request, 16384) != nil {
				t.Fatal("selected parent published invalid request")
			}
			return request, raw
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-op.done:
			t.Fatal("selected parent refused expected mailbox", op.view())
		case <-ctx.Done():
			t.Fatal("selected mailbox did not start", ctx.Err(), op.view())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestDesktopSelectedLatencyControllerKeepsOriginalChoice(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		for _, count := range []int{2, 8} {
			t.Run(fmt.Sprintf("%s-%d", execution, count), func(t *testing.T) {
				f, view := desktopSelectedLatencyControllerFixture(t, execution, count)
				request := desktopOrderedLatencyRequest{Capture: view.Capture, NodeID: view.Nodes[0].NodeID, Position: 0, Request: strings.Repeat("a", 32)}
				foreign := request
				foreign.Capture.SelectedCaptureJSON = ""
				if r := desktopOrderedHTTP(t, f.a, "POST", "/api/speed-lab/ordered-latency", foreign); r.Code != 409 {
					t.Fatal("ordinary capture borrowed selected owner", r.Code)
				}
				if r := desktopOrderedHTTP(t, f.a, "POST", "/api/speed-lab/ordered-latency", request); r.Code != 202 {
					t.Fatal("selected parent request not admitted", r.Code, r.Body.String())
				}
				slot := f.a.desktopOrderedLatencyFor()
				slot.mu.Lock()
				op := slot.current
				slot.mu.Unlock()
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				mailbox, _ := waitDesktopSelectedLatencyFixtureRequest(t, f, op, ctx, desktopSelectedLatencyRequestFile)
				if mailbox.Schema != 1 || mailbox.Operation != "selected-latency-50" || mailbox.Selected != request.Capture.SelectedCaptureJSON ||
					mailbox.Request != request.Request || mailbox.Capture.Progress.Execution != execution || !mtuSuspended(f.a) {
					t.Fatal("selected parent borrowed another execution or MTU owner")
				}
				if _, err := readDesktopRuntimeFileContext(ctx, f.launch, "node-chain-measure-request.json", 16384); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("selected request entered ordinary Local mailbox")
				}
				saved := desktopSelectedLatencyReceiptFixture(view.Capture, view.Nodes[0])
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
					t.Fatal("selected parent did not join", ctx.Err(), op.view())
				}
				completed := op.view()
				history, err := readDesktopSelectedLatencyHistory(f.a)
				if err != nil || completed.Receipt == nil || !completed.Status.Drained || completed.Status.Failure != "" || len(history.Records) != 1 ||
					history.Records[0].Capture != view.Capture.SelectedCaptureJSON || !reflect.DeepEqual(history.Records[0].Receipt, saved) {
					t.Fatal("selected parent did not durably commit exact original receipt", err, completed)
				}
				if f.starts != 1 || f.executionModel.winner != execution || mtuSuspended(f.a) {
					t.Fatal("measurement repeated selection or retained joined MTU hold")
				}
				if r := desktopOrderedHTTP(t, f.a, "POST", "/api/speed-lab/ordered-latency", request); r.Code != 409 {
					t.Fatal("selected request identity reused", r.Code)
				}
			})
		}
	}
}

func TestDesktopSelectedLatencyControllerCancellationJoinsOriginal(t *testing.T) {
	f, view := desktopSelectedLatencyControllerFixture(t, "server", 2)
	request := desktopOrderedLatencyRequest{Capture: view.Capture, NodeID: view.Nodes[1].NodeID, Position: 1, Request: strings.Repeat("b", 32)}
	if r := desktopOrderedHTTP(t, f.a, "POST", "/api/speed-lab/ordered-latency", request); r.Code != 202 {
		t.Fatal(r.Code, r.Body.String())
	}
	slot := f.a.desktopOrderedLatencyFor()
	slot.mu.Lock()
	op := slot.current
	slot.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	mailbox, original := waitDesktopSelectedLatencyFixtureRequest(t, f, op, ctx, desktopSelectedLatencyRequestFile)
	if r := desktopOrderedHTTP(t, f.a, "POST", "/api/speed-lab/ordered-latency/cancel", request); r.Code != 202 {
		t.Fatal(r.Code, r.Body.String())
	}
	_, cancelled := waitDesktopSelectedLatencyFixtureRequest(t, f, op, ctx, desktopSelectedLatencyCancelFile)
	if string(original) != string(cancelled) || !mtuSuspended(f.a) || op.view().Status.Drained {
		t.Fatal("cancel changed original request or released undrained MTU hold")
	}
	result := desktopSelectedLatencyResult{desktopSelectedLatencyRequest: mailbox, CompletedAt: time.Now().UnixMilli(),
		Status: hopmeasure.Status{Request: request.Request, Complete: true, Drained: true, Stage: "cancelled", Failure: "fixture original native cancelled", Results: []hopmeasure.Result{}}}
	raw, _ := json.Marshal(result)
	if err := writeDesktopRuntimeFile(f.launch, desktopSelectedLatencyResultFile, raw, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{desktopSelectedLatencyCancelFile, desktopSelectedLatencyRequestFile} {
		if err := f.launch.directoryRoot.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-op.done:
	case <-ctx.Done():
		t.Fatal("selected cancellation did not join original worker", ctx.Err())
	}
	if !op.view().Status.Drained || op.view().Receipt != nil || mtuSuspended(f.a) || f.starts != 1 {
		t.Fatal("cancelled selected operation changed history or retained original lease")
	}
	if _, err := os.Stat(desktopSelectedLatencyHistoryPath(f.a)); !os.IsNotExist(err) {
		t.Fatal("cancelled selected operation wrote durable history")
	}
}

func TestDesktopSelectedLatencyControllerUnissuedRequest(t *testing.T) {
	for _, source := range []string{"candidate-mailbox", "measurement-lease"} {
		t.Run(source, func(t *testing.T) {
			f, view := desktopSelectedLatencyControllerFixture(t, "server", 3)
			const candidate = "original candidate work"
			var release func(bool)
			if source == "candidate-mailbox" {
				if err := writeDesktopRuntimeFile(f.launch, desktopSelectedCandidateRequestFile, []byte(candidate), false); err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				release, err = beginDesktopNodeChainMeasurementHold(t.Context(), f.a, f.launch)
				if err != nil {
					t.Fatal(err)
				}
				defer release(true)
			}
			q := desktopOrderedLatencyRequest{Capture: view.Capture, NodeID: view.Nodes[0].NodeID, Position: 0, Request: strings.Repeat("c", 32)}
			if w := desktopOrderedHTTP(t, f.a, "POST", "/api/speed-lab/ordered-latency", q); w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			slot := f.a.desktopOrderedLatencyFor()
			slot.mu.Lock()
			op := slot.current
			slot.mu.Unlock()
			select {
			case <-op.done:
			case <-time.After(3 * time.Second):
				t.Fatal("unissued latency request waited for another owner's receipt")
			}
			status := op.view()
			if !status.Status.Complete || !status.Status.Drained || status.Status.Stage != "failed" || status.Receipt != nil {
				t.Fatal("unissued latency request did not finish without a score", status)
			}
			for _, name := range []string{desktopSelectedLatencyRequestFile, desktopSelectedLatencyCancelFile, desktopSelectedLatencyResultFile} {
				if _, err := f.launch.directoryRoot.Lstat(name); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unissued latency changed the native mailbox", name, err)
				}
			}
			if _, err := os.Stat(desktopSelectedLatencyHistoryPath(f.a)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unissued latency changed history", err)
			}
			if source == "candidate-mailbox" {
				raw, err := f.launch.directoryRoot.ReadFile(desktopSelectedCandidateRequestFile)
				if err != nil || string(raw) != candidate {
					t.Fatal("latency observation consumed original candidate work", err)
				}
				if err := f.launch.directoryRoot.Remove(desktopSelectedCandidateRequestFile); err != nil {
					t.Fatal(err)
				}
			} else {
				if !mtuSuspended(f.a) {
					t.Fatal("unissued latency released someone else's measurement lease")
				}
				release(true)
			}
			if mtuSuspended(f.a) || f.starts != 1 {
				t.Fatal("unissued latency retained an MTU hold or reselected the connection")
			}
		})
	}
}
