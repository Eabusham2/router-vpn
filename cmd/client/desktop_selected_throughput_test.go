package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

func selectedThroughputParentRequest(t *testing.T, f *desktopNodeChainOwnedFixture, ctx context.Context, capture string) <-chan *httptest.ResponseRecorder {
	t.Helper()
	q := routedSpeedRequest{EntryID: f.selection.Nodes[0].Profile.ID, ExitID: f.selection.Nodes[len(f.selection.Nodes)-1].Profile.ID,
		OrderedCapture: capture, Bytes: 8 << 20}
	body, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/multihop/speed-test", bytes.NewReader(body))
		f.a.multihopSpeedTest(w, r)
		done <- w
	}()
	return done
}

func selectedThroughputParentCapture(t *testing.T, f *desktopNodeChainOwnedFixture) string {
	t.Helper()
	w := httptest.NewRecorder()
	f.a.nativeMultihopStatus(w, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil))
	var body struct {
		Token string `json:"ordered_capture"`
		Count int    `json:"ordered_nodes"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body.Token) != 64 || body.Count != len(f.selection.Nodes) {
		t.Fatal("public status did not offer the original complete throughput route", w.Code, w.Body)
	}
	return body.Token
}

func selectedThroughputParentReply(t *testing.T, f *desktopNodeChainOwnedFixture, q desktopSelectedLatencyRequest, status hopmeasure.Status) {
	t.Helper()
	result := desktopSelectedLatencyResult{desktopSelectedLatencyRequest: q, CompletedAt: time.Now().UnixMilli(), Status: status}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeDesktopRuntimeFile(f.launch, desktopSelectedThroughputResultFile, raw, false); err != nil {
		t.Fatal(err)
	}
	if err = f.launch.directoryRoot.Remove(desktopSelectedLatencyRequestFile); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopSelectedThroughputPublicController(t *testing.T) {
	for _, choice := range []struct{ requested, winner string }{{"server", "server"}, {"auto", "local"}, {"auto", "server"}} {
		t.Run(choice.requested+"-"+choice.winner, func(t *testing.T) {
			f, view := desktopSelectedMeasurementControllerFixture(t, choice.requested, choice.winner, 3)
			token := selectedThroughputParentCapture(t, f)
			ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
			defer cancel()
			if w := <-selectedThroughputParentRequest(t, f, ctx, strings.Repeat("0", 64)); w.Code != 409 {
				t.Fatal("foreign preflight admitted", w.Code)
			}
			done := selectedThroughputParentRequest(t, f, ctx, token)
			raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedLatencyRequestFile, done)
			var q desktopSelectedLatencyRequest
			if json.Unmarshal(raw, &q) != nil || q.Schema != 2 || q.Operation != "selected-path-throughput" || q.Bytes != 8<<20 ||
				q.NodeID != view.Nodes[2].NodeID || q.Position != 2 || q.Selected != view.Capture.SelectedCaptureJSON || q.Capture.Progress.Execution != choice.winner || !mtuSuspended(f.a) {
				t.Fatal("throughput borrowed a foreign target or MTU hold", q)
			}
			status := hopmeasure.Status{Request: q.Request, Stage: "complete", Complete: true, Drained: true}
			for pos, node := range view.Nodes {
				s := float64(pos + 1)
				tr := hopmeasure.Transfer{Seconds: s, Bytes: 8 << 20, Mbps: float64(8<<20) * 8 / s / 1e6}
				status.Results = append(status.Results, hopmeasure.Result{ID: node.NodeID, Role: node.Role, Kind: node.Kind, Ready: true,
					Label: fmt.Sprintf("Cumulative %s path through node %d of %d", choice.winner, pos+1, len(view.Nodes)),
					Idle:  &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}, Download: &tr, Upload: &tr})
			}
			selectedThroughputParentReply(t, f, q, status)
			w := <-done
			var body struct {
				Hops    []speedLabHopMeasurement `json:"hops"`
				Capture string                   `json:"ordered_capture"`
			}
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Capture != token || len(body.Hops) != len(view.Nodes) || mtuSuspended(f.a) {
				t.Fatal("public throughput lost a prefix or original joined hold", w.Code, w.Body)
			}
			for pos, row := range body.Hops {
				if row.RouterID != q.Capture.Progress.Prefixes[pos].ProfileID || row.Speed == nil || row.Speed.Bytes != 8<<20 || row.Speed.DownloadMs != 1000*float64(pos+1) || !strings.Contains(row.SpeedLabel, choice.winner) {
					t.Fatal("public output changed the selected prefix bytes, duration or label", pos, row)
				}
			}
		})
	}
}

// Model only the original child acknowledgement. The tagged native test
// independently counts real bytes and observes the dedicated transfer handle.
func TestDesktopSelectedThroughputCancellationJoinsOriginal(t *testing.T) {
	f, _ := desktopSelectedMeasurementControllerFixture(t, "auto", "server", 3)
	token := selectedThroughputParentCapture(t, f)
	work, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := selectedThroughputParentRequest(t, f, work, token)
	ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
	defer stop()
	raw := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedLatencyRequestFile, done)
	var q desktopSelectedLatencyRequest
	if json.Unmarshal(raw, &q) != nil || q.Bytes != 8<<20 {
		t.Fatal("missing original request")
	}
	cancel()
	matching := waitDesktopSelectedCandidateParentFile(t, ctx, f, desktopSelectedLatencyCancelFile, done)
	if !bytes.Equal(raw, matching) || !mtuSuspended(f.a) {
		t.Fatal("cancel released MTU before the original transfer joined")
	}
	selectedThroughputParentReply(t, f, q, hopmeasure.Status{Request: q.Request, Complete: true, Drained: true, Stage: "cancelled", Failure: "cancelled", Results: []hopmeasure.Result{}})
	w := <-done
	if w.Code == 200 || mtuSuspended(f.a) || strings.Contains(w.Body.String(), "download_mbps") {
		t.Fatal("cancelled bytes published or original hold retained", w.Code, w.Body)
	}
}

func TestDesktopSelectedThroughputRejectsForeignRows(t *testing.T) {
	f, view := desktopSelectedMeasurementControllerFixture(t, "auto", "server", 3)
	status := hopmeasure.Status{Request: strings.Repeat("1", 32), Complete: true, Drained: true, Stage: "complete"}
	for pos, node := range view.Nodes {
		tr := hopmeasure.Transfer{Bytes: 8 << 20, Seconds: 0.5, Mbps: 8 * float64(8<<20) / 0.5 / 1e6}
		status.Results = append(status.Results, hopmeasure.Result{ID: node.NodeID, Role: node.Role, Kind: node.Kind, Ready: true,
			Label: fmt.Sprintf("Cumulative server path through node %d of 3", pos+1),
			Idle:  &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 4}, Download: &tr, Upload: &tr})
	}
	for _, fault := range []string{"unjoined", "fifty", "winner", "swapped", "missing-final", "wrong-size", "bad-duration", "bad-rate"} {
		t.Run(fault, func(t *testing.T) {
			b, _ := json.Marshal(status)
			var v hopmeasure.Status
			_ = json.Unmarshal(b, &v)
			switch fault {
			case "unjoined":
				v.Drained = false
			case "fifty":
				v.Results[0].Benchmark = &hopmeasure.LatencyBenchmark{}
			case "winner":
				v.Results[1].Label = strings.Replace(v.Results[1].Label, "server", "local", 1)
			case "swapped":
				v.Results[0], v.Results[1] = v.Results[1], v.Results[0]
			case "missing-final":
				v.Results = v.Results[:2]
			case "wrong-size":
				v.Results[2].Download.Bytes--
			case "bad-duration":
				v.Results[1].Download.Seconds = 0
			case "bad-rate":
				v.Results[2].Upload.Mbps++
			}
			if _, err := desktopNodeChainThroughputRows(v, f.selection.Nodes, 8<<20, "server"); err == nil {
				t.Fatal("foreign/incomplete throughput was displayed", fault)
			}
		})
	}
}

func TestDesktopSelectedThroughputTerminalOwnership(t *testing.T) {
	for _, fault := range []string{"provisional", "copied-result", "changed-result", "returned-request"} {
		t.Run(fault, func(t *testing.T) {
			launch := desktopWorkspaceCaptureFixture(t)
			root := launch.directoryRoot
			raw := []byte("bounded terminal record")
			write := func(name string, body []byte) {
				t.Helper()
				f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.Write(body); err != nil {
					t.Fatal(err)
				}
				if err = f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			write(desktopSelectedThroughputResultFile, raw)
			held := new(desktopThroughputResultFile)
			if fault == "provisional" {
				write(desktopSelectedLatencyRequestFile, []byte("original request"))
			}
			first, err := held.read(t.Context(), launch)
			if fault == "provisional" {
				if err != nil || first != nil || held.info != nil {
					t.Fatal("provisional result was read or pinned")
				}
				return
			}
			if err != nil || !bytes.Equal(first, raw) || held.info == nil {
				t.Fatal("complete result lost its original inode", err)
			}
			switch fault {
			case "copied-result":
				if err = root.Rename(desktopSelectedThroughputResultFile, "old-receipt"); err != nil {
					t.Fatal(err)
				}
				write(desktopSelectedThroughputResultFile, raw)
			case "changed-result":
				if err = root.WriteFile(desktopSelectedThroughputResultFile, []byte("changed terminal record"), 0600); err != nil {
					t.Fatal(err)
				}
			case "returned-request":
				write(desktopSelectedLatencyRequestFile, []byte("a later request"))
			}
			if err = held.retire(t.Context(), launch); err == nil {
				t.Fatal("substituted or provisional result retired", fault)
			}
			if _, err = root.Lstat(desktopSelectedThroughputResultFile); err != nil {
				t.Fatal("foreign terminal result was removed", err)
			}
		})
	}
}
