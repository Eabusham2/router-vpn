package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobilemultihop"
)

func TestOrderedPerformanceCaptureBindsEveryNativeMemberAndOwner(t *testing.T) {
	identity := speedLabPathIdentity{SessionID: "controller-session", Network: "physical-network", StateToken: "connected-state", Graph: activeMultihopGraph{EntryID: "a", ExitID: "c", ChainNodes: 3, Started: time.Unix(123, 0)}}
	ready := mobilemultihop.DesktopNodeChainReadyRecord{Identity: mobilemultihop.NodeChainIdentity{EngineID: "engine", SessionID: "session", NetworkID: "network", SourceSHA256: strings.Repeat("a", 64), ConfigSHA256: strings.Repeat("b", 64)}, Generation: 1, Reader: 2, MTU: 1400, ObservedAt: 100}
	members := []string{"a", "b", "c"}
	token, err := orderedPerformanceCapture(identity, ready, members)
	if err != nil || len(token) != 64 {
		t.Fatalf("capture: %q %v", token, err)
	}
	heartbeat := ready
	heartbeat.ObservedAt++
	same, err := orderedPerformanceCapture(identity, heartbeat, members)
	if err != nil || same != token {
		t.Fatal("ordinary heartbeat changed immutable capture")
	}
	for _, field := range []string{"engine", "session", "network", "source", "config", "generation", "reader", "mtu", "middle", "order", "controller", "physical", "state", "graph"} {
		t.Run(field, func(t *testing.T) {
			i, r, m := identity, ready, append([]string(nil), members...)
			switch field {
			case "engine":
				r.Identity.EngineID += "other"
			case "session":
				r.Identity.SessionID += "other"
			case "network":
				r.Identity.NetworkID += "other"
			case "source":
				r.Identity.SourceSHA256 = strings.Repeat("c", 64)
			case "config":
				r.Identity.ConfigSHA256 = strings.Repeat("c", 64)
			case "generation":
				r.Generation++
			case "reader":
				r.Reader++
			case "mtu":
				r.MTU--
			case "middle":
				m[1] = "replacement"
			case "order":
				m[0], m[1] = m[1], m[0]
			case "controller":
				i.SessionID += "other"
			case "physical":
				i.Network += "other"
			case "state":
				i.StateToken += "other"
			case "graph":
				i.Graph.Started = i.Graph.Started.Add(time.Second)
			}
			changed, e := orderedPerformanceCapture(i, r, m)
			if e != nil || changed == token {
				t.Fatalf("%s replacement reused capture: %v", field, e)
			}
		})
	}
	for _, m := range [][]string{nil, {"a"}, {"a", "c"}} {
		if _, err := orderedPerformanceCapture(identity, ready, m); err == nil {
			t.Fatal("incomplete node list captured")
		}
	}
	ready.Identity.EngineID = ""
	if _, err := orderedPerformanceCapture(identity, ready, members); err == nil {
		t.Fatal("unproved engine captured")
	}
}

// Uses the existing explicit native/kernel fixture boundary. The real HTTP
// handlers and retained owner run here; these assertions do not claim TUN traffic.
func TestOrderedPerformanceHTTPPreflightRejectsStaleMiddle(t *testing.T) {
	f := startupProvedNodeChainOwner(t, 3)
	sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "ordered-performance-fixture", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Exit.ID}})
	w := httptest.NewRecorder()
	f.a.multihopStatus(w, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("preflight %d: %s", w.Code, w.Body.String())
	}
	var status struct {
		Entry   string `json:"entry_id"`
		Exit    string `json:"exit_id"`
		Capture string `json:"ordered_capture"`
		Count   int    `json:"ordered_nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status.Count != 3 || len(status.Capture) != 64 {
		t.Fatalf("missing ordered capture: %s %v", w.Body.String(), err)
	}
	// A request that lacks the all-member preflight must never enter a legacy
	// pair proxy, even though its endpoint IDs are correct.
	for _, capture := range []string{"", strings.Repeat("f", 64)} {
		raw, _ := json.Marshal(routedSpeedRequest{EntryID: status.Entry, ExitID: status.Exit, Bytes: 8 << 20, OrderedCapture: capture})
		w = httptest.NewRecorder()
		f.a.multihopSpeedTest(w, httptest.NewRequest(http.MethodPost, "/api/multihop/speed-test", bytes.NewReader(raw)))
		if w.Code != http.StatusConflict {
			t.Fatalf("foreign capture %d: %s", w.Code, w.Body.String())
		}
	}
	f.a.mu.Lock()
	for i := range f.a.profiles.Profiles {
		if f.a.profiles.Profiles[i].ID == f.selection.Nodes[1].Profile.ID {
			f.a.profiles.Profiles[i].APIToken += "changed"
		}
	}
	f.a.mu.Unlock()
	raw, _ := json.Marshal(routedSpeedRequest{EntryID: status.Entry, ExitID: status.Exit, Bytes: 8 << 20, OrderedCapture: status.Capture})
	w = httptest.NewRecorder()
	f.a.multihopSpeedTest(w, httptest.NewRequest(http.MethodPost, "/api/multihop/speed-test", bytes.NewReader(raw)))
	if w.Code != http.StatusConflict {
		t.Fatalf("changed intermediate owner accepted %d: %s", w.Code, w.Body.String())
	}
	if f.launch.chain.measurementGeneration != 0 {
		t.Fatal("rejected capture started native measurement")
	}
}
