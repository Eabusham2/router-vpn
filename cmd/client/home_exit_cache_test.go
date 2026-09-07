package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func provedHomeExitFixture(t *testing.T) *app {
	t.Helper()
	installPublicExitTestTransport(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "203.0.113.12")
	}))
	a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	t.Cleanup(func() { homeExitProofs.Delete(a) })
	w := httptest.NewRecorder()
	a.proveHomeExit(w, httptest.NewRequest(http.MethodPost, "/api/home-summary/prove-exit", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("cannot establish initial proof: %d %s", w.Code, w.Body.String())
	}
	return a
}

func TestHomeExitCacheInvalidatesSameSessionPathChanges(t *testing.T) {
	for _, change := range []string{"state", "phase", "proof", "runtime", "base", "router", "graph", "entry-policy", "exit-credential"} {
		t.Run(change, func(t *testing.T) {
			a := provedHomeExitFixture(t)
			tracker := sessionTrackerFor(a)
			tracker.mu.Lock()
			a.mu.Lock()
			switch change {
			case "state":
				a.state.Connected = false
			case "phase":
				tracker.session.Phase = "checking"
			case "proof":
				tracker.session.PathProof = "failed"
			case "runtime":
				tracker.session.ActualMode = "hysteria2"
			case "base":
				tracker.session.ActualBase = "awg"
			case "router":
				tracker.session.RouterID = "entry"
			case "graph":
				graph, _ := getActiveMultihopGraph(a)
				graph.Started = graph.Started.Add(time.Second)
				activeMultihopGraphs.Store(a, graph)
			case "entry-policy":
				a.profiles.Profiles[0].IPv6Mode = "off"
			case "exit-credential":
				a.profiles.Profiles[1].APIToken = "replacement"
			}
			a.mu.Unlock()
			tracker.mu.Unlock()
			value, err := a.homeSummaryValue()
			if err == nil && (value.ActualExitStatus == "proved" || value.ActualExitIP != "") {
				t.Fatalf("obsolete proof survived %s with the same session UUID: %+v", change, value)
			}
			if _, found := homeExitProofs.Load(a); found {
				t.Fatal("invalid proof remained available for later reuse")
			}
		})
	}
}

func TestHomeExitCacheCannotResurrectAcrossObservedTransitions(t *testing.T) {
	for _, transition := range []string{"recheck", "graph-replace", "graph-clear", "stop-request"} {
		t.Run(transition, func(t *testing.T) {
			a := provedHomeExitFixture(t)
			tracker := sessionTrackerFor(a)
			tracker.mu.Lock()
			tracker.session.DNSProof.Status = "passed" // No unrelated DNS worker.
			tracker.mu.Unlock()
			switch transition {
			case "recheck":
				old := tracker.capture()
				checking := old
				checking.Phase, checking.Connected = "checking", false
				tracker.observe(checking)
				tracker.observe(old)
			case "graph-replace", "graph-clear":
				old, _ := getActiveMultihopGraph(a)
				if transition == "graph-clear" {
					clearActiveMultihopGraph(a)
				} else {
					setActiveMultihopGraph(a, multihopSelection{Entry: a.profiles.Profiles[0], Exit: a.profiles.Profiles[1], Base: old.Base, ExitMode: old.ExitMode})
				}
				// Simulate rollback to the old graph object, not just equal node IDs.
				activeMultihopGraphs.Store(a, old)
			case "stop-request":
				tracker.markStopReason("user")
			}
			value, err := a.homeSummaryValue()
			if err != nil {
				t.Fatal(err)
			}
			if value.ActualExitStatus == "proved" || value.ActualExitIP != "" {
				t.Fatalf("old proof reappeared after %s: %+v", transition, value)
			}
		})
	}
}

func TestHomeExitCachePreservesProofAcrossDisplayAndMeasurementUpdates(t *testing.T) {
	a := provedHomeExitFixture(t)
	a.mu.Lock()
	a.profiles.SelectedID = "exit"
	for i := range a.profiles.Profiles {
		p := &a.profiles.Profiles[i]
		p.Name, p.Location = "renamed", "new label"
		p.LatencyMedianMs = 12.5
		p.PublicIP = "203.0.113.99" // Cached metadata is not this live proof.
		p.FastestDNSHost = "1.1.1.1"
	}
	a.mu.Unlock()
	value, err := a.homeSummaryValue()
	if err != nil {
		t.Fatal(err)
	}
	if value.ActualExitStatus != "proved" || value.ActualExitIP != "203.0.113.12" {
		t.Fatalf("unrelated display/result update altered the live proof: %+v", value)
	}
}
