package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestHomeExitAdoptionRejectsStaleBindingsWithoutWrites(t *testing.T) {
	for _, reason := range []string{"cancel", "operation", "session", "graph", "entry", "storage", "private-ip"} {
		t.Run(reason, func(t *testing.T) {
			a := provedHomeExitFixture(t)
			raw, _ := homeExitProofs.Load(a)
			proof := raw.(*homeExitProof)
			path := a.cfg.ProfilesFile
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := http.StatusConflict
			ip := "203.0.113.20"
			switch reason {
			case "cancel":
				cancel()
			case "operation":
				a.operationMu.Lock()
				defer a.operationMu.Unlock()
			case "session":
				tracker := sessionTrackerFor(a)
				tracker.mu.Lock()
				tracker.session.ID = "replacement-session"
				tracker.mu.Unlock()
			case "graph":
				graph, _ := getActiveMultihopGraph(a)
				graph.Started = graph.Started.Add(time.Second)
				activeMultihopGraphs.Store(a, graph)
			case "entry":
				a.profiles.Profiles[0].APIToken = "replacement"
			case "storage":
				a.cfg.ProfilesFile = t.TempDir()
				want = http.StatusInternalServerError
			case "private-ip":
				ip = "192.168.50.1"
				want = http.StatusBadGateway
			}
			status, err := a.adoptHomeExitProof(ctx, *proof, ip)
			if err == nil || status != want {
				t.Fatalf("status=%d err=%v want=%d", status, err, want)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed proof changed durable profiles")
			}
			if a.profiles.Profiles[1].PublicIP != "203.0.113.12" {
				t.Fatal("failed proof changed live profile metadata")
			}
			if current, _ := homeExitProofs.Load(a); current != proof {
				t.Fatal("failed proof replaced the previous cache")
			}
			if !a.state.Connected {
				t.Fatal("proof adoption mutated the VPN lifecycle")
			}
		})
	}
}

func TestHomeExitAdoptionRechecksCancellationAfterWaitingForStateLock(t *testing.T) {
	a := provedHomeExitFixture(t)
	raw, _ := homeExitProofs.Load(a)
	proof := raw.(*homeExitProof)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.mu.Lock()
	done := make(chan int, 1)
	go func() { status, _ := a.adoptHomeExitProof(ctx, *proof, "203.0.113.20"); done <- status }()
	cancel()
	a.mu.Unlock()
	select {
	case status := <-done:
		if status != http.StatusConflict {
			t.Fatalf("cancelled adoption status=%d", status)
		}
	case <-time.After(time.Second):
		t.Fatal("adoption deadlocked")
	}
	if a.profiles.Profiles[1].PublicIP != "203.0.113.12" {
		t.Fatal("cancelled adoption persisted its address")
	}
}

func TestHomeExitRejectsLaggingTrackerBeforePublicRequests(t *testing.T) {
	var requests atomic.Int32
	installPublicExitTestTransport(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); io.WriteString(w, "203.0.113.12") }))
	a, _, _ := asyncPathFixture(t, "http://10.77.0.1:8787")
	a.state.RuntimeMode = "hysteria2"
	w := httptest.NewRecorder()
	a.proveHomeExit(w, httptest.NewRequest(http.MethodPost, "/exit", nil))
	if w.Code != http.StatusConflict || requests.Load() != 0 {
		t.Fatalf("lagging tracker reached network: %d requests=%d %s", w.Code, requests.Load(), w.Body.String())
	}
}

func TestHomeExitOldSummaryCannotDeleteNewerProof(t *testing.T) {
	a := provedHomeExitFixture(t)
	raw, _ := homeExitProofs.Load(a)
	old := raw.(*homeExitProof)
	newer := *old
	newer.IP = "203.0.113.20"
	homeExitProofs.Store(a, &newer)
	observed := sessionTrackerFor(a).snapshot(0)
	observed.Phase = "checking"
	if a.homeExitProofCurrent(old, a.profiles.Profiles[1], observed) {
		t.Fatal("obsolete summary accepted its old proof")
	}
	if current, _ := homeExitProofs.Load(a); current != &newer {
		t.Fatal("old summary deleted a newer concurrent proof")
	}
}

func TestHomeExitAdoptionRejectsARecheckThatFinishedBetweenObserverTicks(t *testing.T) {
	a := provedHomeExitFixture(t)
	raw, _ := homeExitProofs.Load(a)
	binding := *raw.(*homeExitProof)
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	tracker.session.DNSProof.Status = "passed"
	tracker.mu.Unlock()
	old := tracker.capture()
	checking := old
	checking.Connected, checking.Phase = false, "checking"
	tracker.observe(checking)
	tracker.observe(old)
	status, err := a.adoptHomeExitProof(context.Background(), binding, "203.0.113.20")
	if err == nil || status != http.StatusConflict {
		t.Fatal("completed transient recheck reused an old in-flight binding")
	}
}

func TestHomeExitAllowsFreshProofAfterSameSessionRollback(t *testing.T) {
	a := provedHomeExitFixture(t)
	tracker := sessionTrackerFor(a)
	tracker.mu.Lock()
	tracker.session.DNSProof.Status = "passed"
	tracker.mu.Unlock()
	old := tracker.capture()
	stopping := old
	stopping.Connected, stopping.Phase = false, "stopping"
	tracker.observe(stopping)
	tracker.observe(old)
	w := httptest.NewRecorder()
	a.proveHomeExit(w, httptest.NewRequest(http.MethodPost, "/exit", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("fresh proof disabled after completed rollback: %d %s", w.Code, w.Body.String())
	}
}
