package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestSpeedLabRunRejectsOverlappingCurrentMeasurements(t *testing.T) {
	a := &app{
		state:    state{Connected: true, Phase: "connected", Mode: "wg", RuntimeMode: "wg", Base: "wg", RouterID: "node-a"},
		profiles: common.RouterProfileStore{SelectedID: "node-a", Profiles: []common.RouterProfile{{ID: "node-a", NodeKind: "router-vpn"}}},
	}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "test-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: "node-a"}}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a) })
	entered := make(chan struct{}, 8)
	var requests atomic.Int32
	installSpeedLabSamplingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan struct{})
	first := httptest.NewRecorder()
	t.Cleanup(func() {
		cancel()
		select {
		case <-firstDone:
		case <-time.After(2 * time.Second):
			t.Error("cancelled Speed Lab owner did not release")
		}
	})
	go func() {
		defer close(firstDone)
		a.speedLabRun(first, httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", strings.NewReader(`{"scope":"current"}`)).WithContext(ctx))
	}()
	select {
	case <-entered:
	case <-firstDone:
		t.Fatalf("first run did not start: %s", first.Body.String())
	case <-time.After(2 * time.Second):
		t.Fatal("first run never reached the local provider")
	}

	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelSecond()
	second := httptest.NewRecorder()
	a.speedLabRun(second, httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", strings.NewReader(`{"scope":"current"}`)).WithContext(secondCtx))
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "Speed Lab test is already running") {
		t.Errorf("overlapping run was not refused by its measurement owner: HTTP %d %s", second.Code, second.Body.String())
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("overlapping run emitted provider traffic: got %d requests, want 1", got)
	}
	if ctx.Err() != nil {
		t.Fatal("refusing another measurement cancelled the first request")
	}
	cancel()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first run failed to finish cancellation")
	}
	if !a.state.Connected || !tracker.snapshot(0).Connected {
		t.Fatal("measurement cancellation disconnected the existing VPN")
	}
}

func TestSpeedLabRunOwnerIsPerAppAndReleaseIsIdempotent(t *testing.T) {
	if release, err := beginSpeedLabRun(nil); err == nil || release != nil {
		t.Fatal("nil app obtained a measurement owner")
	}
	a, other := &app{}, &app{}
	first, err := beginSpeedLabRun(a)
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	if release, err := beginSpeedLabRun(a); err == nil || release != nil {
		t.Fatal("overlapping owner was accepted")
	}
	independent, err := beginSpeedLabRun(other)
	if err != nil {
		t.Fatal("unrelated app was blocked:", err)
	}
	independent()
	first()
	replacement, err := beginSpeedLabRun(a)
	if err != nil {
		t.Fatal("owner was not released:", err)
	}
	defer replacement()
	first() // A late duplicate cleanup must not delete the replacement owner.
	if release, err := beginSpeedLabRun(a); err == nil || release != nil {
		t.Fatal("stale cleanup released the new measurement owner")
	}
	replacement()
	if _, exists := speedLabRunOwners.Load(a); exists {
		t.Fatal("completed measurement retained its app owner")
	}
}

func TestSpeedLabRunOwnerHasOneWinnerUnderContention(t *testing.T) {
	a := &app{}
	start, releaseOwner := make(chan struct{}), make(chan struct{})
	var contenders, finished sync.WaitGroup
	var winners atomic.Int32
	contenders.Add(32)
	finished.Add(32)
	for i := 0; i < 32; i++ {
		go func() {
			defer finished.Done()
			<-start
			release, err := beginSpeedLabRun(a)
			if err == nil {
				winners.Add(1)
			}
			contenders.Done()
			if err == nil {
				<-releaseOwner
				release()
			}
		}()
	}
	close(start)
	contenders.Wait()
	got := winners.Load()
	close(releaseOwner)
	finished.Wait()
	if got != 1 {
		t.Fatalf("concurrent Speed Lab owners: got %d, want 1", got)
	}
	if _, exists := speedLabRunOwners.Load(a); exists {
		t.Fatal("winner did not release its owner")
	}
}
