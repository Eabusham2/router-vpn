package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func fastestAdoptionFixture(t *testing.T) (*app, *sessionTracker) {
	t.Helper()
	root := t.TempDir()
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")},
		profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: "a", Profiles: []common.RouterProfile{
			{ID: "a", Name: "A", Endpoint: "one.invalid", LatencySamples: 50, LatencyMedianMs: 40},
			{ID: "b", Name: "B", Endpoint: "two.invalid", LatencySamples: 60, LatencyMedianMs: 30},
		}},
		state: state{Phase: "off", RouterID: "a"},
	}
	tracker := &sessionTracker{a: a, session: &connectionSession{ID: "idle-session", Phase: "off"}}
	sessionTrackers.Store(a, tracker)
	t.Cleanup(func() { sessionTrackers.Delete(a); homeExitProofs.Delete(a) })
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	return a, tracker
}

func fastestMeasuredResult(p common.RouterProfile) liveLatencyResult {
	ms := float64(10)
	if p.ID == "b" {
		ms = 2
	}
	values := make([]float64, fastestProfileSamples)
	for i := range values {
		values[i] = ms
	}
	return profileLatencySummary(p, 443, values, 0)
}

// Adoption controls supply only a stable network identity. The shipping source
// path, actual lock ownership and original request context remain under test.
func fastestAdoptionRequest(a *app, w http.ResponseWriter, r *http.Request, probe func(context.Context, common.RouterProfile, int) (liveLatencyResult, error)) {
	a.fastestProfileWithSources(w, r, probe, func(ctx context.Context) (string, error) { return "captured-adoption-network", ctx.Err() })
}

func TestFastestSelectionUsesTrackerBeforeAppLock(t *testing.T) {
	a, tracker := fastestAdoptionFixture(t)
	measured, finish := make(chan struct{}), make(chan struct{})
	joined := make(chan struct{})
	finishProbe := sync.OnceFunc(func() { close(finish) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		finishProbe()
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("Fastest selection fixture did not join its original request")
		}
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		defer close(joined)
		w := httptest.NewRecorder()
		fastestAdoptionRequest(a, w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{}`)).WithContext(ctx),
			func(_ context.Context, p common.RouterProfile, _ int) (liveLatencyResult, error) {
				if p.ID == "b" {
					close(measured)
					<-finish
				}
				return fastestMeasuredResult(p), nil
			})
		done <- w
	}()
	select {
	case <-measured:
	case w := <-done:
		t.Fatalf("Fastest selection returned before the captured probe: status=%d body=%s", w.Code, w.Body.String())
	case <-time.After(time.Second):
		t.Fatal("Fastest selection did not reach its captured probe")
	}
	// Emulate the observer holding tracker.mu before it reads app.mu. The
	// selector must wait without acquiring app.mu in the opposite order.
	tracker.mu.Lock()
	finishProbe()
	operationOwned, inverted := false, false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if a.operationMu.TryLock() {
			a.operationMu.Unlock()
		} else {
			operationOwned = true
		}
		if a.mu.TryLock() {
			a.mu.Unlock()
		} else {
			inverted = true
		}
		if operationOwned || inverted {
			break
		}
		time.Sleep(time.Millisecond)
	}
	tracker.mu.Unlock()
	select {
	case w := <-done:
		if w.Code != http.StatusOK {
			t.Errorf("valid selection failed: %d %s", w.Code, w.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("selection remained blocked after tracker released")
	}
	if inverted || !operationOwned {
		t.Fatalf("selection inverted tracker/app lock order or missed operation ownership: inverted=%t operation=%t", inverted, operationOwned)
	}
}

func TestFastestSelectionRejectsStaleStateAndPreservesRollback(t *testing.T) {
	for _, scenario := range []string{"working", "cancelled", "session", "selection", "catalog", "credentials", "policy", "connected", "transaction", "persistence"} {
		t.Run(scenario, func(t *testing.T) {
			a, tracker := fastestAdoptionFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			held := false
			defer func() {
				if held {
					a.operationMu.Unlock()
				}
			}()
			probe := func(_ context.Context, p common.RouterProfile, _ int) (liveLatencyResult, error) {
				// No networking may hold either the transaction or state locks.
				if !a.operationMu.TryLock() {
					t.Fatal("measurement holds the operation lock")
				}
				a.operationMu.Unlock()
				if !a.mu.TryLock() {
					t.Fatal("measurement holds app.mu")
				}
				a.mu.Unlock()
				if !tracker.mu.TryLock() {
					t.Fatal("measurement holds tracker.mu")
				}
				tracker.mu.Unlock()
				if p.ID == "b" {
					switch scenario {
					case "cancelled":
						cancel()
					case "session":
						tracker.mu.Lock()
						tracker.session.ID = "new-session"
						tracker.mu.Unlock()
					case "selection":
						a.mu.Lock()
						a.profiles.SelectedID = "manual-choice"
						a.mu.Unlock()
					case "catalog":
						a.mu.Lock()
						a.profiles.Profiles[1].Endpoint = "changed.invalid"
						a.mu.Unlock()
					case "connected":
						a.mu.Lock()
						a.state.Connected = true
						a.state.Phase = "connected"
						a.mu.Unlock()
					case "credentials":
						a.mu.Lock()
						a.profiles.Profiles[1].APIToken = "replacement-private-source"
						a.mu.Unlock()
					case "policy":
						a.mu.Lock()
						a.profiles.Profiles[1].DNSMode = "replacement-policy"
						a.mu.Unlock()
					case "transaction":
						a.operationMu.Lock()
						held = true
					case "persistence":
						a.cfg.ProfilesFile = filepath.Dir(a.cfg.ProfilesFile)
					}
				}
				return fastestMeasuredResult(p), nil
			}
			w := httptest.NewRecorder()
			fastestAdoptionRequest(a, w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{}`)).WithContext(ctx), probe)
			wantStatus, wantSelected := http.StatusConflict, "a"
			switch scenario {
			case "working":
				wantStatus, wantSelected = http.StatusOK, "b"
			case "cancelled":
				wantStatus = http.StatusRequestTimeout
			case "selection":
				wantSelected = "manual-choice"
			case "persistence":
				wantStatus = http.StatusInternalServerError
			}
			if w.Code != wantStatus || a.profiles.SelectedID != wantSelected {
				t.Fatalf("status=%d selected=%s want=%d/%s body=%s", w.Code, a.profiles.SelectedID, wantStatus, wantSelected, w.Body.String())
			}
			if scenario != "working" && a.state.RouterID != "a" {
				t.Fatal("failed selection changed runtime node")
			}
			if a.profiles.Profiles[0].LatencySamples != 50 || a.profiles.Profiles[1].LatencySamples != 60 || a.profiles.Profiles[1].LatencyMedianMs != 30 {
				t.Fatal("Fastest round overwrote the separately saved benchmark")
			}
			file := a.cfg.ProfilesFile
			if scenario == "persistence" {
				file = filepath.Join(file, "routers.json")
			}
			stored, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "working" {
				var store common.RouterProfileStore
				if err := json.Unmarshal(stored, &store); err != nil || store.SelectedID != "b" {
					t.Fatalf("winner not persisted: %s %v", stored, err)
				}
			} else if string(stored) != string(original) {
				t.Fatal("rejected measurement changed durable selection")
			}
		})
	}
}

func TestFastestReadOnlyMeasurementDoesNotAcquireMutationOwnership(t *testing.T) {
	a, _ := fastestAdoptionFixture(t)
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	w := httptest.NewRecorder()
	fastestAdoptionRequest(a, w, httptest.NewRequest(http.MethodPost, "/api/profile/fastest", strings.NewReader(`{"select":false}`)),
		func(_ context.Context, p common.RouterProfile, _ int) (liveLatencyResult, error) {
			return fastestMeasuredResult(p), nil
		})
	if w.Code != http.StatusOK || a.profiles.SelectedID != "a" || a.state.Connected {
		t.Fatalf("read-only measurement changed connection or required mutation: %d %s", w.Code, w.Body.String())
	}
}
