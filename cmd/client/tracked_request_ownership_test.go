package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A refused request is not a connection attempt. In particular it must not
// rewrite a working session's requested mode, error, or public-exit epoch.
func TestTrackedConnectRejectionPreservesExistingSession(t *testing.T) {
	for _, reason := range []string{"connected", "transaction", "method", "json", "trailing-json", "oversized", "missing-mode", "cancelled"} {
		t.Run(reason, func(t *testing.T) {
			a := provedHomeExitFixture(t)
			tracker := sessionTrackerFor(a)
			before := tracker.snapshot(0)
			beforeJSON, _ := json.Marshal(before)
			proof, exists := homeExitProofs.Load(a)
			if !exists {
				t.Fatal("expected a valid initial proof")
			}
			epoch := homeExitProofs.generation(a)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			method, body, want := http.MethodPost, `{"mode":"wg","base":"awg"}`, http.StatusConflict
			switch reason {
			case "transaction":
				a.operationMu.Lock()
				defer a.operationMu.Unlock()
			case "method":
				method, want = http.MethodGet, http.StatusMethodNotAllowed
			case "json":
				body, want = `{`, http.StatusBadRequest
			case "trailing-json":
				body, want = `{"mode":"wg"} {"mode":"awg"}`, http.StatusBadRequest
			case "oversized":
				body, want = `{"mode":"wg"}`+strings.Repeat(" ", 16<<10), http.StatusBadRequest
			case "missing-mode":
				body, want = `{}`, http.StatusBadRequest
			case "cancelled":
				cancel()
				want = http.StatusRequestTimeout
			}
			w := httptest.NewRecorder()
			a.connectLogicalTracked(w, httptest.NewRequest(method, "/api/connect-logical", strings.NewReader(body)).WithContext(ctx))
			if w.Code != want {
				t.Errorf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
			}
			afterJSON, _ := json.Marshal(tracker.snapshot(0))
			if string(beforeJSON) != string(afterJSON) {
				t.Errorf("rejected request changed its unrelated live session:\nbefore=%s\nafter=%s", beforeJSON, afterJSON)
			}
			current, ok := homeExitProofs.Load(a)
			if !ok || current != proof || epoch != homeExitProofs.generation(a) {
				t.Error("rejected request invalidated the live exit proof")
			}
			if !a.state.Connected || a.state.RouterID != "exit" || a.state.RuntimeMode != "shadowsocks" {
				t.Fatal("rejected request modified the actual VPN")
			}
		})
	}
}

func TestTrackedEmergencyStopWrongMethodIsReadOnly(t *testing.T) {
	a := provedHomeExitFixture(t)
	tracker := sessionTrackerFor(a)
	before, _ := json.Marshal(tracker.snapshot(0))
	epoch := homeExitProofs.generation(a)
	w := httptest.NewRecorder()
	a.emergencyStopTracked(w, httptest.NewRequest(http.MethodGet, "/api/emergency-stop", nil))
	after, _ := json.Marshal(tracker.snapshot(0))
	if w.Code != http.StatusMethodNotAllowed || string(before) != string(after) || epoch != homeExitProofs.generation(a) || !a.state.Connected {
		t.Fatalf("GET mutated Emergency Stop state: status=%d before=%s after=%s", w.Code, before, after)
	}
}

func TestOwnedLogicalAttemptStillReportsTypedFailure(t *testing.T) {
	a, tracker := fastestAdoptionFixture(t)
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	w := httptest.NewRecorder()
	// An owned attempt for a missing runtime fails before starting any process.
	a.connectLogicalTracked(w, httptest.NewRequest(http.MethodPost, "/api/connect-logical", strings.NewReader(`{"mode":"missing-runtime","base":"wg"}`)))
	s := tracker.snapshot(0)
	if w.Code != http.StatusServiceUnavailable || s.RequestedMode != "missing-runtime" || s.RequestedBase != "wg" || s.Phase != "failed" || s.Connected || s.Error == nil || s.EndedAt == nil {
		t.Fatalf("accepted failed attempt lost typed progress: status=%d body=%s session=%+v", w.Code, w.Body.String(), s)
	}
	if !a.operationMu.TryLock() {
		t.Fatal("failed attempt retained connection ownership")
	}
	a.operationMu.Unlock()
}
