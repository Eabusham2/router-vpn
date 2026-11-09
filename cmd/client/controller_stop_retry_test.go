package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func stopRetryFixture(t *testing.T) (*app, *sessionTracker, *sessionDNSStopReceipt) {
	t.Helper()
	a, tracker, _, _ := dnsPathFixture(t)
	a.modes = []common.Mode{{ID: "multihop"}}
	a.operationMu.Lock()
	receipt, err := a.drainSessionDNSForStop(context.Background())
	a.operationMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return a, tracker, receipt
}

func stopRetryRequest(a *app, ctx context.Context, method, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.retryDisconnect(w, httptest.NewRequest(method, "/api/disconnect/retry", strings.NewReader(body)).WithContext(ctx))
	return w
}
func stopRetryBody(token string) string {
	raw, _ := json.Marshal(map[string]string{"stop_token": token})
	return string(raw)
}

func TestControllerStatusRetainsExactStopReceiptAndPresentation(t *testing.T) {
	t.Run("no-observer-created", func(t *testing.T) {
		a := &app{state: state{Connected: true, Phase: "connected"}}
		got, err := a.controllerStatusContext(context.Background())
		if err != nil || got.StopPending || got.StopToken != "" || got.state != a.state {
			t.Fatal("status changed presentation or invented cleanup", got, err)
		}
		if _, exists := sessionTrackers.Load(a); exists {
			t.Fatal("status created an observer")
		}
	})
	for _, phase := range []string{"connected", "failed", "off", "stopping"} {
		t.Run(phase, func(t *testing.T) {
			a, tracker, receipt := stopRetryFixture(t)
			a.state.Phase = phase
			original := a.state
			got, err := a.controllerStatusContext(context.Background())
			if err != nil || !got.StopPending || got.StopToken != receipt.token || got.state != original {
				t.Fatal("pending status changed captured presentation", got, err)
			}
			w := httptest.NewRecorder()
			a.status(w, httptest.NewRequest("GET", "/api/status", nil))
			var wire map[string]any
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &wire) != nil || wire["stop_pending"] != true || wire["stop_token"] != receipt.token || wire["connected"] != original.Connected {
				t.Fatal("actual status JSON lost receipt or original Connected", w.Body.String())
			}
			if err := receipt.finish(context.Background()); err != nil {
				t.Fatal(err)
			}
			got, err = a.controllerStatusContext(context.Background())
			if err != nil || got.StopPending || got.StopToken != "" || tracker.dnsProofStop != nil {
				t.Fatal("completed receipt remained retryable", got, err)
			}
		})
	}
}

func TestControllerStatusRefusesUnownedPendingReceipt(t *testing.T) {
	for _, change := range []string{"token", "epoch", "registry"} {
		t.Run(change, func(t *testing.T) {
			a, tracker, receipt := stopRetryFixture(t)
			before := a.state
			switch change {
			case "token":
				receipt.token = "invalid"
			case "epoch":
				tracker.dnsProofEpoch.Add(1)
			case "registry":
				sessionTrackers.Store(a, &sessionTracker{a: &app{}})
			}
			w := httptest.NewRecorder()
			a.status(w, httptest.NewRequest("GET", "/api/status", nil))
			if w.Code != http.StatusConflict || a.state != before || strings.Contains(w.Body.String(), `"stop_pending":false`) {
				t.Fatal("invalid receipt became a false idle status", w.Code, w.Body.String())
			}
		})
	}
}

func TestControllerStatusCancellationPreservesTrackerAppLockOrder(t *testing.T) {
	for _, lock := range []string{"tracker", "app"} {
		t.Run(lock, func(t *testing.T) {
			a, tracker, _ := stopRetryFixture(t)
			parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx := &measurementAdmissionWaitingContext{Context: parent, waiting: make(chan struct{})}
			if lock == "tracker" {
				tracker.mu.Lock()
			} else {
				a.mu.Lock()
			}
			done := make(chan error, 1)
			go func() { _, err := a.controllerStatusContext(ctx); done <- err }()
			<-ctx.waiting
			if lock == "tracker" {
				if !a.mu.TryLock() {
					tracker.mu.Unlock()
					t.Fatal("status reserved app while waiting for tracker")
				}
				a.mu.Unlock()
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Error("status lost original cancellation", err)
			}
			if lock == "tracker" {
				tracker.mu.Unlock()
			} else {
				a.mu.Unlock()
			}
		})
	}
}

func TestOwnedStopRetryRejectsExpiredAndReplacementReceiptsBeforeCancellation(t *testing.T) {
	for _, change := range []string{"finished", "replacement-same-epoch", "changed-token", "closed-controller"} {
		t.Run(change, func(t *testing.T) {
			a, tracker, receipt := stopRetryFixture(t)
			var cancelled atomic.Int32
			a.connectionContext = context.Background()
			a.connectionCancel = func() { cancelled.Add(1) }
			token := receipt.token
			switch change {
			case "finished":
				if err := receipt.finish(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "replacement-same-epoch":
				replacement := &sessionTracker{a: a}
				replacement.dnsProofEpoch.Store(receipt.epoch)
				replacement.dnsProofStop = &sessionDNSStopReceipt{tracker: replacement, epoch: receipt.epoch, token: strings.Repeat("b", 32)}
				sessionTrackers.Store(a, replacement)
			case "changed-token":
				token = strings.Repeat("c", 32)
			case "closed-controller":
				a.closing = true
			}
			a.state = state{Connected: true, Phase: "connected", Mode: "replacement", RouterID: "replacement"}
			original := a.state
			w := stopRetryRequest(a, context.Background(), "POST", stopRetryBody(token))
			if w.Code != http.StatusConflict || cancelled.Load() != 0 || a.state != original || a.connectionCancelIntent != nil {
				t.Fatal("expired Retry cancelled or changed replacement", w.Code, w.Body.String(), cancelled.Load())
			}
			if change == "replacement-same-epoch" && tracker.dnsProofStop != receipt {
				t.Fatal("stale retry modified the old receipt")
			}
		})
	}
}

func TestOwnedStopRetryChecksReceiptAfterWaitingForOperation(t *testing.T) {
	for _, change := range []string{"cancel", "replacement"} {
		t.Run(change, func(t *testing.T) {
			a, _, receipt := stopRetryFixture(t)
			var cancelled atomic.Int32
			a.connectionCancel = func() { cancelled.Add(1) }
			a.connectionContext = context.Background()
			parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx := &measurementAdmissionWaitingContext{Context: parent, waiting: make(chan struct{})}
			a.operationMu.Lock()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- stopRetryRequest(a, ctx, "POST", stopRetryBody(receipt.token)) }()
			<-ctx.waiting
			if change == "cancel" {
				cancel()
			} else {
				if err := receipt.finish(context.Background()); err != nil {
					a.operationMu.Unlock()
					t.Fatal(err)
				}
				if _, err := a.drainSessionDNSForStop(context.Background()); err != nil {
					a.operationMu.Unlock()
					t.Fatal(err)
				}
			}
			a.operationMu.Unlock()
			w := <-done
			if w.Code != http.StatusConflict || cancelled.Load() != 0 {
				t.Fatal("queued retry used a replacement receipt or ignored cancellation", w.Code, cancelled.Load())
			}
		})
	}
}

func TestOwnedStopRetryStrictRequestAndRequiredDrainOwner(t *testing.T) {
	for _, body := range []string{"{}", `{"stop_token":true}`, `{"stop_token":"bad"}`, stopRetryBody(strings.Repeat("a", 32)) + ` {}`, `{"stop_token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}`} {
		t.Run(body, func(t *testing.T) {
			a, _, _ := stopRetryFixture(t)
			w := stopRetryRequest(a, context.Background(), "POST", body)
			if w.Code != 400 {
				t.Fatal("malformed retry accepted", w.Code)
			}
		})
	}
	a, _, receipt := stopRetryFixture(t)
	if w := stopRetryRequest(a, context.Background(), "GET", stopRetryBody(receipt.token)); w.Code != 405 {
		t.Fatal("GET mutated cleanup", w.Code)
	}
	if err := receipt.finish(context.Background()); err != nil {
		t.Fatal(err)
	}
	replacement, err := a.drainSessionDNSForStop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if replacement.token == receipt.token {
		t.Fatal("new cleanup reused token")
	}
	if _, err := a.drainCapturedSessionDNSForStop(context.Background(), receipt); err == nil {
		t.Fatal("required old receipt rebound to replacement")
	}
}

func TestOwnedStopRetryCompletesOriginalCleanupAndReconnects(t *testing.T) {
	a, tracker, _, _ := dnsPathFixture(t)
	// The original ordinary Stop really fails at its missing runtime cleanup.
	if err := ordinaryDNSStop(t, a); err == nil || a.state.Phase != "failed" {
		t.Fatal("fixture did not reach the original runtime cleanup failure", err)
	}
	receipt := tracker.dnsProofStop
	if receipt == nil || !validStopRetryToken(receipt.token) {
		t.Fatal("failed Stop lost its owned retry")
	}
	a.modes = []common.Mode{{ID: "multihop"}}
	// Only the platform protection helper is modeled. The real retry handler,
	// ordinary teardown, receipt completion and connection admission execute.
	scripts := t.TempDir()
	a.cfg.ScriptsDir = scripts
	if err := os.WriteFile(filepath.Join(scripts, "kill-switch-platform.py"), []byte("import sys\nassert sys.argv[1:] == ['release']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	windowsHelper := filepath.Join(os.Getenv("HOMEVPN_ROOT"), "client")
	if err := os.MkdirAll(windowsHelper, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(windowsHelper, "windows-kill-switch.ps1"), []byte("param($Action,$Root)\nif($Action -cne 'release'){exit 1}\nexit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var cancelled atomic.Int32
	a.connectionCancel = func() { cancelled.Add(1) }
	a.connectionContext = context.Background()
	a.state.Connected = false
	a.state.Phase = "failed"
	w := stopRetryRequest(a, context.Background(), "POST", stopRetryBody(receipt.token))
	if w.Code != 200 || cancelled.Load() != 1 || tracker.dnsProofStop != nil || tracker.dnsProofClosed || a.state.Phase != "off" {
		t.Fatal("owned retry did not finish its exact reusable cleanup", w.Code, w.Body.String())
	}
	// Model the already-cancelled transaction's normal deferred owner release.
	a.connectionCancel = nil
	a.connectionContext = nil
	a.connectionCancelIntent = nil
	ordinaryDNSReconnect(t, a, tracker)
	if a.state.Phase != "connected" {
		t.Fatal("successful retry prevented reconnect")
	}
	before := a.state
	w = stopRetryRequest(a, context.Background(), "POST", stopRetryBody(receipt.token))
	if w.Code != 409 || a.state != before || cancelled.Load() != 1 {
		t.Fatal("completed old retry affected reconnect", w.Code)
	}
}

func TestPendingStopBlocksOrdinaryMutationButRetainsOwnedOff(t *testing.T) {
	for _, phase := range []string{"failed", "off"} {
		t.Run(phase, func(t *testing.T) {
			a, tracker, receipt := stopRetryFixture(t)
			a.state.Connected = false
			a.state.Phase = phase
			before := cloneRouterProfileStore(a.profiles)
			for _, internal := range []bool{false, true} {
				r := httptest.NewRequest("POST", "/api/profile/settings", strings.NewReader(`{"base_tunnel":"awg"}`))
				if internal {
					r = withInternalMutationContext(r)
				}
				release, err := a.beginMutationOperation(r)
				if release != nil {
					release()
				}
				if !errors.Is(err, errSessionDNSStopPending) || release != nil {
					t.Fatal("pending Stop admitted ordinary/internal profile mutation", internal, err)
				}
			}
			w := httptest.NewRecorder()
			a.profileSettings(w, httptest.NewRequest("POST", "/api/profile/settings", strings.NewReader(`{"base_tunnel":"awg"}`)))
			if w.Code != http.StatusConflict || !reflect.DeepEqual(before, a.profiles) || tracker.dnsProofStop != receipt {
				t.Fatal("stale editor changed captured pending owner", w.Code, w.Body.String())
			}
			if !a.operationMu.TryLock() {
				t.Fatal("rejected mutation retained transaction")
			}
			a.operationMu.Unlock()
		})
	}
	t.Run("owned-off", func(t *testing.T) {
		f := newDesktopProtectionOffFixture(t)
		tracker := &sessionTracker{a: f.a}
		sessionTrackers.Store(f.a, tracker)
		t.Cleanup(func() { sessionTrackers.Delete(f.a) })
		f.a.operationMu.Lock()
		receipt, err := f.a.drainSessionDNSForStop(context.Background())
		f.a.operationMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		capture := ownedProtectionGet(t, f.a)
		before := cloneRouterProfileStore(f.a.profiles)
		for _, policy := range []string{"always", "on-connect"} {
			w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, policy)))
			if w.Code != http.StatusConflict || f.calls != 0 || !reflect.DeepEqual(before, f.a.profiles) {
				t.Fatal("pending Stop admitted a non-Off protection mutation", w.Code, w.Body.String())
			}
		}
		w := postProtectionForTest(f.a, bytes.NewReader(ownedProtectionBody(t, capture, "off")))
		if w.Code != http.StatusOK || f.calls != 1 || f.kernel.target != nil || f.a.nodeProtection != nil || tracker.dnsProofStop != receipt {
			t.Fatal("pending Stop blocked or broadened exact owned protection Off", w.Code, w.Body.String())
		}
	})
}
