//go:build linux

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpeedLabServiceCallerContextCapture(t *testing.T) {
	for _, mode := range []string{"identity", "expected", "restore-plan"} {
		t.Run(mode, func(t *testing.T) {
			a := &app{}
			launch := &linuxStandardServiceLaunch{app: a}
			linuxStandardServiceOwners.Store(a, launch)
			defer linuxStandardServiceOwners.Delete(a)
			launch.mu.Lock()
			defer launch.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch mode {
				case "identity":
					_, _, err = captureSpeedLabIdentityContext(ctx, a)
				case "expected":
					_, _, err = a.captureExpectedSpeedLabIdentityContext(ctx, speedLabRequest{})
				case "restore-plan":
					_, err = a.speedLabCaptureRestorePlanContext(ctx, speedLabTemporarySnapshot{State: state{Connected: true, Phase: "connected"}, Runtime: &exec.Cmd{}})
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("capture lost original deadline", err)
				}
			case <-time.After(time.Second):
				t.Fatal("shipping capture outlived original caller behind launch gate")
			}
			if launch.joined || launch.copiesClosed {
				t.Fatal("observation expiry retired original service")
			}
		})
	}
}

func TestSpeedLabServiceObserverJoinsCaller(t *testing.T) {
	for _, mode := range []string{"request-cancel", "explicit-stop"} {
		t.Run(mode, func(t *testing.T) {
			a := &app{}
			launch := &linuxStandardServiceLaunch{app: a}
			path := &linuxStandardServiceSpeedLabPath{owner: launch}
			identity := speedLabPathIdentity{Standard: path}
			launch.mu.Lock()
			held := true
			defer func() {
				if held {
					launch.mu.Unlock()
				}
			}()
			parent, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			entered := make(chan struct{})
			var calls atomic.Int32
			observer, stop, err := speedLabPathContextWithCaller(parent, func(ctx context.Context) error {
				if calls.Add(1) == 1 {
					return nil
				} // Initial proof precedes the deliberately held later observation.
				close(entered)
				return validateSpeedLabIdentityContext(ctx, a, identity)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("observer never reached original service gate")
			}
			joined := make(chan struct{})
			if mode == "request-cancel" {
				cancel()
			}
			go func() { stop(); close(joined) }()
			select {
			case <-joined:
			case <-time.After(250 * time.Millisecond):
				launch.mu.Unlock()
				held = false
				<-joined
				t.Fatal("observer join waited on a renewed background budget")
			}
			if !errors.Is(context.Cause(observer), context.Canceled) {
				t.Fatal("observer lost original cancellation", context.Cause(observer))
			}
			if launch.joined || launch.copiesClosed {
				t.Fatal("observer cancellation retired original service")
			}
			if mode == "explicit-stop" && parent.Err() != nil {
				t.Fatal("observer stop canceled parent path")
			}
		})
	}
}

func TestSpeedLabServiceCallerContextAppGate(t *testing.T) {
	for _, mode := range []string{"snapshot", "temporary-admission", "owner", "expected-with-profiles", "current-handler", "public-validation"} {
		t.Run(mode, func(t *testing.T) {
			a := &app{}
			a.mu.Lock()
			defer a.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				switch mode {
				case "snapshot":
					_, err = a.speedLabSnapshotTemporaryContext(ctx)
				case "temporary-admission":
					_, _, _, err = a.beginSpeedLabTemporaryOperationExpectedContext(ctx, nil)
				case "owner":
					err = a.speedLabCheckOwnerContext(ctx, &speedLabTemporaryOwner{})
				case "expected-with-profiles":
					_, _, err = a.captureExpectedSpeedLabIdentityContext(ctx, speedLabRequest{ExpectedSelectedNodeID: "policy", ExpectedProfileTokens: map[string]string{}})
				case "current-handler":
					_, _, _, err = a.speedLabCurrentExpected(httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", nil).WithContext(ctx), speedLabRequest{}, speedLabDuration{}, time.Second, time.Second)
				case "public-validation":
					request := httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", strings.NewReader(`{"expected_selected_node_id":"policy","expected_profile_tokens":{}}`)).WithContext(ctx)
					response := httptest.NewRecorder()
					a.speedLabRun(response, request)
					if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), context.DeadlineExceeded.Error()) {
						err = errors.New("public handler did not preserve original validation deadline")
					} else {
						err = ctx.Err()
					}
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("app gate lost original caller", err)
				}
			case <-time.After(time.Second):
				t.Fatal("app gate ignored original caller")
			}
			if raw, exists := speedLabTemporaryOwners.Load(a); exists {
				t.Fatal("expired admission published owner", raw)
			}
			if !a.operationMu.TryLock() {
				t.Fatal("failed admission retained mutation lock")
			}
			a.operationMu.Unlock()
		})
	}
}
