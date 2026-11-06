package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStandaloneThroughputSharesAdmissionAndMTUUntilCancellation(t *testing.T) {
	for _, route := range []string{"single", "connection", "entry", "exit", "pair"} {
		t.Run(route, func(t *testing.T) {
			entered, drained := make(chan struct{}, 1), make(chan struct{}, 1)
			fixtureRoute := route
			if route == "connection" {
				fixtureRoute = "single"
			}
			a, handle, body := routedSpeedPathFixture(t, fixtureRoute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				<-r.Context().Done()
				drained <- struct{}{}
			}))
			if route == "connection" {
				handle = a.connectionSpeedTest
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				w := httptest.NewRecorder()
				handle(w, httptest.NewRequest(http.MethodPost, "/speed", strings.NewReader(body)).WithContext(ctx))
				done <- w
			}()
			select {
			case <-entered:
			case w := <-done:
				t.Fatalf("transfer never started: %d %s", w.Code, w.Body.String())
			case <-time.After(3 * time.Second):
				t.Fatal("transfer never reached captured endpoint")
			}
			if !mtuSuspended(a) {
				t.Fatal("standalone transfer allowed automatic MTU changes")
			}
			lock := mtuRetestLockFor(a)
			if lock.TryLock() {
				lock.Unlock()
				t.Fatal("standalone transfer failed to retain MTU exclusion")
			}
			if finish, err := beginSpeedLabRun(a); err == nil {
				finish()
				t.Fatal("Speed Lab overlapped standalone throughput")
			}
			// The normal connection mutex remains available, including Disconnect.
			if !a.mu.TryLock() {
				t.Fatal("measurement owns connection mutation mutex")
			}
			connected := a.state.Connected
			a.mu.Unlock()
			if !connected {
				t.Fatal("measurement stopped the original VPN")
			}
			duplicate := httptest.NewRecorder()
			handle(duplicate, httptest.NewRequest(http.MethodPost, "/speed", strings.NewReader(body)))
			if duplicate.Code != http.StatusConflict {
				t.Fatalf("duplicate throughput admitted: %d %s", duplicate.Code, duplicate.Body.String())
			}
			cancel()
			select {
			case w := <-done:
				if w.Code != http.StatusRequestTimeout {
					t.Fatalf("cancel returned %d: %s", w.Code, w.Body.String())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancelled transfer did not return")
			}
			select {
			case <-drained:
			case <-time.After(time.Second):
				t.Fatal("captured network request remained open")
			}
			if mtuSuspended(a) {
				t.Fatal("cancelled standalone transfer leaked its MTU suspension")
			}
			finish, err := beginSpeedLabRun(a)
			if err != nil {
				t.Fatal("cancelled transfer leaked admission", err)
			}
			finish()
			a.mu.Lock()
			connected = a.state.Connected
			a.mu.Unlock()
			if !connected {
				t.Fatal("measurement cancellation stopped VPN")
			}
		})
	}
}

func TestStandaloneThroughputWaitsForCapturedMTURetirement(t *testing.T) {
	a := &app{}
	lock := mtuRetestLockFor(a)
	lock.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		finish, err := a.beginStandaloneThroughput(ctx)
		if finish != nil {
			finish()
		}
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for !mtuSuspended(a) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !mtuSuspended(a) {
		lock.Unlock()
		cancel()
		t.Fatal("MTU retirement was not requested")
	}
	if finish, err := beginSpeedLabRun(a); err == nil {
		finish()
		lock.Unlock()
		cancel()
		t.Fatal("admission released before MTU retirement")
	}
	select {
	case err := <-done:
		lock.Unlock()
		cancel()
		t.Fatal("pending MTU work was bypassed", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled MTU capture succeeded")
		}
	case <-time.After(time.Second):
		lock.Unlock()
		t.Fatal("cancel did not end waiting capture")
	}
	if lock.TryLock() {
		lock.Unlock()
		t.Fatal("cancel released another MTU owner's mutex")
	}
	lock.Unlock()
	if mtuSuspended(a) {
		t.Fatal("failed capture leaked MTU suspension")
	}
	finish, err := beginSpeedLabRun(a)
	if err != nil {
		t.Fatal("failed capture leaked run owner", err)
	}
	finish()
}
