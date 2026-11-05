package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDesktopMTUActualWritersKeepCallerDeadline(t *testing.T) {
	for _, restore := range []bool{false, true} {
		name := "retest"
		if restore {
			name = "captured-restore"
		}
		t.Run(name, func(t *testing.T) {
			a, launch := desktopMTUControllerFixture(t, "mtu-deadline")
			deadline := time.Now().Add(4 * time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			if restore {
				desktopMeasurementMTUSession(launch).restoreMTU = 1392
				if err := a.restoreDesktopCapturedMTU(ctx, launch); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := a.runDesktopExternalMTU(ctx, launch, true); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := readDesktopRuntimeFile(launch, "mtu-observed-request.json", 4096)
			if err != nil {
				t.Fatal(err)
			}
			var request desktopMTURequest
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Fatal(err)
			}
			if request.DeadlineNS != deadline.UnixNano() {
				t.Fatalf("mailbox renewed/lost caller deadline: got %d want %d", request.DeadlineNS, deadline.UnixNano())
			}
			if desktopMTUControlFor(request).DeadlineNS != request.DeadlineNS {
				t.Fatal("commit discarded original request deadline")
			}
		})
	}
}
func TestDesktopMTUExpiredWriterDoesNotPublish(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	_ = a
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := desktopMTURequest{Generation: 1, Request: strings.Repeat("a", 32), DeadlineNS: time.Now().Add(time.Minute).UnixNano()}
	if err := writeDesktopMTUControlContext(ctx, launch, "mtu-request.json", request); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := readDesktopRuntimeFile(launch, "mtu-request.json", 4096); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired writer published mailbox input", err)
	}
}

func TestDesktopMTUViewContextCannotWaitForCapturedProof(t *testing.T) {
	a, launch := desktopTorMTUControllerFixture(t, "tor-mtu-hold")
	launch.tor.proofMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	response := httptest.NewRecorder()
	go func() {
		a.writeDesktopMTUViewStatus(response, httptest.NewRequest(http.MethodGet, "/api/mtu/status", nil).WithContext(ctx))
		close(done)
	}()
	select {
	case <-done:
		launch.tor.proofMu.Unlock()
	case <-time.After(time.Second):
		launch.tor.proofMu.Unlock()
		<-done
		t.Fatal("MTU view escaped original observation deadline")
	}
	if response.Code == http.StatusOK {
		t.Fatal("expired MTU view published current proof")
	}
	if a.cmd != launch.command {
		t.Fatal("view expiry discarded its original connection")
	}
}

func TestDesktopMTURetestContextIncludesHTTPAdmission(t *testing.T) {
	a, launch := desktopMTUControllerFixture(t, "mtu-hold")
	for name, lock := range map[string]*sync.Mutex{"application": &a.mu, "suspension": &mtuSuspensionFor(a).mu, "view": &mtuViewSlotFor(a).mu} {
		t.Run(name, func(t *testing.T) {
			lock.Lock()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			done := make(chan struct{})
			response := httptest.NewRecorder()
			go func() {
				a.retestMTU(response, httptest.NewRequest(http.MethodPost, "/api/mtu/retest", strings.NewReader(`{}`)).WithContext(ctx))
				close(done)
			}()
			select {
			case <-done:
				lock.Unlock()
			case <-time.After(time.Second):
				lock.Unlock()
				<-done
				t.Fatal("HTTP admission escaped caller budget")
			}
			if response.Code == http.StatusOK {
				t.Fatal("expired request admitted a native measurement")
			}
			if a.cmd != launch.command {
				t.Fatal("HTTP expiry retired its healthy original connection")
			}
		})
	}
}
