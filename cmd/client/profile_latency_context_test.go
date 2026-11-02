package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestProfileLatencyCancelledRequestCannotProbeOrPersist(t *testing.T) {
	a := &app{profiles: common.RouterProfileStore{SelectedID: "node-a", Profiles: []common.RouterProfile{{
		ID: "node-a", Name: "A", NodeKind: "router-vpn", Endpoint: "127.0.0.1",
		LatencySamples: 50, LatencyMedianMs: 99,
	}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/profile/latency", strings.NewReader(`{"id":"node-a","samples":200}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	started := time.Now()
	a.profileLatency(w, req)
	if w.Code != http.StatusRequestTimeout || !strings.Contains(w.Body.String(), "cancelled") {
		t.Fatalf("cancelled durable latency = HTTP %d %q", w.Code, w.Body.String())
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("cancelled durable latency kept probing ports")
	}
	got := a.profiles.Profiles[0]
	if got.LatencySamples != 50 || got.LatencyMedianMs != 99 {
		t.Fatalf("cancelled durable latency changed persisted fields: samples=%d median=%v", got.LatencySamples, got.LatencyMedianMs)
	}
}

// This observes a real contended save, rather than guessing how long the TCP
// samples take. The caller owns app.mu only after an accepted connection proves
// the handler has released its initial profile-read lock. A profileLatency frame
// blocked in Mutex.Lock therefore identifies its terminal persistence boundary.
func waitProfileLatencySaveLock(t *testing.T, done <-chan struct{}) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		count, _ := runtime.GoroutineProfile(nil)
		if count > 4096 {
			t.Fatal("too many goroutines to observe the owned latency save")
		}
		records := make([]runtime.StackRecord, count+16)
		if count, ok := runtime.GoroutineProfile(records); ok {
			for _, record := range records[:count] {
				frames := runtime.CallersFrames(record.Stack())
				previous := ""
				for {
					frame, more := frames.Next()
					// The handler must directly own the contended Lock frame;
					// a mutex inside DialContext is still a measurement, not a save.
					if strings.HasSuffix(frame.Function, ".(*app).profileLatency") && (previous == "sync.(*Mutex).Lock" || previous == "internal/sync.(*Mutex).Lock" || previous == "internal/sync.(*Mutex).lockSlow") {
						return
					}
					if !more {
						break
					}
					previous = frame.Function
				}
			}
		}
		select {
		case <-done:
			t.Fatal("latency handler finished before its contended terminal save was observed")
		case <-time.After(time.Millisecond):
		}
	}
	t.Fatal("latency handler did not reach its contended terminal save")
}

func TestProfileLatencyTerminalSaveOwnsCancellationAndProfile(t *testing.T) {
	for _, scenario := range []string{"minimum", "maximum", "cancelled", "replaced", "removed", "persistence"} {
		t.Run(scenario, func(t *testing.T) {
			// macOS may expose its temporary directory through /var -> /private/var.
			// Canonicalize only this fixture's root; the writer still rejects aliases.
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			a := &app{
				cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")},
				profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: "node-a", Profiles: []common.RouterProfile{{
					ID: "node-a", Name: "A", NodeKind: "router-vpn", Endpoint: "127.0.0.1", NodeProofID: strings.Repeat("a", 64),
					LatencySamples: 60, LatencyMedianMs: 99, LatencyLastTest: "2026-01-01T00:00:00Z",
				}}},
			}
			if err := common.NormalizeRouterProfileStore(&a.profiles); err != nil {
				t.Fatal(err)
			}
			if err := a.persistProfilesLocked(); err != nil {
				t.Fatal(err)
			}
			profilesFile := a.cfg.ProfilesFile
			originalBytes, err := os.ReadFile(profilesFile)
			if err != nil {
				t.Fatal(err)
			}
			originalStore := cloneRouterProfileStore(a.profiles)
			listener, err := net.Listen("tcp", "127.0.0.1:8388")
			if err != nil {
				t.Fatal(err)
			}
			accepted, serverDone := make(chan struct{}), make(chan struct{})
			var connections atomic.Int32
			go func() {
				defer close(serverDone)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					_ = conn.Close()
					if connections.Add(1) == 1 {
						close(accepted)
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			w := httptest.NewRecorder()
			done := make(chan struct{})
			held := false
			defer func() {
				cancel()
				if held {
					a.mu.Unlock()
				}
				_ = listener.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("owned latency handler did not join after cancellation")
				}
				select {
				case <-serverDone:
				case <-time.After(3 * time.Second):
					t.Error("owned TCP listener did not join after close")
				}
			}()
			requested, wanted := 1, 50
			if scenario == "maximum" {
				requested, wanted = 201, 200
			}
			go func() {
				defer close(done)
				req := httptest.NewRequest(http.MethodPost, "/api/profile/latency", strings.NewReader(fmt.Sprintf(`{"id":"node-a","samples":%d}`, requested))).WithContext(ctx)
				a.profileLatency(w, req)
			}()
			select {
			case <-accepted:
			case <-done:
				t.Fatalf("latency handler made no owned TCP connection: HTTP %d %s", w.Code, w.Body.String())
			case <-time.After(3 * time.Second):
				t.Fatal("latency handler did not reach the owned TCP listener")
			}
			a.mu.Lock()
			held = true
			waitProfileLatencySaveLock(t, done)
			// One port-discovery handshake plus the actual requested/clamped sample
			// count must reach this listener. No synthetic latency result is used.
			if got := connections.Load(); got != int32(wanted+1) {
				t.Fatalf("owned TCP handshakes = %d, want %d", got, wanted+1)
			}
			wantStatus := http.StatusOK
			switch scenario {
			case "cancelled":
				cancel()
				wantStatus = http.StatusRequestTimeout
			case "replaced":
				a.profiles.Profiles[0].NodeProofID = strings.Repeat("b", 64)
				wantStatus = http.StatusConflict
			case "removed":
				a.profiles.Profiles = nil
				a.profiles.SelectedID = ""
				wantStatus = http.StatusConflict
			case "persistence":
				a.cfg.ProfilesFile = filepath.Dir(profilesFile)
				wantStatus = http.StatusInternalServerError
			}
			if scenario == "replaced" || scenario == "removed" {
				if err := a.persistProfilesLocked(); err != nil {
					t.Fatal(err)
				}
				originalStore = cloneRouterProfileStore(a.profiles)
				originalBytes, err = os.ReadFile(profilesFile)
				if err != nil {
					t.Fatal(err)
				}
			}
			a.mu.Unlock()
			held = false
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("latency handler remained blocked after the save lock was released")
			}
			storedBytes, err := os.ReadFile(profilesFile)
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != wantStatus {
				t.Fatalf("%s terminal save = HTTP %d, want %d; memory_changed=%t file_changed=%t; body=%s", scenario, w.Code, wantStatus, !reflect.DeepEqual(a.profiles, originalStore), !bytes.Equal(storedBytes, originalBytes), w.Body.String())
			}
			if wantStatus != http.StatusOK {
				if !reflect.DeepEqual(a.profiles, originalStore) || !bytes.Equal(storedBytes, originalBytes) {
					t.Fatal("rejected terminal save changed the current profile store in memory or on disk")
				}
				return
			}
			var response latencyResponse
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			var saved common.RouterProfileStore
			if err := json.Unmarshal(storedBytes, &saved); err != nil {
				t.Fatal(err)
			}
			if response.Port != 8388 || response.Samples != wanted || response.Failed != 0 || !strings.HasPrefix(response.Description, "TCP handshake latency;") {
				t.Fatalf("unexpected real TCP benchmark result: %+v", response)
			}
			if !reflect.DeepEqual(saved, a.profiles) || saved.SelectedID != "node-a" || saved.Profiles[0].LatencySamples != wanted || saved.Profiles[0].LatencyMedianMs != response.MedianMs || saved.Profiles[0].LatencyTrimmedMeanMs != response.TrimmedMs || saved.Profiles[0].LatencyLastTest != response.MeasuredAt.Format(time.RFC3339) {
				t.Fatalf("completed benchmark did not durably save its exact result: %+v", saved)
			}
		})
	}
}
