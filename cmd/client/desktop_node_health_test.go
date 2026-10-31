package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// The real HTTP client/parsers and native ready/private-file admission run.
// Only the network connection and retained process/BFE boundaries are modeled;
// these cases do not establish a Windows tunnel or native kernel execution.
func TestDesktopOwnedNodeHealthUsesSealedSourceAfterSavedBundleChanges(t *testing.T) {
	for _, saved := range []string{"missing", "replaced"} {
		t.Run(saved, func(t *testing.T) {
			t.Setenv("HOMEVPN_ROOT", t.TempDir())
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopOwnedNodeTestFixture(t)
				f.a.cfg.AutoTestSeconds = 8
				f.a.cfg.HealthURL = "http://10.88.0.1:8787/another-node"
				if err := f.start(t, context.Background(), nil); err != nil {
					t.Fatal(err)
				}
				defer f.process.Close(context.Background())
				if saved == "replaced" {
					path := filepath.Join(os.Getenv("HOMEVPN_ROOT"), "generated", f.profile.ID, "wg", "wg.conf")
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					_, files := desktopNodeFixture(t, f.profile.Endpoint)
					changed := strings.ReplaceAll(string(files["wg.conf"]), testWGKey('q'), testWGKey('s'))
					if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
						t.Fatal(err)
					}
				}
				body, _ := json.Marshal(map[string]any{"ok": true, "node_id": f.profile.NodeProofID, "proof": desktopNodeProofKind})
				if validateSelectedNodeProof(f.profile, body) == nil {
					t.Fatal("ordinary proof stopped validating its current saved bundle")
				}
				calls, drain := desktopNodeStartupHTTP(t, f.profile, 40*time.Millisecond, nil, f.profile.NodeProofID)
				defer drain()
				before := f.kernel.prepared
				latency, err := f.a.testStartedModeHealth(context.Background(), f.profile, f.launch)
				if err != nil || latency != 40*time.Millisecond || calls.Load() != 1 || f.kernel.prepared != before+2 {
					t.Fatal("owned proof reread a replacement bundle or skipped its current captured path", latency, err, calls.Load(), f.kernel.prepared-before)
				}
				if f.a.state.Connected || f.a.cmd != f.launch.command || f.process.closed {
					t.Fatal("proof itself changed connection state or retired its captured native process")
				}
			})
		})
	}
}

func TestDesktopOwnedNodeHealthRejectsWrongOrRetiredProof(t *testing.T) {
	for _, fault := range []string{"wrong-node", "operation", "cancel", "generation", "target", "process", "profile", "selected-dns"} {
		t.Run(fault, func(t *testing.T) {
			t.Setenv("HOMEVPN_ROOT", t.TempDir())
			synctest.Test(t, func(t *testing.T) {
				f := newDesktopOwnedNodeTestFixture(t)
				f.a.cfg.AutoTestSeconds = 8
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.a.connectionContext, f.a.connectionCancel = ctx, cancel
				if err := f.start(t, ctx, nil); err != nil {
					t.Fatal(err)
				}
				defer f.process.Close(context.Background())
				replacement, cancelReplacement := context.WithCancel(context.Background())
				defer cancelReplacement()
				node := f.profile.NodeProofID
				if fault == "wrong-node" {
					node = strings.Repeat("f", 64)
				}
				change := func() {
					switch fault {
					case "operation":
						f.a.mu.Lock()
						f.a.connectionContext, f.a.connectionCancel = replacement, cancelReplacement
						f.a.mu.Unlock()
					case "cancel":
						cancel()
					case "generation":
						f.launch.ownedNode.slot.mu.Lock()
						f.launch.ownedNode.slot.generation++
						f.launch.ownedNode.slot.mu.Unlock()
					case "target":
						f.kernel.target.Capture.SessionID = strings.Repeat("f", 32)
					case "process":
						f.process.aliveErr = errors.New("original process retired during HTTP proof")
					case "profile":
						f.a.mu.Lock()
						f.a.profiles.Profiles[0].APIToken = "replacement-private-node-credential"
						f.a.mu.Unlock()
					case "selected-dns":
						ready := *f.launch.ownedNode.ready
						ready.DNSConfigSHA256 = strings.Repeat("f", 64)
						desktopOwnedNodeTestWrite(t, f.launch, "node-ready.json", ready)
					}
				}
				calls, drain := desktopNodeStartupHTTP(t, f.profile, 20*time.Millisecond, change, node)
				defer drain()
				if _, err := f.a.testStartedModeHealth(ctx, f.profile, f.launch); err == nil || calls.Load() != 1 {
					t.Fatal("wrong or retired native HTTP proof was accepted", err, calls.Load())
				}
				if f.a.state.Connected || f.a.cmd != f.launch.command || f.process.closed || replacement.Err() != nil {
					t.Fatal("rejected proof changed a replacement operation or native runtime")
				}
			})
		})
	}
}

func TestDesktopOwnedNodeHealthRejectsUncapturedProfileBeforeNetwork(t *testing.T) {
	t.Setenv("HOMEVPN_ROOT", t.TempDir())
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopOwnedNodeTestFixture(t)
		f.a.cfg.AutoTestSeconds = 8
		if err := f.start(t, context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		defer f.process.Close(context.Background())
		calls, drain := desktopNodeStartupHTTP(t, f.profile, 0, nil, f.profile.NodeProofID)
		defer drain()
		changed := f.profile
		changed.NodeProofID = strings.Repeat("f", 64)
		if _, err := f.a.testStartedModeHealth(context.Background(), changed, f.launch); err == nil || calls.Load() != 0 {
			t.Fatal("native proof used an uncaptured UI profile or performed its HTTP request", err, calls.Load())
		}
	})
}
