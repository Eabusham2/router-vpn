package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

func desktopTorPrelaunchFailureChild(kind, directory string, expected mobiletor.DesktopBridgeMetadata, write func(string, any)) bool {
	if !strings.HasPrefix(kind, "prelaunch-failed") {
		return false
	}
	witness := desktopTorPrelaunchFailure{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, NoNativeProcess: true}
	write("prelaunch-failed.json", witness)
	if kind == "prelaunch-failed-held" {
		for {
			if _, err := os.Stat(os.Getenv("ROUTERVPN_TOR_TEST_RELEASE")); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	return true
}

func waitDesktopTorFixtureExit(t *testing.T, launch *desktopNodeLaunch) {
	t.Helper()
	select {
	case <-desktopNodeProcessDone(launch):
	case <-time.After(10 * time.Second):
		t.Fatal("captured wrapper fixture did not exit")
	}
}

func TestDesktopTorPrelaunchFailureRetiresOnlyAfterWrapperExit(t *testing.T) {
	a, launch, release := desktopTorRunningFixture(t, "prelaunch-failed-held")
	deadline := time.After(10 * time.Second)
	for {
		if _, err := readDesktopRuntimeFile(launch, "prelaunch-failed.json", 4096); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("fixture did not publish its distinct prelaunch witness")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if unused, err := desktopTorNoNativeWork(launch); unused || err != nil {
		t.Fatal("a witness alone replaced actual wrapper exit", unused, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	err := requestDesktopTorStop(ctx, a, launch, launch.command)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending wrapper ownership was released", err)
	}
	if err := stopDesktopTorRuntime(a, launch, launch.command); err == nil {
		t.Fatal("private input cleanup ran before actual wrapper exit")
	}
	if err := os.WriteFile(release, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	waitDesktopTorFixtureExit(t, launch)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
		t.Fatal(err)
	}
	launch.tor.mu.Lock()
	prelaunch, nativeDrain := launch.tor.prelaunchAcknowledged, launch.tor.stopAcknowledged
	launch.tor.mu.Unlock()
	if !prelaunch || nativeDrain {
		t.Fatal("a failed wrapper was mislabeled as a drained native session")
	}
	if _, err := os.Stat(filepath.Join(launch.directory, "stopped.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the wrapper path fabricated native drain")
	}
	if found, err := stopDesktopNodeRuntime(a, launch.command); !found || err != nil {
		t.Fatal("unused captured workspace did not retire", err)
	}
	if err := finishDesktopNodeRuntime(a); err != nil {
		t.Fatal("reconnect ownership was not released after the surrounding stop committed", err)
	}
	if _, found := desktopNodeOwners.Load(a); found {
		t.Fatal("a known pre-native failure permanently blocked reconnect")
	}
}

func TestDesktopTorPrelaunchFailureCannotExcuseNativeAdmissionOrChangedInputs(t *testing.T) {
	for _, mutation := range []string{"session", "source", "config", "claim", "unknown-field", "progress", "partial-progress", "proof", "native-stopped", "unknown-file", "data", "replaced-input", "changed-input", "missing-input", "adopted", "observed", "replacement-owner"} {
		t.Run(mutation, func(t *testing.T) {
			a, launch, _ := desktopTorRunningFixture(t, "prelaunch-failed")
			waitDesktopTorFixtureExit(t, launch)
			path := filepath.Join(launch.directory, "prelaunch-failed.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var witness map[string]any
			if err := json.Unmarshal(raw, &witness); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "session":
				witness["session_id"] = strings.Repeat("f", 32)
			case "source":
				witness["source_sha256"] = strings.Repeat("f", 64)
			case "config":
				witness["config_sha256"] = strings.Repeat("f", 64)
			case "claim":
				witness["no_native_process"] = false
			case "unknown-field":
				witness["closed"] = true
			case "progress", "partial-progress", "proof", "native-stopped", "unknown-file":
				name := map[string]string{"progress": "progress.json", "partial-progress": ".progress.json.pending", "proof": "proof.json", "native-stopped": "stopped.json", "unknown-file": "foreign"}[mutation]
				if err := os.WriteFile(filepath.Join(launch.directory, name), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "data":
				if err := os.WriteFile(filepath.Join(launch.directory, "tor-data", "owned-by-native"), []byte("private"), 0600); err != nil {
					t.Fatal(err)
				}
			case "replaced-input":
				original := filepath.Join(launch.directory, "torrc")
				contents, _ := os.ReadFile(original)
				if err := os.Rename(original, filepath.Join(t.TempDir(), "retained-torrc")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(original, contents, 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-input":
				if err := os.WriteFile(filepath.Join(launch.directory, "torrc"), []byte("changed in place"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-input":
				if err := os.Remove(filepath.Join(launch.directory, "torrc")); err != nil {
					t.Fatal(err)
				}
			case "adopted":
				launch.tor.adopted = &desktopTorProof{}
			case "observed":
				launch.tor.admissionObserved = true
			case "replacement-owner":
				desktopNodeOwners.Store(a, &desktopNodeLaunch{})
			}
			raw, _ = json.Marshal(witness)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := requestDesktopTorStop(ctx, a, launch, launch.command); err == nil {
				t.Fatal("invalid pre-native witness released protection", mutation)
			}
			if _, err := os.Stat(launch.directory); err != nil {
				t.Fatal("rejected witness removed private inputs", err)
			}
		})
	}
}

func TestDesktopTorPrelaunchCleanupRechecksAdmission(t *testing.T) {
	a, launch, _ := desktopTorRunningFixture(t, "prelaunch-failed")
	waitDesktopTorFixtureExit(t, launch)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(launch.directory, "progress.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stopDesktopTorRuntime(a, launch, launch.command); err == nil {
		t.Fatal("no-work cleanup ignored newly observed native admission")
	}
}
