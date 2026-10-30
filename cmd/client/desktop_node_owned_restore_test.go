package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func desktopOwnedNodeRestoreFixture(t *testing.T) *desktopOwnedNodeTestFixture {
	t.Helper()
	f := newDesktopOwnedNodeTestFixture(t)
	if err := f.start(t, context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	f.a.state.Connected, f.a.state.Phase = true, "connected"
	f.a.mu.Unlock()
	return f
}

func TestDesktopOwnedNodeRestoreCapturesOriginalGraphAndLiveMTU(t *testing.T) {
	f := desktopOwnedNodeRestoreFixture(t)
	live, err := readDesktopNodeMTU(f.launch)
	if err != nil {
		t.Fatal(err)
	}
	live.MTU, live.Reader, live.Index = 1392, 2, live.Index+1
	desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
	profile := cloneRouterProfile(f.profile)
	profile.EffectiveMTU = 1392
	f.a.mu.Lock()
	f.a.profiles.Profiles[0].EffectiveMTU = 1392
	f.a.mu.Unlock()
	before := append([]byte(nil), f.launch.ownedNode.source...)
	restored, err := f.a.captureDesktopOwnedNodeRestore(f.launch, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSpeedLabRestorePlan(speedLabRestorePlan{native: restored})
	if restored.ownedNode == nil || restored.ownedNode.attempt != nil || restored.ownedNode.slot != nil || restored.command != nil || restored.directory != "" {
		t.Fatal("restore plan acquired an obsolete predecessor or running owner")
	}
	meta := restored.ownedNode.policy.Metadata()
	if meta.RestoredMTU != 1392 || meta.SessionID == f.launch.mtuSession || meta.SourceSHA256 == f.launch.ownedNode.policy.Metadata().SourceSHA256 ||
		meta.ProfileID != f.profile.ID || restored.mode != f.launch.mode || restored.endpoint != f.launch.endpoint ||
		!bytes.Equal(restored.ownedNode.source, before) || !bytes.Equal(f.launch.ownedNode.source, before) ||
		restored.ownedNode.policy.OriginalProfile().Config() != f.original.Config() || restored.ownedNode.policy.OriginalProfile().Metadata() != f.original.Metadata() {
		t.Fatal("restore changed original private inputs or lost the independently captured live TUN value")
	}
	capture, err := restored.ownedNode.policy.Capture()
	oldCapture, oldErr := f.launch.ownedNode.policy.Capture()
	if err != nil || oldErr != nil || !reflect.DeepEqual(capture, oldCapture) {
		t.Fatal("restored live MTU rewrote the original DNS, credentials or configured policy", err, oldErr)
	}
}

func TestDesktopOwnedNodeRestoreConsumesLatestTrialTargetAtStaging(t *testing.T) {
	f := desktopOwnedNodeRestoreFixture(t)
	restored, err := f.a.captureDesktopOwnedNodeRestore(f.launch, f.profile)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSpeedLabRestorePlan(speedLabRestorePlan{native: restored})
	firstTarget := *f.kernel.target
	f.retirement(t)
	if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err != nil {
		t.Fatal(err)
	}
	profile, original := desktopOwnedNodeTestSource(t, "node-B", "198.51.100.8", "wg")
	trial := desktopOwnedNodeTestCapture(t, f.a, f.kernel, profile, original, "wg", "2", 0)
	if err := trial.start(t, context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	latestTarget := *f.kernel.target
	if latestTarget == firstTarget {
		t.Fatal("trial did not create a distinct exact target")
	}
	trial.retirement(t)
	if err := trial.a.retireDesktopOwnedNode(context.Background(), trial.launch); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(restored.root, "restored-private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(restored, directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.directoryRoot.Close() })
	if err := stageDesktopOwnedNodeInputs(f.a, restored); err != nil {
		t.Fatal(err)
	}
	if target := restored.ownedNode.attempt.transfer.Predecessor; target == nil || *target != latestTarget || *target == firstTarget {
		t.Fatal("restored original graph reused its obsolete original protection target")
	}
	if restored.ownedNode.policy.OriginalProfile().SourceSHA256() != f.original.SourceSHA256() {
		t.Fatal("latest protection predecessor replaced the original restored graph")
	}
	if err := f.a.retireDesktopOwnedNode(context.Background(), restored); err != nil {
		t.Fatal(err)
	}
	if f.kernel.target == nil || *f.kernel.target != latestTarget {
		t.Fatal("discarding an unstarted restore changed the latest retained trial baseline")
	}
}

func TestDesktopOwnedNodeRestoreRejectsChangedCapture(t *testing.T) {
	for _, fault := range []string{"source", "compiled-config", "profile", "active-mtu", "failed-mtu", "network", "process"} {
		t.Run(fault, func(t *testing.T) {
			f := desktopOwnedNodeRestoreFixture(t)
			profile := cloneRouterProfile(f.profile)
			switch fault {
			case "source":
				raw := append([]byte(nil), f.launch.ownedNode.source...)
				raw = append(raw, '\n')
				if err := f.launch.directoryRoot.Remove("node-source.json"); err != nil {
					t.Fatal(err)
				}
				if err := writeDesktopRuntimeFile(f.launch, "node-source.json", raw, false); err != nil {
					t.Fatal(err)
				}
			case "compiled-config":
				desktopOwnedNodeTestWrite(t, f.launch, "sing-box.json", map[string]any{"changed": true})
			case "profile":
				profile.APIToken += "-replacement"
			case "active-mtu", "failed-mtu":
				live, err := readDesktopNodeMTU(f.launch)
				if err != nil {
					t.Fatal(err)
				}
				if fault == "active-mtu" {
					live.Active = true
				} else {
					live.Failure = "captured TUN operation rejected"
				}
				desktopOwnedNodeTestWrite(t, f.launch, "node-mtu-status.json", live)
			case "network":
				f.launch.ownedNode.network += "-replacement"
			case "process":
				f.process.aliveErr = errors.New("fixture native owner retired")
			}
			if restored, err := f.a.captureDesktopOwnedNodeRestore(f.launch, profile); err == nil || restored != nil {
				t.Fatal("restore adopted changed source, policy, process or live MTU", err)
			}
		})
	}
}

func TestDesktopOwnedNodeRestoreClearsOnlyItsPrivateCopies(t *testing.T) {
	f := desktopOwnedNodeRestoreFixture(t)
	restored, err := f.a.captureDesktopOwnedNodeRestore(f.launch, f.profile)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), f.launch.ownedNode.source...)
	clearSpeedLabRestorePlan(speedLabRestorePlan{native: restored})
	for _, raw := range [][]byte{restored.config, restored.metadata, restored.ownedNode.source} {
		if len(raw) == 0 || !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("retired restore plan retained private constructor or graph bytes")
		}
	}
	if !bytes.Equal(before, f.launch.ownedNode.source) {
		t.Fatal("clearing an unused restore plan changed the running original input")
	}
}

func TestDesktopOwnedNodeDNSReportsCapturedNativeMeasurement(t *testing.T) {
	f := desktopOwnedNodeRestoreFixture(t)
	observed := observedConnection{Connected: true, Mode: "wg", RuntimeMode: "wg", RouterID: f.profile.ID, Phase: "connected", Profile: f.profile}
	called := false
	result := proveSelectedDNSWithLookup(context.Background(), f.a, observed, "wg", func(context.Context, string) ([]string, error) {
		called = true
		return []string{"203.0.113.1"}, nil
	})
	if result.Status != "passed" || result.LatencyMs != 1.25 || called || strings.Contains(result.Reason, "OS resolver") {
		t.Fatal("native DNS readiness was replaced by an unrelated resolver or timing", result)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if result := proveSelectedDNSWithLookup(cancelled, f.a, observed, "wg", nil); result.Status == "passed" {
		t.Fatal("cancelled native DNS observation adopted old readiness")
	}
	observed.Profile.APIToken += "-replacement"
	if result := proveSelectedDNSWithLookup(context.Background(), f.a, observed, "wg", nil); result.Status == "passed" {
		t.Fatal("native DNS observation changed its original private profile")
	}
}

func TestDesktopOwnedNodeWorkspaceRefusesPendingProtection(t *testing.T) {
	f := newDesktopOwnedNodeTestFixture(t)
	if err := cleanupDesktopNodeLaunch(f.launch); err == nil {
		t.Fatal("workspace was deleted while its exact transfer was still active")
	}
	if _, err := readDesktopRuntimeFile(f.launch, "node-protection-transfer.json", 2048); err != nil {
		t.Fatal("pending protection lost its private recovery input", err)
	}
	if err := f.a.retireDesktopOwnedNode(context.Background(), f.launch); err != nil {
		t.Fatal(err)
	}
	if err := cleanupDesktopNodeLaunch(f.launch); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("joined unstarted workspace was not removed", err)
	}
}
