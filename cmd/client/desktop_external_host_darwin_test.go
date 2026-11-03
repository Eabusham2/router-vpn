//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Only the native PF command is a test dependency here. The session, app
// publication, immutable capture, exact private directory cleanup and Stop
// retry state all execute their shipping implementations. These cases do not
// establish native execution of the installed helper, guardian or engine.
func desktopMacOSRetirementFixture(t *testing.T) (*desktopMacOSExternalHost, *[]string) {
	t.Helper()
	p, s, c, _, _ := macOSParentFixture(t)
	launch := desktopExternalPhysicalLaunchFixture(t, "http-connect", "on-connect", "off", false)
	if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil || launch.external.physical == nil {
		t.Fatal(err)
	}
	a := &app{localController: c, state: state{Mode: "external-node", RuntimeMode: launch.mode, RouterID: launch.profileID}}
	launch.command = &exec.Cmd{}
	a.cmd = launch.command
	meta := launch.external.physical.Metadata()
	h := &desktopMacOSExternalHost{parent: &desktopMacOSSessionCapture{app: a, controller: c, parent: p, session: s}, launch: launch,
		policy: launch.external.physical, gate: make(chan struct{}, 1), entered: true, published: true, baselineEntered: true,
		selection: desktopMacOSExternalSelection{Schema: 1, ProfileID: launch.profileID, Protocol: meta.Protocol, Session: meta.SessionID,
			Source: meta.SourceSHA256, Config: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}}
	h.gate <- struct{}{}
	h.baseline = &desktopMacOSExternalReceipt{Schema: 1, Capture: h.selection, Phase: "active", Token: "417", Baseline: desktopMacOSBaselineProof{Present: true, Rules: strings.Repeat("a", 64)}}
	launch.external.retained = h
	s.external = h
	if err := s.Retain(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	desktopExternalRetainedLaunches.Store(a, launch)
	t.Cleanup(func() { desktopExternalRetainedLaunches.Delete(a); activeDNSRuntimeIdentities.Delete(a) })
	directory := filepath.Join(t.TempDir(), "original-workspace")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	h.stageDirectory = directory
	if err := writeDesktopRuntimeFile(launch, "source.json", []byte(`{"original":true}`), false); err != nil {
		t.Fatal(err)
	}
	actions := &[]string{}
	h.baselineRun = func(ctx context.Context, parent *desktopMacOSSessionCapture, selection desktopMacOSExternalSelection, action string, expected *desktopMacOSExternalReceipt, _ func()) (*desktopMacOSExternalReceipt, error) {
		if parent != h.parent || selection != h.selection || expected == nil || expected.Capture != selection || expected.Token != "417" || !h.nativeRetired {
			return nil, errors.New("fixture rejected changed original authority or unjoined native owner")
		}
		*actions = append(*actions, action)
		value := *expected
		switch action {
		case "retire":
			value.Phase = "held"
		case "release":
			value.Phase = "retired"
			value.Baseline = desktopMacOSBaselineProof{}
		default:
			return nil, errors.New("unexpected native action")
		}
		return &value, nil
	}
	return h, actions
}

func TestDesktopMacOSExternalRetirementRetryEscalatesHeldBaseline(t *testing.T) {
	h, actions := desktopMacOSRetirementFixture(t)
	unknown := filepath.Join(h.launch.directory, "replacement-owner")
	if err := os.WriteFile(unknown, []byte("retain unknown file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.closeWithIntent(context.Background(), true); err == nil {
		t.Fatal("failed private cleanup discarded its original host")
	}
	if h.closed || !h.baselineRetired || h.baseline.Phase != "held" || !reflect.DeepEqual(*actions, []string{"retire"}) {
		t.Fatal("held native baseline lost its retry state", *actions)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	stop, err := h.CaptureStop()
	if err != nil {
		t.Fatal(err)
	}
	if err := stop.Retire(context.Background(), h.launch.command, true); err != nil {
		t.Fatal(err)
	}
	if !h.closed || !h.workspaceRetired || h.baseline.Phase != "retired" || !reflect.DeepEqual(*actions, []string{"retire", "release"}) {
		t.Fatal("Disconnect retry did not release the same previously held On-connect baseline", *actions)
	}
	if _, err := os.Stat(h.launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("joined original workspace was not removed", err)
	}
}

func TestDesktopMacOSExternalRetirementRetryDoesNotRemoveWorkspaceTwice(t *testing.T) {
	h, actions := desktopMacOSRetirementFixture(t)
	a := h.parent.app
	original := a.cmd
	a.cmd = &exec.Cmd{}
	if err := h.closeWithIntent(context.Background(), true); err == nil || !h.workspaceRetired || h.closed {
		t.Fatal("changed publication lost successful original cleanup progress", err)
	}
	a.cmd = original
	if err := h.closeWithIntent(context.Background(), false); err != nil {
		t.Fatal("same native owner could not retry after joined workspace retirement", err)
	}
	if !h.closed || !reflect.DeepEqual(*actions, []string{"retire", "release"}) {
		t.Fatal("retry changed native release ownership", *actions)
	}
}

func TestDesktopMacOSExternalRetirementPreservesReplacementDNSIdentity(t *testing.T) {
	h, _ := desktopMacOSRetirementFixture(t)
	replacement := activeDNSRuntimeIdentity{ProfileID: h.launch.profileID, RuntimeID: h.launch.mode, Config: filepath.Join(filepath.Dir(h.launch.directory), "replacement-workspace", "sing-box.json")}
	activeDNSRuntimeIdentities.Store(h.parent.app, replacement)
	if err := h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if actual, exists := activeDNSRuntimeIdentities.Load(h.parent.app); !exists || actual != replacement {
		t.Fatal("old retired host erased a replacement DNS identity")
	}
}
