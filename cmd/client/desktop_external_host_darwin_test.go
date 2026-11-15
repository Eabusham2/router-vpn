//go:build darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopMacOSExternalOffRequiresOriginalController(t *testing.T) {
	for _, fault := range []string{"app", "controller", "source", "capture", "profile-policy", "captured-source", "missing-protection", "changed-protection", "changed-shape"} {
		t.Run(fault, func(t *testing.T) {
			launch := desktopExternalPhysicalLaunchFixture(t, "http-connect", "off", "off", false)
			if !desktopMacOSExternalEligible(launch) {
				t.Fatal("original all-Off graph did not reach native preparation")
			}
			a := &app{}
			switch fault {
			case "app":
				a = nil
			case "source":
				launch.external.source = []byte(`{}`)
			case "capture":
				launch.external.capture = []byte(`{}`)
			case "profile-policy":
				launch.external.profile.KillSwitchPolicy = "on-connect"
			case "captured-source":
				launch.external.expected.SourceSHA256 = strings.Repeat("f", 64)
			case "missing-protection":
				launch.external.protection = desktopExternalProtectionCapture{}
			case "changed-protection":
				launch.external.protection.policy = "on-connect"
			case "changed-shape":
				launch.external.selection = "server"
			}
			config := bytes.Clone(launch.config)
			if retained, err := prepareDesktopRetainedExternal(a, launch); err == nil || retained != nil {
				t.Fatal("Off escaped its original installed controller through legacy fallback", err)
			}
			if launch.external.physical != nil || launch.external.retained != nil || launch.command != nil || launch.directory != "" || !bytes.Equal(config, launch.config) {
				t.Fatal("refused Off preparation changed its untouched original launch")
			}
		})
	}
}

func TestDesktopMacOSExternalOffPreservesLegacyRouterExecution(t *testing.T) {
	for _, selection := range []string{"local", "server", "auto"} {
		t.Run(selection, func(t *testing.T) {
			profile, initialExit := desktopExternalNativeFixture(t, "shadowsocks")
			entry, files := desktopNodeFixture(t, "198.51.100.8")
			profile.KillSwitch, profile.KillSwitchPolicy = false, "off"
			entry.KillSwitch, entry.KillSwitchPolicy = false, "off"
			profile.MultihopExecution, profile.MultihopEntryMode = selection, "wg"
			profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + initialExit.Server + "/node-response", ServerName: "exit.example.test"}
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if desktopExternalCapturedProtectionPolicy(launch.external) != "off" || desktopMacOSExternalEligible(launch) || desktopExternalOffRequiresRetainedForOS(launch.external, "darwin") {
				t.Fatal("original legacy Router execution acquired a retained Darwin obligation")
			}
			config := bytes.Clone(launch.config)
			if retained, err := prepareDesktopRetainedExternal(&app{}, launch); retained != nil || err != nil {
				t.Fatal("unchanged legacy Router execution lost its existing fallback", err)
			}
			if launch.external.physical != nil || launch.external.retained != nil || !bytes.Equal(config, launch.config) {
				t.Fatal("legacy Router fallback changed its original graph")
			}
		})
	}
}

// Only the native PF command is a test dependency here. The session, app
// publication, immutable capture, exact private directory cleanup and Stop
// retry state all execute their shipping implementations. These cases do not
// establish native execution of the installed helper, guardian or engine.
func desktopMacOSRetirementFixture(t *testing.T, protection ...string) (*desktopMacOSExternalHost, *[]string) {
	t.Helper()
	policy := "on-connect"
	if len(protection) > 1 {
		t.Fatal("retirement fixture requires one original protection choice")
	}
	if len(protection) == 1 {
		policy = protection[0]
	}
	p, s, c, _, _ := macOSParentFixture(t)
	launch := desktopExternalPhysicalLaunchFixture(t, "http-connect", policy, "off", false)
	if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil || launch.external.physical == nil {
		t.Fatal(err)
	}
	a := &app{localController: c, state: state{Mode: "external-node", RuntimeMode: launch.mode, RouterID: launch.profileID}}
	launch.command = &exec.Cmd{}
	a.cmd = launch.command
	meta := launch.external.physical.Metadata()
	captured, err := launch.external.physical.Capture()
	if err != nil {
		t.Fatal(err)
	}
	h := &desktopMacOSExternalHost{parent: &desktopMacOSSessionCapture{app: a, controller: c, parent: p, session: s}, launch: launch,
		policy: launch.external.physical, gate: make(chan struct{}, 1), entered: true, published: true, baselineEntered: true,
		selection: desktopMacOSExternalSelection{Schema: 2, ProfileID: launch.policyProfileID, EntryProfileID: captured.EntryID,
			FinalPolicy: captured.FinalKillSwitchPolicy, EntryPolicy: captured.EntryKillSwitchPolicy, Protocol: meta.Protocol, Session: meta.SessionID,
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
			if selection.Policy == "off" {
				value.Baseline = desktopMacOSBaselineProof{}
			}
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

func TestDesktopMacOSExternalOffRetirementKeepsOriginalRetry(t *testing.T) {
	h, actions := desktopMacOSRetirementFixture(t, "off")
	originalSelection := h.selection
	unknown := filepath.Join(h.launch.directory, "replacement-owner")
	if err := os.WriteFile(unknown, []byte("retain unknown file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.closeWithIntent(context.Background(), true); err == nil {
		t.Fatal("failed Off workspace cleanup discarded the original owner")
	}
	if h.closed || !h.nativeRetired || !h.baselineRetired || h.workspaceRetired || h.baseline.Phase != "held" || h.baseline.Baseline.Present || h.baseline.Capture != originalSelection || !reflect.DeepEqual(*actions, []string{"retire"}) {
		t.Fatal("Off cleanup lost original retry state or retained host protection", *actions)
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
	if !h.closed || !h.workspaceRetired || h.baseline.Phase != "retired" || h.baseline.Baseline.Present || h.baseline.Capture != originalSelection || !reflect.DeepEqual(*actions, []string{"retire", "release"}) {
		t.Fatal("Off retry replaced its original capture or failed joined release", *actions)
	}
	if _, err := os.Stat(h.launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Off joined cleanup retained the original workspace", err)
	}
}

func TestDesktopMacOSExternalOffRetirementPreservesReplacementOwner(t *testing.T) {
	h, actions := desktopMacOSRetirementFixture(t, "off")
	a := h.parent.app
	original := a.cmd
	replacement := &exec.Cmd{}
	a.cmd = replacement
	dns := activeDNSRuntimeIdentity{ProfileID: h.launch.profileID, RuntimeID: h.launch.mode, Config: filepath.Join(filepath.Dir(h.launch.directory), "replacement-workspace", "sing-box.json")}
	activeDNSRuntimeIdentities.Store(a, dns)
	if err := h.closeWithIntent(context.Background(), true); err == nil || h.closed || !h.workspaceRetired {
		t.Fatal("Off cleanup accepted a replacement publication or lost its progress", err)
	}
	if a.cmd != replacement {
		t.Fatal("Off cleanup changed the replacement command")
	}
	if actual, exists := activeDNSRuntimeIdentities.Load(a); !exists || actual != dns {
		t.Fatal("Off cleanup erased the replacement DNS owner")
	}
	a.cmd = original
	if err := h.closeWithIntent(context.Background(), false); err != nil {
		t.Fatal("Off original owner could not retry joined cleanup", err)
	}
	if !h.closed || h.baseline.Baseline.Present || !reflect.DeepEqual(*actions, []string{"retire", "release"}) {
		t.Fatal("Off retry changed its original baseline release", *actions)
	}
	if actual, exists := activeDNSRuntimeIdentities.Load(a); !exists || actual != dns {
		t.Fatal("Off retirement erased replacement DNS after retry")
	}
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
