//go:build linux

package main

import (
	"context"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
	"strings"
	"testing"
)

func TestDesktopLinuxOrderedOffRetainsCapturedLaunchAndProof(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch = false
		a.profiles.Profiles[i].KillSwitchPolicy = "off"
	}
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selected, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selected, err = captureNativeMultihopSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selected, strings.Repeat("a", 32), "linux")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDesktopNodeChainLaunch(context.Background(), launch); err != nil {
		t.Fatal(err)
	}
	_, meta, capture, err := launch.chain.readPolicy()
	if err != nil || meta.KillSwitchPolicy != "off" || len(meta.Prefixes) != 3 || capture.SelectedDNS.Physical {
		t.Fatal("Off public selection lost ordered source or selected DNS", err)
	}
	parsed, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(launch.chain.input)
	if err != nil || parsed.Metadata().KillSwitchPolicy != "off" || parsed.Config() != string(launch.config) {
		t.Fatal("private launch projection lost explicit Off", err)
	}
	selection := linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	host := &desktopLinuxNodeHost{chain: launch.chain.policy, launch: launch, source: []byte(launch.chain.input), selection: selection}
	transaction := &desktopLinuxNodeTransaction{chain: host.chain, chainSources: &desktopNodeChainSources{selection: selected}, selection: selection, profileID: selected.Control.ID, mode: meta.Mode}
	if err := transaction.validatePolicy(); err != nil {
		t.Fatal(err)
	}
	policy, err := host.readyPolicy()
	if err != nil || policy != host.chain {
		t.Fatal("Off readiness replaced original native policy", err)
	}
	proof, err := host.capturedProofProfile()
	if err != nil || proof.ID != selected.Exit.ID || proof.NodeProofID != selected.Exit.NodeProofID || proof.APIToken != selected.Exit.APIToken {
		t.Fatal("Off proof lost original final authority", err)
	}
	inputs := host.privateInputs()
	if len(inputs) != 2 || string(inputs[1].body) != launch.chain.input {
		t.Fatal("Off runtime lost complete private source")
	}
	transaction.selection.Policy = "on-connect"
	if err := transaction.validatePolicy(); err == nil {
		t.Fatal("changed protection adopted same original transaction")
	}
	transaction.selection = selection
	transaction.selection.SourceSHA256 = strings.Repeat("f", 64)
	if err := transaction.validatePolicy(); err == nil {
		t.Fatal("foreign source adopted Off transaction")
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateDesktopNodeChainLaunch(ended, launch); err == nil {
		t.Fatal("cancelled request admitted original Off launch")
	}
}

func TestDesktopLinuxOrderedOffRecoveryRequiresJoinedOriginalRelease(t *testing.T) {
	for _, fault := range []string{"original", "mode-mismatch", "deny-missing", "engine-live", "foreign-source", "saved-off", "always"} {
		t.Run(fault, func(t *testing.T) {
			old, current, checkpoint := linuxReleaseRecoveryComparison()
			target := checkpoint.Record.Committed.Target
			target.Policy = "off"
			target.Native.HostProtectionOff = true
			target.Native.DenyHandle = 301
			switch fault {
			case "mode-mismatch":
				target.Native.HostProtectionOff = false
			case "deny-missing":
				target.Native.DenyHandle = 0
			case "engine-live":
				engine := target.Guardian
				checkpoint.Record.Committed.Engine = &engine
			case "foreign-source":
				checkpoint.Record.Intent.RequestID = strings.Repeat("f", 32)
			case "saved-off":
				checkpoint.Record.Intent.Action = "off"
			case "always":
				target.Policy = "always"
			}
			pids, err := checkDesktopLinuxEmptyRecoveryCheckpoint(old, current, checkpoint)
			if (err == nil) != (fault == "original") {
				t.Fatal("Off recovery accepted incomplete or changed original release", err)
			}
			if fault == "original" && (len(pids) != 3 || pids[0] != old.ProcessID || pids[2] != target.Guardian.ProcessID) {
				t.Fatal("Off recovery lost original process absence obligations", pids)
			}
		})
	}
}
