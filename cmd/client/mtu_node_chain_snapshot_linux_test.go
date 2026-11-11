//go:build linux

package main

import (
	"os/exec"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// This comparison model retains real ordered source/policy objects and the
// existing Linux MTU owner structure. It cannot pass the native parent,
// process, journal, TUN or activation proof and supplies no OS acceptance.
func linuxOrderedMTUComparisonModel(t *testing.T) (*desktopLinuxNodeMTUOwner, *mtuNodeChainComparisonFixture) {
	t.Helper()
	owner := linuxNodeMTUComparisonModel(t)
	f := newMTUNodeChainComparisonFixture(t, 4, true)
	h := owner.host
	h.parent.app = f.a
	h.policy, h.chain, h.launch = nil, f.launch.chain.policy, f.launch
	h.revision = desktopOwnedNodeProfileToken(f.selection.Control)
	h.options, h.savedOptions = [3]bool{}, [3]bool{}
	meta := h.chain.Metadata()
	h.selection.SessionID, h.selection.SourceSHA256, h.selection.ConfigSHA256 = meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256
	h.selection.Policy, h.selection.HomeLAN = meta.KillSwitchPolicy, meta.HomeLANAccess
	h.network = f.native.network
	h.process.command = f.launch.command
	h.activation.policy, h.activation.chain, h.activation.launch = nil, h.chain, h.launch
	h.activation.selection, h.activation.revision, h.activation.network = h.selection, h.revision, h.network
	h.activation.options, h.activation.savedOptions = h.options, h.savedOptions
	h.transaction.policy, h.transaction.chain = nil, h.chain
	h.transaction.selection, h.transaction.revision, h.transaction.network = h.selection, h.revision, h.network
	h.transaction.options, h.transaction.savedOptions = h.options, h.savedOptions
	h.transaction.profileID, h.transaction.mode = h.launch.profileID, h.launch.mode
	owner.launch, owner.snapshot = h.launch, f.snapshot
	owner.initial.Session, owner.initial.Config = meta.SessionID, meta.ConfigSHA256
	owner.native.launch, owner.native.record = h.launch, owner.initial
	platform := h.launch.chain.platform
	platform.host, platform.session, platform.capture = h, owner.session, h.launch.chain.capture
	platform.capture.platform.parent = h.parent
	return owner, f
}

func TestDesktopLinuxOrderedMTUSnapshotUsesCompleteOriginalPlatform(t *testing.T) {
	owner, f := linuxOrderedMTUComparisonModel(t)
	if err := validateDesktopLinuxMTUSnapshot(owner.host, f.snapshot); err != nil {
		t.Fatal("ordered Linux source comparison required an unrelated ordinary TUN", err)
	}
	if err := owner.originalLocked(); err != nil {
		t.Fatal("ordered Linux MTU comparison lost its original cleanup association", err)
	}
	// Full native validation must still refuse this comparison-only fixture.
	// The state-only boundary is not a substitute for native Current.
	if err := validateMTURetestSnapshot(f.a, f.snapshot); err == nil {
		t.Fatal("comparison-only Linux source fabricated a current native owner")
	}
	for i := range f.a.profiles.Profiles {
		if f.a.profiles.Profiles[i].ID == f.selection.Nodes[1].Profile.ID {
			f.a.profiles.Profiles[i].APIToken += "-replaced-middle-source"
		}
	}
	if err := validateDesktopLinuxMTUSnapshot(owner.host, f.snapshot); err == nil {
		t.Fatal("Linux ordered MTU ignored a changed intermediate source")
	}
	// A changed saved source blocks a new measurement; it does not erase the
	// old object's separate obligation to close its exact retained lease.
	if err := owner.originalLocked(); err != nil {
		t.Fatal("changed source erased original Linux MTU cleanup ownership", err)
	}
}

func TestDesktopLinuxOrderedMTURejectsReplacedCleanupObjects(t *testing.T) {
	for _, fault := range []string{
		"snapshot", "runtime", "host", "session", "capture", "policy", "ordinary-policy",
		"activation-chain", "transaction-chain", "native-launch", "command",
	} {
		t.Run(fault, func(t *testing.T) {
			owner, f := linuxOrderedMTUComparisonModel(t)
			h, platform := owner.host, owner.launch.chain.platform
			switch fault {
			case "snapshot":
				owner.snapshot.Multihop = nil
			case "runtime":
				owner.launch.chain.platform = &desktopNodeChainPlatformRuntime{}
			case "host":
				platform.host = &desktopLinuxNodeHost{}
			case "session":
				// Keep the same parent and journal to prove pointer identity,
				// rather than a coincidentally matching saved session label.
				platform.session = &desktopLinuxNodeSession{parent: owner.session.parent, journal: owner.session.journal, active: h}
			case "capture":
				platform.capture = &desktopNodeChainHostCapture{}
			case "policy":
				h.chain = nil
			case "ordinary-policy":
				h.policy = &mobilemultihop.DesktopNodePolicy{}
			case "activation-chain":
				owner.activation.chain = nil
			case "transaction-chain":
				owner.transaction.chain = nil
			case "native-launch":
				owner.native.launch = &desktopNodeLaunch{}
			case "command":
				owner.process.command = &exec.Cmd{Path: "replacement"}
			}
			if err := owner.originalLocked(); err == nil {
				t.Fatal("ordered Linux MTU cleanup accepted replacement authority", fault, f.snapshot.SelectedID)
			}
		})
	}
}
