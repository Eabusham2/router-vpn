package main

import (
	"context"
	"errors"
	"testing"

	"router-vpn/internal/common"
)

// This runs the shipping capture, projection, parent admission and retirement
// against an explicit kernel/process model. Actual SID traffic is separately
// mandatory in the native Windows WFP and installed SOCKS/CONNECT gates.
func TestDesktopWindowsOrderedOffCapturedLifecycle(t *testing.T) {
	for _, family := range []string{"node", "socks", "connect"} {
		t.Run(family, func(t *testing.T) {
			var a *app
			var nodes []common.MultihopNodeSelection
			switch family {
			case "node":
				a, nodes = desktopNodeChainCaptureFixture(t, 3)
			case "socks":
				a, nodes = desktopSOCKSCaptureFixture(t, "wg", "password", "off")
			case "connect":
				a, nodes = desktopCONNECTCaptureFixture(t, "wg", "password", "off")
			}
			for i := range a.profiles.Profiles {
				a.profiles.Profiles[i].KillSwitch = false
				a.profiles.Profiles[i].KillSwitchPolicy = "off"
			}
			control, _ := a.profileByIDLocked(a.profiles.SelectedID)
			selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
			if err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
			_, meta, _, err := f.launch.chain.readPolicy()
			if err != nil || meta.TargetOS != "windows" || meta.KillSwitchPolicy != "off" {
				t.Fatal("Off lost original Windows aggregate capture", err)
			}
			f.stagePublish(t)
			if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
				t.Fatal(err)
			}
			owned := f.launch.ownedNode
			if owned.attempt == nil || owned.attempt.transfer.Policy != "off" || !owned.attempt.matchesOwned(owned) || !f.kernel.locked {
				t.Fatal("Off bypassed exact captured protection admission")
			}
			if err := proveDesktopNodeChainContext(f.operation, f.a, f.selection, f.launch.command); err != nil {
				t.Fatal(err)
			}
			cause := errors.New("original Off source still joining")
			f.processes[0].closeErr = cause
			if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); !errors.Is(err, cause) || owned.retired || !f.kernel.locked {
				t.Fatal("Off failed join released source protection", err)
			}
			f.processes[0].closeErr = nil
			if err := closeDesktopNodeChainLaunch(context.Background(), f.a, f.launch); err != nil || !owned.retired || f.kernel.locked {
				t.Fatal("Off did not join original source", err)
			}
			if err := f.a.nodeProtection.release(context.Background()); err != nil || f.kernel.target != nil {
				t.Fatal("Off normal retirement retained protection", err)
			}
		})
	}
}
