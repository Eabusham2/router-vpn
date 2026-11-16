package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func desktopSOCKSExecutionLaunchFixture(t *testing.T, mode, authentication, target, choice string) (*desktopNodeLaunch, *desktopNodeChainExecutionLaunch) {
	t.Helper()
	a, nodes := desktopSOCKSCaptureFixture(t, mode, authentication, "off")
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := newDesktopNodeChainExecutionSource(launch.chain, choice)
	if err != nil {
		t.Fatal("typed original SOCKS execution preparation", err)
	}
	return launch, execution
}

func TestDesktopSOCKSExecutionParentRetainsOriginalAssociationSource(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, authentication := range []string{"password", "none"} {
				for _, choice := range []string{"server", "auto"} {
					t.Run(target+"/"+mode+"/"+authentication+"/"+choice, func(t *testing.T) {
						launch, e := desktopSOCKSExecutionLaunchFixture(t, mode, authentication, target, choice)
						if e.physical != nil || e.connectPhysical != nil || e.socksPhysical == nil || launch.chain.policy != nil || launch.chain.connectPolicy != nil {
							t.Fatal("SOCKS acquired paired or CONNECT execution authority")
						}
						original := launch.chain.socksPolicy
						retained, err := e.socksPhysical.OriginalDesktopSOCKSPolicy()
						native, nativeErr := original.NativeSource()
						captured, sourceErr := e.preparation.OriginalSOCKSSource()
						if err != nil || retained != original || nativeErr != nil || sourceErr != nil || native != captured {
							t.Fatal("SOCKS execution replaced its original policy or association source", err, nativeErr, sourceErr)
						}
						var local mobilemultihop.NodeChainSource
						if json.Unmarshal([]byte(e.preparation.LocalSource()), &local) != nil || local.Schema != 3 || local.IdentitySources[1] != "" {
							t.Fatal("SOCKS execution changed protocol family or invented middle pairing")
						}
						config, meta, physicalCapture, err := e.readPolicy()
						if err != nil || config != e.preparation.Config() || meta.TargetOS != target || meta.SessionID != launch.mtuSession || meta.FinalTag != mobilemultihop.SelectorTag || len(meta.Prefixes) != 3 || physicalCapture.SelectedDNS.Detour != mobilemultihop.SelectorTag || physicalCapture.SelectedDNS.Physical || len(physicalCapture.PhysicalRoots) != 1 {
							t.Fatal("SOCKS execution changed selected DNS or its original physical entry", err)
						}
						if _, err := mobilemultihop.ParseDesktopNodeChainExecutionPreparation(e.preparation.Source()); err == nil {
							t.Fatal("SOCKS entered paired preparation parser")
						}
						if _, err := mobilemultihop.ParseDesktopNodeChainCONNECTExecutionPreparation(e.preparation.Source()); err == nil {
							t.Fatal("SOCKS entered CONNECT preparation parser")
						}
						if err := e.attach(launch); err != nil {
							t.Fatal("original SOCKS preparation could not attach", err)
						}
						physical, err := launch.chain.physicalPolicy()
						if err != nil || physical != e.socksPhysical || e.bound(launch) != nil || launch.chain.input != e.preparation.Source() || string(launch.config) != config || e.attach(launch) == nil {
							t.Fatal("SOCKS parent lost its original single preparation attachment", err)
						}
					})
				}
			}
		}
	}
}

func TestDesktopSOCKSExecutionParentRejectsSubstitutedAuthority(t *testing.T) {
	for _, fault := range []string{"equal-policy", "equal-preparation", "source-pointer", "paired-physical", "connect-physical", "missing-physical", "paired-policy", "connect-policy", "changed-credential", "changed-final-token", "late-workspace"} {
		t.Run(fault, func(t *testing.T) {
			launch, e := desktopSOCKSExecutionLaunchFixture(t, "awg2-strong", "password", "linux", "auto")
			var err error
			switch fault {
			case "equal-policy":
				launch.chain.socksPolicy, err = mobilemultihop.ParseDesktopNodeChainSOCKSLaunchInput(launch.chain.input)
			case "equal-preparation":
				e.preparation, err = mobilemultihop.ParseDesktopNodeChainSOCKSExecutionPreparation(e.preparation.Source())
			case "source-pointer":
				copy := *launch.chain.selection.Native.chain.socks.source
				launch.chain.selection.Native.chain.socks.source = &copy
			case "paired-physical":
				e.physical = &mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy{}
			case "connect-physical":
				e.connectPhysical = &mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy{}
			case "missing-physical":
				e.socksPhysical = nil
			case "paired-policy":
				launch.chain.policy = &mobilemultihop.DesktopNodeChainPolicy{}
			case "connect-policy":
				launch.chain.connectPolicy = &mobilemultihop.DesktopNodeChainCONNECTPolicy{}
			case "changed-credential":
				launch.chain.selection.Nodes[1].Profile.External.SOCKS5.Password += "-replaced"
			case "changed-final-token":
				launch.chain.selection.Nodes[2].Profile.APIToken += "-replaced"
			case "late-workspace":
				launch.directory = t.TempDir()
				if e.attach(launch) == nil {
					t.Fatal("SOCKS execution replaced an entered private workspace")
				}
				return
			}
			if err != nil {
				t.Fatal("replacement fixture failed before original owner check", err)
			}
			if e.validateSource() == nil || e.attach(launch) == nil {
				t.Fatal("substituted or mixed SOCKS execution authority was accepted")
			}
		})
	}
}
