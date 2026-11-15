package main

import (
	"context"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func desktopCONNECTExecutionLaunchFixture(t *testing.T, mode, protocol, target, choice string) (*desktopNodeLaunch, *desktopNodeChainExecutionLaunch) {
	t.Helper()
	a, nodes := desktopCONNECTCaptureFixture(t, mode, "password", "off")
	if protocol == "http-connect" {
		middle := &a.profiles.Profiles[1]
		proxy := *middle.External.HTTPSConnect
		proxy.TLSServerName = ""
		middle.External.Protocol, middle.External.HTTPSConnect, middle.External.HTTPConnect = protocol, nil, &proxy
		nodes[1].Mode = protocol
	} else if protocol != "https-connect" {
		t.Fatal("unknown original CONNECT fixture")
	}
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
		t.Fatal("typed original CONNECT execution preparation", err)
	}
	return launch, execution
}

func TestDesktopCONNECTExecutionParentKeepsOriginalSourceAndPhysicalOwner(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, protocol := range []string{"http-connect", "https-connect"} {
				for _, choice := range []string{"server", "auto"} {
					t.Run(target+"/"+mode+"/"+protocol+"/"+choice, func(t *testing.T) {
						launch, e := desktopCONNECTExecutionLaunchFixture(t, mode, protocol, target, choice)
						original := launch.chain.connectPolicy
						if e.physical != nil || e.connectPhysical == nil || launch.chain.policy != nil || launch.chain.socksPolicy != nil {
							t.Fatal("CONNECT acquired paired or SOCKS execution authority")
						}
						retained, err := e.connectPhysical.OriginalDesktopCONNECTPolicy()
						if err != nil || retained != original {
							t.Fatal("execution replaced its exact original policy", err)
						}
						native, err := original.NativeSource()
						captured, sourceErr := e.preparation.OriginalCONNECTSource()
						if err != nil || sourceErr != nil || native != captured {
							t.Fatal("execution borrowed another native CONNECT source")
						}
						config, meta, capture, err := e.readPolicy()
						if err != nil || config != e.preparation.Config() || meta.TargetOS != target || meta.SessionID != launch.mtuSession || meta.FinalTag != mobilemultihop.SelectorTag || len(meta.Prefixes) != 3 || capture.SelectedDNS.Detour != mobilemultihop.SelectorTag || capture.SelectedDNS.Physical || len(capture.PhysicalRoots) != 1 {
							t.Fatal("execution changed source, selected DNS or first physical root", err)
						}
						if _, err := mobilemultihop.ParseDesktopNodeChainExecutionPreparation(e.preparation.Source()); err == nil {
							t.Fatal("CONNECT preparation entered generic paired parser")
						}
						if err := e.attach(launch); err != nil {
							t.Fatal("captured typed execution could not attach", err)
						}
						physical, err := launch.chain.physicalPolicy()
						if err != nil || physical != e.connectPhysical || e.bound(launch) != nil || launch.chain.input != e.preparation.Source() || string(launch.config) != config {
							t.Fatal("parent substituted preparation or source on attach", err)
						}
						if err := e.attach(launch); err == nil {
							t.Fatal("entered execution attached twice")
						}
					})
				}
			}
		}
	}
}

func TestDesktopCONNECTExecutionParentRefusesReplacedAndMixedAuthority(t *testing.T) {
	for _, fault := range []string{"equal-policy", "equal-preparation", "source-pointer", "mixed-physical", "missing-physical", "paired-policy", "changed-member", "late-workspace"} {
		t.Run(fault, func(t *testing.T) {
			launch, e := desktopCONNECTExecutionLaunchFixture(t, "awg2-strong", "https-connect", "linux", "auto")
			var err error
			switch fault {
			case "equal-policy":
				launch.chain.connectPolicy, err = mobilemultihop.ParseDesktopNodeChainCONNECTLaunchInput(launch.chain.input)
			case "equal-preparation":
				e.preparation, err = mobilemultihop.ParseDesktopNodeChainCONNECTExecutionPreparation(e.preparation.Source())
			case "source-pointer":
				copy := *launch.chain.selection.Native.chain.connect.source
				launch.chain.selection.Native.chain.connect.source = &copy
			case "mixed-physical":
				e.physical = &mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy{}
			case "missing-physical":
				e.connectPhysical = nil
			case "paired-policy":
				_, other := desktopNodeChainLaunchFixture(t, 3, "linux")
				launch.chain.policy = other.chain.policy
			case "changed-member":
				launch.chain.selection.Nodes[1].Profile.External.HTTPSConnect.Password += "-replaced"
			case "late-workspace":
				launch.directory = t.TempDir()
				if e.attach(launch) == nil {
					t.Fatal("execution replaced an entered private workspace")
				}
				return
			}
			if err != nil {
				t.Fatal("replacement fixture failed before ownership check", err)
			}
			if e.validateSource() == nil || e.attach(launch) == nil {
				t.Fatal("foreign or mixed CONNECT execution owner was admitted")
			}
		})
	}
}
