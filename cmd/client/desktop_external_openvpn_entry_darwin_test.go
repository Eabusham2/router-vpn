//go:build darwin

package main

import (
	"context"
	"reflect"
	"router-vpn/internal/common"
	"testing"
)

func TestDesktopDarwinOpenVPNEntryRetainsOriginalPair(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			profile, entry, launch := desktopExternalOpenVPNEntryFixture(t, network)
			if !desktopMacOSExternalEligible(launch) {
				t.Fatal("bounded pair lost native Darwin host")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil {
				t.Fatal(err)
			}
			selection, err := desktopProtectionSelectionFor(nil, launch.external.physical)
			if err != nil || selection.profileID != profile.ID || selection.profileID == entry.ID || selection.source != launch.external.physical.Metadata().SourceSHA256 {
				t.Fatal("journal replaced final policy with physical entry", err)
			}
			capture, err := launch.external.physical.Capture()
			if err != nil || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "custom-exit" || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Tag != "external-entry" || capture.PhysicalRoots[0].Type != "openvpn-client" || len(capture.PhysicalRoots[0].Destinations) != 1 || capture.PhysicalRoots[0].Destinations[0].Network != network {
				t.Fatal("OpenVPN entry lost physical or selected DNS authority", err)
			}
			if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
				t.Fatal(err)
			}
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			saved := &speedLabExternalRestore{source: append([]byte(nil), launch.external.source...), profile: cloneRouterProfile(profile), entry: cloneRouterProfile(entry), execution: "local", root: "retained-root", network: "retained-network", mtu: 1360}
			if err := captureSpeedLabExternalRestoreSeal(saved, launch.external); err != nil {
				t.Fatal(err)
			}
			restored, err := compileSpeedLabExternalRestore(saved, exit)
			if err != nil || !desktopMacOSExternalEligible(restored) || restored.external.session == launch.external.session || !reflect.DeepEqual(restored.external.source, launch.external.source) {
				t.Fatal("Darwin restore substituted captured pair or session", err)
			}
			if err := prepareDesktopExternalPhysicalCaptured(restored, "darwin"); err != nil || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
				t.Fatal("Darwin restore omitted captured MTU", err)
			}
		})
	}
}
func TestDesktopDarwinOpenVPNEntryRejectsUnsupportedCapture(t *testing.T) {
	profile, entry, _ := desktopExternalOpenVPNEntryFixture(t, "tcp")
	for _, fault := range []string{"multiple-remotes", "entry-layer", "final-layer", "server-execution", "same-owner", "unprotected", "non-SS2022-final", "direct-with-entry"} {
		t.Run(fault, func(t *testing.T) {
			p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
			direct := false
			switch fault {
			case "multiple-remotes":
				e.External.OpenVPN.Config += "\nremote 203.0.113.26 1194 udp\n"
			case "entry-layer":
				e.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				p.StartLayer = common.StartLayerAES256GCM
			case "server-execution":
				p.MultihopExecution = "server"
			case "same-owner":
				e.ID = p.ID
			case "unprotected":
				p.KillSwitch, p.KillSwitchPolicy = false, "off"
				e.KillSwitch, e.KillSwitchPolicy = false, "off"
			case "non-SS2022-final":
				p.External.Shadowsocks.Method = "aes-256-gcm"
			case "direct-with-entry":
				direct = true
			}
			exit, err := standardExitFromExternalProfile(p)
			if err != nil {
				return
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), p, e, exit, direct, "", nil, nil, nil)
			if err == nil && desktopMacOSExternalEligible(launch) {
				t.Fatal("unsupported OpenVPN pair acquired Darwin host", fault)
			}
		})
	}
}

func TestDesktopDarwinExternalFallbackCannotBorrowWindowsEntry(t *testing.T) {
	_, _, launch := desktopWindowsRouterServerFixture(t, "server")
	if !desktopWindowsExternalEligible(launch) || desktopExternalRetainedEntryForOS(launch.external, "darwin") {
		t.Fatal("fixture lost its Windows-only composed authority")
	}
	if desktopMacOSExternalEligible(launch) {
		t.Fatal("direct fallback borrowed a composed Windows native owner")
	}
}
