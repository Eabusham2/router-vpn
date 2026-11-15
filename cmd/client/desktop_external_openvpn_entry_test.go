package main

import (
	"context"
	"router-vpn/internal/common"
	"strings"
	"testing"
)

func desktopExternalOpenVPNEntryFixture(t *testing.T, network string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	entry, _ := desktopRetainedOpenVPNFixture(t, network, "always")
	entry.ID = "captured-ordinary-openvpn-entry"
	lines := strings.Split(entry.External.OpenVPN.Config, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !strings.HasPrefix(line, "remote 203.0.113.21 ") {
			kept = append(kept, line)
		}
	}
	entry.External.OpenVPN.Config = strings.Join(kept, "\n")
	entry.MTUPolicy, entry.ManualMTU = "manual", 1500
	final, exit := desktopExternalNativeFixture(t, "shadowsocks")
	final.KillSwitchPolicy, final.KillSwitch, final.MultihopExecution = "always", true, "local"
	final.MTUPolicy, final.ManualMTU = "manual", 1360
	launch, err := compileDesktopExternalCaptured(context.Background(), final, entry, exit, false, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return final, entry, launch
}
func TestDesktopOpenVPNEntryRetainsBothSourcesAndSupportedScope(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			profile, entry, launch := desktopExternalOpenVPNEntryFixture(t, network)
			if !desktopExternalRetainedEntryForOS(launch.external, "linux") || !desktopExternalRetainedEntryForOS(launch.external, "darwin") || !desktopExternalRetainedEntryForOS(launch.external, "windows") {
				t.Fatal("ordinary OpenVPN entry escaped its native target boundary")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
				t.Fatal(err)
			}
			if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
				t.Fatal("original independently captured profiles rejected", err)
			}
			if launch.profileID != entry.ID || launch.policyProfileID != profile.ID || desktopExternalPathProfileID(launch) != profile.ID {
				t.Fatal("entry borrowed final presentation authority")
			}
			measure, err := capturedDesktopMeasurementRuntime(launch)
			if err != nil || measure.node != profile.ID {
				t.Fatal("measurement replaced final owner", err)
			}
			for _, fault := range []string{"entry-config", "entry-username", "entry-password", "entry-id", "entry-mtu", "final-key", "final-id", "dns", "mtu", "execution"} {
				t.Run(fault, func(t *testing.T) {
					p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
					switch fault {
					case "entry-config":
						e.External.OpenVPN.Config += "# replacement\n"
					case "entry-username":
						e.External.OpenVPN.Username += "changed"
					case "entry-password":
						e.External.OpenVPN.Password += "changed"
					case "entry-id":
						e.ID += "changed"
					case "entry-mtu":
						e.ManualMTU--
					case "final-key":
						p.External.Shadowsocks.Password = testWGKey('x')
					case "final-id":
						p.ID += "changed"
					case "dns":
						p.DNSPort++
					case "mtu":
						p.ManualMTU--
					case "execution":
						p.MultihopExecution = "server"
					}
					if validateDesktopMacOSExternalSources(p, e, launch) == nil {
						t.Fatal("changed source reused original owner")
					}
					if validateDesktopMacOSExternalSources(profile, entry, launch) != nil {
						t.Fatal("rejected stale source mutated original")
					}
				})
			}
		})
	}
}
