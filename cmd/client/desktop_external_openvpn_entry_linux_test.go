//go:build linux

package main

import (
	"reflect"
	"router-vpn/internal/common"
	"testing"
)

func TestDesktopLinuxOpenVPNEntryHostKeepsOriginalPairAndRestore(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			profile, entry, launch := desktopExternalOpenVPNEntryFixture(t, network)
			if !desktopLinuxExternalEligible(launch) {
				t.Fatal("captured OpenVPN entry bypasses retained Linux owner")
			}
			if err := prepareDesktopExternalPhysicalCaptured(launch, "linux"); err != nil {
				t.Fatal(err)
			}
			a := &app{profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{profile, entry}}}
			h := &desktopLinuxNodeHost{launch: launch, revision: desktopOwnedNodeProfileToken(profile), externalEntryRevision: desktopOwnedNodeProfileToken(entry),
				savedOptions: [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}, externalEntryOptions: [3]bool{entry.DAITAEnabled, entry.JumboTUN, entry.SocksEnabled}}
			if err := h.externalSourcesLocked(a); err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"entry-credentials", "entry-options", "entry-missing", "final-credentials", "final-missing", "dns", "mtu"} {
				p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
				switch fault {
				case "entry-credentials":
					e.External.OpenVPN.Password += "changed"
				case "entry-options":
					e.SocksEnabled = !e.SocksEnabled
				case "entry-missing":
					e.ID = "foreign"
				case "final-credentials":
					p.External.Shadowsocks.Password = testWGKey('x')
				case "final-missing":
					p.ID = "foreign"
				case "dns":
					p.DNSPort++
				case "mtu":
					p.ManualMTU++
				}
				a.profiles.Profiles = []common.RouterProfile{p, e}
				if h.externalSourcesLocked(a) == nil {
					t.Fatal("retained host accepted replaced source", fault)
				}
				a.profiles.Profiles = []common.RouterProfile{profile, entry}
				if h.externalSourcesLocked(a) != nil {
					t.Fatal("stale refusal changed retained original")
				}
			}
			exit, err := standardExitFromExternalProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			saved := &speedLabExternalRestore{source: append([]byte(nil), launch.external.source...), profile: cloneRouterProfile(launch.external.profile), entry: cloneRouterProfile(launch.external.entry), execution: "local", root: "retained-root", network: "retained-network", mtu: 1360}
			if err = captureSpeedLabExternalRestoreSeal(saved, launch.external); err != nil {
				t.Fatal(err)
			}
			restored, err := compileSpeedLabExternalRestore(saved, exit)
			if err != nil || !desktopLinuxExternalEligible(restored) || restored.external.session == launch.external.session || !reflect.DeepEqual(restored.external.source, launch.external.source) {
				t.Fatal("restore substituted original pair/session", err)
			}
			if err = prepareDesktopExternalPhysicalCaptured(restored, "linux"); err != nil || restored.external.physical == nil {
				t.Fatal("restore omitted retained owner", err)
			}
			if validateDesktopLinuxExternalSource(profile, restored, entry) != nil || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
				t.Fatal("restore changed saved credentials or selected MTU")
			}
		})
	}
}
