package main

import (
	"context"
	"router-vpn/internal/common"
	"testing"
)

func desktopExternalWGEntryFixture(t *testing.T, kill string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, exit := desktopExternalNativeFixture(t, "shadowsocks")
	entry, _ := desktopExternalNativeFixture(t, "wireguard")
	entry.ID = "captured-wg-entry"
	profile.KillSwitchPolicy, profile.KillSwitch, profile.MultihopExecution = kill, true, "local"
	profile.MTUPolicy, profile.ManualMTU = "manual", 1360
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, entry, launch
}
func TestDesktopExternalWireGuardEntryRetainsBothSourcesAndMeasurementOwner(t *testing.T) {
	for _, kill := range []string{"on-connect", "always"} {
		profile, entry, launch := desktopExternalWGEntryFixture(t, kill)
		if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil || launch.external.physical == nil {
			t.Fatal(err)
		}
		if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
			t.Fatal(err)
		}
		meta, err := capturedDesktopExternalPhysical(launch.external)
		if err != nil || meta == nil || meta.RootType != "wireguard" || meta.Protocol != "shadowsocks" {
			t.Fatal("lost captured first root", err)
		}
		measure, err := capturedDesktopMeasurementRuntime(launch)
		if err != nil || measure.node != profile.ID || measure.source != meta.SourceSHA256 || measure.config != meta.ConfigSHA256 {
			t.Fatal("measurement borrowed entry identity", err)
		}
		resolver, err := capturedDesktopDNSRuntime(launch)
		if err != nil || resolver.node != profile.ID || resolver.source != meta.SourceSHA256 {
			t.Fatal("DNS mailbox borrowed entry identity", err)
		}
		for _, fault := range []string{"entry-key", "entry-psk", "entry-address", "entry-public", "entry-option", "exit-key", "exit-public", "dns", "mtu", "lan", "ipv6"} {
			t.Run(kill+"/"+fault, func(t *testing.T) {
				p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
				switch fault {
				case "entry-key":
					e.External.WireGuard.PrivateKey = profile.External.Shadowsocks.Password
				case "entry-psk":
					e.External.WireGuard.PresharedKey = profile.External.Shadowsocks.Password
				case "entry-address":
					e.Endpoint = "192.0.2.222"
				case "entry-public":
					e.External.ExpectedPublicIP = "198.51.100.21"
				case "entry-option":
					e.DAITAEnabled = !e.DAITAEnabled
				case "exit-key":
					p.External.Shadowsocks.Password += "different"
				case "exit-public":
					p.External.ExpectedPublicIP = "198.51.100.22"
				case "dns":
					p.DNSPort++
				case "mtu":
					p.ManualMTU++
				case "lan":
					p.HomeLANAccess = !p.HomeLANAccess
				case "ipv6":
					p.IPv6Mode = "on"
				}
				if err := validateDesktopMacOSExternalSources(p, e, launch); err == nil {
					t.Fatal("replaced source accepted", fault)
				}
				if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
					t.Fatal("rejected replacement changed original", err)
				}
			})
		}
	}
}

func TestDesktopExternalWireGuardEntryRestoreKeepsCompleteSourceAndNewSession(t *testing.T) {
	for _, kill := range []string{"on-connect", "always"} {
		_, _, initial := desktopExternalWGEntryFixture(t, kill)
		exit, err := standardExitFromExternalProfile(initial.external.profile)
		if err != nil {
			t.Fatal(err)
		}
		saved := &speedLabExternalRestore{source: append([]byte(nil), initial.external.source...), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(initial.external.entry), direct: false, execution: "local", root: "captured-root", network: "captured-physical-network", mtu: 1360}
		restored, err := compileSpeedLabExternalRestore(saved, exit)
		if err != nil {
			t.Fatal(err)
		}
		if restored.external.session == initial.external.session || restored.profileID != saved.entry.ID || restored.policyProfileID != saved.profile.ID || desktopExternalPathProfileID(restored) != saved.profile.ID || restored.external.direct || restored.external.selection != "local" || restored.external.expected.EntryID != saved.entry.ID || !restored.external.expected.EntryProven || restored.external.predecessor != "" || restored.external.expected.EntryNodeID != "" || restored.external.network != saved.network || restored.root != saved.root || desktopOwnedNodeProfileToken(restored.external.profile) != desktopOwnedNodeProfileToken(saved.profile) || desktopOwnedNodeProfileToken(restored.external.entry) != desktopOwnedNodeProfileToken(saved.entry) || string(restored.external.source) != string(saved.source) {
			t.Fatal("restore substituted original two-node source or reused its native session")
		}
		if err := prepareDesktopExternalPhysicalCaptured(restored, "darwin"); err != nil || restored.external.physical == nil {
			t.Fatal("restored graph lost captured firstroot", err)
		}
		if restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
			t.Fatal("restore discarded original selected MTU")
		}
		for _, fault := range []string{"entry-key", "entry-ip", "final-key", "source", "server"} {
			t.Run(kill+"/restore-"+fault, func(t *testing.T) {
				copy := *saved
				copy.profile = cloneRouterProfile(saved.profile)
				copy.entry = cloneRouterProfile(saved.entry)
				copy.source = append([]byte(nil), saved.source...)
				switch fault {
				case "entry-key":
					copy.entry.External.WireGuard.PrivateKey = testWGKey('z')
				case "entry-ip":
					copy.entry.External.WireGuard.Endpoint = "192.0.2.21:51820"
				case "final-key":
					copy.profile.External.Shadowsocks.Password = testWGKey('z')
				case "source":
					copy.source = []byte(`{}`)
				case "server":
					copy.execution = "server"
				}
				if next, err := compileSpeedLabExternalRestore(&copy, exit); err == nil || next != nil {
					t.Fatal("changed restore source acquired another runtime", fault)
				}
			})
		}
	}
}
