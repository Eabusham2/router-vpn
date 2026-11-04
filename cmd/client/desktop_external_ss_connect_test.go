package main

import (
	"context"
	"router-vpn/internal/common"
	"testing"
)

func desktopSSCONNECTFixture(t *testing.T, kill, method, protocol string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, _ := desktopExternalNativeFixture(t, protocol)
	_, entry, _ := desktopSSEntryFixture(t, kill, method, desktopSSEntryMethods[1], "tcp")
	profile.KillSwitchPolicy, profile.KillSwitch, profile.MultihopExecution = kill, true, "local"
	profile.MTUPolicy, profile.ManualMTU, profile.DNSProtocol = "manual", 1360, "tcp"
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, entry, launch
}
func mutateSSCONNECTFinal(p *common.RouterProfile, field string) {
	proxy := p.External.HTTPConnect
	if p.External.Protocol == "https-connect" {
		proxy = p.External.HTTPSConnect
	}
	switch field {
	case "username":
		proxy.Username += "changed"
	case "password":
		proxy.Password += "changed"
	case "tls":
		proxy.TLSServerName = "changed.example"
	case "host":
		proxy.Host = "198.51.100.99"
	case "port":
		proxy.Port++
	case "public":
		p.External.ExpectedPublicIP = "203.0.113.99"
	case "option":
		p.DAITAEnabled = !p.DAITAEnabled
	}
}
func TestDesktopExternalSSCONNECTRetainsBothSourcesAndMeasurement(t *testing.T) {
	for _, method := range desktopSSEntryMethods {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, kill := range []string{"always", "on-connect"} {
				profile, entry, launch := desktopSSCONNECTFixture(t, kill, method, protocol)
				if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil {
					t.Fatal(err)
				}
				if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
					t.Fatal(err)
				}
				meta, err := capturedDesktopExternalPhysical(launch.external)
				if err != nil || meta == nil || meta.RootType != "shadowsocks" || meta.RootTag != "external-entry" {
					t.Fatal("CONNECT lost original SS physical root", err)
				}
				measure, err := capturedDesktopMeasurementRuntime(launch)
				if err != nil || measure.node != profile.ID || measure.source != meta.SourceSHA256 || measure.config != meta.ConfigSHA256 {
					t.Fatal("CONNECT measurement lost final owner", err)
				}
				resolver, err := capturedDesktopDNSRuntime(launch)
				if err != nil || resolver.node != profile.ID || resolver.source != meta.SourceSHA256 {
					t.Fatal("CONNECT DNS lost final owner", err)
				}
				for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
					e := cloneRouterProfile(entry)
					mutateDesktopSSSource(&e, fault)
					if validateDesktopMacOSExternalSources(profile, e, launch) == nil {
						t.Fatal("CONNECT accepted changed original SS entry", fault)
					}
				}
				for _, fault := range []string{"username", "password", "tls", "host", "port", "public", "option"} {
					p := cloneRouterProfile(profile)
					mutateSSCONNECTFinal(&p, fault)
					if validateDesktopMacOSExternalSources(p, entry, launch) == nil {
						t.Fatal("SS accepted changed CONNECT source", fault)
					}
				}
			}
		}
	}
}
func TestDesktopExternalSSCONNECTRestoreRetainsCompleteLocalGraph(t *testing.T) {
	for _, method := range desktopSSEntryMethods {
		for _, protocol := range []string{"http-connect", "https-connect"} {
			for _, kill := range []string{"always", "on-connect"} {
				_, _, initial := desktopSSCONNECTFixture(t, kill, method, protocol)
				exit, err := standardExitFromExternalProfile(initial.external.profile)
				if err != nil {
					t.Fatal(err)
				}
				saved := &speedLabExternalRestore{source: append([]byte(nil), initial.external.source...), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(initial.external.entry), direct: false, execution: "local", root: "captured-root", network: "captured-original-network", mtu: 1360}
				if err := captureSpeedLabExternalRestoreSeal(saved, initial.external); err != nil {
					t.Fatal(err)
				}
				restored, err := compileSpeedLabExternalRestore(saved, exit)
				if err != nil {
					t.Fatal(err)
				}
				if restored.external.session == initial.external.session || restored.profileID != saved.entry.ID || restored.policyProfileID != saved.profile.ID || restored.external.selection != "local" || restored.external.expected.EntryID != saved.entry.ID || !restored.external.expected.EntryProven || restored.external.predecessor != "" || restored.external.network != saved.network || string(restored.external.source) != string(saved.source) || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
					t.Fatal("CONNECT restore reran selection or lost original graph")
				}
				if err := prepareDesktopExternalPhysicalCaptured(restored, "darwin"); err != nil {
					t.Fatal(err)
				}
				for _, fault := range []string{"username", "password", "tls", "host", "port", "public", "option"} {
					copy := *saved
					copy.profile = cloneRouterProfile(saved.profile)
					mutateSSCONNECTFinal(&copy.profile, fault)
					if next, e := compileSpeedLabExternalRestore(&copy, exit); e == nil || next != nil {
						t.Fatal("CONNECT restore accepted changed final source", fault)
					}
				}
				for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
					copy := *saved
					copy.entry = cloneRouterProfile(saved.entry)
					mutateDesktopSSSource(&copy.entry, fault)
					if next, e := compileSpeedLabExternalRestore(&copy, exit); e == nil || next != nil {
						t.Fatal("CONNECT restore accepted changed SS source", fault)
					}
				}
			}
		}
	}
}
func TestDesktopExternalSSCONNECTPreservesUnavailableUDPAndUnsupportedGraphs(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		profile, entry, _ := desktopSSCONNECTFixture(t, "always", desktopSSEntryMethods[1], protocol)
		profile.DNSProtocol = "udp"
		exit, e := standardExitFromExternalProfile(profile)
		if e == nil {
			next, e := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", nil, nil, nil)
			if e == nil || next != nil {
				t.Fatal("CONNECT admitted selected UDP DNS")
			}
		}
		for _, fault := range []string{"server", "auto", "predecessor", "off", "entry-layer", "final-layer", "legacy-entry", "other-final"} {
			_, _, launch := desktopSSCONNECTFixture(t, "always", desktopSSEntryMethods[1], protocol)
			copy := launch.external
			switch fault {
			case "server", "auto":
				copy.selection = fault
			case "predecessor":
				copy.predecessor = "foreign"
			case "off":
				copy.profile.KillSwitchPolicy = "off"
				copy.profile.KillSwitch = false
			case "entry-layer":
				copy.entry.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				copy.profile.StartLayer = common.StartLayerAES256GCM
			case "legacy-entry":
				copy.entry.External.Shadowsocks.Method = "aes-256-gcm"
			case "other-final":
				copy.profile.External.Protocol = "hysteria2"
			}
			if desktopExternalRetainedEntryOwner(copy) {
				t.Fatal("CONNECT widened unsupported graph", fault)
			}
		}
	}
}
