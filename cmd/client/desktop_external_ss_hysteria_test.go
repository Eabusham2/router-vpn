package main

import (
	"router-vpn/internal/common"
	"testing"
)

func TestDesktopExternalSSHysteriaRetainsBothSourcesAndMeasurement(t *testing.T) {
	for _, method := range desktopSSEntryMethods {
		for _, protocol := range []string{"hysteria2"} {
			for _, kill := range []string{"always", "on-connect"} {
				profile, entry, launch := desktopWindowsSSFinalFixture(t, kill, method, protocol)
				if err := prepareDesktopExternalPhysicalCaptured(launch, "darwin"); err != nil {
					t.Fatal(err)
				}
				if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
					t.Fatal(err)
				}
				meta, err := capturedDesktopExternalPhysical(launch.external)
				if err != nil || meta == nil || meta.RootType != "shadowsocks" || meta.RootTag != "external-entry" {
					t.Fatal("HY2 lost original SS physical root", err)
				}
				measure, err := capturedDesktopMeasurementRuntime(launch)
				if err != nil || measure.node != profile.ID || measure.source != meta.SourceSHA256 || measure.config != meta.ConfigSHA256 {
					t.Fatal("HY2 measurement lost final owner", err)
				}
				resolver, err := capturedDesktopDNSRuntime(launch)
				if err != nil || resolver.node != profile.ID || resolver.source != meta.SourceSHA256 {
					t.Fatal("HY2 DNS lost final owner", err)
				}
				for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
					e := cloneRouterProfile(entry)
					mutateDesktopSSSource(&e, fault)
					if validateDesktopMacOSExternalSources(profile, e, launch) == nil {
						t.Fatal("HY2 accepted changed original SS entry", fault)
					}
				}
				for _, fault := range []string{"password", "tls", "host", "port", "public", "option"} {
					p := cloneRouterProfile(profile)
					mutateWindowsSSFinal(&p, fault)
					if validateDesktopMacOSExternalSources(p, entry, launch) == nil {
						t.Fatal("SS accepted changed HY2 source", fault)
					}
				}
			}
		}
	}
}
func TestDesktopExternalSSHysteriaRestoreRetainsCompleteLocalGraph(t *testing.T) {
	for _, method := range desktopSSEntryMethods {
		for _, protocol := range []string{"hysteria2"} {
			for _, kill := range []string{"always", "on-connect"} {
				_, _, initial := desktopWindowsSSFinalFixture(t, kill, method, protocol)
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
					t.Fatal("HY2 restore reran selection or lost original graph")
				}
				if err := prepareDesktopExternalPhysicalCaptured(restored, "darwin"); err != nil {
					t.Fatal(err)
				}
				for _, fault := range []string{"password", "tls", "host", "port", "public", "option"} {
					copy := *saved
					copy.profile = cloneRouterProfile(saved.profile)
					mutateWindowsSSFinal(&copy.profile, fault)
					if next, e := compileSpeedLabExternalRestore(&copy, exit); e == nil || next != nil {
						t.Fatal("HY2 restore accepted changed final source", fault)
					}
				}
				for _, fault := range []string{"password", "method", "server", "port", "public", "id", "option"} {
					copy := *saved
					copy.entry = cloneRouterProfile(saved.entry)
					mutateDesktopSSSource(&copy.entry, fault)
					if next, e := compileSpeedLabExternalRestore(&copy, exit); e == nil || next != nil {
						t.Fatal("HY2 restore accepted changed SS source", fault)
					}
				}
			}
		}
	}
}

func TestDesktopExternalSSHysteriaRetainsOffLayerAndLocalScope(t *testing.T) {
	for _, fault := range []string{"entry-layer", "final-layer", "entry-layer-object", "final-layer-object", "legacy-entry", "same-id", "predecessor", "server", "auto", "off"} {
		t.Run(fault, func(t *testing.T) {
			_, _, launch := desktopWindowsSSFinalFixture(t, "always", desktopSSEntryMethods[1], "hysteria2")
			o := launch.external
			switch fault {
			case "entry-layer":
				o.entry.StartLayer = common.StartLayerAES256GCM
			case "final-layer":
				o.profile.StartLayer = common.StartLayerAES256GCM
			case "entry-layer-object":
				o.entry.External.StartLayer = &common.ExternalStartLayer{Mode: common.StartLayerAES256GCM}
			case "final-layer-object":
				o.profile.External.StartLayer = &common.ExternalStartLayer{Mode: common.StartLayerAES256GCM}
			case "legacy-entry":
				o.entry.External.Shadowsocks.Method = "aes-256-gcm"
			case "same-id":
				o.entry.ID = o.profile.ID
			case "predecessor":
				o.predecessor = "foreign"
			case "server", "auto":
				o.selection = fault
			case "off":
				o.profile.KillSwitchPolicy = "off"
				o.profile.KillSwitch = false
			}
			for _, target := range []string{"windows", "darwin", "linux"} {
				if desktopExternalRetainedEntryForOS(o, target) {
					t.Fatal("SS HY2 scope widened", target, fault)
				}
			}
		})
	}
}
