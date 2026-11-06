package main

import (
	"context"
	"fmt"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"testing"
)

func TestDesktopWindowsExternalSSEntryHysteriaIndependentLayersSources(t *testing.T) {
	modes := []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR}
	for i, entryMode := range modes {
		for j, finalMode := range modes {
			for _, target := range []string{"linux", "darwin", "windows"} {
				t.Run(fmt.Sprintf("layer%d-layer%d/%s", i, j, target), func(t *testing.T) {
					profile, entry, launch := desktopSSHysteriaLayerFixture(t, desktopSSEntryMethods[1], desktopSSEntryMethods[2], entryMode, finalMode, "always")
					if !desktopWindowsExternalGraphEligible(profile, entry, false, "") {
						t.Fatal("independent original layers rejected")
					}
					if err := prepareDesktopExternalPhysicalCaptured(launch, target); err != nil || launch.external.physical == nil {
						t.Fatal("physical owner not retained", err)
					}
					root := "external-entry"
					if entryMode != common.StartLayerOff {
						root = mobilemultihop.ExternalEntryStartLayerTag
					}
					if launch.external.physical.Metadata().RootTag != root || launch.profileID != entry.ID || launch.policyProfileID != profile.ID {
						t.Fatal("entry physical identity or final policy identity changed")
					}
					if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
						t.Fatal(err)
					}
					selection, err := desktopProtectionSelectionFor(nil, launch.external.physical)
					if target == "windows" && (err != nil || selection.profileID != profile.ID) {
						t.Fatal("protection journal lost final source", err)
					}
					measure, err := capturedDesktopMeasurementRuntime(launch)
					if err != nil || measure.node != profile.ID {
						t.Fatal("measurement lost final source", err)
					}
					for _, which := range []string{"entry", "final"} {
						for _, fault := range []string{"selected-mode", "provision-mode", "api", "outer-key", "outer-server", "raw-key"} {
							p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
							selected := &p
							if which == "entry" {
								selected = &e
							}
							if selected.StartLayer == common.StartLayerOff && fault != "selected-mode" && fault != "raw-key" {
								continue
							}
							switch fault {
							case "selected-mode":
								selected.StartLayer = "foreign-mode"
							case "provision-mode":
								selected.External.StartLayer.Mode = "foreign-mode"
							case "api":
								selected.External.StartLayer.API = "http://10.99.0.1:8787"
							case "outer-key":
								selected.External.StartLayer.Transport["password"] = desktopSSEntryKey(desktopSSEntryMethods[1], 'z')
							case "outer-server":
								selected.External.StartLayer.Transport["server"] = "192.0.2.99"
							case "raw-key":
								if selected.External.Protocol == "hysteria2" {
									selected.External.Hysteria2.Password += "wrong"
								} else {
									selected.External.Shadowsocks.Password = desktopSSEntryKey(selected.External.Shadowsocks.Method, 'z')
								}
							}
							if err := validateDesktopMacOSExternalSources(p, e, launch); err == nil {
								t.Fatal("replacement adopted", which, fault)
							}
							if err := validateDesktopMacOSExternalSources(profile, entry, launch); err != nil {
								t.Fatal("rejection damaged original", err)
							}
						}
					}
				})
			}
		}
	}
}

func TestDesktopWindowsExternalSSEntryHysteriaIndependentLayersRestore(t *testing.T) {
	modes := []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR}
	for i, first := range modes {
		for j, last := range modes {
			t.Run(fmt.Sprintf("layer%d-layer%d", i, j), func(t *testing.T) {
				profile, _, initial := desktopSSHysteriaLayerFixture(t, desktopSSEntryMethods[1], desktopSSEntryMethods[2], first, last, "always")
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				saved := &speedLabExternalRestore{source: append([]byte(nil), initial.external.source...), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(initial.external.entry), direct: false, execution: "local", root: "captured-root", network: "captured-network", mtu: 1360}
				if err := captureSpeedLabExternalRestoreSeal(saved, initial.external); err != nil {
					t.Fatal(err)
				}
				restored, err := compileSpeedLabExternalRestore(saved, exit)
				if err != nil {
					t.Fatal(err)
				}
				if restored.external.session == initial.external.session || string(restored.external.source) != string(initial.external.source) || restored.profileID != saved.entry.ID || restored.policyProfileID != saved.profile.ID || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
					t.Fatal("restoration changed original layers or owner identity")
				}
				for _, target := range []string{"windows", "linux", "darwin"} {
					fresh, err := compileSpeedLabExternalRestore(saved, exit)
					if err != nil {
						t.Fatal(err)
					}
					if err := prepareDesktopExternalPhysicalCaptured(fresh, target); err != nil || fresh.external.physical == nil {
						t.Fatal("restored native layer owner missing", target, err)
					}
				}
				for _, entry := range []bool{true, false} {
					changed := *saved
					changed.profile = cloneRouterProfile(saved.profile)
					changed.entry = cloneRouterProfile(saved.entry)
					selected := &changed.profile
					if entry {
						selected = &changed.entry
					}
					if selected.External.StartLayer != nil {
						selected.External.StartLayer.Transport["password"] = desktopSSEntryKey(desktopSSEntryMethods[1], 'z')
					} else {
						selected.StartLayer = common.StartLayerAES256GCM
					}
					if next, err := compileSpeedLabExternalRestore(&changed, exit); err == nil || next != nil {
						t.Fatal("saved layer replacement adopted")
					}
				}
			})
		}
	}
}

func desktopSSHysteriaLayerFixture(t *testing.T, entryMethod, unused, entryMode, finalMode, kill string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, entry, _ := desktopWindowsSSFinalFixture(t, kill, entryMethod, "hysteria2")
	desktopSSProvisionLayer(&entry, entryMode, "10.94.0.1", 'a')
	desktopSSProvisionLayer(&profile, finalMode, "10.93.0.1", 'b')
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
