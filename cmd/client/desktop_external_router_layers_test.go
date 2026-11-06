package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

// This fixture compiles captured files and profiles only. It starts no provider,
// tunnel, encrypted connection, registry operation or native firewall owner.
func desktopWindowsRouterFinalLayerFixture(t *testing.T, execution, layer, method, kill string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, _ := desktopExternalNativeFixture(t, "shadowsocks")
	entry, files := desktopNodeFixture(t, "198.51.100.8")
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal(err)
	}
	profile.External.Shadowsocks.Method = method
	profile.External.Shadowsocks.Password = desktopSSEntryKey(method, 'f')
	profile.MultihopExecution, profile.MultihopEntryMode, profile.KillSwitchPolicy = execution, "wg", kill
	profile.KillSwitch = true
	profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + profile.External.Shadowsocks.Server + "/node-response", ServerName: "exit.example.test"}
	desktopSSProvisionLayer(&profile, layer, "10.93.0.1", 'l')
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal("captured final profile invalid", err)
	}
	launch, err := compileDesktopWindowsExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
	if err != nil {
		t.Fatal("captured paired source did not compile", err)
	}
	return profile, entry, launch
}

func TestDesktopWindowsExternalRouterServerFinalLayers(t *testing.T) {
	testDesktopWindowsRouterFinalLayers(t, "server")
}
func TestDesktopWindowsExternalRouterLocalFinalLayers(t *testing.T) {
	testDesktopWindowsRouterFinalLayers(t, "local")
}
func TestDesktopWindowsExternalRouterCompareFinalLayers(t *testing.T) {
	testDesktopWindowsRouterFinalLayers(t, "auto")
}

func testDesktopWindowsRouterFinalLayers(t *testing.T, execution string) {
	for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		for _, method := range desktopSSEntryMethods {
			for _, kill := range []string{"on-connect", "always"} {
				t.Run(layer+"/"+method+"/"+kill, func(t *testing.T) {
					profile, entry, launch := desktopWindowsRouterFinalLayerFixture(t, execution, layer, method, kill)
					if !desktopWindowsExternalGraphEligible(profile, entry, false, "") || !desktopWindowsExternalEligible(launch) {
						t.Fatal("captured independent final layer lost Windows host admission")
					}
					if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil || launch.external.physical == nil {
						t.Fatal("captured final layer lost its original physical source", err)
					}
					if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, launch); err != nil {
						t.Fatal("captured original profiles were not retained", err)
					}
					capture, err := launch.external.physical.Capture()
					if err != nil || capture.StartLayer != layer || capture.EntryStartLayer != "" || capture.Execution != execution || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Type != "wireguard" ||
						launch.profileID != entry.ID || launch.policyProfileID != profile.ID || launch.external.profile.StartLayer != layer || launch.external.entry.StartLayer != entry.StartLayer {
						t.Fatal("physical entry and final-layer identities were conflated", err)
					}
					selection, err := desktopProtectionSelectionFor(nil, launch.external.physical)
					if err != nil || selection.profileID != profile.ID {
						t.Fatal("protection selection lost the final source", err)
					}
					measure, err := capturedDesktopMeasurementRuntime(launch)
					if err != nil || measure.node != profile.ID {
						t.Fatal("measurement capture lost the final source", err)
					}
					winners := []string{execution}
					if execution == "auto" {
						winners = []string{"local", "server"}
					}
					for _, winner := range winners {
						t.Run("restore-"+winner, func(t *testing.T) {
							testDesktopWindowsRouterFinalLayerRestore(t, launch, profile, entry, layer, winner)
						})
					}
				})
			}
		}
	}
}

func testDesktopWindowsRouterFinalLayerRestore(t *testing.T, launch *desktopNodeLaunch, profile, entry common.RouterProfile, layer, winner string) {
	t.Helper()
	saved := &speedLabExternalRestore{source: bytes.Clone(launch.external.source), profile: cloneRouterProfile(launch.external.profile), entry: cloneRouterProfile(launch.external.entry), predecessor: launch.external.predecessor, execution: winner, root: "captured-root", network: "captured-network", mtu: 1360}
	if err := captureSpeedLabExternalRestoreSeal(saved, launch.external); err != nil {
		t.Fatal(err)
	}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := compileSpeedLabExternalRestore(saved, exit)
	if err != nil {
		t.Fatal("independent final layer did not restore", err)
	}
	if restored.external.selection != winner || restored.external.profile.MultihopExecution != profile.MultihopExecution || restored.external.session == launch.external.session ||
		!bytes.Equal(restored.external.source, launch.external.source) || restored.external.predecessor != launch.external.predecessor || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
		t.Fatal("restoration changed the original sources, reran Compare or reused its session")
	}
	if err := prepareDesktopExternalPhysicalCaptured(restored, "windows"); err != nil {
		t.Fatal(err)
	}
	if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, restored); err != nil {
		t.Fatal("restored original source became stale", err)
	}
	var before, after struct {
		Execution struct {
			Selection string
			Request   struct {
				Session  string `json:"session_id"`
				Password string `json:"listener_password"`
				Layer    string `json:"exit_start_layer"`
			}
		}
	}
	if json.Unmarshal(launch.external.capture, &before) != nil || json.Unmarshal(restored.external.capture, &after) != nil || after.Execution.Selection != winner ||
		after.Execution.Request.Layer != layer || before.Execution.Request.Layer != layer || after.Execution.Request.Session == before.Execution.Request.Session || after.Execution.Request.Password == before.Execution.Request.Password {
		t.Fatal("restored final layer lost its fresh fixed execution proposal")
	}
	var originalGraph, restoredGraph map[string]any
	if json.Unmarshal(launch.config, &originalGraph) != nil || json.Unmarshal(restored.config, &restoredGraph) != nil {
		t.Fatal("captured layer graphs are invalid")
	}
	for _, tag := range []string{mobilemultihop.LocalTag, multihoprelay.ExitStartLayerTag} {
		if !reflect.DeepEqual(taggedRuntimeItem(originalGraph["outbounds"].([]any), tag), taggedRuntimeItem(restoredGraph["outbounds"].([]any), tag)) {
			t.Fatal("restoration changed the original inner or outer final", tag)
		}
	}
	if !reflect.DeepEqual(originalGraph["dns"], restoredGraph["dns"]) {
		t.Fatal("restoration replaced selected DNS")
	}
	proof := restored.external.expected
	proof.Execution = winner
	if !desktopWindowsExternalExecutionProof(restored.external, proof) {
		t.Fatal("restored fixed execution rejected its original entry identity")
	}
	if winner == "local" {
		proof.Execution = "server"
	} else {
		proof.Execution = "local"
	}
	if desktopWindowsExternalExecutionProof(restored.external, proof) {
		t.Fatal("restored final layer accepted a different execution")
	}
	changed := *saved
	changed.profile = cloneRouterProfile(saved.profile)
	changed.profile.External.StartLayer.Transport["password"] = desktopSSEntryKey(desktopSSEntryMethods[1], 'z')
	if next, err := compileSpeedLabExternalRestore(&changed, exit); err == nil || next != nil {
		t.Fatal("restoration accepted a replaced final-layer key")
	}
}

func TestDesktopWindowsExternalRouterServerFinalLayerSourcesRejectReplacement(t *testing.T) {
	for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		profile, entry, launch := desktopWindowsRouterFinalLayerFixture(t, "server", layer, desktopSSEntryMethods[1], "always")
		if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil || launch.external.physical == nil {
			t.Fatal(err)
		}
		if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, launch); err != nil {
			t.Fatal("replacement controls did not begin with a valid retained source", err)
		}
		for _, fault := range []string{"selected-layer", "provision-mode", "private-api", "outer-key", "outer-node", "inner-key", "entry-token", "entry-layer", "selected-dns"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
				switch fault {
				case "selected-layer":
					p.StartLayer = common.StartLayerOff
				case "provision-mode":
					p.External.StartLayer.Mode = common.StartLayerOff
				case "private-api":
					p.External.StartLayer.API = "http://10.94.0.1:8787"
				case "outer-key":
					p.External.StartLayer.Transport["password"] = desktopSSEntryKey(desktopSSEntryMethods[1], 'z')
				case "outer-node":
					p.External.StartLayer.Transport["server"] = "203.0.113.99"
				case "inner-key":
					p.External.Shadowsocks.Password = desktopSSEntryKey(p.External.Shadowsocks.Method, 'z')
				case "entry-token":
					e.APIToken = "foreign-entry-token"
				case "entry-layer":
					e.StartLayer = common.StartLayerAES256GCM
				case "selected-dns":
					p.DNSHost = "203.0.113.99"
				}
				if err := validateDesktopRetainedExternalSourcesLocked(p, e, launch); err == nil {
					t.Fatal("captured final layer adopted a changed private source")
				}
				if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, launch); err != nil {
					t.Fatal("source rejection damaged its original owner", err)
				}
			})
		}
	}
}
