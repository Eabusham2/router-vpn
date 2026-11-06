package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
)

// These tests use captured files, the real compilers and host preparation.
// Native executable verification/preflight is an explicit fixture boundary;
// no provider, encrypted socket, TUN or Windows firewall is started here.
func desktopWindowsRouterEntryLayerSources(t *testing.T, execution, first, last, method, kill string) (common.RouterProfile, common.RouterProfile, map[string][]byte, map[string][]byte) {
	t.Helper()
	profile, _ := desktopExternalNativeFixture(t, "shadowsocks")
	entry, files := desktopNodeFixture(t, "198.51.100.8")
	entry.StartLayer = first
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal(err)
	}
	profile.External.Shadowsocks.Method, profile.External.Shadowsocks.Password = method, desktopSSEntryKey(method, 'f')
	profile.MultihopExecution, profile.MultihopEntryMode = execution, "wg"
	profile.KillSwitch, profile.KillSwitchPolicy = true, kill
	profile.MTUPolicy, profile.ManualMTU = "manual", 1360
	profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + profile.External.Shadowsocks.Server + "/node-response", ServerName: "exit.example.test"}
	desktopSSProvisionLayer(&profile, last, "10.93.0.1", 'l')
	return profile, entry, files, desktopOwnedNodePreparationAES(t, entry.Endpoint)
}

func TestDesktopWindowsExternalRouterServerEntryLayers(t *testing.T) {
	testDesktopWindowsRouterEntryLayers(t, "server")
}
func TestDesktopWindowsExternalRouterLocalEntryLayers(t *testing.T) {
	testDesktopWindowsRouterEntryLayers(t, "local")
}
func TestDesktopWindowsExternalRouterCompareEntryLayers(t *testing.T) {
	testDesktopWindowsRouterEntryLayers(t, "auto")
}

func testDesktopWindowsRouterEntryLayers(t *testing.T, execution string) {
	for _, first := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		for _, last := range []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			for _, method := range desktopSSEntryMethods {
				for _, kill := range []string{"on-connect", "always"} {
					t.Run(first+"/final-"+last+"/"+method+"/"+kill, func(t *testing.T) {
						profile, entry, files, start := desktopWindowsRouterEntryLayerSources(t, execution, first, last, method, kill)
						filesBefore, startBefore := encodeDesktopNodeAssets(files), encodeDesktopNodeAssets(start)
						exit, err := standardExitFromExternalProfile(profile)
						if err != nil {
							t.Fatal(err)
						}
						launch, err := compileDesktopWindowsExternalCaptured(context.Background(), profile, entry, exit, false, "", files, start, nil)
						if err != nil || !desktopWindowsExternalGraphEligible(profile, entry, false, "") || !desktopWindowsExternalEligible(launch) {
							t.Fatal("captured independent Router entry lost Windows admission", err)
						}
						if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil || launch.external.physical == nil {
							t.Fatal("captured entry layer did not adopt its physical owner", err)
						}
						if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, launch); err != nil {
							t.Fatal("independent entry did not retain both original sources", err)
						}
						capture, err := launch.external.physical.Capture()
						meta := launch.external.physical.Metadata()
						capturedFinalLayer := last
						if capturedFinalLayer == common.StartLayerOff {
							capturedFinalLayer = ""
						}
						if err != nil || capture.EntryStartLayer != first || capture.StartLayer != capturedFinalLayer || capture.Execution != execution || capture.ConfiguredMTU != 1360 ||
							meta.StartupEndpointTag != capture.EntryTag || meta.StartupEndpointType != "wireguard" || meta.RootTag == capture.EntryTag || meta.RootType == "wireguard" ||
							launch.profileID != entry.ID || launch.policyProfileID != profile.ID || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Family != "outbounds" {
							t.Fatal("entry/final or eager/physical roles were conflated", err)
						}
						selection, err := desktopProtectionSelectionFor(nil, launch.external.physical)
						if err != nil || selection.profileID != profile.ID {
							t.Fatal("independent entry lost final protection identity", err)
						}
						measurement, err := capturedDesktopMeasurementRuntime(launch)
						if err != nil || measurement.node != profile.ID {
							t.Fatal("independent entry lost captured measurement identity", err)
						}
						if encodeDesktopNodeAssets(files) != filesBefore || encodeDesktopNodeAssets(start) != startBefore {
							t.Fatal("entry preparation modified the caller's original asset bytes")
						}
						winners := []string{execution}
						if execution == "auto" {
							winners = []string{"local", "server"}
						}
						for _, winner := range winners {
							t.Run("restore-"+winner, func(t *testing.T) {
								testDesktopWindowsRouterEntryLayerRestore(t, launch, profile, entry, winner)
							})
						}
					})
				}
			}
		}
	}
}

func testDesktopWindowsRouterEntryLayerRestore(t *testing.T, launch *desktopNodeLaunch, profile, entry common.RouterProfile, winner string) {
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
	if err != nil || restored.external.selection != winner || restored.external.profile.MultihopExecution != profile.MultihopExecution || restored.external.session == launch.external.session ||
		restored.external.predecessor != launch.external.predecessor || !bytes.Equal(restored.external.source, launch.external.source) || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
		t.Fatal("entry restoration replaced captured source or reran Compare", err)
	}
	if err := prepareDesktopExternalPhysicalCaptured(restored, "windows"); err != nil || restored.external.physical == nil {
		t.Fatal("entry restoration lost its exact physical owner", err)
	}
	if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, restored); err != nil {
		t.Fatal("entry restoration changed the original source", err)
	}
	before, after := launch.external.physical.Metadata(), restored.external.physical.Metadata()
	if before.StartupEndpointTag != after.StartupEndpointTag || before.StartupEndpointType != after.StartupEndpointType || before.StartupEndpointSHA256 != after.StartupEndpointSHA256 || before.OriginalRootSHA256 != after.OriginalRootSHA256 {
		t.Fatal("entry restoration swapped the original eager endpoint or outer credentials")
	}
	var oldGraph, newGraph map[string]any
	if json.Unmarshal([]byte(launch.external.physical.OriginalPolicy().Config()), &oldGraph) != nil || json.Unmarshal([]byte(restored.external.physical.OriginalPolicy().Config()), &newGraph) != nil {
		t.Fatal("entry restoration has no complete original graphs")
	}
	for _, tag := range []string{before.RootTag, mobilemultihop.LocalTag, multihoprelay.ExitStartLayerTag} {
		if !reflect.DeepEqual(taggedRuntimeItem(oldGraph["outbounds"].([]any), tag), taggedRuntimeItem(newGraph["outbounds"].([]any), tag)) {
			t.Fatal("entry restoration replaced an original layer", tag)
		}
	}
	if !reflect.DeepEqual(oldGraph["endpoints"], newGraph["endpoints"]) || !reflect.DeepEqual(oldGraph["dns"], newGraph["dns"]) {
		t.Fatal("entry restoration replaced WG credentials or selected DNS")
	}
	var oldCapture, newCapture struct {
		Execution struct {
			Request struct {
				Session  string `json:"session_id"`
				Password string `json:"listener_password"`
			}
		}
	}
	if json.Unmarshal(launch.external.capture, &oldCapture) != nil || json.Unmarshal(restored.external.capture, &newCapture) != nil || oldCapture.Execution.Request.Session == newCapture.Execution.Request.Session || oldCapture.Execution.Request.Password == newCapture.Execution.Request.Password {
		t.Fatal("entry restoration reused its old relay credentials")
	}
	changed := *saved
	changed.entry = cloneRouterProfile(saved.entry)
	changed.entry.StartLayer = common.StartLayerOff
	if next, err := compileSpeedLabExternalRestore(&changed, exit); err == nil || next != nil {
		t.Fatal("entry restoration ignored replacement of the original layer")
	}
	changed = *saved
	var predecessor map[string]any
	if json.Unmarshal([]byte(changed.predecessor), &predecessor) != nil {
		t.Fatal("original predecessor is unavailable")
	}
	taggedRuntimeItem(predecessor["outbounds"].([]any), mobilemultihop.NativeStartLayerTag)["password"] = testWGKey('z')
	replacement, err := json.Marshal(predecessor)
	if err != nil {
		t.Fatal(err)
	}
	changed.predecessor = string(replacement)
	if next, err := compileSpeedLabExternalRestore(&changed, exit); err == nil || next != nil {
		t.Fatal("entry restoration borrowed a replaced credential bundle")
	}
}

func TestDesktopWindowsExternalRouterServerEntryLayerHostAssets(t *testing.T) {
	for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		for _, fault := range []string{"valid", "missing", "foreign-only", "bad-key", "cancelled-before", "cancelled-preflight", "controller-replaced", "network-missing", "network-lost", "network-changed"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				f := newDesktopOwnedNodePreparationFixture(t, "wg")
				entry := cloneRouterProfile(f.profile)
				entry.StartLayer = layer
				if err := common.NormalizeRouterProfile(&entry); err != nil {
					t.Fatal(err)
				}
				profile, _, _, _ := desktopWindowsRouterEntryLayerSources(t, "server", layer, common.StartLayerAES256GCMXOR, mobilemultihop.NativeStartLayerMethod, "always")
				start := desktopOwnedNodePreparationAES(t, entry.Endpoint)
				if fault == "bad-key" {
					var graph map[string]any
					_ = json.Unmarshal(start["sing-box.json"], &graph)
					graph["outbounds"].([]any)[0].(map[string]any)["password"] = "invalid-captured-key"
					start["sing-box.json"], _ = json.Marshal(graph)
				}
				assetID := entry.ID
				if fault == "foreign-only" {
					assetID = "unrelated-router"
				}
				path := filepath.Join(f.capture.dataRoot, "generated", assetID, "shadowsocks", "sing-box.json")
				if fault != "missing" {
					if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, start["sing-box.json"], 0600); err != nil {
						t.Fatal(err)
					}
				}
				preflights, directory := 0, ""
				host := &desktopNodeConnectionHost{
					capture: func(a *app) (desktopOwnedNodePreparation, error) {
						if a != f.a {
							return desktopOwnedNodePreparation{}, errors.New("changed fixture application")
						}
						return f.capture, nil
					}, verify: f.verify, lookup: f.lookup,
					startExternal: func(context.Context, *app, *desktopNodeLaunch, []string, []string, string) (desktopNodeProcess, error) {
						t.Fatal("source preparation started a native provider")
						return nil, errors.New("unreachable")
					},
					externalPreflight: func(ctx context.Context, binary string, args, env []string, dir string) error {
						preflights++
						directory = dir
						if fault == "cancelled-preflight" {
							f.cancel()
						}
						if fault == "controller-replaced" {
							f.controller = errors.New("captured controller replaced")
						}
						if fault == "network-lost" {
							f.network = ""
						}
						if fault == "network-changed" {
							f.network = strings.Repeat("c", 64)
						}
						return ctx.Err()
					},
				}
				if fault == "cancelled-before" {
					f.cancel()
				}
				if fault == "network-missing" {
					f.network = ""
				}
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				beforeCommand, beforeState := f.a.cmd, f.a.state
				// Model only the physical-network observation. The shipping wrapper
				// supplies physicalNetworkIdentity, while the same preparation body
				// loads the original private assets and owns both preflight stages.
				launch, err := prepareDesktopWindowsExternalLaunchWith(f.a, host, profile, entry, exit, false, "", func() string { return f.network })
				if fault == "valid" {
					if err != nil || launch == nil || launch.external.physical == nil || preflights != 2 {
						t.Fatal("Windows host omitted the captured entry Start Layer bundle", err)
					}
					capture, err := launch.external.physical.Capture()
					if err != nil || capture.EntryStartLayer != layer || capture.StartLayer != common.StartLayerAES256GCMXOR || capture.EntryID != entry.ID || launch.root != f.capture.dataRoot {
						t.Fatal("Windows host borrowed another node's layer assets", err)
					}
					var graph map[string]any
					if json.Unmarshal([]byte(launch.external.predecessor), &graph) != nil || taggedRuntimeItem(graph["outbounds"].([]any), mobilemultihop.NativeStartLayerTag)["password"] != testWGKey('+') {
						t.Fatal("Windows host lost the original entry layer credential")
					}
				} else {
					if err == nil {
						t.Fatal("Windows host admitted missing, replaced or cancelled entry source")
					}
					// The existing final host read returns its candidate with an
					// error. That candidate is not an admitted connection, and its
					// retained host must still reject the replaced controller.
					if launch != nil && (fault != "controller-replaced" || launch.external == nil || launch.external.windowsHost.current() == nil) {
						t.Fatal("failed preparation returned a candidate with live host authority")
					}
				}
				if f.a.cmd != beforeCommand || f.a.state != beforeState || f.a.nodeProtection != nil || f.lookupCalls != 0 {
					t.Fatal("entry preparation changed the replacement runtime or used ambient resolution")
				}
				if directory != "" {
					if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("entry preflight retained its private workspace", err)
					}
				}
				if fault != "missing" {
					if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, start["sing-box.json"]) {
						t.Fatal("entry preparation changed saved private assets", err)
					}
				}
			})
		}
	}
}
