package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"router-vpn/internal/common"
)

func desktopWindowsRouterServerFixture(t *testing.T, choices ...string) (common.RouterProfile, common.RouterProfile, *desktopNodeLaunch) {
	t.Helper()
	profile, exit := desktopExternalNativeFixture(t, "shadowsocks")
	entry, files := desktopNodeFixture(t, "198.51.100.8")
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal(err)
	}
	execution := "server"
	if len(choices) != 0 {
		execution = choices[0]
	}
	profile.MultihopExecution, profile.MultihopEntryMode, profile.KillSwitchPolicy = execution, "wg", "always"
	profile.KillSwitch = true
	profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + exit.Server + "/node-response", ServerName: "exit.example.test"}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := compileDesktopWindowsExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if execution == "local" {
		ordinary, e := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
		if e != nil {
			t.Fatal("ordinary compiler changed", e)
		}
		var captured map[string]any
		if json.Unmarshal(ordinary.external.capture, &captured) != nil || captured["execution"] != nil {
			t.Fatal("generic desktop Local implicitly acquired Windows controller")
		}
		if e = prepareDesktopExternalPhysicalCaptured(ordinary, "windows"); e == nil {
			t.Fatal("ordinary capture bypassed explicit Windows preparation")
		}
	}
	return profile, entry, launch
}

func TestDesktopWindowsExternalRouterServerRestoresOriginal(t *testing.T) {
	testDesktopWindowsRouterRestore(t, "server")
}
func TestDesktopWindowsExternalRouterLocalRestoresOriginal(t *testing.T) {
	testDesktopWindowsRouterRestore(t, "local")
}
func testDesktopWindowsRouterRestore(t *testing.T, execution string) {
	profile, _, initial := desktopWindowsRouterServerFixture(t, execution)
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	saved := &speedLabExternalRestore{source: bytes.Clone(initial.external.source), profile: cloneRouterProfile(initial.external.profile), entry: cloneRouterProfile(initial.external.entry), predecessor: initial.external.predecessor, execution: execution, root: "captured-root", network: "captured-network", mtu: 1360}
	if err := captureSpeedLabExternalRestoreSeal(saved, initial.external); err != nil {
		t.Fatal(err)
	}
	restored, err := compileSpeedLabExternalRestore(saved, exit)
	if err != nil {
		t.Fatal(err)
	}
	if restored.external.selection != execution || restored.external.session == initial.external.session || restored.external.predecessor != initial.external.predecessor || !bytes.Equal(restored.external.source, initial.external.source) || restored.profileID != saved.entry.ID || restored.policyProfileID != saved.profile.ID || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1360 {
		t.Fatal("restoration changed paired assets, proved selection or MTU")
	}
	var before, after struct {
		Execution struct {
			Selection string
			Request   struct {
				SessionID string `json:"session_id"`
				Username  string `json:"listener_username"`
				Password  string `json:"listener_password"`
			}
		}
	}
	if json.Unmarshal(initial.external.capture, &before) != nil || json.Unmarshal(restored.external.capture, &after) != nil || before.Execution.Selection != execution || after.Execution.Selection != execution || before.Execution.Request.SessionID == "" || after.Execution.Request.SessionID == "" || before.Execution.Request.SessionID == after.Execution.Request.SessionID || before.Execution.Request == after.Execution.Request || before.Execution.Request.Password == after.Execution.Request.Password {
		t.Fatal("restoration reused an original relay lease or reran comparison")
	}
	if err := prepareDesktopExternalPhysicalCaptured(restored, "windows"); err != nil || restored.external.physical == nil {
		t.Fatal("restored Windows owner", err)
	}
	for _, field := range []string{"entry", "final", "assets", "selection", "controller"} {
		t.Run(field, func(t *testing.T) {
			changed := *saved
			changed.profile = cloneRouterProfile(saved.profile)
			changed.entry = cloneRouterProfile(saved.entry)
			switch field {
			case "controller":
				seal := *saved.seal
				seal.executionController = !seal.executionController
				changed.seal = &seal
			case "entry":
				changed.entry.APIToken = "replacement"
			case "final":
				changed.profile.External.Shadowsocks.Password = testWGKey('z')
			case "assets":
				changed.predecessor += " "
			case "selection":
				changed.execution = "local"
				if execution == "local" {
					changed.execution = "server"
				}
			}
			if next, err := compileSpeedLabExternalRestore(&changed, exit); err == nil || next != nil {
				t.Fatal("restoration adopted replacement authority")
			}
		})
	}
}

func TestDesktopWindowsExternalRouterServerSources(t *testing.T) {
	profile, entry, launch := desktopWindowsRouterServerFixture(t)
	if !desktopWindowsExternalGraphEligible(profile, entry, false, "") || !desktopWindowsExternalEligible(launch) {
		t.Fatal("exact Server graph refused")
	}
	if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil || launch.external.physical == nil {
		t.Fatal("physical capture", err)
	}
	selected, err := desktopProtectionSelectionFor(nil, launch.external.physical)
	if err != nil || selected.profileID != profile.ID || launch.profileID != entry.ID {
		t.Fatal("journal replaced entry or final", err)
	}
	if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, launch); err != nil {
		t.Fatal("original source", err)
	}
	for name, mutate := range map[string]func(*common.RouterProfile, *common.RouterProfile){
		"compare":     func(p, e *common.RouterProfile) { p.MultihopExecution = "auto" },
		"local":       func(p, e *common.RouterProfile) { p.MultihopExecution = "local" },
		"other-entry": func(p, e *common.RouterProfile) { e.ID = "another" },
		"node-proof":  func(p, e *common.RouterProfile) { e.NodeProofID = "" },
		"api-token":   func(p, e *common.RouterProfile) { e.APIToken = "another-token" },
		"final-key":   func(p, e *common.RouterProfile) { p.External.Shadowsocks.Password = testWGKey('z') },
		"entry-layer": func(p, e *common.RouterProfile) { e.StartLayer = common.StartLayerAES256GCM },
		"final-layer": func(p, e *common.RouterProfile) { p.StartLayer = common.StartLayerAES256GCM },
	} {
		t.Run(name, func(t *testing.T) {
			p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
			mutate(&p, &e)
			if validateDesktopRetainedExternalSourcesLocked(p, e, launch) == nil {
				t.Fatal("changed source adopted")
			}
		})
	}
	if desktopWindowsExternalGraphEligible(profile, entry, false, "local") || desktopWindowsExternalGraphEligible(profile, entry, true, "") {
		t.Fatal("Server restore/direct broadened")
	}
	proof := launch.external.expected
	proof.Execution = "server"
	if !desktopWindowsExternalExecutionProof(launch.external, proof) {
		t.Fatal("original paired Server proof refused")
	}
	proof.Execution = "local"
	if desktopWindowsExternalExecutionProof(launch.external, proof) {
		t.Fatal("Local selector accepted as Server")
	}
	proof.Execution, proof.EntryNodeID = "server", ""
	if desktopWindowsExternalExecutionProof(launch.external, proof) {
		t.Fatal("missing original Router identity accepted")
	}
	proof.EntryNodeID = profile.ID
	if desktopWindowsExternalExecutionProof(launch.external, proof) {
		t.Fatal("final profile substituted for Router identity")
	}
}

func TestDesktopWindowsExternalRouterLocalSources(t *testing.T) {
	profile, entry, launch := desktopWindowsRouterServerFixture(t, "local")
	if !desktopWindowsExternalGraphEligible(profile, entry, false, "") || !desktopWindowsExternalEligible(launch) {
		t.Fatal("captured Local refused")
	}
	if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil {
		t.Fatal(err)
	}
	if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, launch); err != nil {
		t.Fatal(err)
	}
	selected, err := desktopProtectionSelectionFor(nil, launch.external.physical)
	if err != nil || selected.profileID != profile.ID || launch.profileID != entry.ID {
		t.Fatal("Local identities changed", err)
	}
	proof := launch.external.expected
	proof.Execution = "local"
	if !desktopWindowsExternalExecutionProof(launch.external, proof) {
		t.Fatal("Local paired proof refused")
	}
	for _, change := range []string{"server", "auto", "node", "key", "token"} {
		t.Run(change, func(t *testing.T) {
			p, e := cloneRouterProfile(profile), cloneRouterProfile(entry)
			switch change {
			case "server", "auto":
				p.MultihopExecution = change
			case "node":
				e.NodeProofID = ""
			case "key":
				p.External.Shadowsocks.Password = testWGKey('z')
			case "token":
				e.APIToken = "foreign"
			}
			if validateDesktopRetainedExternalSourcesLocked(p, e, launch) == nil {
				t.Fatal("replacement Local source adopted")
			}
		})
	}
	proof.Execution = "server"
	if desktopWindowsExternalExecutionProof(launch.external, proof) {
		t.Fatal("Server proof adopted as Local")
	}
}
