package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDesktopWindowsExternalRouterCompareSources(t *testing.T) {
	profile, entry, launch := desktopWindowsRouterServerFixture(t, "auto")
	if !desktopWindowsExternalGraphEligible(profile, entry, false, "") || !desktopWindowsExternalEligible(launch) {
		t.Fatal("captured Compare refused")
	}
	if err := prepareDesktopExternalPhysicalCaptured(launch, "windows"); err != nil {
		t.Fatal(err)
	}
	if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, launch); err != nil {
		t.Fatal(err)
	}
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			proof := launch.external.expected
			proof.Execution = winner
			if !desktopWindowsExternalExecutionProof(launch.external, proof) {
				t.Fatal("original winner refused")
			}
			changed := cloneRouterProfile(profile)
			changed.MultihopExecution = winner
			if validateDesktopRetainedExternalSourcesLocked(changed, entry, launch) == nil {
				t.Fatal("winner replaced saved auto")
			}
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
				t.Fatal(err)
			}
			if restored.external.profile.MultihopExecution != "auto" || restored.external.selection != winner || restored.external.session == launch.external.session {
				t.Fatal("restoration reran Compare or replaced saved choice")
			}
			var capture struct{ Execution struct{ Selection string } }
			if json.Unmarshal(restored.external.capture, &capture) != nil || capture.Execution.Selection != winner {
				t.Fatal("restoration did not pin original winner")
			}
			if err := prepareDesktopExternalPhysicalCaptured(restored, "windows"); err != nil {
				t.Fatal(err)
			}
			if err := validateDesktopRetainedExternalSourcesLocked(profile, entry, restored); err != nil {
				t.Fatal("saved auto source became stale", err)
			}
			changedProof := restored.external.expected
			changedProof.Execution = winner
			if !desktopWindowsExternalExecutionProof(restored.external, changedProof) {
				t.Fatal("restored proof refused")
			}
			if winner == "local" {
				changedProof.Execution = "server"
			} else {
				changedProof.Execution = "local"
			}
			if desktopWindowsExternalExecutionProof(restored.external, changedProof) {
				t.Fatal("restored winner changed")
			}
			saved.execution = changedProof.Execution
			if _, err := compileSpeedLabExternalRestore(saved, exit); err == nil {
				t.Fatal("unsealed winner replaced")
			}
		})
	}
	proof := launch.external.expected
	proof.Execution = "auto"
	if desktopWindowsExternalExecutionProof(launch.external, proof) {
		t.Fatal("unproved Compare adopted")
	}
	proof.Execution = "local"
	proof.EntryNodeID = ""
	if desktopWindowsExternalExecutionProof(launch.external, proof) {
		t.Fatal("missing entry proof adopted")
	}
}
