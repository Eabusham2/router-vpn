package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func speedLabTorPreparedFixture(t *testing.T) (*app, *torBridgePrelaunch, func() error) {
	t.Helper()
	a, prepared := torPrelaunchFixture(t)
	profile := existingTorImportProfile("captured-tor")
	a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
	a.state = state{Mode: "off", Phase: "off", RouterID: profile.ID}
	operation, cancel := context.WithCancel(context.Background())
	a.connectionContext, a.connectionCancel = operation, cancel
	temporary := &speedLabTemporaryOwner{intent: operation, test: operation, current: operation, cancelIntent: cancel, cancelTest: cancel}
	speedLabTemporaryOwners.Store(a, temporary)
	t.Cleanup(cancel)
	t.Cleanup(func() { speedLabTemporaryOwners.Delete(a) })
	prepared.command = exec.Command(os.Args[0], "-test.run=^TestStartupExternalProcessFixture$")
	prepared.command.Env = envWithValue(os.Environ(), "ROUTERVPN_STARTUP_EXTERNAL_CHILD", "cleanup")
	return a, prepared, a.speedLabTorPrelaunchCheck(profile)
}

func TestSpeedLabTorCancelledOrReplacedPreparationCannotStart(t *testing.T) {
	for _, change := range []string{"cancel", "operation", "temporary-owner", "runtime", "profile", "selection"} {
		t.Run(change, func(t *testing.T) {
			a, prepared, check := speedLabTorPreparedFixture(t)
			replacementDNS := activeDNSRuntimeIdentity{ProfileID: "replacement", RuntimeID: "external-hysteria2", Config: filepath.Join(t.TempDir(), "sing-box.json")}
			switch change {
			case "cancel":
				a.connectionCancel()
			case "operation":
				a.connectionContext = context.Background()
			case "temporary-owner":
				speedLabTemporaryOwners.Store(a, &speedLabTemporaryOwner{current: a.connectionContext})
			case "runtime":
				a.cmd = exec.Command("replacement-runtime")
				a.state = state{Connected: true, Phase: "connected", RuntimeMode: "replacement", RouterID: "replacement"}
				activeDNSRuntimeIdentities.Store(a, replacementDNS)
			case "profile":
				a.profiles.Profiles[0].External.TorBridge.Bridges = []string{torImportSnowflakeBridge}
			case "selection":
				a.profiles.SelectedID = "replacement-selection"
			}
			before, command := a.state, a.cmd
			err := prepared.start(check)
			if !errors.Is(err, errTorPrelaunchRejected) {
				t.Fatal("retired Speed Lab preparation was not rejected", change, err)
			}
			if change == "cancel" && !errors.Is(err, errConnectionOperationCancelled) {
				t.Fatal("cancelled Tor launch lost its cancellation identity", err)
			}
			if prepared.command.Process != nil || a.cmd != command || a.state != before {
				t.Fatal("retired Tor preparation started or mutated a replacement owner", change)
			}
			if _, err := os.Stat(prepared.workspace.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("retired Tor preparation leaked its private workspace", change, err)
			}
			if current, exists := activeDNSRuntimeIdentities.Load(a); change == "runtime" && (!exists || current != replacementDNS) || change != "runtime" && exists {
				t.Fatal("Tor preparation retired the wrong DNS owner", change)
			}
		})
	}
}

func TestSpeedLabTorStartFailureCleansInputsAndSuccessHandsOff(t *testing.T) {
	t.Run("exec failure", func(t *testing.T) {
		_, prepared, check := speedLabTorPreparedFixture(t)
		prepared.command = exec.Command(filepath.Join(t.TempDir(), "absent-native-helper"))
		if err := prepared.start(check); err == nil || errors.Is(err, errTorPrelaunchRejected) {
			t.Fatal("missing executable was not reported as a start failure", err)
		}
		if _, err := os.Stat(prepared.workspace.directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed Tor exec leaked prepared credentials", err)
		}
	})
	t.Run("real isolated child handoff", func(t *testing.T) {
		a, prepared, check := speedLabTorPreparedFixture(t)
		if err := prepared.start(check); err != nil {
			t.Fatal(err)
		}
		if err := prepared.command.Wait(); err != nil {
			t.Fatal(err)
		}
		if a.state.Connected {
			t.Fatal("process startup was substituted for Tor path proof")
		}
		if _, err := os.Stat(filepath.Join(prepared.workspace.directory, "torrc")); err != nil {
			t.Fatal("prepared input vanished before native teardown", err)
		}
		if err := prepared.cleanup(); err == nil {
			t.Fatal("controller prelaunch cleanup took over a started child's workspace")
		}
	})
}

func TestSpeedLabTorPrelaunchRejectsChangedPrivateDirectory(t *testing.T) {
	_, prepared, check := speedLabTorPreparedFixture(t)
	directory := prepared.workspace.directory
	if err := os.Rename(directory, directory+"-captured"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(directory, "torrc")
	if err := os.WriteFile(foreign, []byte("replacement private data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepared.start(check); !errors.Is(err, errTorPrelaunchRejected) {
		t.Fatal("changed private workspace reached exec.Start", err)
	}
	if prepared.command.Process != nil {
		t.Fatal("a child started against a replacement private workspace")
	}
	if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "replacement private data" {
		t.Fatal("rejected Tor preparation deleted foreign private data", err)
	}
}

func TestTorUsesOwnedDynamicAdapterInsteadOfFixedExitStore(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	profile := existingTorImportProfile("captured-tor")
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil || exit.Protocol != "tor-bridge" {
		t.Fatal("private Tor node no longer reaches its dedicated adapter", err)
	}
	if err := validateStandardExit(&exit); err == nil {
		t.Fatal("fixed-exit store unexpectedly admitted dynamic Tor proof")
	}
	raw, _ := json.Marshal(standardExitStore{SchemaVersion: standardExitStoreVersion, Exits: []standardExit{exit}})
	if err := atomicWritePrivate(standardExitStorePath(), raw); err != nil {
		t.Fatal(err)
	}
	if _, err := standardExitByID(exit.ID); err == nil {
		t.Fatal("a forged fixed-exit store made the dormant Tor branch reachable")
	}
	if command, err := nativeStandardExitCommand(&app{}, profile, common.RouterProfile{}, exit, true); command != nil || err == nil || !strings.Contains(err.Error(), "owned external connection adapter") {
		t.Fatal("generic builder discarded the required Tor workspace owner", err)
	}
	// These are the two shipping call sites. Both retain the prepared owner;
	// neither can reintroduce the old command-only adapter around our tested
	// cancellation/start-failure cleanup boundary.
	for _, caller := range []struct{ file, function, prepare string }{
		{"speed_lab_tor_path.go", "func (a *app) startPreparedSpeedLabTorPath", "prepared.prelaunch.start(current)"},
		{"tor_bridge_routes.go", "func (a *app) torBridgeConnectSelectionOwned", "prepareTorBridgeCommandWithRuntime(a, policy, profile, selection.predecessor, driver)"},
	} {
		source := sourceFunctionForTest(t, caller.file, caller.function)
		if !strings.Contains(source, caller.prepare) || !strings.Contains(source, "prelaunch.start(") {
			t.Fatal("shipping Tor caller dropped its prepared workspace owner", caller.file)
		}
	}
	preparation := sourceFunctionForTest(t, "speed_lab_tor_path.go", "func (a *app) prepareSpeedLabTorPathWithRuntime")
	if !strings.Contains(preparation, "prepareTorBridgeCommandWithRuntime(a, selection.policy, profile, selection.predecessor, driver)") {
		t.Fatal("Speed Lab lost exact predecessor preparation before stopping its previous runtime")
	}
}
