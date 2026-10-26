package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestTorBridgePrelaunchHistoricalMTUKeepsExactPolicyAndAdmissionGuards(t *testing.T) {
	for _, changed := range []string{"none", "derived-history", "bridge-key", "dns-policy", "manual-mtu", "protection", "network", "replacement-command", "final-cancel"} {
		t.Run(changed, func(t *testing.T) {
			profile, _ := desktopTorPolicyFixture(t, func(profile *common.RouterProfile) {
				profile.EffectiveMTU, profile.EffectiveMTUSource = 1350, "historical-fixture"
				profile.EffectiveMTUPathKey = strings.Repeat("a", 64)
			})
			root := t.TempDir()
			tor := installFakeExecutable(t, t.TempDir(), "tor")
			native := installFakeExecutable(t, t.TempDir(), "sing-box-routervpn")
			prepared, err := stageDesktopTorInputs(root, profile, profile, tor, native)
			if err != nil {
				t.Fatal(err)
			}
			launch := prepared.Launch
			launch.tor.network = "captured-test-network"
			launch.tor.networkIdentity = func() string { return "captured-test-network" }
			a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json")}, profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{common.CloneRouterProfile(profile)}}}
			owner := desktopTorPreparedOwner(t, a, prepared)
			owner.command = exec.Command(os.Args[0], "-test.run=^TestStartupExternalProcessFixture$")
			owner.command.Env = envWithValue(os.Environ(), "ROUTERVPN_STARTUP_EXTERNAL_CHILD", "cleanup")
			owner.command.Env = envWithValue(owner.command.Env, "GORACE", "atexit_sleep_ms=0")
			t.Cleanup(func() {
				if owner.command.Process != nil {
					_ = owner.command.Process.Kill()
					<-desktopNodeProcessDone(launch)
				}
				_ = launch.directoryRoot.Close()
				desktopNodeOwners.Delete(a)
				activeDNSRuntimeIdentities.Delete(a)
			})
			raw, err := readDesktopRuntimeFile(launch, "tor-profile.json", 4<<20)
			var captured common.RouterProfile
			if err != nil || json.Unmarshal(raw, &captured) != nil || captured.EffectiveMTU != 1350 ||
				launch.tor.profileToken != desktopTorSourceIdentityToken(captured) || launch.tor.profileToken == asyncMeasurementProfileToken(captured) {
				t.Fatal("prelaunch did not stage the actual profile with historical MTU", err)
			}
			switch changed {
			case "derived-history":
				a.profiles.Profiles[0].EffectiveMTU = 1380
				a.profiles.Profiles[0].EffectiveMTUSource = "measured-tor-system-tun-transfer"
			case "bridge-key":
				a.profiles.Profiles[0].External.TorBridge.Bridges[0] += " replacement-credential"
			case "dns-policy":
				a.profiles.Profiles[0].DNSPort++
			case "manual-mtu":
				a.profiles.Profiles[0].MTUPolicy, a.profiles.Profiles[0].ManualMTU = "manual", 1400
			case "protection":
				a.profiles.Profiles[0].KillSwitchPolicy += "-replacement"
			case "network":
				launch.tor.networkIdentity = func() string { return "replacement-network" }
			case "replacement-command":
				a.cmd = exec.Command("replacement")
			}
			previous := a.cmd
			checks := 0
			err = owner.start(func() error {
				checks++
				if changed == "final-cancel" && checks == 2 {
					return context.Canceled
				}
				return nil
			})
			if changed != "none" && changed != "derived-history" {
				if !errors.Is(err, errTorPrelaunchRejected) || owner.command.Process != nil || a.cmd != previous {
					t.Fatal("changed policy or stale admission reached the real child", changed, err)
				}
				if _, exists := desktopNodeOwners.Load(a); exists {
					t.Fatal("rejected prelaunch retained native admission")
				}
				return
			}
			if err != nil || checks != 2 || owner.command.Process == nil {
				t.Fatal("historical MTU rejected the unchanged captured Tor source before exec", err)
			}
			if current, exists := desktopNodeOwners.Load(a); !exists || current != launch {
				t.Fatal("prelaunch did not register the exact started child")
			}
			<-desktopNodeProcessDone(launch)
			if owner.command.ProcessState == nil || !owner.command.ProcessState.Success() {
				t.Fatal("captured prelaunch child did not execute and join successfully")
			}
		})
	}
}

func torPrelaunchFixture(t *testing.T) (*app, *torBridgePrelaunch) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	directory, err := newPrivateRuntimeDir(root, "tor-bridge")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, "tor-data"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"torrc": "ClientOnly 1\n", "sing-box.json": `{"dns":{"servers":[]}}`} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json")}}
	if err := registerActiveDNSRuntimeConfig(a, "captured-tor", "external-tor-bridge", filepath.Join(directory, "sing-box.json")); err != nil {
		t.Fatal(err)
	}
	owner, err := captureTorBridgePrelaunch(a, "captured-tor", directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.close)
	t.Cleanup(func() { activeDNSRuntimeIdentities.Delete(a) })
	return a, owner
}

func TestTorBridgePrelaunchCancellationAndStartFailureRetireOnlyPreparedInputs(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel-before-start", true: "failed-exec-start"}[failStart], func(t *testing.T) {
			a, owner := torPrelaunchFixture(t)
			owner.command = exec.Command(filepath.Join(t.TempDir(), "missing-runtime"))
			if failStart && owner.command.Start() == nil {
				t.Fatal("missing executable unexpectedly started")
			}
			if err := owner.cleanup(); err != nil {
				t.Fatal("unstarted Tor workspace was not retired", err)
			}
			if _, err := os.Stat(owner.workspace.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("Tor private inputs survived cancellation/start failure", err)
			}
			if _, exists := activeDNSRuntimeIdentities.Load(a); exists {
				t.Fatal("retired Tor input kept active DNS identity")
			}
			if err := owner.cleanup(); err != nil {
				t.Fatal("owned cleanup retry was not idempotent", err)
			}
		})
	}
}

func TestTorBridgePrelaunchRetainsReplacementDNSIdentity(t *testing.T) {
	a, owner := torPrelaunchFixture(t)
	replacement := activeDNSRuntimeIdentity{ProfileID: "replacement", RuntimeID: "external-hysteria2", Config: filepath.Join(t.TempDir(), "sing-box.json")}
	activeDNSRuntimeIdentities.Store(a, replacement)
	if err := owner.cleanup(); err != nil {
		t.Fatal(err)
	}
	if current, _ := activeDNSRuntimeIdentities.Load(a); current != replacement {
		t.Fatal("old Tor prelaunch cleanup cleared replacement DNS owner")
	}
}

func TestTorBridgePrelaunchRejectsReplacementWorkspaceAndInputs(t *testing.T) {
	for _, kind := range []string{"directory", "symlink", "file", "extra-file", "active-data"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "symlink" && runtime.GOOS == "windows" {
				t.Skip("Windows symlinks require the separate privileged link gate")
			}
			_, owner := torPrelaunchFixture(t)
			directory := owner.workspace.directory
			preserved := filepath.Join(directory, "torrc")
			switch kind {
			case "directory", "symlink":
				if err := os.Rename(directory, directory+"-original"); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					foreign := t.TempDir()
					if err := os.WriteFile(filepath.Join(foreign, "torrc"), []byte("foreign owner"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(foreign, directory); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(directory, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(preserved, []byte("foreign owner"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "file":
				if err := os.Rename(preserved, directory+"-original-torrc"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(preserved, []byte("foreign owner"), 0600); err != nil {
					t.Fatal(err)
				}
			case "extra-file":
				preserved = filepath.Join(directory, "foreign.txt")
				if err := os.WriteFile(preserved, []byte("foreign owner"), 0600); err != nil {
					t.Fatal(err)
				}
			case "active-data":
				preserved = filepath.Join(directory, "tor-data", "state")
				if err := os.WriteFile(preserved, []byte("native Tor state"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(preserved)
			if err != nil {
				t.Fatal(err)
			}
			if err := owner.cleanup(); err == nil {
				t.Fatal("unowned Tor workspace was retired", kind)
			}
			after, err := os.ReadFile(preserved)
			if err != nil || string(after) != string(before) {
				t.Fatal("prelaunch cleanup erased another owner's data", kind, err)
			}
		})
	}
}

func TestTorBridgePrelaunchCannotDeleteStartedChildWorkspace(t *testing.T) {
	_, owner := torPrelaunchFixture(t)
	command := exec.Command(os.Args[0], "-test.run=^TestStartupExternalProcessFixture$")
	command.Env = envWithValue(os.Environ(), "ROUTERVPN_STARTUP_EXTERNAL_CHILD", "cleanup")
	owner.command = command
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Wait()
	if err := owner.cleanup(); err == nil {
		t.Fatal("prelaunch cleanup took ownership from a started native process")
	}
	if _, err := os.Stat(filepath.Join(owner.workspace.directory, "torrc")); err != nil {
		t.Fatal("started child lost private inputs", err)
	}
}
