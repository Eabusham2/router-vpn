package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

const clientMeekBridge = "meek_lite 192.0.2.2:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://meek.example.net/ front=front.example.net"

func desktopTorPreparedFixture(t *testing.T, bridges ...string) (*app, torBridgeRuntime) {
	t.Helper()
	root := t.TempDir()
	profile := existingTorImportProfile("captured-tor")
	profile.External.TorBridge.Transport = "custom"
	profile.External.TorBridge.Bridges = append([]string(nil), bridges...)
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "tcp", "9.9.9.9", 5353
	profile.KillSwitch, profile.KillSwitchPolicy = false, "off"
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	tor := installFakeExecutable(t, t.TempDir(), "tor")
	native := installFakeExecutable(t, t.TempDir(), "sing-box-routervpn")
	prepared, err := stageDesktopTorInputs(root, profile, profile, tor, native)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Launch.tor.network = "captured-test-network"
	prepared.Launch.tor.networkIdentity = func() string { return "captured-test-network" }
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json")}, profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}}
	t.Cleanup(func() {
		if prepared.Launch.command != nil && prepared.Launch.command.Process != nil {
			_ = prepared.Launch.command.Process.Kill()
			<-desktopNodeProcessDone(prepared.Launch)
		}
		_ = prepared.Launch.directoryRoot.Close()
		desktopNodeOwners.Delete(a)
		activeDNSRuntimeIdentities.Delete(a)
	})
	return a, prepared
}

func desktopTorPreparedOwner(t *testing.T, a *app, prepared torBridgeRuntime) *torBridgePrelaunch {
	t.Helper()
	owner, err := captureTorBridgePrelaunch(a, prepared.Launch.profileID, prepared.RuntimeDir, prepared.Launch)
	if err != nil {
		t.Fatal(err)
	}
	if err := registerActiveDNSRuntimeConfig(a, prepared.Launch.profileID, "external-tor-bridge", filepath.Join(prepared.RuntimeDir, "sing-box.json")); err != nil {
		t.Fatal(err)
	}
	owner.command = exec.Command(filepath.Join(t.TempDir(), "not-a-runtime"))
	return owner
}

func TestDesktopTorStagingCapturesAllTransportFamiliesAndDisabledInputs(t *testing.T) {
	for _, bridges := range [][]string{{clientTorBridge}, {clientMeekBridge}, {clientSnowflakeBridge}, {clientWebTunnelBridge}, {clientTorBridge, clientMeekBridge, clientSnowflakeBridge, clientWebTunnelBridge}} {
		t.Run(strings.Fields(bridges[0])[0]+"-"+string(rune('0'+len(bridges))), func(t *testing.T) {
			a, prepared := desktopTorPreparedFixture(t, bridges...)
			launch := prepared.Launch
			profileRaw, err := readDesktopRuntimeFile(launch, "tor-profile.json", 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			captureRaw, err := readDesktopRuntimeFile(launch, "tor-capture.json", 16<<10)
			if err != nil {
				t.Fatal(err)
			}
			inputs, err := mobiletor.DecodeDesktopBridgeCapture(string(profileRaw), string(captureRaw), prepared.RuntimeDir)
			if err != nil || inputs.Digests() != launch.tor.digests || inputs.Policy().Metadata() != launch.tor.expected {
				t.Fatal("staged native inputs cannot reproduce their exact private capture", err)
			}
			if inputs.Capture().TorBinary != prepared.TorBinary || inputs.Capture().TargetOS != runtime.GOOS || len(inputs.Capture().SessionID) != 32 || len(inputs.Capture().IsolationSecret) != 64 {
				t.Fatal("standalone child, OS or fresh isolation identity was not captured")
			}
			for name, expected := range map[string]string{"torrc": inputs.Torrc(), "tor-defaults": "\n", "tor-profile.json": inputs.Policy().Profile(), "tor-capture.json": inputs.JSON(), "sing-box.json": inputs.Policy().Config()} {
				raw, err := readDesktopRuntimeFile(launch, name, 4<<20)
				if err != nil || string(raw) != expected || desktopTorDigest(raw) != launch.tor.inputs[name].digest {
					t.Fatal("captured input bytes changed", name, err)
				}
			}
			for _, required := range []string{"DisableNetwork 1\n", "SocksPort 0\n", "CookieAuthentication 1\n", "RunAsDaemon 0\n", "Log notice stdout\n"} {
				if !strings.Contains(inputs.Torrc(), required) {
					t.Fatal("standalone Tor could start outside authenticated native ownership", required)
				}
			}
			for _, unowned := range []string{"ClientTransportPlugin", "Bridge ", "tor.log", "exec "} {
				if strings.Contains(inputs.Torrc(), unowned) {
					t.Fatal("untrusted PT execution or data leaked into startup torrc", unowned)
				}
			}
			if launch.tor.expected.DNS.Address != "9.9.9.9" || launch.tor.expected.DNS.Port != 5353 || launch.tor.expected.DNS.Transport != "tcp" {
				t.Fatal("staging substituted the selected DNS")
			}
			if launch.tor.profileToken != desktopTorSourceIdentityToken(a.profiles.Profiles[0]) {
				t.Fatal("staging changed the stored private profile identity")
			}
			if err := desktopTorPreparedOwner(t, a, prepared).cleanup(); err != nil {
				t.Fatal("unstarted exact inputs did not retire", err)
			}
		})
	}
}

func TestDesktopTorEnvironmentReplacesAllStaleCapturesWithoutExportingSecrets(t *testing.T) {
	_, prepared := desktopTorPreparedFixture(t, clientTorBridge)
	launch := prepared.Launch
	base := []string{"PATH=/captured/bin", "HOMEVPN_TOR_SESSION=old", "homevpn_tor_source_sha256=old", "HOMEVPN_TOR_PLUGIN_TRANSPORTS=unowned", "HOMEVPN_TOR_PT_BINARY=/unowned/helper", "HOMEVPN_PROFILE_ID=wrong"}
	environment := desktopTorEnvironment(base, launch.root, launch.profileID, prepared.BridgeEndpoint, launch.tor.digests, launch.tor.expected.SessionID, prepared.TorSHA256)
	actual := map[string]string{}
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if !found || actual[strings.ToUpper(key)] != "" {
			t.Fatal("captured environment has an ambiguous key")
		}
		actual[strings.ToUpper(key)] = value
	}
	if actual["HOMEVPN_TOR_SESSION"] != launch.tor.expected.SessionID || actual["HOMEVPN_TOR_SOURCE_SHA256"] != launch.tor.digests.SourceSHA256 || actual["HOMEVPN_TOR_BINARY_SHA256"] != prepared.TorSHA256 || actual["HOMEVPN_PROFILE_ID"] != launch.profileID || actual["HOMEVPN_STANDARD_ENGINE"] != "native" || actual["PATH"] != "/captured/bin" {
		t.Fatal("native launch did not retain the exact environment capture")
	}
	for _, name := range []string{"HOMEVPN_TOR_PLUGIN_TRANSPORTS", "HOMEVPN_TOR_PT_BINARY"} {
		if _, exists := actual[name]; exists {
			t.Fatal("legacy executable override survived", name)
		}
	}
	raw, _ := readDesktopRuntimeFile(launch, "tor-capture.json", 16<<10)
	var capture mobiletor.DesktopBridgeCapture
	if json.Unmarshal(raw, &capture) != nil || strings.Contains(strings.Join(environment, "\n"), capture.IsolationSecret) {
		t.Fatal("private isolation secret entered the child environment")
	}
}

func TestDesktopTorPreflightChecksNativeCommandAndRetainsInputIdentity(t *testing.T) {
	for _, change := range []string{"none", "cancel-before", "cancel-during", "same-inode-contents", "replacement-input", "failed-command"} {
		t.Run(change, func(t *testing.T) {
			_, prepared := desktopTorPreparedFixture(t, clientTorBridge)
			launch := prepared.Launch
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if change == "cancel-before" {
				cancel()
			}
			var calls [][]string
			run := func(ctx context.Context, binary string, args, env []string, directory string) error {
				if binary != prepared.NativeBinary || directory != launch.directory || !reflect.DeepEqual(env, []string{"captured=environment"}) {
					t.Fatal("preflight used a mutable executable, environment or directory")
				}
				deadline, bounded := ctx.Deadline()
				if !bounded || time.Until(deadline) > 30*time.Second {
					t.Fatal("native utility lacks a bounded operation lifetime")
				}
				calls = append(calls, append([]string(nil), args...))
				if len(calls) == 1 {
					switch change {
					case "cancel-during":
						cancel()
					case "same-inode-contents", "replacement-input":
						path := filepath.Join(launch.directory, "torrc")
						if change == "replacement-input" {
							if err := os.Rename(path, path+"-captured"); err != nil {
								t.Fatal(err)
							}
						}
						if err := os.WriteFile(path, []byte("DisableNetwork 0\n"), 0600); err != nil {
							t.Fatal(err)
						}
					case "failed-command":
						return errors.New("native utility failed")
					}
				}
				return nil
			}
			err := preflightDesktopTorLaunch(ctx, prepared.NativeBinary, launch, []string{"captured=environment"}, run)
			if change == "none" {
				want := [][]string{{"routervpn-tor", "--help"}, {"check", "-D", launch.directory, "-c", filepath.Join(launch.directory, "sing-box.json")}}
				if err != nil || !reflect.DeepEqual(calls, want) {
					t.Fatal("preflight did not exercise both actual native commands", err, calls)
				}
			} else if err == nil {
				t.Fatal("changed or cancelled preparation passed", change)
			}
			if change == "cancel-before" && len(calls) != 0 {
				t.Fatal("cancelled operation invoked a utility")
			}
		})
	}
}

func TestDesktopTorPrelaunchKeepsBorrowedHandleOnRejectedCapture(t *testing.T) {
	a, prepared := desktopTorPreparedFixture(t, clientTorBridge)
	path := filepath.Join(prepared.RuntimeDir, "tor-defaults")
	original, err := os.ReadFile(path)
	if err != nil || os.Remove(path) != nil {
		t.Fatal("fixture could not remove one input", err)
	}
	if _, err := captureTorBridgePrelaunch(a, prepared.Launch.profileID, prepared.RuntimeDir, prepared.Launch); err == nil {
		t.Fatal("incomplete native capture was admitted")
	}
	if _, err := prepared.Launch.directoryRoot.Stat("."); err != nil {
		t.Fatal("rejected prelaunch closed its caller's retained cleanup handle", err)
	}
	delete(prepared.Launch.tor.inputs, "tor-defaults")
	if err := writeDesktopTorInput(prepared.Launch, "tor-defaults", original); err != nil {
		t.Fatal(err)
	}
	if err := cleanupDesktopTorLaunch(prepared.Launch); err != nil {
		t.Fatal("captured caller could not retry exact input cleanup", err)
	}
}

func TestDesktopTorPreparedStartRejectsStaleOwnersAndSameInodeChanges(t *testing.T) {
	for _, change := range []string{"cancel-first", "cancel-final", "network", "profile", "replacement-process", "replacement-owner", "input-contents", "exec-failure"} {
		t.Run(change, func(t *testing.T) {
			a, prepared := desktopTorPreparedFixture(t, clientTorBridge)
			owner := desktopTorPreparedOwner(t, a, prepared)
			replacement := &desktopNodeLaunch{profileID: "replacement"}
			var before []byte
			switch change {
			case "network":
				prepared.Launch.tor.networkIdentity = func() string { return "changed-network" }
			case "profile":
				a.profiles.Profiles[0].DNSHost = "8.8.8.8"
			case "replacement-process":
				a.cmd = exec.Command("replacement")
			case "replacement-owner":
				desktopNodeOwners.Store(a, replacement)
			case "input-contents":
				before = []byte("DisableNetwork 0\n")
				if err := os.WriteFile(filepath.Join(prepared.RuntimeDir, "torrc"), before, 0600); err != nil {
					t.Fatal(err)
				}
			}
			checks := 0
			err := owner.start(func() error {
				checks++
				if change == "cancel-first" || change == "cancel-final" && checks == 2 {
					return context.Canceled
				}
				return nil
			})
			if err == nil || owner.command.Process != nil {
				t.Fatal("stale private inputs reached a child", change, err)
			}
			if change == "cancel-final" && checks != 2 {
				t.Fatal("final cancellation did not exercise post-admission operation ownership")
			}
			current, exists := desktopNodeOwners.Load(a)
			if change == "replacement-owner" && (!exists || current != replacement) || change != "replacement-owner" && exists {
				t.Fatal("failed prelaunch retained itself or erased a replacement owner", change)
			}
			if change == "input-contents" {
				after, err := os.ReadFile(filepath.Join(prepared.RuntimeDir, "torrc"))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("cleanup erased modified private data", err)
				}
			} else if _, err := os.Stat(prepared.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unstarted captured inputs leaked", change, err)
			}
		})
	}
}

func TestDesktopTorPreparedRealChildTransfersToCheckedDrain(t *testing.T) {
	a, prepared := desktopTorPreparedFixture(t, clientTorBridge)
	owner := desktopTorPreparedOwner(t, a, prepared)
	expected, _ := json.Marshal(prepared.Launch.tor.expected)
	command := exec.Command(os.Args[0], "-test.run=^TestDesktopTorProcessFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_TOR_TEST_CHILD=proof", "ROUTERVPN_TOR_TEST_DIRECTORY="+prepared.RuntimeDir, "ROUTERVPN_TOR_TEST_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "GORACE=atexit_sleep_ms=0")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	owner.command = command
	if err := owner.start(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	a.cmd = command
	if _, err := prepared.Launch.directoryRoot.Stat("."); err != nil {
		t.Fatal("successful Start closed the native workspace owner", err)
	}
	if owner.cleanup() == nil || a.state.Connected {
		t.Fatal("process startup substituted for proof or allowed prelaunch cleanup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, prepared.Launch); err != nil {
		t.Fatal(err)
	}
	if err := requestDesktopTorStop(ctx, a, prepared.Launch, command); err != nil {
		t.Fatal(err)
	}
	if err := stopDesktopTorRuntime(a, prepared.Launch, command); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(prepared.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("proved and joined child retained its retired private workspace", err)
	}
}

func TestDesktopTorExecutableCaptureRejectsUnsafeInputs(t *testing.T) {
	file := installFakeExecutable(t, t.TempDir(), "tor")
	raw, _ := os.ReadFile(file)
	if digest, err := captureDesktopTorExecutable(file); err != nil || digest != desktopTorDigest(raw) {
		t.Fatal("standalone executable did not capture its actual bytes", err)
	}
	if err := os.WriteFile(file, []byte("changed executable bytes"), 0700); err != nil {
		t.Fatal(err)
	}
	if digest, err := captureDesktopTorExecutable(file); err != nil || digest == desktopTorDigest(raw) {
		t.Fatal("changed executable reused its old byte identity", err)
	}
	for _, path := range []string{filepath.Dir(file), filepath.Join(t.TempDir(), "absent"), "tor"} {
		if _, err := captureDesktopTorExecutable(path); err == nil {
			t.Fatal("noncaptured binary was admitted", path)
		}
	}
	if runtime.GOOS != "windows" {
		linked := filepath.Join(t.TempDir(), "tor-link")
		if err := os.Symlink(file, linked); err != nil {
			t.Fatal(err)
		}
		if _, err := captureDesktopTorExecutable(linked); err == nil {
			t.Fatal("linked binary was admitted after canonical capture")
		}
	}
}
