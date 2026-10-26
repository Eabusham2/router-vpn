package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/mobiletor"
)

func desktopTorEntryFixture(t *testing.T, host string) (*app, common.RouterProfile, map[string][]byte) {
	t.Helper()
	t.Setenv("HOMEVPN_ROOT", "")
	root := t.TempDir()
	entry, files := desktopNodeFixture(t, host)
	profile := existingTorImportProfile("captured-tor")
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "tcp", "9.9.9.9", 5353
	profile.KillSwitch, profile.KillSwitchPolicy = false, "off"
	profile.HomeLANAccess = false
	profile.MultihopEnabled, profile.MultihopEntryID, profile.MultihopExitID = true, entry.ID, profile.ID
	profile.MultihopEntryMode, profile.MultihopExecution = "wg", "local"
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "generated", entry.ID, "wg")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "profiles.json")}, profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile, entry}}}
	return a, profile, files
}

func TestDesktopTorPredecessorCapturesOriginalAssetsAndLiteralLaunchCopy(t *testing.T) {
	a, profile, files := desktopTorEntryFixture(t, "entry.example.test")
	before := cloneRouterProfileStore(a.profiles)
	original := string(files["wg.conf"])
	lookups := 0
	captured, err := captureDesktopTorPredecessor(a, profile, func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups++
		if host != "entry.example.test" {
			t.Fatal("looked up another node", host)
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 1 || captured.entry.Endpoint != "entry.example.test" || captured.endpoint != "198.51.100.8" || captured.native.ID() != captured.entry.ID || captured.native.Mode() != "wg" || !strings.Contains(captured.native.Profile(), `"endpoint":"198.51.100.8"`) || !strings.Contains(captured.native.Config(), `"address":"198.51.100.8"`) {
		t.Fatal("entry capture changed original identity or lost its literal endpoint")
	}
	expected, err := startupExternalSourceToken(a, captured.entry, "wg")
	if err != nil || expected != captured.assetsSHA256 || expected != captured.native.AssetsSHA256() || string(files["wg.conf"]) != original || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("entry capture rewrote the original profile or source", err)
	}
	if err := captured.current(a); err != nil {
		t.Fatal(err)
	}
	// Derived path history and display selection are not source ownership.
	a.profiles.SelectedID = captured.entry.ID
	a.profiles.Profiles[1].EffectiveMTU = 1400
	if err := captured.current(a); err != nil {
		t.Fatal("a derived measurement or selection retired the captured entry", err)
	}
	a.profiles.Profiles[1].APIToken = "replacement-private-token"
	if captured.current(a) == nil {
		t.Fatal("replacement Router credentials acquired the retained Tor entry")
	}
}

func TestDesktopTorPredecessorRejectsRelinkCancellationAndUnownedSelection(t *testing.T) {
	for _, fault := range []string{"server", "compare", "missing-entry", "same-node", "wrong-exit", "external-entry", "changed-source", "changed-profile", "cancelled", "invalid-source"} {
		t.Run(fault, func(t *testing.T) {
			a, profile, files := desktopTorEntryFixture(t, "entry.example.test")
			path := filepath.Join(clientRoot(a), "generated", "captured", "wg", "wg.conf")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.connectionContext = ctx
			calls := 0
			switch fault {
			case "server":
				profile.MultihopExecution = "server"
			case "compare":
				profile.MultihopExecution = "auto"
			case "missing-entry":
				profile.MultihopEntryID = "missing"
			case "same-node":
				profile.MultihopEntryID = profile.ID
			case "wrong-exit":
				profile.MultihopExitID = "another-exit"
			case "external-entry":
				a.profiles.Profiles[1].NodeKind = "external"
			case "invalid-source":
				if err := os.WriteFile(path, []byte("[Interface]\nPrivateKey=invalid\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			captured, err := captureDesktopTorPredecessor(a, profile, func(context.Context, string) ([]netip.Addr, error) {
				calls++
				switch fault {
				case "changed-source":
					if err := os.WriteFile(path, append(files["wg.conf"], []byte("\n# relinked source\n")...), 0600); err != nil {
						t.Fatal(err)
					}
				case "changed-profile":
					a.profiles.Profiles[1].APIToken = "replacement-token"
				case "cancelled":
					cancel()
				}
				return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
			})
			if err == nil || captured != nil {
				t.Fatal("unowned entry was retained", fault)
			}
			if fault != "changed-source" && fault != "changed-profile" && fault != "cancelled" && calls != 0 {
				t.Fatal("invalid selection reached bootstrap", calls)
			}
		})
	}
}

func TestDesktopTorPredecessorStagingAndProofRetainBothIdentities(t *testing.T) {
	a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
	captured, err := captureDesktopTorPredecessor(a, profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	tor := installFakeExecutable(t, t.TempDir(), "tor")
	native := installFakeExecutable(t, t.TempDir(), "sing-box-routervpn")
	prepared, err := stageDesktopTorInputsWithPredecessor(clientRoot(a), profile, profile, tor, native, captured)
	if err != nil {
		t.Fatal(err)
	}
	launch := prepared.Launch
	t.Cleanup(func() { _ = launch.directoryRoot.Close() })
	if launch.profileID != profile.ID || launch.endpoint != captured.endpoint || launch.tor.profileToken != desktopTorSourceIdentityToken(profile) || launch.tor.predecessor != captured || launch.tor.expected.HomeLANAccess {
		t.Fatal("staging substituted entry and exit controller identities")
	}
	profileRaw, err := readDesktopRuntimeFile(launch, "tor-profile.json", desktopTorInputLimit("tor-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var physical struct {
		Egress []mobilemultihop.PhysicalEgress `json:"desktop_physical_egress"`
	}
	if err := json.Unmarshal(profileRaw, &physical); err != nil {
		t.Fatal(err)
	}
	expectedEgress, err := mobilemultihop.NodePhysicalEgress(captured.mode, captured.native.Profile(), captured.native.Config())
	if err != nil || len(physical.Egress) == 0 || !reflect.DeepEqual(physical.Egress, expectedEgress) {
		t.Fatal("staging lost the exact physical graph projection", err)
	}
	saved, err := json.Marshal(profile)
	if err != nil || strings.Contains(string(saved), "desktop_physical_egress") {
		t.Fatal("runtime physical projection entered the durable private node schema", err)
	}
	captureRaw, err := readDesktopRuntimeFile(launch, "tor-capture.json", desktopTorInputLimit("tor-capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := mobiletor.DecodeDesktopBridgeCapture(string(profileRaw), string(captureRaw), launch.directory)
	if err != nil || decoded.Digests() != launch.tor.digests || decoded.Policy().Metadata() != launch.tor.expected || decoded.Policy().Predecessor().AssetsSHA256() != captured.assetsSHA256 {
		t.Fatal("native process cannot reconstruct the complete immutable entry", err)
	}
	now := time.Now().UTC()
	launch.tor.started = now
	valid := desktopTorFixtureProof(launch.tor.expected, now)
	valid.EntryProof = &mobiletor.DesktopBridgeEntryProof{EntryID: captured.entry.ID, EntrySHA256: captured.native.Proof().Fingerprint(), CheckedAt: now}
	raw, _ := json.Marshal(valid)
	if _, err := validateDesktopTorProof(raw, launch.tor, now); err != nil {
		t.Fatal("captured private entry plus Tor exit proof was rejected", err)
	}
	for _, fault := range []string{"absent", "other-node", "other-source", "stale", "future", "replacement-proof"} {
		proof := valid
		copy := *valid.EntryProof
		proof.EntryProof = &copy
		switch fault {
		case "absent":
			proof.EntryProof = nil
		case "other-node":
			copy.EntryID = "different-entry"
		case "other-source":
			copy.EntrySHA256 = strings.Repeat("a", 64)
		case "stale":
			copy.CheckedAt = now.Add(-2 * time.Second)
		case "future":
			copy.CheckedAt = now.Add(2 * time.Second)
		case "replacement-proof":
			launch.tor.adopted = &valid
			copy.CheckedAt = now.Add(time.Millisecond)
		}
		raw, _ := json.Marshal(proof)
		if _, err := validateDesktopTorProof(raw, launch.tor, now); err == nil {
			t.Fatal("unowned entry proof was accepted", fault)
		}
	}
	launch.tor.adopted = nil
	owner := desktopTorPreparedOwner(t, a, prepared)
	launch.tor.network, launch.tor.networkIdentity = "entry-test-network", func() string { return "entry-test-network" }
	calls := 0
	err = owner.start(func() error {
		calls++
		if calls == 2 {
			a.profiles.Profiles[1].APIToken = "changed-after-registration"
		}
		return nil
	})
	if !errors.Is(err, errTorPrelaunchRejected) || calls != 2 || owner.command.Process != nil {
		t.Fatal("changed entry reached child admission", calls, err)
	}
	if _, found := desktopNodeOwners.Load(a); found {
		t.Fatal("unstarted rejected entry retained a native owner")
	}
	if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unstarted exact entry workspace was not cleaned", err)
	}
}

// This child exercises the controller's private protocol and owner checks.
// The separately prepared native suite exercises actual entry encryption/PT.
func desktopTorRunningEntryFixture(t *testing.T, kind string, changes ...func(*common.RouterProfile, *common.RouterProfile)) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
	for _, change := range changes {
		change(&profile, &a.profiles.Profiles[1])
	}
	a.profiles.Profiles[0] = profile
	captured, err := captureDesktopTorPredecessor(a, profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := stageDesktopTorInputsWithPredecessor(clientRoot(a), profile, profile, installFakeExecutable(t, t.TempDir(), "tor"), installFakeExecutable(t, t.TempDir(), "native"), captured)
	if err != nil {
		t.Fatal(err)
	}
	launch := prepared.Launch
	launch.tor.network, launch.tor.networkIdentity = "entry-test-network", func() string { return "entry-test-network" }
	owner := desktopTorPreparedOwner(t, a, prepared)
	expected, _ := json.Marshal(launch.tor.expected)
	command := exec.Command(os.Args[0], "-test.run=^TestDesktopTorProcessFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_TOR_TEST_CHILD="+kind, "ROUTERVPN_TOR_TEST_DIRECTORY="+launch.directory,
		"ROUTERVPN_TOR_TEST_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "ROUTERVPN_TOR_TEST_RELEASE="+filepath.Join(t.TempDir(), "release"), "GORACE=atexit_sleep_ms=0")
	var output desktopTorFixtureOutput
	command.Stderr = &output
	owner.command = command
	if err := owner.start(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	a.cmd = command
	a.state.RouterID, a.state.Mode, a.state.RuntimeMode = profile.ID, "external-node", "external-tor-bridge"
	t.Cleanup(func() {
		_ = command.Process.Kill()
		<-desktopNodeProcessDone(launch)
		if t.Failed() {
			t.Log(output.String())
		}
		desktopNodeOwners.CompareAndDelete(a, launch)
		activeDNSRuntimeIdentities.Delete(a)
		_ = launch.directoryRoot.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal("entry controller could not retain its child receipt", err)
	}
	return a, launch
}

func TestDesktopTorPredecessorCurrentReceiptRejectsSourceReplacement(t *testing.T) {
	for _, fault := range []string{"credentials", "mode-source", "missing-source", "removed-owner", "wrong-owner", "entry-policy"} {
		t.Run(fault, func(t *testing.T) {
			a, launch := desktopTorRunningEntryFixture(t, "proof")
			path := filepath.Join(clientRoot(a), "generated", "captured", "wg", "wg.conf")
			switch fault {
			case "credentials":
				a.profiles.Profiles[1].APIToken = "replacement"
			case "mode-source":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, []byte("\n# replaced\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-source":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "removed-owner":
				launch.tor.predecessor = nil
			case "wrong-owner":
				launch.tor.predecessor.mode = "awg2-fast"
			case "entry-policy":
				a.profiles.Profiles[1].DNSMode = "rescue"
			}
			if _, err := a.readDesktopTorProof(launch); err == nil {
				t.Fatal("stale Router-entry source accepted a current Tor receipt", fault)
			}
		})
	}
}
