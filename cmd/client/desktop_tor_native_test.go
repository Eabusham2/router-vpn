package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

func desktopTorPolicyFixture(t *testing.T, changes ...func(*common.RouterProfile)) (common.RouterProfile, *mobiletor.DesktopBridgeInputs) {
	t.Helper()
	profile := existingTorImportProfile("captured-tor")
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "tcp", "9.9.9.9", 5353
	for _, change := range changes {
		change(&profile)
	}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	inputs, err := mobiletor.NewDesktopBridgeCapture(string(raw), strings.Repeat("a", 32), strings.Repeat("b", 64), runtime.GOOS, filepath.Join(root, "tor"), filepath.Join(root, "runtime"))
	if err != nil {
		t.Fatal(err)
	}
	return profile, inputs
}

func desktopTorFixtureProof(expected mobiletor.DesktopBridgeMetadata, now time.Time) desktopTorProof {
	name := expected.InterfaceName
	if name == "" {
		name = "utun9"
	}
	proof := desktopTorProof{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, Policy: expected,
		Proof:         mobiletor.Proof{SessionID: expected.SessionID, IP: "203.0.113.8", IsTor: true, DNSProven: true, CheckedAt: now.UTC()},
		InterfaceName: name, InterfaceIndex: 99, EffectiveMTU: expected.ConfiguredMTU, Healthy: true, HeartbeatAt: now.UnixMilli()}
	if expected.EntryID != "" {
		proof.EntryProof = &mobiletor.DesktopBridgeEntryProof{EntryID: expected.EntryID, EntrySHA256: expected.EntrySHA256, EntryKind: expected.EntryProofKind, CheckedAt: now.UTC()}
	}
	return proof
}

func TestDesktopTorProofBindsPolicyDNSReadbackAndEverySession(t *testing.T) {
	_, inputs := desktopTorPolicyFixture(t)
	now := time.Now()
	owner := &desktopTorRuntime{expected: inputs.Policy().Metadata(), started: now}
	valid := desktopTorFixtureProof(owner.expected, now)
	bytes, _ := json.Marshal(valid)
	if _, err := validateDesktopTorProof(bytes, owner, now); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"schema", "session", "source", "config", "node", "resolver", "transport", "port", "sni", "path", "lan", "ipv6", "kill", "mtu-policy", "configured-mtu", "proof-session", "ip", "private-ip", "multicast-ip", "dns", "tor", "checked-past", "checked-future", "heartbeat-past", "heartbeat-future", "heartbeat-before-proof", "interface", "index", "readback", "health"} {
		t.Run(kind, func(t *testing.T) {
			proof := valid
			switch kind {
			case "schema":
				proof.Schema = 2
			case "session":
				proof.SessionID = "different"
			case "source":
				proof.SourceSHA256 = strings.Repeat("0", 64)
			case "config":
				proof.ConfigSHA256 = strings.Repeat("0", 64)
			case "node":
				proof.Policy.NodeID = "another-node"
			case "resolver":
				proof.Policy.DNS.Address = "1.1.1.1"
			case "transport":
				proof.Policy.DNS.Transport = "udp"
			case "port":
				proof.Policy.DNS.Port = 53
			case "sni":
				proof.Policy.DNS.ServerName = "another.example"
			case "path":
				proof.Policy.DNS.Path = "/other"
			case "lan":
				proof.Policy.HomeLANAccess = !proof.Policy.HomeLANAccess
			case "ipv6":
				proof.Policy.IPv6Mode = "off"
			case "kill":
				proof.Policy.KillSwitchPolicy = "off"
			case "mtu-policy":
				proof.Policy.MTUPolicy = "manual"
			case "configured-mtu":
				proof.Policy.ConfiguredMTU++
			case "proof-session":
				proof.Proof.SessionID = "different"
			case "ip":
				proof.Proof.IP = "not-an-ip"
			case "private-ip":
				proof.Proof.IP = "192.168.50.133"
			case "multicast-ip":
				proof.Proof.IP = "224.0.0.1"
			case "dns":
				proof.Proof.DNSProven = false
			case "tor":
				proof.Proof.IsTor = false
			case "checked-past":
				proof.Proof.CheckedAt = now.Add(-3 * time.Second)
			case "checked-future":
				proof.Proof.CheckedAt = now.Add(3 * time.Second)
			case "heartbeat-past":
				proof.HeartbeatAt = now.Add(-mobiletor.DesktopBridgeHeartbeatMaxAge - time.Second).UnixMilli()
			case "heartbeat-future":
				proof.HeartbeatAt = now.Add(5 * time.Second).UnixMilli()
			case "heartbeat-before-proof":
				proof.HeartbeatAt = now.Add(-time.Second).UnixMilli()
			case "interface":
				proof.InterfaceName = "invalid\nowner"
			case "index":
				proof.InterfaceIndex = 0
			case "readback":
				proof.EffectiveMTU++
			case "health":
				proof.Healthy = false
			}
			raw, _ := json.Marshal(proof)
			if _, err := validateDesktopTorProof(raw, owner, now); err == nil {
				t.Fatal("unowned proof accepted", kind)
			}
		})
	}
	for _, raw := range []string{string(bytes) + "{}", `{"schema":1,"schema":1}`, strings.Replace(string(bytes), `"schema":1`, `"schema":1,"unknown":true`, 1), `null`, strings.Repeat(" ", 64<<10) + string(bytes)} {
		if _, err := validateDesktopTorProof([]byte(raw), owner, now); err == nil {
			t.Fatal("ambiguous or oversized proof admitted")
		}
	}
	owner.adopted = &valid
	for _, kind := range []string{"ip", "time", "interface", "index"} {
		proof := valid
		switch kind {
		case "ip":
			proof.Proof.IP = "203.0.113.9"
		case "time":
			proof.Proof.CheckedAt = now.Add(time.Millisecond)
			proof.HeartbeatAt = proof.Proof.CheckedAt.UnixMilli()
		case "interface":
			proof.InterfaceName = "utun10"
		case "index":
			proof.InterfaceIndex++
		}
		raw, _ := json.Marshal(proof)
		if _, err := validateDesktopTorProof(raw, owner, now); err == nil {
			t.Fatal("retained proof silently acquired a replacement", kind)
		}
	}
}

// This child is a private IPC peer. It neither creates a TUN nor claims real
// Tor traffic; the real native engine has independent transport/path tests.
func TestDesktopTorProcessFixture(t *testing.T) {
	kind := os.Getenv("ROUTERVPN_TOR_TEST_CHILD")
	if kind == "" {
		return
	}
	directory := os.Getenv("ROUTERVPN_TOR_TEST_DIRECTORY")
	raw, _ := base64.StdEncoding.DecodeString(os.Getenv("ROUTERVPN_TOR_TEST_EXPECTED"))
	var expected mobiletor.DesktopBridgeMetadata
	if json.Unmarshal(raw, &expected) != nil {
		os.Exit(91)
	}
	publisher, err := newDesktopNativeFixturePublisher(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.root.Close()
	write := func(name string, value any) {
		raw, _ := json.Marshal(value)
		if err := publisher.publish(name, raw); err != nil {
			fmt.Fprintf(os.Stderr, "isolated Tor fixture publication %s: %v\n", name, err)
			os.Exit(92)
		}
	}
	if desktopTorPrelaunchFailureChild(kind, directory, expected, write) {
		return
	}
	checked := time.Now()
	proof := desktopTorFixtureProof(expected, checked)
	write("progress.json", desktopTorProgress{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, Stage: "proving"})
	dnsTick := desktopTorDNSChildFixture(kind, directory, expected, write)
	mtuTick := desktopTorMTUChildFixture(kind, directory, expected, &proof, write)
	pathTick := desktopTorPathChildFixture(kind, directory, expected, write)
	comparisonTick := desktopTorComparisonChildFixture(kind, publisher.root, expected, write)
	for {
		desktopTorFixturePublicationBarrier(kind, expected)
		dnsTick()
		mtuTick()
		pathTick()
		comparisonTick()
		proof.HeartbeatAt = time.Now().UnixMilli()
		write("proof.json", proof)
		raw, err := os.ReadFile(filepath.Join(directory, "stop.json"))
		if err == nil && desktopTorFixtureStopRequested(raw, expected.SessionID, expected.SourceSHA256) {
			if kind == "without-receipt" {
				return
			}
			if kind == "wrong-receipt" {
				expected.SessionID = "replacement"
			}
			write("stopped.json", desktopExternalStop{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, Closed: true})
			if kind == "receipt-before-exit" {
				for {
					if _, err := os.Stat(os.Getenv("ROUTERVPN_TOR_TEST_RELEASE")); err == nil {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func desktopTorRunningFixture(t *testing.T, kind string, changes ...func(*common.RouterProfile)) (*app, *desktopNodeLaunch, string) {
	t.Helper()
	profile, inputs := desktopTorPolicyFixture(t, changes...)
	directory := inputs.RuntimeDir()
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	launch := &desktopNodeLaunch{profileID: profile.ID, mode: "external-tor-bridge", tor: &desktopTorRuntime{expected: inputs.Policy().Metadata(), digests: inputs.Digests(), profileToken: desktopTorSourceIdentityToken(profile), network: "fixture-network", networkIdentity: func() string { return "fixture-network" }, inputs: map[string]desktopTorInput{}}}
	if err := captureDesktopRuntimeDirectory(launch, directory); err != nil {
		t.Fatal(err)
	}
	if err := launch.directoryRoot.Mkdir("tor-data", 0700); err != nil {
		t.Fatal(err)
	}
	launch.tor.dataInfo, _ = launch.directoryRoot.Lstat("tor-data")
	for name, contents := range map[string]string{"torrc": inputs.Torrc(), "tor-defaults": inputs.Defaults(), "tor-profile.json": inputs.Policy().Profile(), "tor-capture.json": inputs.JSON(), "sing-box.json": inputs.Policy().Config()} {
		if err := writeDesktopRuntimeFile(launch, name, []byte(contents), false); err != nil {
			t.Fatal(err)
		}
		info, _ := launch.directoryRoot.Lstat(name)
		launch.tor.inputs[name] = desktopTorInput{info: info, digest: desktopTorDigest([]byte(contents))}
	}
	release := filepath.Join(t.TempDir(), "release-child")
	expected, _ := json.Marshal(launch.tor.expected)
	command := exec.Command(os.Args[0], "-test.run=^TestDesktopTorProcessFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_TOR_TEST_CHILD="+kind, "ROUTERVPN_TOR_TEST_DIRECTORY="+directory, "ROUTERVPN_TOR_TEST_EXPECTED="+base64.StdEncoding.EncodeToString(expected), "ROUTERVPN_TOR_TEST_RELEASE="+release, "GORACE=atexit_sleep_ms=0")
	var childOutput desktopTorFixtureOutput
	command.Stdout, command.Stderr = io.Discard, &childOutput
	launch.command = command
	launch.tor.started = time.Now()
	a := &app{profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}, state: state{Mode: "external-node", RuntimeMode: launch.mode, RouterID: profile.ID}}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	a.cmd = command
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() {
		if t.Failed() && strings.HasPrefix(kind, "tor-dns-") {
			record, err := readDesktopDNSDrainRecord(launch)
			t.Logf("isolated Tor DNS mailbox before fixture cleanup: generation=%d request=%q status=%+v error=%v", record.Generation, record.Request, record.Status, err)
		}
		_ = command.Process.Kill()
		<-desktopNodeProcessDone(launch)
		if t.Failed() {
			t.Logf("isolated Tor fixture process status: %v; stderr:\n%s", command.ProcessState, childOutput.String())
		}
		desktopNodeOwners.Delete(a)
		_ = launch.directoryRoot.Close()
	})
	return a, launch, release
}

func TestDesktopTorActualChildProofAndCheckedDrain(t *testing.T) {
	a, launch, _ := desktopTorRunningFixture(t, "proof")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proof, err := a.waitDesktopTorProof(ctx, launch)
	if err != nil || proof.Proof.IP != "203.0.113.8" {
		t.Fatal("actual child proof not retained", err)
	}
	if a.state.Connected {
		t.Fatal("receipt alone mutated Connected")
	}
	if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
		t.Fatal(err)
	}
	if !desktopNodeProcessExited(launch) {
		t.Fatal("drain returned before joining child")
	}
	if err := stopDesktopTorRuntime(a, launch, launch.command); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(launch.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("checked private workspace survived drain", err)
	}
	if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
		t.Fatal("checked cleanup retry lost owner", err)
	}
}

func TestDesktopTorReceiptCannotReplaceProcessJoin(t *testing.T) {
	a, launch, release := desktopTorRunningFixture(t, "receipt-before-exit")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: launch.tor.expected.SessionID, SourceSHA256: launch.tor.expected.SourceSHA256})
	if err := writeDesktopRuntimeFile(launch, "stop.json", request, false); err != nil {
		t.Fatal(err)
	}
	// Observe the actual early acknowledgement before starting the short
	// pending-close deadline; runner scheduling cannot turn this into a test
	// that timed out before the child reached the intended boundary.
	for {
		closed, err := desktopTorStopped(launch)
		if err != nil {
			t.Fatal(err)
		}
		if closed {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture did not publish its early receipt", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	pending, cancelPending := context.WithTimeout(ctx, 250*time.Millisecond)
	err := requestDesktopTorStop(pending, a, launch, launch.command)
	cancelPending()
	if !errors.Is(err, context.DeadlineExceeded) || desktopNodeProcessExited(launch) {
		t.Fatal("early receipt replaced actual process join", err)
	}
	if err := stopDesktopTorRuntime(a, launch, launch.command); err == nil {
		t.Fatal("pending child workspace deleted")
	}
	if err := os.WriteFile(release, []byte("exit now"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
		t.Fatal("real exit did not finish retained drain", err)
	}
}

func TestDesktopTorWrongOrAbsentReceiptRetainsPrivateOwner(t *testing.T) {
	for _, kind := range []string{"wrong-receipt", "without-receipt"} {
		t.Run(kind, func(t *testing.T) {
			a, launch, _ := desktopTorRunningFixture(t, kind)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
				t.Fatal(err)
			}
			if err := requestDesktopTorStop(ctx, a, launch, launch.command); err == nil {
				t.Fatal("unproved drain accepted")
			}
			if err := stopDesktopTorRuntime(a, launch, launch.command); err == nil {
				t.Fatal("unproved process exit released private inputs")
			}
			if _, err := os.Stat(filepath.Join(launch.directory, "tor-capture.json")); err != nil {
				t.Fatal("unproved drain erased inputs", err)
			}
		})
	}
}

func TestDesktopTorRetiredNetworkProfileAndProcessCannotAdopt(t *testing.T) {
	for _, kind := range []string{"network", "profile", "command", "map", "directory", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			fixtureKind := "proof"
			if kind == "directory" {
				fixtureKind = "proof-directory-retire"
			}
			a, launch, control := desktopTorRunningFixture(t, fixtureKind)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "network":
				launch.tor.network = "previous-network"
			case "profile":
				a.mu.Lock()
				a.profiles.Profiles[0].External.TorBridge.Bridges = []string{torImportSnowflakeBridge}
				a.mu.Unlock()
			case "command":
				a.mu.Lock()
				a.cmd = exec.Command("replacement")
				a.mu.Unlock()
			case "map":
				desktopNodeOwners.Store(a, &desktopNodeLaunch{})
			case "directory":
				pauseDesktopTorFixturePublications(t, ctx, launch, control)
				if err := os.Rename(launch.directory, launch.directory+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(launch.directory, 0700); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			if _, err := a.waitDesktopTorProof(ctx, launch); err == nil {
				t.Fatal("retired Tor capture admitted", kind)
			}
			if kind == "command" || kind == "map" {
				if err := requestDesktopTorStop(ctx, a, launch, launch.command); err == nil {
					t.Fatal("old close admitted replacement")
				}
				if _, err := os.Stat(filepath.Join(launch.directory, "stop.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("replacement received stale stop")
				}
			}
		})
	}
}

func TestDesktopTorCheckedCleanupRetainsUnknownChangedAndLinkedFiles(t *testing.T) {
	for _, kind := range []string{"unknown", "changed", "replacement", "data", "data-replaced", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "symlink" && runtime.GOOS == "windows" {
				t.Skip("privileged Windows link gate is separate")
			}
			a, launch, _ := desktopTorRunningFixture(t, "proof")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
				t.Fatal(err)
			}
			if err := requestDesktopTorStop(ctx, a, launch, launch.command); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(launch.directory, "torrc")
			switch kind {
			case "unknown":
				name = filepath.Join(launch.directory, "another-owner.json")
			case "replacement":
				if err := os.Rename(name, name+".previous"); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(name + ".previous"); err != nil {
					t.Fatal(err)
				}
			case "data":
				name = filepath.Join(launch.directory, "tor-data", "state")
			case "data-replaced":
				dir := filepath.Join(launch.directory, "tor-data")
				if err := os.Rename(dir, dir+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				name = filepath.Join(dir, "state")
			case "symlink":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				foreign := filepath.Join(t.TempDir(), "foreign")
				if err := os.WriteFile(foreign, []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(foreign, name); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "symlink" {
				if err := os.WriteFile(name, []byte("retained foreign data"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := stopDesktopTorRuntime(a, launch, launch.command); err == nil {
				t.Fatal("foreign state deleted", kind)
			}
			after, err := os.ReadFile(name)
			if err != nil || string(before) != string(after) {
				t.Fatal("failed cleanup erased another owner", kind, err)
			}
		})
	}
}
