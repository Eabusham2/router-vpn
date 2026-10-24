package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
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
	"router-vpn/internal/routechoice"
)

func desktopExternalNativeFixture(t *testing.T, protocol string) (common.RouterProfile, standardExit) {
	t.Helper()
	var profile common.RouterProfile
	var err error
	if protocol == "amneziawg" {
		profile = desktopAWGProfile(t)
		profile.External.AmneziaWG.PrivateKey = testWGKey('a')
	} else {
		exit := validTestStandardExit(protocol)
		if protocol == "wireguard" {
			exit.WGAddresses = []string{"10.50.0.2/32", "fd50::2/128"}
		}
		if protocol == "shadowsocks" {
			exit.Secret = testWGKey('s')
		}
		profile, err = desktopExternalCapture(common.RouterProfile{DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "203.0.113.53", DNSPort: 5353, IPv6Mode: "off", HomeLANAccess: false, MTUPolicy: "auto", EffectiveMTU: 9000}, exit)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	return profile, exit
}

func TestDesktopExternalCapturedHostnameKeepsProtocolTLSAndDNS(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"} {
		t.Run(protocol, func(t *testing.T) {
			profile, exit := desktopExternalNativeFixture(t, protocol)
			exit.Server = "node.example.test"
			profile, err := desktopExternalCapture(profile, exit)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(profile)
			calls := 0
			lookup := func(ctx context.Context, host string) ([]netip.Addr, error) {
				calls++
				if host != "node.example.test" || ctx.Err() != nil {
					t.Fatal("unowned bootstrap", host)
				}
				return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("198.51.100.31")}, nil
			}
			launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, lookup)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(profile)
			if calls != 1 || !bytes.Equal(before, after) || launch.endpoint != "198.51.100.31" || launch.external.profile.Endpoint != launch.endpoint {
				t.Fatal("bootstrap mutated saved identity or reused an unbound hostname")
			}
			if !bytes.Contains(launch.config, []byte(profile.DNSHost)) || !bytes.Contains(launch.config, []byte(`"server_port":5353`)) && protocol != "amneziawg" {
				t.Fatal("selected DNS policy was substituted")
			}
			if exit.TLSServerName != "" && !bytes.Contains(launch.config, []byte(exit.TLSServerName)) {
				t.Fatal("bootstrap changed TLS identity")
			}
			for _, address := range []string{"127.0.0.1", "192.168.50.1", "100.64.0.1", "::ffff:198.51.100.9", "ff02::1"} {
				if _, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr(address)}, nil
				}); err == nil {
					t.Fatal("unsafe bootstrap accepted", address)
				}
			}
			cancelled, cancel := context.WithCancel(context.Background())
			if _, err := compileDesktopExternalCaptured(cancelled, profile, common.RouterProfile{}, exit, true, "", nil, nil, func(context.Context, string) ([]netip.Addr, error) {
				cancel()
				return []netip.Addr{netip.MustParseAddr("198.51.100.31")}, nil
			}); err == nil {
				t.Fatal("cancelled bootstrap adopted")
			}
			profile.ManualMTU, profile.MTUPolicy = 600, "manual"
			previous := calls
			if _, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, lookup); err == nil || previous != calls {
				t.Fatal("malformed policy reached the resolver")
			}
		})
	}
}

func TestDesktopExternalRouterDDNSAndPairedHostBinding(t *testing.T) {
	entry, files := desktopNodeFixture(t, "router.example.test")
	profile, exit := desktopExternalNativeFixture(t, "hysteria2")
	profile.MultihopEntryMode = "wg"
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "home", "udp", "", 53
	profile.AdGuardIPv4 = entry.AdGuardIPv4
	before := encodeDesktopNodeAssets(files)
	calls := 0
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("198.51.100.44")}, nil
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || launch.endpoint != "198.51.100.44" || launch.external.entry.Endpoint != launch.endpoint || before != encodeDesktopNodeAssets(files) || !strings.Contains(launch.external.predecessor, entry.AdGuardIPv4) {
		t.Fatal("Router DDNS substituted its source or Home AdGuard")
	}
	files["wg.conf"] = []byte(strings.ReplaceAll(string(files["wg.conf"]), entry.Endpoint, "another-router.example.test"))
	previous := calls
	if _, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, lookup); err == nil || calls != previous {
		t.Fatal("wrong Router source reached bootstrap")
	}
	paired := desktopLayerProfile(t, "hysteria2", common.StartLayerAES256GCM)
	paired.Endpoint, paired.External.Hysteria2.Server = "paired.example.test", "paired.example.test"
	if _, err := freezeDesktopExternalProfile(paired, "198.51.100.44"); err == nil {
		t.Fatal("hostname bootstrap silently changed paired response/layer identity")
	}
}

func TestDesktopExternalFullRouterPredecessorAndRestoredChoice(t *testing.T) {
	count := 0
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, protocol := range []string{"wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"} {
				for _, execution := range []string{"local", "server", "auto"} {
					t.Run(mode+"/"+layer+"/"+protocol+"/"+execution, func(t *testing.T) {
						entry, files := viaEntryBaseFixture(t, mode)
						entry.StartLayer, entry.MTUPolicy, entry.ManualMTU = layer, "manual", 1500
						entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword = "10.77.0.1", 1080, "captured-entry", "captured-secret"
						var start map[string][]byte
						if layer != "off" {
							source, _ := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": entry.Endpoint, "server_port": 8388, "method": mobilemultihop.NativeStartLayerMethod, "password": testWGKey('s')}}})
							start = map[string][]byte{"sing-box.json": source}
						}
						profile, exit := desktopExternalNativeFixture(t, protocol)
						profile.MultihopEntryMode, profile.MultihopExecution = mode, execution
						profile.External.ResponseProbe = &common.ExternalResponseProbe{URL: "https://" + exit.Server + "/node-response", ServerName: "exit.example.test"}
						if protocol == "wireguard" || protocol == "amneziawg" {
							profile.External.ServerPeer = &common.ExternalServerPeer{PublicKey: desktopFormServerPublic, Addresses: []string{"10.94.0.3/32", "fd94::3/128"}, MTU: 1500, PersistentKeepalive: 25}
						}
						exit, err := standardExitFromExternalProfile(profile)
						if err != nil {
							t.Fatal(err)
						}
						original, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, start, nil)
						if err != nil {
							t.Fatal(err)
						}
						if original.external.predecessor == "" || original.external.profile.MultihopEntryMode != mode || original.external.entry.StartLayer != layer {
							t.Fatal("captured entry mode/layer was dropped")
						}
						if layer == "aes-256-gcm+xor-whitening" && !bytes.Contains(original.config, []byte(`"routervpn-aes-xor"`)) {
							t.Fatal("entry whitening was replaced")
						}
						if mode != "wg" && !bytes.Contains(original.config, []byte(`"amnezia"`)) {
							t.Fatal("AWG entry silently became WireGuard")
						}
						var capture map[string]any
						_ = json.Unmarshal(original.external.capture, &capture)
						if capture["entry_tag"] != "external-entry" || capture["predecessor_config"] != original.external.predecessor {
							t.Fatal("full predecessor lost its captured ownership")
						}
						chosen := execution
						if chosen == "auto" {
							chosen = "server"
						}
						saved := &speedLabExternalRestore{source: original.external.source, predecessor: original.external.predecessor, profile: original.external.profile, entry: original.external.entry, execution: chosen, network: "captured-network"}
						restored, err := compileSpeedLabExternalRestore(saved, exit)
						if err != nil {
							t.Fatal(err)
						}
						if restored.external.predecessor != original.external.predecessor || restored.external.selection != chosen || restored.external.session == original.external.session {
							t.Fatal("restore changed its predecessor, reran Compare or reused a session")
						}
						if export := os.Getenv("ROUTERVPN_DESKTOP_EXTERNAL_GRAPHS"); export != "" {
							name := strings.Join([]string{mode, layer, protocol, execution}, "-") + ".json"
							if err := os.WriteFile(filepath.Join(export, name), original.config, 0600); err != nil {
								t.Fatal(err)
							}
						}
						count++
					})
				}
			}
		}
	}
	if count != 189 {
		t.Fatal("full native predecessor matrix did not run", count)
	}
}

func TestDesktopExternalProofRejectsStaleWrongAndChangedWinner(t *testing.T) {
	now := time.Now()
	expected := mobilemultihop.ExternalProofResult{Schema: 1, SessionID: strings.Repeat("a", 32), SourceSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), ExitID: "exit", EntryID: "entry", EntryNodeID: strings.Repeat("d", 64), IP: "203.0.113.8", DNSProven: true, EntryProven: true, CheckedAt: now.UnixMilli(), Execution: "server"}
	owner := &desktopExternalRuntime{expected: expected, started: now, selection: "auto"}
	valid := desktopExternalProof{ExternalProofResult: expected, Healthy: true, HeartbeatAt: now.UnixMilli()}
	raw, _ := json.Marshal(valid)
	if _, err := validateDesktopExternalProof(raw, owner, now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"session", "source", "config", "node", "entry", "exit", "ip", "dns", "entry-proof", "heartbeat", "checked", "unhealthy", "winner", "new-proof"} {
		t.Run(name, func(t *testing.T) {
			proof := valid
			switch name {
			case "session":
				proof.SessionID = "other"
			case "source":
				proof.SourceSHA256 = "other"
			case "config":
				proof.ConfigSHA256 = "other"
			case "node":
				proof.EntryNodeID = "other"
			case "entry":
				proof.EntryID = "other"
			case "exit":
				proof.ExitID = "other"
			case "ip":
				proof.IP = "203.0.113.9"
			case "dns":
				proof.DNSProven = false
			case "entry-proof":
				proof.EntryProven = false
			case "heartbeat":
				proof.HeartbeatAt = now.Add(-4 * time.Second).UnixMilli()
			case "checked":
				proof.CheckedAt = now.Add(-2 * time.Second).UnixMilli()
			case "unhealthy":
				proof.Healthy = false
			case "winner":
				owner.execution = "server"
				proof.Execution = "local"
			case "new-proof":
				owner.checkedAt = valid.CheckedAt
				proof.CheckedAt = valid.CheckedAt + 1
				proof.HeartbeatAt++
			}
			data, _ := json.Marshal(proof)
			if _, err := validateDesktopExternalProof(data, owner, now); err == nil {
				t.Fatal("invalid proof accepted")
			}
			owner.execution, owner.checkedAt = "", 0
		})
	}
}

// A real isolated child exercises the controller's command/wait/record protocol
// without installing a host TUN or contacting a private server.
func TestDesktopExternalProcessFixture(t *testing.T) {
	kind := os.Getenv("ROUTERVPN_DESKTOP_EXTERNAL_CHILD")
	if kind == "" {
		return
	}
	dir := os.Getenv("ROUTERVPN_DESKTOP_EXTERNAL_DIRECTORY")
	var expected mobilemultihop.ExternalProofResult
	data, _ := base64.StdEncoding.DecodeString(os.Getenv("ROUTERVPN_DESKTOP_EXTERNAL_EXPECTED"))
	if json.Unmarshal(data, &expected) != nil {
		os.Exit(91)
	}
	if kind == "crash" {
		os.Exit(7)
	}
	write := func(name string, value any) {
		data, _ := json.Marshal(value)
		if atomicWritePrivate(filepath.Join(dir, name), data) != nil {
			os.Exit(92)
		}
	}
	closeOwner := func() {
		_ = os.Remove(filepath.Join(dir, "proof.json"))
		if kind == "foreign-close" {
			expected.SessionID = "foreign"
		}
		write("stopped.json", desktopExternalStop{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, Closed: true})
	}
	if kind == "closed" {
		closeOwner()
		return
	}
	checked := time.Now().UnixMilli()
	write("progress.json", desktopExternalProgressRecord{Schema: 1, SessionID: expected.SessionID, SourceSHA256: expected.SourceSHA256, ConfigSHA256: expected.ConfigSHA256, Stage: "proving", Progress: mobilemultihop.Progress{Stage: "prepared", Measurements: []routechoice.Measurement{}}})
	for {
		data, err := os.ReadFile(filepath.Join(dir, "stop.json"))
		if err == nil {
			var stop desktopExternalStop
			if decodeRelayControlJSON(data, &stop) == nil && stop.Schema == 1 && stop.SessionID == expected.SessionID && stop.SourceSHA256 == expected.SourceSHA256 {
				closeOwner()
				return
			}
		}
		if kind != "waiting" && kind != "foreign-close" {
			expected.CheckedAt, expected.Execution = checked, "local"
			write("proof.json", desktopExternalProof{ExternalProofResult: expected, Healthy: true, HeartbeatAt: time.Now().UnixMilli()})
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func desktopExternalRunningFixture(t *testing.T, kind string) (*app, *desktopNodeLaunch) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	profile, exit := desktopExternalNativeFixture(t, "hysteria2")
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch.root, launch.external.network = root, physicalNetworkIdentity()
	a := &app{cfg: common.ClientConfig{ScriptsDir: filepath.Join(root, "modes")}}
	if err := stageDesktopNodeLaunch(a, launch); err != nil {
		t.Fatal(err)
	}
	expected, _ := json.Marshal(launch.external.expected)
	command := exec.Command(os.Args[0], "-test.run=^TestDesktopExternalProcessFixture$")
	command.Env = append(os.Environ(), "ROUTERVPN_DESKTOP_EXTERNAL_CHILD="+kind, "ROUTERVPN_DESKTOP_EXTERNAL_DIRECTORY="+launch.directory, "ROUTERVPN_DESKTOP_EXTERNAL_EXPECTED="+base64.StdEncoding.EncodeToString(expected))
	command.Stdout, command.Stderr = io.Discard, io.Discard
	launch.command = command
	launch.external.started = time.Now()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	a.cmd = command
	desktopNodeOwners.Store(a, launch)
	t.Cleanup(func() {
		_ = command.Process.Kill()
		<-desktopExternalProcessDone(launch)
		desktopNodeOwners.Delete(a)
		_ = launch.directoryRoot.Close()
	})
	return a, launch
}

func TestDesktopExternalActualProcessProofStopAndCancellation(t *testing.T) {
	t.Run("proved and acknowledged", func(t *testing.T) {
		a, launch := desktopExternalRunningFixture(t, "proof")
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		proof, err := a.waitDesktopExternalProof(ctx, launch)
		if err != nil || proof.Execution != "local" {
			t.Fatal("real child proof rejected", err)
		}
		if err = prepareDesktopExternalStop(a, launch.command); err != nil {
			t.Fatal(err)
		}
		select {
		case <-desktopExternalProcessDone(launch):
		case <-ctx.Done():
			t.Fatal("exact child was not joined")
		}
		if !launch.external.stopAcknowledged {
			t.Fatal("unchecked stop adopted")
		}
		if err := cleanupDesktopNodeLaunch(launch); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(launch.directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned private workspace retained", err)
		}
		if err := prepareDesktopExternalStop(a, nil); err != nil {
			t.Fatal("closed owner cannot retry protection teardown", err)
		}
	})
	for _, kind := range []string{"closed", "crash"} {
		t.Run(kind, func(t *testing.T) {
			a, launch := desktopExternalRunningFixture(t, kind)
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := a.waitDesktopExternalProof(ctx, launch); err == nil || time.Since(start) >= 2*time.Second {
				t.Fatal("early native failure waited for full proof deadline", err)
			}
			err := prepareDesktopExternalStop(a, launch.command)
			if kind == "closed" && err != nil || kind == "crash" && err == nil {
				t.Fatal("close acknowledgement ownership lost", err)
			}
			if _, ok := desktopNodeOwners.Load(a); !ok {
				t.Fatal("failed native owner discarded")
			}
		})
	}
	t.Run("cancel proof and drain", func(t *testing.T) {
		a, launch := desktopExternalRunningFixture(t, "waiting")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := a.waitDesktopExternalProof(ctx, launch); !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled proof adopted", err)
		}
		if err := prepareDesktopExternalStop(a, launch.command); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("foreign acknowledgement", func(t *testing.T) {
		a, launch := desktopExternalRunningFixture(t, "foreign-close")
		if err := prepareDesktopExternalStop(a, launch.command); err == nil {
			t.Fatal("foreign close acknowledged")
		}
		if launch.external.stopAcknowledged {
			t.Fatal("foreign close changed ownership")
		}
	})
}

func TestDesktopExternalWorkspaceReplacementAndHeartbeatOwnership(t *testing.T) {
	a, launch := desktopExternalRunningFixture(t, "proof")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := a.waitDesktopExternalProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	other := exec.Command("replacement")
	a.cmd = other
	if _, err := a.readDesktopExternalProof(launch); err == nil {
		t.Fatal("old proof adopted replacement")
	}
	if err := prepareDesktopExternalStop(a, other); err == nil {
		t.Fatal("old stop accepted replacement command")
	}
	a.cmd = launch.command
	network := launch.external.network
	launch.external.network = "retired-network"
	if _, err := a.readDesktopExternalProof(launch); err == nil {
		t.Fatal("proof survived physical network retirement")
	}
	launch.external.network = network
	// The child is closed before renaming, keeping this test independent of a
	// platform's open-file rename semantics and preventing fixture writes into
	// the deliberate replacement directory.
	if err := prepareDesktopExternalStop(a, launch.command); err != nil {
		t.Fatal(err)
	}
	<-desktopExternalProcessDone(launch)
	old := launch.directory + "-retired"
	if err := os.Rename(launch.directory, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(launch.directory, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(launch.directory, "replacement-owner")
	if err := os.WriteFile(marker, []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() error{
		func() error { _, err := readDesktopRuntimeFile(launch, "stopped.json", 4096); return err },
		func() error { return writeDesktopRuntimeFile(launch, "stop.json", []byte(`{"schema":1}`), false) },
		func() error { return prepareDesktopExternalStop(a, launch.command) },
		func() error { return cleanupDesktopNodeLaunch(launch) },
	} {
		if err := operation(); err == nil {
			t.Fatal("replacement directory accepted")
		}
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "retain" {
		t.Fatal("replacement files changed", err)
	}
	if _, err := os.Lstat(filepath.Join(launch.directory, "stop.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old owner wrote into replacement directory")
	}
}

func TestDesktopExternalPreflightUsesReadOnlyCommandsAndRetainsReplacement(t *testing.T) {
	for _, scenario := range []string{"success", "missing-command", "invalid-graph", "cancelled", "replaced-workspace", "changed-input"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOMEVPN_ROOT", root)
			profile, exit := desktopExternalNativeFixture(t, "hysteria2")
			launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch.root = root
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls [][]string
			marker := ""
			run := func(ctx context.Context, executable string, args, environment []string, directory string) error {
				calls = append(calls, append([]string{}, args...))
				if executable != binary || strings.Contains(strings.Join(environment, "\n"), "HOMEVPN_EXTERNAL_SESSION=") {
					t.Fatal("preflight acquired a runtime owner")
				}
				if len(calls) == 1 && !reflect.DeepEqual(args, []string{"routervpn-external", "--help"}) {
					t.Fatal("preflight did not check native command")
				}
				if len(calls) == 2 && (len(args) != 5 || args[0] != "check" || args[1] != "-D" || args[2] != directory || args[3] != "-c" || args[4] != filepath.Join(directory, "sing-box.json")) {
					t.Fatal("preflight ran a launcher mutation", args)
				}
				switch scenario {
				case "missing-command":
					return errors.New("missing")
				case "invalid-graph":
					if len(calls) == 2 {
						return errors.New("invalid")
					}
				case "cancelled":
					cancel()
					return ctx.Err()
				case "changed-input":
					if err := os.WriteFile(filepath.Join(directory, "sing-box.json"), []byte(`{"changed":true}`), 0600); err != nil {
						t.Fatal(err)
					}
				case "replaced-workspace":
					if err := os.Rename(directory, directory+"-old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(directory, 0700); err != nil {
						t.Fatal(err)
					}
					marker = filepath.Join(directory, "foreign")
					if err := os.WriteFile(marker, []byte("retain"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			err = preflightDesktopExternalLaunch(ctx, binary, launch, run)
			if (scenario == "success") != (err == nil) {
				t.Fatal("preflight result", scenario, err)
			}
			if scenario == "success" && len(calls) != 2 || launch.command != nil || launch.directory != "" {
				t.Fatal("preflight staged a real runtime")
			}
			if marker != "" {
				if raw, e := os.ReadFile(marker); e != nil || string(raw) != "retain" {
					t.Fatal("preflight cleaned replacement", e)
				}
			}
		})
	}
}
