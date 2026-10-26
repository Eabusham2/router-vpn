package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/mobilemultihop"
)

func retainedGraph(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var graph map[string]any
	if err := json.Unmarshal(data, &graph); err != nil {
		t.Fatal(err)
	}
	return graph
}

func TestNativeMultihopRetainedGraphFinalizesServerAndOnlyRestoresSystemMTU(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			exitModes := []string{"shadowsocks", "hysteria2"}
			if mode == "awg2-strong" && layer == "aes-256-gcm+xor-whitening" {
				exitModes = mobilemultihop.NodeMultihopExitModes()
			}
			for _, exitMode := range exitModes {
				for _, execution := range []string{"local", "server"} {
					t.Run(mode+"/"+layer+"/"+exitMode+"/"+execution, func(t *testing.T) {
						root, sel := nativeMultihopCapturedFixture(t, mode, layer)
						sel.ExitMode = exitMode
						if awgpolicy.IsMode(exitMode) {
							sel.Entry.MTUPolicy, sel.Entry.ManualMTU = "manual", 1500
							sel.Control.MTUPolicy, sel.Control.ManualMTU = "manual", 1500
						}
						sel, err := captureNativeMultihopSelection(context.Background(), root, sel, exitModes, nil)
						if err != nil {
							t.Fatal(err)
						}
						originalSource := sel.Native.configs[exitMode]
						var descriptor *desktopExecutionDescriptor
						if execution == "server" {
							_, d := executionFixture()
							d.Lease.ExitMode = exitMode
							if layer != "off" {
								d.Lease.ExitStartLayer = layer
							}
							descriptor = &d
						}
						initial, err := compileRetainedNativeMultihopLaunch(sel, descriptor)
						if err != nil {
							t.Fatal(err)
						}
						restoredSelection := sel
						restoredSelection.restoreMTU = 1360
						restored, err := compileRetainedNativeMultihopLaunch(restoredSelection, descriptor)
						if err != nil {
							t.Fatal(err)
						}
						before, after := retainedGraph(t, initial.config), retainedGraph(t, restored.config)
						for key, value := range before {
							if key != "inbounds" && !reflect.DeepEqual(value, after[key]) {
								t.Fatal("MTU restore changed entry, exit, DNS or protection", key)
							}
						}
						originalIn, restoredIn := before["inbounds"].([]any), after["inbounds"].([]any)
						count := 0
						for i, raw := range restoredIn {
							in := raw.(map[string]any)
							if in["type"] == "tun" {
								count++
								if in["mtu"] != float64(1360) {
									t.Fatal("live system MTU was not restored")
								}
								baseline := originalIn[i].(map[string]any)
								in["mtu"] = baseline["mtu"]
								if !reflect.DeepEqual(in, baseline) {
									t.Fatal("restore changed system TUN protection")
								}
							} else if !reflect.DeepEqual(raw, originalIn[i]) {
								t.Fatal("restore changed a proof lane")
							}
						}
						if count != 1 || sel.Native.configs[exitMode] != originalSource || sel.Native.validate(sel) != nil {
							t.Fatal("restore rewrote the original native capture")
						}
						for _, launch := range []*desktopNodeLaunch{initial, restored} {
							var receipt map[string]any
							_ = json.Unmarshal(launch.metadata, &receipt)
							digest := sha256.Sum256(launch.config)
							if receipt["config_sha256"] != hex.EncodeToString(digest[:]) || receipt["execution"] != execution || receipt["entry_mode"] != mode || receipt["graph_source_sha256"] != sel.Native.source || receipt["mtu_scope"] != "multihop-exit-path" {
								t.Fatal("final capture was hashed before exact execution/MTU composition")
							}
							if launch.profileID != sel.Exit.ID || launch.policyProfileID != sel.Control.ID || launch.endpoint != sel.Native.endpoint {
								t.Fatal("entry, exit and control ownership were conflated")
							}
							if binary := os.Getenv("ROUTERVPN_VIA_ENTRY_NATIVE_CLI"); binary != "" {
								directory := t.TempDir()
								path := filepath.Join(directory, "sing-box.json")
								if err := os.WriteFile(path, launch.config, 0600); err != nil {
									t.Fatal(err)
								}
								command := exec.Command(binary, "check", "-D", directory, "-c", path)
								command.Env = nativeLibraryEnvironment(os.Environ(), filepath.Dir(binary))
								if output, err := command.CombinedOutput(); err != nil {
									t.Fatalf("actual native runtime rejected retained graph: %v: %s", err, output)
								}
							}
						}
					})
				}
			}
		}
	}
}

func TestNativeMultihopRetainedStageBindsFreshSessionAndExactConfig(t *testing.T) {
	f := newRetainedMultihopFixture(t, "server")
	raw, err := readDesktopRuntimeFile(f.launch, "sing-box.json", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if f.launch.configSHA256 != hex.EncodeToString(digest[:]) || len(f.launch.mtuSession) != 32 || len(f.launch.config) != 0 || len(f.launch.metadata) != 0 {
		t.Fatal("stage lost final immutable source or retained secrets unnecessarily")
	}
	environment := strings.Join(f.launch.command.Env, "\n")
	for _, expected := range []string{"HOMEVPN_PROFILE_ID=entry", "HOMEVPN_POLICY_PROFILE_ID=control", "HOMEVPN_ENDPOINT=" + f.launch.endpoint, "HOMEVPN_NODE_SESSION=" + f.launch.mtuSession, "HOMEVPN_NODE_CONFIG_SHA256=" + f.launch.configSHA256} {
		if !strings.Contains(environment, expected) {
			t.Fatal("wrong staged ownership", expected)
		}
	}
	graph := retainedGraph(t, raw)
	for _, value := range graph["outbounds"].([]any) {
		out := value.(map[string]any)
		if out["tag"] == "proxy" && (out["type"] != "socks" || out["detour"] != "entry-wg") {
			t.Fatal("server substitution was not finalized before staging")
		}
	}
	selection := f.selection
	selection.restoreMTU = 1360
	_, descriptor := executionFixture()
	descriptor.Lease.ExitMode, descriptor.Lease.ExitStartLayer = selection.ExitMode, selection.Exit.StartLayer
	descriptor.Lease.Password = strings.Repeat("c", 48)
	second, err := compileRetainedNativeMultihopLaunch(selection, &descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := stageOwnedNativeMultihopCommand(f.a, selection, second); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := retireUnstartedNativeMultihop(second); err != nil {
			t.Error(err)
		}
	}()
	if second.mtuSession == f.launch.mtuSession || second.configSHA256 == f.launch.configSHA256 || second.directory == f.launch.directory {
		t.Fatal("restored server reused the previous session, credentials or workspace")
	}
	if err := desktopExternalDirectoryCurrent(f.launch); err != nil {
		t.Fatal("new staging retired the old captured directory", err)
	}
}

func TestNativeMultihopRetainedSpeedLabRestoresLiveMTUAndProvedWinner(t *testing.T) {
	for _, execution := range []string{"local", "server"} {
		t.Run(execution, func(t *testing.T) {
			f := newRetainedMultihopFixture(t, execution)
			t.Setenv("HOMEVPN_ROOT", f.launch.root)
			manifest := filepath.Join(f.launch.root, "runtime", "native", "NATIVE-RUNTIME.json")
			if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifest, []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			// Retest changed only saved measurement metadata after the original
			// graph began. The actual readback is authoritative for restoration.
			f.a.profiles.Profiles[2].EffectiveMTU = 1380
			f.a.profiles.Profiles[2].EffectiveMTUSource = "auto-throughput-multihop-exit-path"
			snapshot := speedLabTemporarySnapshot{Profiles: cloneRouterProfileStore(f.a.profiles), State: f.a.state, Runtime: f.a.cmd}
			plan, err := f.a.speedLabCaptureRestorePlan(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if plan.multihop == nil || plan.multihop.Native != f.selection.Native || plan.multihop.restoreMTU != 1360 || plan.request.Execution != execution || plan.request.Execution == "auto" || plan.multihop.Control.MultihopExecution != "auto" {
				t.Fatal("restore recaptured a different graph or repeated Compare")
			}
			if plan.multihop.Entry.EffectiveMTU != 1500 || plan.multihop.Exit.EffectiveMTU != 1300 {
				t.Fatal("live TUN MTU was mixed into frozen entry/exit profile source")
			}
			f.a.profiles.Profiles[0].SocksPassword = "new-control-secret"
			if plan.multihop.Control.SocksPassword == "new-control-secret" {
				t.Fatal("restore borrowed mutable control credentials")
			}
		})
	}
}

func TestNativeMultihopRetainedRestoreRefusesUnconfirmedMTUAndReplacement(t *testing.T) {
	for _, change := range []string{"active", "failed", "wrong-session", "wrong-config", "changed-command", "changed-owner", "changed-policy"} {
		t.Run(change, func(t *testing.T) {
			f := newRetainedMultihopFixture(t, "local")
			control, entry, exit := f.selection.Control, f.selection.Entry, f.selection.Exit
			r := f.readback
			switch change {
			case "active":
				r.Active = true
			case "failed":
				r.Failure = "rollback pending"
			case "wrong-session":
				r.Session = strings.Repeat("f", 32)
			case "wrong-config":
				r.Config = strings.Repeat("f", 64)
			case "changed-command":
				f.launch.command = &exec.Cmd{}
			case "changed-owner":
				nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
			case "changed-policy":
				exit.DNSMode = "system"
			}
			f.publish(t, r)
			if _, err := captureNativeMultihopRestore(f.a, f.a.cmd, f.graph, control, entry, exit); err == nil {
				t.Fatal("unconfirmed restore accepted", change)
			}
		})
	}
}

func TestNativeMultihopRetainedPreflightReadsExactGraphAndPreservesFailure(t *testing.T) {
	for _, failure := range []string{"none", "native-check", "changed-config", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			root, sel := nativeMultihopCapturedFixture(t, "wg", "off")
			sel, err := captureNativeMultihopSelection(context.Background(), root, sel, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := compileRetainedNativeMultihopLaunch(sel, nil)
			if err != nil {
				t.Fatal(err)
			}
			original := append([]byte(nil), launch.config...)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			directory := ""
			run := func(_ context.Context, binary string, args, environment []string, dir string) error {
				calls++
				directory = dir
				if calls == 1 && !reflect.DeepEqual(args, []string{"routervpn-node", "--help"}) {
					t.Fatal("node ownership command was not checked first")
				}
				if calls == 2 {
					if args[0] != "check" {
						t.Fatal("preflight attempted to start a tunnel")
					}
					checked, err := os.ReadFile(filepath.Join(dir, "sing-box.json"))
					if err != nil || !bytes.Equal(checked, original) {
						t.Fatal("preflight read a different graph")
					}
					switch failure {
					case "native-check":
						return errors.New("native check rejected graph")
					case "changed-config":
						return os.WriteFile(filepath.Join(dir, "sing-box.json"), []byte(`{}`), 0600)
					case "cancel":
						cancel()
					}
				}
				return nil
			}
			binary := filepath.Join(root, "runtime", "native", "sing-box")
			if runtime.GOOS == "windows" {
				binary += ".exe"
			}
			err = preflightRetainedNativeMultihop(ctx, binary, launch, run)
			if (err == nil) != (failure == "none") {
				t.Fatal("preflight lost exact native failure", failure, err)
			}
			if calls != 2 || launch.command != nil || launch.directory != "" || !bytes.Equal(original, launch.config) {
				t.Fatal("preflight mutated active launch or source")
			}
			if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight workspace was not retired", err)
			}
		})
	}
}

func TestNativeMultihopRetainedLateProofCannotEraseReplacementGraph(t *testing.T) {
	f := newRetainedMultihopFixture(t, "local")
	replacementLaunch := &desktopNodeLaunch{command: &exec.Cmd{}}
	replacementGraph := f.graph
	replacementGraph.Started = replacementGraph.Started.Add(1)
	replacement := &nativeMultihopRuntime{launch: replacementLaunch, graph: replacementGraph}
	nativeMultihopOwners.Store(f.a, replacement)
	activeMultihopGraphs.Store(f.a, replacementGraph)
	retireNativeMultihopGraph(f.a, f.launch)
	if raw, ok := nativeMultihopOwners.Load(f.a); !ok || raw != replacement {
		t.Fatal("retired proof erased replacement TUN owner")
	}
	if graph, ok := getActiveMultihopGraph(f.a); !ok || graph != replacementGraph {
		t.Fatal("retired proof erased replacement graph")
	}
	retireNativeMultihopGraph(f.a, replacementLaunch)
	if _, ok := nativeMultihopOwners.Load(f.a); ok {
		t.Fatal("matching retired owner was not released")
	}
	if _, ok := getActiveMultihopGraph(f.a); ok {
		t.Fatal("matching retired graph was not released")
	}
}
