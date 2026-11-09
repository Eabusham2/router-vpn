package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/routechoice"
)

type speedLabImportedFixture struct {
	a        *app
	q        speedLabRequest
	driver   speedLabMultihopPreparationRuntime
	owner    *speedLabTemporaryOwner
	caller   context.Context
	cancel   context.CancelFunc
	original common.RouterProfileStore
	checks   int
}

func newSpeedLabImportedFixture(t *testing.T, protocol string) *speedLabImportedFixture {
	t.Helper()
	root, selection := desktopImportedFixture(t, protocol, "reality-vision")
	t.Setenv("HOMEVPN_ROOT", root)
	manifest := filepath.Join(root, "runtime", "native", "NATIVE-RUNTIME.json")
	if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	// An unrelated selected complete profile supplies selection defaults, never
	// private node credentials or the imported path's final DNS policy.
	selected := cloneRouterProfile(selection.Exit)
	selected.ID, selected.Name = "selected", "Original selected complete profile"
	selected.MultihopEntryMode, selected.MultihopExecution = protocol, "auto"
	selected.AdGuardIPv4 = "192.168.50.155"
	selection.Exit.MultihopEntryMode, selection.Exit.MultihopExecution = "wg", "server"
	selection.Exit.MTUPolicy, selection.Exit.ManualMTU = "manual", 1280
	selection.Exit.EffectiveMTU = 1280
	selection.Exit.IPv6Mode = "off"
	selection.Control = cloneRouterProfile(selection.Exit)
	operation, stopOperation := context.WithCancel(context.Background())
	caller, cancel := context.WithCancel(operation)
	previous := &exec.Cmd{}
	a := &app{cfg: common.ClientConfig{ScriptsDir: filepath.Join(root, "modes")}, profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion,
		SelectedID: selected.ID, Profiles: []common.RouterProfile{selected, selection.Entry, selection.Exit}},
		state: state{Mode: "captured-previous", Phase: "connected", Connected: true, RouterID: selected.ID},
		cmd:   previous, connectionContext: operation, connectionCancel: stopOperation}
	owner := &speedLabTemporaryOwner{intent: operation, test: operation, current: operation, runtime: previous, network: "captured-physical-network", cancelIntent: stopOperation, cancelTest: cancel}
	speedLabTemporaryOwners.Store(a, owner)
	f := &speedLabImportedFixture{a: a, owner: owner, caller: caller, cancel: cancel, original: cloneRouterProfileStore(a.profiles),
		q: speedLabRequest{Scope: "temporary", Topology: "multihop", EntryID: selection.Entry.ID, EntryMode: protocol,
			ExitID: selection.Exit.ID, ExitMode: "reality-vision", Execution: "local", Base: "auto"}}
	f.driver = speedLabMultihopPreparationRuntime{
		network: func(ctx context.Context) (string, error) { return owner.network, ctx.Err() },
		capture: func(ctx context.Context, a *app, selection multihopSelection, modes []string) (multihopSelection, error) {
			return captureNativeMultihopSelection(ctx, root, selection, modes, nil)
		},
		preflight: func(ctx context.Context, a *app, selection multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			launch, err := compileRetainedNativeMultihopLaunch(selection, descriptor)
			if err != nil {
				return nil, err
			}
			// Execute the shipping private preflight/staging-input checks. Only
			// the installed CLI is modeled; this is not native engine evidence.
			err = preflightRetainedNativeMultihop(ctx, filepath.Join(root, "fixture-native"), launch,
				func(ctx context.Context, binary string, args, env []string, directory string) error {
					f.checks++
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if a.cmd != previous || !reflect.DeepEqual(a.profiles, f.original) || owner.mutated {
						return errors.New("preflight altered the original VPN or private profiles")
					}
					if len(args) != 0 && args[0] == "check" {
						raw, err := os.ReadFile(filepath.Join(directory, "sing-box.json"))
						if err != nil || !bytes.Equal(raw, launch.config) {
							return errors.New("preflight did not read the original captured graph")
						}
					}
					return nil
				})
			return launch, err
		},
	}
	t.Cleanup(func() {
		cancel()
		stopOperation()
		speedLabTemporaryOwners.Delete(a)
		activeDNSRuntimeIdentities.Delete(a)
	})
	return f
}

func (f *speedLabImportedFixture) suspend(t *testing.T) {
	t.Helper()
	snapshot := speedLabTemporarySnapshot{Owner: f.owner}
	if err := f.a.speedLabSuspendPreviousWith(snapshot, false, func(hold bool) error {
		if !hold || f.a.cmd != f.owner.runtime {
			return errors.New("suspension lost its captured previous runtime")
		}
		f.a.mu.Lock()
		f.a.cmd, f.owner.runtime = nil, nil
		f.a.state = state{Mode: "off", Phase: "off"}
		f.a.mu.Unlock()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSpeedLabImportedPreparationOwnsOriginalEntryAndFinalPolicy(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			f := newSpeedLabImportedFixture(t, protocol)
			requireEncryption := true
			f.q.RequireEncrypted = &requireEncryption
			prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.releaseUnused()
			if f.checks != 2 || f.owner.mutated || !reflect.DeepEqual(f.a.profiles, f.original) {
				t.Fatal("capture/preflight changed the previous connection before suspension")
			}
			if prepared.selection.Control.ID != f.q.ExitID || prepared.selection.EntryMode != protocol ||
				!prepared.selection.Control.AutoRequireEncrypted || prepared.selection.Entry.AutoRequireEncrypted ||
				!reflect.DeepEqual(prepared.selection.Entry, f.original.Profiles[1]) ||
				prepared.selection.Control.MultihopExecution != "server" || prepared.selection.Control.MultihopEntryMode != "wg" ||
				prepared.selection.Control.ManualMTU != 1280 || prepared.selection.Control.IPv6Mode != "off" {
				t.Fatal("temporary override borrowed another source or changed saved final settings")
			}
			graph := retainedGraph(t, prepared.launch.config)
			server := graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if server["detour"] != "proxy" || strings.Contains(string(prepared.launch.config), "192.168.50.155") ||
				prepared.selection.Exit.DNSMode == "home" && server["server"] != prepared.selection.Exit.AdGuardIPv4 {
				t.Fatal("temporary graph did not retain paired-final selected DNS", server)
			}
			if _, err := prepared.apply(f.caller, f.a, f.q); err == nil || f.owner.mutated {
				t.Fatal("prepared graph overwrote an undrained previous connection")
			}
			f.suspend(t)
			selected, err := prepared.apply(f.caller, f.a, f.q)
			if err != nil || selected.Native != prepared.selection.Native || f.a.profiles.SelectedID != f.q.ExitID ||
				!reflect.DeepEqual(f.a.profiles.Profiles[0], f.original.Profiles[0]) || !reflect.DeepEqual(f.a.profiles.Profiles[1], f.original.Profiles[1]) ||
				!reflect.DeepEqual(f.a.profiles.Profiles[2], selected.Control) {
				t.Fatal("temporary admission changed another profile or rebuilt the captured graph", err)
			}
			if _, err := prepared.apply(f.caller, f.a, f.q); err == nil {
				t.Fatal("temporary preparation could be applied twice")
			}
			checked := append([]byte(nil), prepared.launch.config...)
			candidate := routechoice.Candidate{Execution: routechoice.Local, EntryID: selected.Entry.ID, ExitID: selected.Exit.ID, Transport: selected.ExitMode}
			launch, err := prepared.stage(f.caller, f.a, selected, candidate)
			if err != nil || launch != prepared.launch || launch.command == nil || launch.command.Process != nil || launch.policyProfileID != selected.Exit.ID {
				t.Fatal("temporary launcher did not stage its exact checked native capture", err)
			}
			staged, err := readDesktopRuntimeFile(launch, "sing-box.json", 4<<20)
			if err != nil || !bytes.Equal(staged, checked) || launch.nodePhysicalCapture == nil || !prepared.consumed {
				t.Fatal("temporary staging changed the preflighted bytes or physical ownership", err)
			}
			if _, err := prepared.stage(f.caller, f.a, selected, candidate); err == nil {
				t.Fatal("a consumed native launch could be staged again")
			}
		})
	}
}

func TestSpeedLabImportedPreparationKeepsFinalBaseAndOriginalRequest(t *testing.T) {
	for _, choice := range []struct{ requested, saved string }{{"wg", "awg"}, {"awg", "wg"}} {
		t.Run(choice.requested, func(t *testing.T) {
			f := newSpeedLabImportedFixture(t, "shadowsocks")
			f.q.Base = choice.requested
			f.a.profiles.Profiles[2].BaseTunnel = choice.saved
			f.original = cloneRouterProfileStore(f.a.profiles)
			requireEncryption := true
			f.q.RequireEncrypted = &requireEncryption
			wantFinal := cloneRouterProfile(f.original.Profiles[2])
			wantFinal.AutoRequireEncrypted = true
			prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.releaseUnused()
			if f.q.Base != choice.requested || f.checks != 2 || f.owner.mutated || !reflect.DeepEqual(f.a.profiles, f.original) {
				t.Fatal("entry-base preparation changed the original request, profiles or current VPN")
			}
			if !reflect.DeepEqual(prepared.selection.Control, wantFinal) || !reflect.DeepEqual(prepared.selection.Exit, wantFinal) ||
				!reflect.DeepEqual(prepared.selection.Entry, f.original.Profiles[1]) || prepared.selection.Base != "native" ||
				prepared.selection.Native == nil || prepared.selection.Native.validate(prepared.selection) != nil {
				t.Fatal("entry Base changed the paired final's saved preference or imported native capture")
			}
			checked := append([]byte(nil), prepared.launch.config...)
			f.suspend(t)
			changed := f.q
			changed.Base = "auto"
			if _, err := prepared.apply(f.caller, f.a, changed); err == nil || prepared.applied || !reflect.DeepEqual(f.a.profiles, f.original) {
				t.Fatal("policy-only Base clearing changed the original request's admission identity")
			}
			selected, err := prepared.apply(f.caller, f.a, f.q)
			if err != nil || selected.Native != prepared.selection.Native || selected.Base != "native" ||
				!reflect.DeepEqual(f.a.profiles.Profiles[2], wantFinal) {
				t.Fatal("temporary admission changed the original final base or rebuilt its native graph", err)
			}
			candidate := routechoice.Candidate{Execution: routechoice.Local, EntryID: selected.Entry.ID, ExitID: selected.Exit.ID, Transport: selected.ExitMode}
			launch, err := prepared.stage(f.caller, f.a, selected, candidate)
			if err != nil || launch != prepared.launch {
				t.Fatal("entry Base changed the preflighted native launch", err)
			}
			staged, err := readDesktopRuntimeFile(launch, "sing-box.json", 4<<20)
			if err != nil || !bytes.Equal(staged, checked) || selected.Native.validate(selected) != nil {
				t.Fatal("entry Base changed the actual retained native graph", err)
			}
		})
	}
}

func TestSpeedLabImportedUnstartedRetirementKeepsReplacementDNSOwner(t *testing.T) {
	for _, fault := range []string{"none", "cancel-after-stage", "replacement-before-registration", "replacement-after-stage"} {
		t.Run(fault, func(t *testing.T) {
			f := newSpeedLabImportedFixture(t, "wireguard")
			prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.releaseUnused()
			f.suspend(t)
			selection, err := prepared.apply(f.caller, f.a, f.q)
			if err != nil {
				t.Fatal(err)
			}
			replacement := activeDNSRuntimeIdentity{ProfileID: "replacement", RuntimeID: "wg", Config: filepath.Join(clientRoot(f.a), "run", "replacement", "sing-box.json")}
			originalNetwork := prepared.readNetwork
			prepared.readNetwork = func(ctx context.Context) (string, error) {
				_, registered := activeDNSRuntimeIdentities.Load(f.a)
				if prepared.launch.command != nil && fault == "replacement-before-registration" && !registered {
					activeDNSRuntimeIdentities.Store(f.a, replacement)
					f.a.mu.Lock()
					f.a.cmd = &exec.Cmd{}
					f.a.mu.Unlock()
				} else if prepared.launch.command != nil && registered && fault != "none" && fault != "replacement-before-registration" {
					if fault == "replacement-after-stage" {
						activeDNSRuntimeIdentities.Store(f.a, replacement)
					}
					f.cancel()
				}
				return originalNetwork(ctx)
			}
			candidate := routechoice.Candidate{Execution: routechoice.Local, EntryID: selection.Entry.ID, ExitID: selection.Exit.ID, Transport: selection.ExitMode}
			_, err = prepared.stage(f.caller, f.a, selection, candidate)
			if (err != nil) != (fault != "none") {
				t.Fatal("stage lost original cancellation boundary", err)
			}
			if fault == "none" {
				registered, present := activeDNSRuntimeIdentities.Load(f.a)
				if !present || registered != prepared.dns || prepared.dns.Config == "" {
					t.Fatal("stage did not own its exact private DNS registration")
				}
			}
			if err := prepared.releaseUnused(); err != nil {
				t.Fatal(err)
			}
			registered, present := activeDNSRuntimeIdentities.Load(f.a)
			if strings.HasPrefix(fault, "replacement-") {
				if !present || registered != replacement {
					t.Fatal("old unstarted graph removed replacement DNS owner")
				}
			} else if present {
				t.Fatal("unstarted graph left its old DNS registration")
			}
			if prepared.launch.directory != "" || len(prepared.launch.config) != 0 && bytes.Count(prepared.launch.config, []byte{0}) != len(prepared.launch.config) {
				t.Fatal("unstarted graph retained its private material")
			}
		})
	}
}

func TestSpeedLabImportedPreparationRejectsChangedOriginalBeforeSuspension(t *testing.T) {
	for _, fault := range []string{"entry-credentials", "final-dns", "selected-profile", "runtime", "operation", "caller", "network", "invalid-native", "failed-preflight"} {
		t.Run(fault, func(t *testing.T) {
			f := newSpeedLabImportedFixture(t, "wireguard")
			capture := f.driver.capture
			f.driver.capture = func(ctx context.Context, a *app, selection multihopSelection, modes []string) (multihopSelection, error) {
				captured, err := capture(ctx, a, selection, modes)
				if err != nil {
					return captured, err
				}
				switch fault {
				case "entry-credentials":
					a.profiles.Profiles[1].External.WireGuard.PrivateKey = testWGKey('z')
				case "final-dns":
					a.profiles.Profiles[2].AdGuardIPv4 = "192.168.50.166"
				case "selected-profile":
					a.profiles.SelectedID = selection.Entry.ID
				case "runtime":
					a.cmd = &exec.Cmd{}
				case "operation":
					a.connectionContext = context.Background()
				case "caller":
					f.cancel()
				case "network":
					f.owner.network = "replacement-network"
				case "invalid-native":
					captured.Native = nil
				}
				return captured, nil
			}
			if fault == "failed-preflight" {
				f.driver.preflight = func(context.Context, *app, multihopSelection, *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
					return nil, errors.New("installed CLI rejected exact graph")
				}
			}
			if prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver); err == nil || prepared != nil || f.owner.mutated {
				t.Fatal("invalid/changed preparation suspended or replaced the original connection", err)
			}
		})
	}
}

func TestSpeedLabImportedPreparationRejectsWrongModeExecutionAndGraph(t *testing.T) {
	for _, fault := range []string{"wrong-explicit-mode", "wrong-saved-mode", "server", "compare", "same-node", "foreign-final", "unsupported-final", "dynamic-socks-relay"} {
		t.Run(fault, func(t *testing.T) {
			protocol := "openvpn"
			if fault == "dynamic-socks-relay" {
				protocol = "socks5"
			}
			f := newSpeedLabImportedFixture(t, protocol)
			switch fault {
			case "wrong-explicit-mode":
				f.q.EntryMode = "wg"
			case "wrong-saved-mode":
				f.q.EntryMode = ""
				f.a.profiles.Profiles[0].MultihopEntryMode = "wg"
			case "server":
				f.q.Execution = "server"
			case "compare":
				f.q.Execution = "auto"
			case "same-node":
				f.q.ExitID = f.q.EntryID
			case "foreign-final":
				f.a.profiles.Profiles[2].NodeKind = "external"
			case "unsupported-final":
				f.q.ExitMode = "max"
			case "dynamic-socks-relay":
				f.q.ExitMode = "shadowsocks"
			}
			before := cloneRouterProfileStore(f.a.profiles)
			prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver)
			if err == nil || prepared != nil || f.checks != 0 || f.owner.mutated || !reflect.DeepEqual(f.a.profiles, before) {
				t.Fatal("unavailable imported authority reached preflight or changed current setup", err)
			}
		})
	}
}

func TestSpeedLabImportedPreparedAdmissionDoesNotBorrowChangedRequestOrSource(t *testing.T) {
	for _, fault := range []string{"request", "source", "selected", "caller", "replacement", "cancel-intent", "config", "metadata", "candidate"} {
		t.Run(fault, func(t *testing.T) {
			f := newSpeedLabImportedFixture(t, "openvpn")
			prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.releaseUnused()
			f.suspend(t)
			request := f.q
			switch fault {
			case "request":
				request.Execution = "auto"
			case "source":
				f.a.profiles.Profiles[1].External.OpenVPN.Password += "replacement"
			case "selected":
				f.a.profiles.SelectedID = f.q.EntryID
			case "caller":
				f.cancel()
			case "replacement":
				f.a.cmd = &exec.Cmd{}
			case "cancel-intent":
				f.a.connectionCancelIntent = f.a.connectionContext
			}
			before := cloneRouterProfileStore(f.a.profiles)
			selection, err := prepared.apply(f.caller, f.a, request)
			if fault != "config" && fault != "metadata" && fault != "candidate" {
				if err == nil || !reflect.DeepEqual(f.a.profiles, before) {
					t.Fatal("late result changed a replacement source or user selection", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			candidate := routechoice.Candidate{EntryID: f.q.EntryID, ExitID: f.q.ExitID, Transport: f.q.ExitMode, Execution: routechoice.Local}
			switch fault {
			case "config":
				prepared.launch.config[0] ^= 1
			case "metadata":
				prepared.launch.metadata[0] ^= 1
			case "candidate":
				candidate.Execution = routechoice.Server
			}
			if launch, err := prepared.stage(f.caller, f.a, selection, candidate); err == nil || launch != nil || prepared.launch.command != nil {
				t.Fatal("changed retained graph reached native staging", err)
			}
		})
	}
}

func TestSpeedLabImportedPreparationHonorsOriginalCallerDuringCaptureAndPreflight(t *testing.T) {
	for _, phase := range []string{"capture", "preflight", "controller-lock", "identity-lock"} {
		t.Run(phase, func(t *testing.T) {
			f := newSpeedLabImportedFixture(t, "wireguard")
			entered := make(chan struct{})
			wait := func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
			if phase == "capture" {
				f.driver.capture = func(ctx context.Context, _ *app, selection multihopSelection, _ []string) (multihopSelection, error) {
					return selection, wait(ctx)
				}
			} else if phase == "preflight" {
				f.driver.preflight = func(ctx context.Context, _ *app, _ multihopSelection, _ *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
					return nil, wait(ctx)
				}
			} else {
				f.a.mu.Lock()
				defer f.a.mu.Unlock()
				close(entered)
			}
			done := make(chan error, 1)
			go func() {
				if phase == "identity-lock" {
					session := &desktopExecutionSession{driver: &desktopExecutionDriver{a: f.a}, command: f.a.cmd}
					if session.identityContext(f.caller) != "" {
						done <- errors.New("cancelled original caller produced an identity")
					} else {
						done <- f.caller.Err()
					}
					return
				}
				_, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver)
				done <- err
			}()
			<-entered
			f.cancel()
			select {
			case err := <-done:
				if err == nil || f.owner.mutated || !reflect.DeepEqual(f.a.profiles, f.original) {
					t.Fatal("cancelled original preparation changed prior runtime", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancelled original preparation waited for an unrelated owner")
			}
		})
	}
}

func TestSpeedLabImportedPreparedAdmissionCancelsWhilePreparationLockIsHeld(t *testing.T) {
	for _, phase := range []string{"apply", "stage"} {
		t.Run(phase, func(t *testing.T) {
			f := newSpeedLabImportedFixture(t, "openvpn")
			prepared, err := f.a.prepareSpeedLabImportedMultihopWithRuntime(f.caller, f.q, f.driver)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.releaseUnused()
			f.suspend(t)
			var selection multihopSelection
			if phase == "stage" {
				selection, err = prepared.apply(f.caller, f.a, f.q)
				if err != nil {
					t.Fatal(err)
				}
			}
			before := cloneRouterProfileStore(f.a.profiles)
			candidate := routechoice.Candidate{EntryID: f.q.EntryID, ExitID: f.q.ExitID, Transport: f.q.ExitMode, Execution: routechoice.Local}
			ctx, cancel := context.WithCancel(f.caller)
			defer cancel()
			prepared.mu.Lock()
			done := make(chan error, 1)
			go func() {
				if phase == "apply" {
					_, err := prepared.apply(ctx, f.a, f.q)
					done <- err
				} else {
					_, err := prepared.stage(ctx, f.a, selection, candidate)
					done <- err
				}
			}()
			cancel()
			select {
			case err = <-done:
				prepared.mu.Unlock()
				if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(f.a.profiles, before) ||
					prepared.applied != (phase == "stage") || prepared.consumed || prepared.launch.command != nil || prepared.dns.Config != "" {
					t.Fatal("cancelled preparation admission changed profiles or staged a native owner", err)
				}
			case <-time.After(2 * time.Second):
				prepared.mu.Unlock()
				<-done // Join the failed admission before retiring private inputs.
				t.Fatal("cancelled preparation admission waited for a held preparation lock")
			}
		})
	}
}
