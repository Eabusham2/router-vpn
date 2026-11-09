package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// These finite children are the current test executable, with no TUN, routes,
// firewall or sockets. The production CommandContext/Output path owns and joins
// them. Native bundle receipt verification remains a separate strict boundary.
func init() {
	if os.Getenv("ROUTERVPN_TOR_CALLER_CHILD") != "1" || len(os.Args) < 2 {
		return
	}
	phase := os.Args[1]
	switch phase {
	case "--version":
		phase = "tor-version"
	case "version":
		phase = "native-version"
	case "routervpn-tor":
		phase = "help"
	case "check":
	default:
		return
	}
	directory := os.Getenv("ROUTERVPN_TOR_CALLER_DIRECTORY")
	raw, _ := json.Marshal(preflightContextChild{PID: os.Getpid(), Directory: directory})
	if os.WriteFile(filepath.Join(directory, phase+".json"), raw, 0600) != nil {
		os.Exit(41)
	}
	if phase == os.Getenv("ROUTERVPN_TOR_CALLER_HOLD") {
		_, _ = fmt.Fprintln(os.Stdout, "owned Tor verifier entered")
		_, _ = fmt.Fprintln(os.Stderr, "owned Tor verifier diagnostics")
		time.Sleep(4 * time.Second)
		os.Exit(42)
	}
	if phase == "tor-version" {
		_, _ = fmt.Fprintln(os.Stdout, "Tor version 0.4.9.14.")
	}
	if phase == "native-version" {
		_, _ = fmt.Fprintln(os.Stdout, "sing-box version 1.14.1-routervpn-native."+preflightContextFixturePolicy)
	}
	os.Exit(0)
}

func desktopTorCallerNetwork(ctx context.Context) (string, error) {
	return "explicit-caller-test-network", ctx.Err()
}

func desktopTorCallerRequest(t *testing.T, f *desktopTorConnectFixture, ctx context.Context, q externalProfileConnectRequest) (*httptest.ResponseRecorder, <-chan struct{}) {
	t.Helper()
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/tor-bridge/connect", bytes.NewReader(raw)).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if f.unified {
			f.a.externalProfileConnectWithRuntime(w, r, externalConnectRuntime{tor: f.driver})
		} else {
			f.a.torBridgeConnectWithRuntime(w, r, f.driver)
		}
	}()
	return w, done
}

func desktopTorCallerJoin(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("original Tor caller did not join its entered operation")
	}
}

func TestDesktopTorCallerContextCancelsHeldRegistryAndInputOwners(t *testing.T) {
	for _, boundary := range []string{"selection", "predecessor", "prelaunch-capture", "speed-lab-prelaunch", "private-input"} {
		t.Run(boundary, func(t *testing.T) {
			a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
			operation, cancel := context.WithCancel(context.Background())
			defer cancel()
			a.connectionContext = operation
			held := &a.mu
			var prepared torBridgeRuntime
			if boundary == "prelaunch-capture" || boundary == "private-input" {
				a, prepared = desktopTorPreparedFixture(t, clientTorBridge)
				held = &prepared.Launch.workspaceMu
			}
			before := cloneRouterProfileStore(a.profiles)
			connectionAdmissionCancelHeld(t, held, func(ctx context.Context) error {
				switch boundary {
				case "selection":
					_, err := captureDesktopTorSelectionContext(ctx, a, profile, externalProfileConnectRequest{ProfileID: profile.ID}, nil)
					return err
				case "predecessor":
					_, err := captureDesktopTorPredecessorContext(ctx, a, profile, nil)
					return err
				case "speed-lab-prelaunch":
					_, err := a.speedLabTorPrelaunchCheckContext(ctx, operation, profile)
					return err
				case "prelaunch-capture":
					_, err := captureTorBridgePrelaunchContext(ctx, a, prepared.Launch.profileID, prepared.RuntimeDir, prepared.Launch)
					return err
				default:
					return writeDesktopTorInputContext(ctx, prepared.Launch, "torrc", []byte("not published"))
				}
			})
			if operation.Err() != nil || !reflect.DeepEqual(a.profiles, before) {
				t.Fatal("cancelled observer changed the retained source or original operation")
			}
		})
	}
}

func TestDesktopTorCallerContextResolverUsesPublicCompareAndTemporaryIntent(t *testing.T) {
	for _, path := range []string{"public", "unified", "compare", "temporary"} {
		t.Run(path, func(t *testing.T) {
			f := newDesktopTorConnectFixture(t)
			f.driver.readNetwork = desktopTorCallerNetwork
			f.unified = path == "unified"
			entry := &f.a.profiles.Profiles[1]
			originalEndpoint := entry.Endpoint
			entry.Endpoint = "entry.example.test"
			file := filepath.Join(clientRoot(f.a), "generated", entry.ID, "wg", "wg.conf")
			raw, err := os.ReadFile(file)
			if err != nil || !bytes.Contains(raw, []byte(originalEndpoint)) {
				t.Fatal("resolver fixture lost its actual private endpoint", err)
			}
			if err := os.WriteFile(file, bytes.ReplaceAll(raw, []byte(originalEndpoint), []byte(entry.Endpoint)), 0600); err != nil {
				t.Fatal(err)
			}
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			f.driver.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
				if host != "entry.example.test" {
					return nil, errors.New("resolver received another captured endpoint")
				}
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			profile := f.a.profiles.Profiles[0]
			before := cloneRouterProfileStore(f.a.profiles)
			var response *httptest.ResponseRecorder
			var done <-chan struct{}
			var result error
			var original context.Context
			if path == "public" || path == "unified" {
				response, done = desktopTorCallerRequest(t, f, request, externalProfileConnectRequest{ProfileID: profile.ID})
			} else {
				operation, retire := context.WithCancel(context.Background())
				defer retire()
				original = operation
				f.a.connectionContext, f.a.connectionCancel = operation, retire
				f.driver.operation, f.driver.requestContext = operation, request
				joined := make(chan struct{})
				done = joined
				if path == "temporary" {
					owner := &speedLabTemporaryOwner{intent: operation, test: operation, current: operation, network: "explicit-caller-test-network"}
					speedLabTemporaryOwners.Store(f.a, owner)
					t.Cleanup(func() { speedLabTemporaryOwners.Delete(f.a) })
				}
				go func() {
					defer close(joined)
					if path == "compare" {
						_, result = newDesktopTorComparisonDriver(f.a, profile, externalProfileConnectRequest{ProfileID: profile.ID, Execution: "auto"}, nil, f.driver)
					} else {
						q := speedLabRequest{NodeID: profile.ID, EntryID: profile.MultihopEntryID, EntryMode: "wg", Execution: "local"}
						_, result = f.a.prepareSpeedLabTorPathWithRuntime(q, speedLabProfileOverrides(profile, q), nil, f.driver)
					}
				}()
			}
			select {
			case <-entered:
			case <-done:
				t.Fatalf("Tor %s never entered its captured resolver: %v, %v", path, result, response)
			case <-time.After(3 * time.Second):
				cancel()
				t.Fatal("Tor resolver admission did not complete")
			}
			cancel()
			desktopTorCallerJoin(t, done)
			if response != nil && response.Code == http.StatusOK || response == nil && result == nil || f.launch != nil || f.commands != 0 || f.preflight != 0 || !reflect.DeepEqual(before, f.a.profiles) || original != nil && original.Err() != nil {
				t.Fatal("cancelled Tor resolver published a path, rewrote sources, or cancelled another owner", result)
			}
		})
	}
}

func TestDesktopTorCallerContextPrelaunchCancelsBeforeHeldRegistry(t *testing.T) {
	a, prepared := desktopTorPreparedFixture(t, clientTorBridge)
	owner := desktopTorPreparedOwner(t, a, prepared)
	owner.command = exec.Command(os.Args[0], "-test.run=^TestStartupExternalProcessFixture$")
	owner.command.Env = envWithValue(os.Environ(), "ROUTERVPN_STARTUP_EXTERNAL_CHILD", "cleanup")
	connectionAdmissionCancelHeld(t, &a.mu, func(ctx context.Context) error {
		return owner.startContext(ctx, ctx.Err)
	})
	if owner.command.Process != nil || a.cmd != nil || a.state.Connected {
		t.Fatal("cancelled prelaunch passed the held original registry")
	}
	if _, exists := desktopNodeOwners.Load(a); exists {
		t.Fatal("cancelled prelaunch retained a native owner")
	}
	if _, err := os.Stat(prepared.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled prelaunch did not retire its unused inputs", err)
	}
}

func TestDesktopTorCallerContextRejectsLatePreflightAndRecordedDisconnect(t *testing.T) {
	for _, change := range []string{"request", "operation", "generation", "disconnect-intent", "command-request", "live"} {
		t.Run(change, func(t *testing.T) {
			f := newDesktopTorConnectFixture(t)
			f.driver.readNetwork = desktopTorCallerNetwork
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			before := cloneRouterProfileStore(f.a.profiles)
			var replacement context.Context
			preflight := f.driver.preflight
			f.driver.preflight = func(ctx context.Context, binary string, args, environment []string, directory string) error {
				if err := preflight(ctx, binary, args, environment, directory); err != nil {
					return err
				}
				if f.preflight != 1 {
					return nil
				}
				switch change {
				case "request":
					cancel()
				case "operation":
					f.a.mu.Lock()
					retire := f.a.connectionCancel
					f.a.mu.Unlock()
					retire()
				case "generation":
					var retire context.CancelFunc
					replacement, retire = context.WithCancel(context.Background())
					t.Cleanup(retire)
					f.a.mu.Lock()
					f.a.connectionContext, f.a.connectionCancel = replacement, retire
					f.a.state.Phase = "replacement-requested"
					f.a.mu.Unlock()
				case "disconnect-intent":
					f.a.mu.Lock()
					f.a.connectionCancelIntent = f.a.connectionContext
					if f.a.connectionContext.Err() != nil {
						t.Error("fixture cancelled before recording Disconnect intent")
					}
					f.a.mu.Unlock()
				}
				return nil
			}
			if change == "command-request" {
				command := f.driver.command
				f.driver.command = func(a *app, prepared torBridgeRuntime, environment []string) (*exec.Cmd, error) {
					cmd, err := command(a, prepared, environment)
					cancel()
					return cmd, err
				}
			}
			response, done := desktopTorCallerRequest(t, f, request, externalProfileConnectRequest{ProfileID: before.SelectedID})
			desktopTorCallerJoin(t, done)
			if change == "live" {
				if response.Code != http.StatusOK || !f.a.state.Connected || f.launch == nil || f.launch.command.Process == nil || f.preflight != 2 || f.commands != 1 {
					t.Fatal("ordinary live original caller could not prove and adopt its actual fixture child", response.Code, response.Body.String())
				}
				stopDesktopTorLifecycleFixture(t, f.a)
				return
			}
			if response.Code == http.StatusOK || f.launch == nil || f.launch.command != nil && f.launch.command.Process != nil || !reflect.DeepEqual(before, f.a.profiles) {
				t.Fatal("late caller reached exec.Start or changed saved sources", response.Code, response.Body.String())
			}
			if change != "command-request" && (f.preflight != 1 || f.commands != 0) {
				t.Fatal("retired preflight was allowed to prepare a later child", f.preflight, f.commands)
			}
			if _, err := os.Stat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cancelled Tor preparation retained its exact unused private workspace", err)
			}
			if replacement != nil && (f.a.connectionContext != replacement || replacement.Err() != nil || f.a.state.Phase != "replacement-requested") {
				t.Fatal("retired caller finish changed the replacement operation")
			}
		})
	}
}

func TestDesktopTorCallerContextJoinsActualVerificationChildren(t *testing.T) {
	for _, phase := range []string{"native-version", "tor-version", "help", "check"} {
		t.Run(phase, func(t *testing.T) {
			f := newDesktopTorConnectFixture(t)
			f.driver.readNetwork = desktopTorCallerNetwork
			directory := t.TempDir()
			t.Setenv("ROUTERVPN_TOR_CALLER_CHILD", "1")
			t.Setenv("ROUTERVPN_TOR_CALLER_DIRECTORY", directory)
			t.Setenv("ROUTERVPN_TOR_CALLER_HOLD", phase)
			t.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0")
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			f.driver.runtime = nil
			f.driver.runtimeContext = func(ctx context.Context, root string, policy, profile common.RouterProfile, predecessor *desktopTorPredecessorCapture) (torBridgeRuntime, error) {
				if _, err := verifyBundledNativeVersion(ctx, binary, directory, preflightContextFixturePolicy); err != nil {
					return torBridgeRuntime{}, err
				}
				if _, err := verifyBundledTorVersion(ctx, binary, directory); err != nil {
					return torBridgeRuntime{}, err
				}
				prepared, err := stageDesktopTorInputsWithPredecessorContext(ctx, root, policy, profile, binary, binary, predecessor)
				f.launch = prepared.Launch
				return prepared, err
			}
			f.driver.preflight = runDesktopExternalPreflightCommand
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			response, done := desktopTorCallerRequest(t, f, request, externalProfileConnectRequest{ProfileID: f.a.profiles.SelectedID})
			var child preflightContextChild
			until := time.After(3 * time.Second)
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for child.PID == 0 {
				if raw, err := os.ReadFile(filepath.Join(directory, phase+".json")); err == nil {
					_ = json.Unmarshal(raw, &child)
				}
				if child.PID != 0 {
					break
				}
				select {
				case <-done:
					t.Fatal("Tor did not enter its actual finite child", phase, response.Code, response.Body.String())
				case <-until:
					cancel()
					desktopTorCallerJoin(t, done)
					t.Fatal("Tor finite child never entered", phase)
				case <-ticker.C:
				}
			}
			process, err := os.FindProcess(child.PID)
			if err != nil {
				t.Fatal(err)
			}
			defer process.Release()
			defer process.Kill()
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				_ = process.Kill()
				desktopTorCallerJoin(t, done)
				t.Fatal("original caller did not stop and join its verifier", phase)
			}
			if response.Code == http.StatusOK || f.commands != 0 {
				t.Fatal("cancelled verifier allowed the tunnel child to start", phase)
			}
			if runtime.GOOS != "windows" {
				if _, err := process.Wait(); err == nil {
					t.Fatal("verifier returned before its actual child was reaped")
				}
			}
			if f.launch != nil {
				if _, err := os.Stat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("cancelled preflight retained its unused workspace", err)
				}
			}
		})
	}
}

func TestDesktopTorCallerContextShippingRuntimeAndHashKeepOriginalCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	file := installFakeExecutable(t, t.TempDir(), "captured-tor")
	if _, err := captureDesktopTorExecutableContext(ctx, file); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled hash returned an executable identity", err)
	}
	if _, err := verifyBundledTorContext(ctx, t.TempDir()); err == nil {
		t.Fatal("cancelled bundle verifier attempted a new verification")
	}
	for _, check := range []struct{ file, function, required string }{
		{"desktop_tor_prepare.go", "func prepareTorBridgeCommandWithRuntimeContext", "driver.runtimeContext(ctx, root, policy, profile, predecessor)"},
		{"desktop_tor_prepare.go", "func prepareTorBridgeRuntimeWithPredecessorContext", "verifyBundledNativeContext(ctx, desktopAmneziaPackageRoot())"},
		{"desktop_tor_prepare.go", "func prepareTorBridgeRuntimeWithPredecessorContext", "stageDesktopTorInputsWithPredecessorContext(ctx, root, policy, profile, tor, native, predecessor)"},
		{"desktop_tor_prepare.go", "func stageDesktopTorInputsWithPredecessorContext", "captureDesktopTorExecutableContext(ctx, tor)"},
		{"tor_bridge_runtime.go", "func torBridgeRuntimeCapabilityForExecutionContext", "verifyBundledNativeContext(ctx, desktopAmneziaPackageRoot())"},
		{"bundled_tor.go", "func verifyBundledTorVersion", "context.WithTimeout(ctx, 5*time.Second)"},
	} {
		if source := sourceFunctionForTest(t, check.file, check.function); !strings.Contains(source, check.required) {
			t.Fatal("shipping Tor verification detached its original caller", check.file, check.required)
		}
	}
}

func TestDesktopTorCallerContextRestoreEntryKeepsOriginalCleanupWhileHeld(t *testing.T) {
	for _, boundary := range []string{"restore", "restart"} {
		t.Run(boundary, func(t *testing.T) {
			a, _, _ := desktopTorEntryFixture(t, "198.51.100.8")
			request, cancelRequest := context.WithCancel(context.Background())
			cancelRequest()
			driver := desktopTorConnectRuntime{requestContext: request}
			plan := speedLabRestorePlan{tor: &speedLabTorRestore{}}
			before := cloneRouterProfileStore(a.profiles)
			connectionAdmissionCancelHeld(t, &a.mu, func(cleanup context.Context) error {
				if boundary == "restart" {
					return a.speedLabRestartPlanWithTorRuntimeContext(cleanup, plan, driver)
				}
				return a.startSpeedLabTorRestoreWithRuntimeContext(cleanup, plan, driver)
			})
			if a.connectionContext != nil || a.cmd != nil || !reflect.DeepEqual(before, a.profiles) {
				t.Fatal("expired cleanup admission changed a replacement or installed old profiles")
			}
		})
	}
}

func TestDesktopTorCallerContextCoordinatorPassesExactIndependentRestoreOperation(t *testing.T) {
	a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
	type restoreKey struct{}
	intent, cancelIntent := context.WithCancel(context.WithValue(context.Background(), restoreKey{}, "original restoration intent"))
	defer cancelIntent()
	test, cancelTest := context.WithCancel(intent)
	defer cancelTest()
	command := &exec.Cmd{}
	owner := &speedLabTemporaryOwner{intent: intent, test: test, current: test, cancelIntent: cancelIntent, cancelTest: cancelTest, runtime: command, mutated: true, network: "captured-restore-network"}
	a.connectionContext, a.connectionCancel, a.cmd = test, cancelIntent, command
	a.state = state{Connected: true, Phase: "connected", RouterID: profile.ID}
	snapshot := speedLabTemporarySnapshot{Owner: owner, Profiles: cloneRouterProfileStore(a.profiles), State: a.state, Plan: speedLabRestorePlan{profile: profile}}
	speedLabTemporaryOwners.Store(a, owner)
	t.Cleanup(func() { speedLabTemporaryOwners.Delete(a) })
	cancelTest() // Simulates the already-ended HTTP measurement, not Disconnect.
	var captured context.Context
	starts := 0
	actions := speedLabRestoreActions{
		stop: speedLabFakeStop(a, owner), persist: func(common.RouterProfileStore) error { return nil }, network: func() string { return owner.network },
		restart: func(speedLabRestorePlan) error {
			return errors.New("shipping coordinator used the contextless restart")
		},
		restartContext: func(cleanup context.Context, _ speedLabRestorePlan) error {
			starts++
			captured = cleanup
			deadline, bounded := cleanup.Deadline()
			if cleanup != owner.current || cleanup != a.connectionContext || cleanup == test || cleanup.Err() != nil || cleanup.Value(restoreKey{}) != "original restoration intent" || !bounded || time.Until(deadline) > 180*time.Second {
				return errors.New("coordinator substituted or renewed its captured cleanup operation")
			}
			fresh := &exec.Cmd{}
			a.mu.Lock()
			a.cmd, owner.runtime, a.state = fresh, fresh, snapshot.State
			a.mu.Unlock()
			return nil
		},
	}
	if err := a.speedLabRestoreWith(snapshot, actions); err != nil || starts != 1 || captured == nil || !owner.restored || intent.Err() != nil {
		t.Fatal("cancelled test did not restore under the exact independent cleanup owner", err)
	}
	if captured.Err() != context.Canceled {
		t.Fatal("coordinator did not end its original cleanup allowance after completion")
	}
	for _, edge := range []struct{ file, function, call string }{
		{"speed_lab_paths.go", "func (a *app) speedLabRestoreTemporary", "restartContext: a.speedLabRestartPlanContext"},
		{"desktop_external_comparison_runner.go", "func (a *app) desktopComparisonRuntime", "restartContext: a.speedLabRestartPlanContext"},
		{"speed_lab_transaction.go", "func (a *app) speedLabRestoreWith", "actions.restartContext(restoreCtx, snapshot.Plan)"},
		{"speed_lab_transaction.go", "func (a *app) speedLabRestartPlanWithTorRuntimeContext", "a.startSpeedLabTorRestoreWithRuntimeContext(ctx, plan, torDriver)"},
	} {
		if !strings.Contains(sourceFunctionForTest(t, edge.file, edge.function), edge.call) {
			t.Fatal("shipping restore lost the coordinator's exact context", edge.file)
		}
	}
}

func TestDesktopTorCallerContextInitialRegistryRetainsDisconnectOperation(t *testing.T) {
	for _, boundary := range []string{"external", "temporary-preview"} {
		t.Run(boundary, func(t *testing.T) {
			a, profile, _ := desktopTorEntryFixture(t, "198.51.100.8")
			parent, cancelOperation := context.WithCancel(context.Background())
			defer cancelOperation()
			operation := &connectionAdmissionWaitingContext{Context: parent, waiting: make(chan struct{})}
			request, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			a.connectionContext, a.connectionCancel = operation, cancelOperation
			driver := desktopTorConnectRuntime{operation: operation, requestContext: request}
			a.mu.Lock()
			var once sync.Once
			unlock := func() { once.Do(a.mu.Unlock) }
			defer unlock()
			done := make(chan error, 1)
			go func() {
				if boundary == "external" {
					w := httptest.NewRecorder()
					a.externalProfileConnectOwned(w, externalProfileConnectRequest{ProfileID: profile.ID}, "", nil, externalConnectRuntime{tor: driver})
					if w.Code != http.StatusConflict {
						done <- fmt.Errorf("cancelled initial registry returned %d: %s", w.Code, w.Body.String())
						return
					}
					done <- nil
					return
				}
				prepared, err := a.prepareSpeedLabExternalPathWithRuntime(speedLabRequest{NodeID: profile.ID}, nil, driver)
				if prepared != nil || !errors.Is(err, context.Canceled) {
					done <- fmt.Errorf("cancelled preview retained an unrelated caller: %v", err)
					return
				}
				done <- nil
			}()
			// The operation must be subscribed before the first held registry
			// lock, even while the independent HTTP request remains live.
			select {
			case <-operation.waiting:
			case err := <-done:
				t.Fatal("initial admission omitted its original operation", err)
			case <-time.After(2 * time.Second):
				cancelRequest()
				unlock()
				<-done
				t.Fatal("initial registry never subscribed to Disconnect")
			}
			cancelOperation()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				cancelRequest()
				unlock()
				<-done
				t.Fatal("Disconnect waited for an unrelated registry owner")
			}
			if request.Err() != nil {
				t.Fatal("operation cancellation replaced HTTP intent")
			}
		})
	}
	public := sourceFunctionForTest(t, "tor_bridge_routes.go", "func (a *app) torBridgeConnectWithRuntime")
	if !strings.Contains(public, "desktopnetwork.LockContext(operation, &a.mu)") {
		t.Fatal("public Tor profile admission detached the already-captured operation")
	}
}
