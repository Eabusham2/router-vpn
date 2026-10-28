package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/routechoice"
)

const preflightContextFixturePolicy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// The fixture child is the current Go test executable. It owns no tunnel,
// routes, firewall or network sockets. Only the private package-verification
// boundary is overlaid below; driver, captured graph, command construction,
// version/help/check processes, cancellation, Wait and workspace cleanup are
// the unchanged shipping implementations.
func init() {
	if os.Getenv("ROUTERVPN_PREFLIGHT_CHILD") != "1" || len(os.Args) < 2 {
		return
	}
	phase := os.Args[1]
	if phase == "routervpn-node" {
		phase = "help"
	}
	if phase != "version" && phase != "help" && phase != "check" {
		return
	}
	directory := os.Getenv("ROUTERVPN_PREFLIGHT_CHILD_DIR")
	cwd, err := os.Getwd()
	if err != nil {
		os.Exit(35)
	}
	if phase == os.Getenv("ROUTERVPN_PREFLIGHT_HOLD") {
		// Exercise exec's real output-copy workers before cancellation.
		_, _ = fmt.Fprintln(os.Stdout, "owned preflight child entered")
		_, _ = fmt.Fprintln(os.Stderr, "owned preflight diagnostic entered")
	}
	entered, _ := json.Marshal(preflightContextChild{PID: os.Getpid(), Directory: cwd})
	if os.WriteFile(filepath.Join(directory, phase+".json"), entered, 0600) != nil {
		os.Exit(36)
	}
	if phase == os.Getenv("ROUTERVPN_PREFLIGHT_HOLD") {
		until := time.Now().Add(4 * time.Second)
		for time.Now().Before(until) {
			if _, err := os.Stat(filepath.Join(directory, "release")); err == nil {
				os.Exit(37) // An ignored cancellation never becomes a success.
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(38)
	}
	if phase == "version" {
		_, _ = fmt.Fprintln(os.Stdout, "sing-box version 1.14.1-routervpn-native."+preflightContextFixturePolicy)
	}
	os.Exit(0)
}

type preflightContextChild struct {
	PID       int    `json:"pid"`
	Directory string `json:"directory"`
}

// This function is referenced only by the declared overlay in this test. It
// substitutes the package/build-metadata verifier, then executes the actual
// production version check. The strict verifier's receipt/hash/provenance
// tests still execute against the real implementation without this overlay.
func preflightContextPackageBoundary(ctx context.Context, _ string) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", errors.New("fixture package owner is canceled")
	}
	binary, err := os.Executable()
	if err != nil {
		return "", err
	}
	return verifyBundledNativeVersion(ctx, binary, os.Getenv("ROUTERVPN_PREFLIGHT_CHILD_DIR"), preflightContextFixturePolicy)
}

func runPreflightContextOverlay(t *testing.T) {
	t.Helper()
	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(module, "cmd", "client", "multihop_native_launch.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := "verifyBundledNativeContext(ctx, desktopAmneziaPackageRoot())"
	if strings.Count(string(source), old) != 1 {
		t.Fatal("the explicit package-verification boundary changed")
	}
	directory := t.TempDir()
	overlaySource := filepath.Join(directory, "multihop_native_launch.go")
	if err := os.WriteFile(overlaySource, []byte(strings.Replace(string(source), old, "preflightContextPackageBoundary(ctx, desktopAmneziaPackageRoot())", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	replacements := map[string]string{path: overlaySource}
	// A caller's deliberate production mutation remains active inside the
	// composed test; it cannot be hidden by this one explicit dependency overlay.
	if active := os.Getenv("ROUTERVPN_PREFLIGHT_MUTATION_OVERLAY"); active != "" {
		var prior struct{ Replace map[string]string }
		body, err := os.ReadFile(active)
		if err != nil || json.Unmarshal(body, &prior) != nil {
			t.Fatal("invalid explicit preflight mutation overlay", err)
		}
		for original, replacement := range prior.Replace {
			if original == path {
				body, err := os.ReadFile(replacement)
				if err != nil || strings.Count(string(body), old) != 1 {
					t.Fatal("native preflight mutation changed the declared package boundary", err)
				}
				if err := os.WriteFile(overlaySource, []byte(strings.Replace(string(body), old, "preflightContextPackageBoundary(ctx, desktopAmneziaPackageRoot())", 1)), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				replacements[original] = replacement
			}
		}
	}
	overlay := filepath.Join(directory, "overlay.json")
	body, _ := json.Marshal(map[string]any{"Replace": replacements})
	if err := os.WriteFile(overlay, body, 0600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"test", "-overlay=" + overlay, "-count=1", "-timeout=30s", "-v", "-run=^TestDesktopMultihopCandidateContextOwnsPreflight$"}
	if executable, err := os.Executable(); err == nil {
		if metadata, err := buildinfo.ReadFile(executable); err == nil {
			for _, setting := range metadata.Settings {
				if setting.Key == "-race" && setting.Value == "true" {
					arguments = append(arguments, "-race")
				}
			}
		}
	}
	arguments = append(arguments, "./cmd/client")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), arguments...)
	command.Dir = module
	command.Env = append(os.Environ(), "ROUTERVPN_PREFLIGHT_BOUNDARY=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual candidate/preflight process gate failed: %v\n%s", err, output)
	}
	t.Logf("actual candidate/preflight process gate: %s", output)
}

func TestDesktopMultihopCandidateContextOwnsPreflight(t *testing.T) {
	if os.Getenv("ROUTERVPN_PREFLIGHT_BOUNDARY") != "1" {
		runPreflightContextOverlay(t)
		return
	}
	for _, phase := range []string{"version", "help", "check"} {
		for _, reason := range []string{"cancel", "deadline"} {
			t.Run(phase+"/"+reason, func(t *testing.T) {
				root, selection := nativeMultihopCapturedFixture(t, "wg", "off")
				t.Setenv("HOMEVPN_ROOT", root)
				selection, err := captureNativeMultihopSelection(context.Background(), root, selection, []string{"shadowsocks"}, nil)
				if err != nil {
					t.Fatal(err)
				}
				childDirectory := t.TempDir()
				t.Setenv("ROUTERVPN_PREFLIGHT_CHILD", "1")
				t.Setenv("ROUTERVPN_PREFLIGHT_CHILD_DIR", childDirectory)
				t.Setenv("ROUTERVPN_PREFLIGHT_HOLD", phase)
				// Race instrumentation remains enabled. Its default one-second
				// post-exit sleep is unrelated to the captured native phase.
				t.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0")
				intent, stopIntent := context.WithCancel(context.Background())
				defer stopIntent()
				original := &exec.Cmd{}
				a := &app{cmd: original, connectionContext: intent, connectionCancel: stopIntent}
				driver := &desktopExecutionDriver{a: a, selection: selection, network: physicalNetworkIdentity()}
				var ctx context.Context
				var cancel context.CancelFunc
				if reason == "deadline" {
					ctx, cancel = context.WithTimeout(intent, 3*time.Second)
				} else {
					ctx, cancel = context.WithCancel(intent)
				}
				defer cancel()
				type outcome struct {
					session routechoice.Session
					err     error
				}
				done := make(chan outcome, 1)
				go func() {
					session, err := driver.Open(ctx, routechoice.Candidate{Execution: routechoice.Local, Transport: "shadowsocks", EntryID: selection.Entry.ID, ExitID: selection.Exit.ID})
					done <- outcome{session, err}
				}()
				var entered preflightContextChild
				until := time.Now().Add(3 * time.Second)
				for entered.PID == 0 && time.Now().Before(until) {
					if raw, err := os.ReadFile(filepath.Join(childDirectory, phase+".json")); err == nil {
						_ = json.Unmarshal(raw, &entered)
					}
					if entered.PID == 0 {
						select {
						case result := <-done:
							t.Fatalf("candidate did not reach its actual %s child: %v", phase, result.err)
						case <-time.After(5 * time.Millisecond):
						}
					}
				}
				if entered.PID == 0 {
					t.Fatal("captured child did not enter")
				}
				process, err := os.FindProcess(entered.PID)
				if err != nil {
					t.Fatal(err)
				}
				defer process.Release()
				defer process.Kill()
				replacement := &exec.Cmd{}
				a.mu.Lock()
				a.cmd = replacement
				a.mu.Unlock()
				if reason == "cancel" {
					cancel()
				}
				<-ctx.Done()
				started := time.Now()
				var result outcome
				select {
				case result = <-done:
				case <-time.After(time.Second):
					_ = process.Kill()
					select {
					case <-done:
					case <-time.After(3 * time.Second):
					}
					t.Fatal("candidate cancellation did not stop and join its actual " + phase + " preflight child")
				}
				if result.err == nil || time.Since(started) > time.Second || intent.Err() != nil || !a.ownsConnectionRuntime(replacement) {
					t.Fatal("preflight canceled a different owner, returned success, or escaped its deadline", result.err)
				}
				if runtime.GOOS != "windows" {
					// Wait must already have reaped this child. A second successful
					// Wait would prove that the command returned without joining it.
					if _, err := process.Wait(); err == nil {
						t.Fatal("preflight returned before its child was joined")
					}
				}
				if phase != "version" {
					if _, err := os.Lstat(entered.Directory); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("owned preflight workspace survived cancellation", err)
					}
				}
				if result.session == nil {
					t.Fatal("driver lost its owned failed-start session")
				}
				cleanup, stopCleanup := context.WithTimeout(context.Background(), time.Second)
				defer stopCleanup()
				if err := result.session.Close(cleanup); err != nil || !a.ownsConnectionRuntime(replacement) {
					t.Fatal("failed preflight cleanup affected the replacement", err)
				}
				t.Logf("%s child %s joined in %s; live intent and replacement retained", phase, strconv.Itoa(entered.PID), time.Since(started))
			})
		}
	}
}

func TestNativePreflightContextRejectsMissingOrRetiredOwner(t *testing.T) {
	if _, err := verifyBundledNativeContext(nil, t.TempDir()); err == nil {
		t.Fatal("missing version-verification owner accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifyBundledNativeContext(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatal("retired candidate reached package verification", err)
	}
	if _, _, _, err := desktopExecutionCommandContext(ctx, &app{}, multihopSelection{}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("retired candidate reached command preparation", err)
	}
}
