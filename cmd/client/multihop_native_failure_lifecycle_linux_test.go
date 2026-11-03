package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// This fixture replaces installed-engine/proof boundaries only. The real
// compiler, private staging, child process, Stop acknowledgement, workspace,
// graph registry and public handler transaction execute on Linux.
type nativeMultihopFailureFixture struct {
	a        *app
	driver   nativeMultihopConnectRuntime
	launches []*desktopNodeLaunch
	proof    func(*desktopNodeLaunch) error
	root     string
	hold     string
	release  string
}

func newNativeMultihopFailureFixture(t *testing.T, policy string) *nativeMultihopFailureFixture {
	t.Helper()
	root, sel := nativeMultihopCapturedFixture(t, "wg", "off")
	t.Setenv("HOMEVPN_ROOT", root)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	directory := filepath.Join(root, "runtime", "native")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	// Platform dispatch only; the injected image boundary is not package proof.
	if err := os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	sel.Control.ID = "control"
	sel.Control.MTUPolicy, sel.Control.ManualMTU = "manual", 1420
	sel.Control.KillSwitch, sel.Control.KillSwitchPolicy = true, policy
	sel.Control.MultihopEntryID, sel.Control.MultihopExitID, sel.Control.MultihopEntryMode = sel.Entry.ID, sel.Exit.ID, "wg"
	a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json"), ScriptsDir: filepath.Join(root, "modes")}, profiles: common.RouterProfileStore{SchemaVersion: 4, SelectedID: sel.Control.ID, Profiles: []common.RouterProfile{sel.Control, sel.Entry, sel.Exit}}, state: state{Mode: "off", Phase: "off"}}
	if err := a.persistProfilesLocked(); err != nil {
		t.Fatal(err)
	}
	release := externalFailureReleaseHelper(t, a, 0)
	f := &nativeMultihopFailureFixture{a: a, root: root, release: release}
	f.driver = nativeMultihopConnectRuntime{
		capture: func(a *app, selection multihopSelection, modes []string) (multihopSelection, error) {
			return captureNativeMultihopSelection(a.connectionOperationContextOrBackground(), root, selection, modes, nil)
		},
		preflight: func(_ *app, selection multihopSelection, descriptor *desktopExecutionDescriptor) (*desktopNodeLaunch, error) {
			return compileRetainedNativeMultihopLaunch(selection, descriptor)
		},
		stage: func(a *app, selection multihopSelection, launch *desktopNodeLaunch) error {
			if err := stageOwnedNativeMultihopCommand(a, selection, launch); err != nil {
				return err
			}
			prior := launch.command
			launch.command = exec.Command(os.Args[0], "-test.run=^TestMTUStopChildFixture$")
			launch.command.Dir = prior.Dir
			launch.command.Env = append(prior.Env, "ROUTERVPN_MTU_STOP_TEST_DIRECTORY="+launch.directory, "ROUTERVPN_MTU_STOP_TEST_SESSION="+launch.mtuSession, "ROUTERVPN_MTU_STOP_TEST_CONFIG="+launch.configSHA256)
			if f.hold != "" {
				launch.command.Args[1] = "-test.run=^TestNativeMultihopHeldStopChild$"
				launch.command.Env = append(launch.command.Env, "ROUTERVPN_MULTIHOP_STOP_HOLD="+f.hold)
			}
			launch.stop = []string{os.Args[0], "-test.run=^TestNativeMultihopFailureStopBoundary$"}
			f.launches = append(f.launches, launch)
			return nil
		},
		proof: func(a *app, selection multihopSelection, command *exec.Cmd) error {
			launch := f.launches[len(f.launches)-1]
			if selection.Native == nil || selection.Native.validate(selection) != nil || command != launch.command || !a.ownsConnectionRuntime(command) {
				return errors.New("proof boundary lost original captured graph")
			}
			if f.proof != nil {
				return f.proof(launch)
			}
			return errors.New("modeled authenticated exit proof rejected")
		},
	}
	t.Cleanup(func() {
		for _, launch := range f.launches {
			if launch.command.Process != nil {
				_ = launch.command.Process.Kill()
				<-desktopNodeProcessDone(launch)
			}
			if launch.directoryRoot != nil {
				_ = launch.directoryRoot.Close()
			}
		}
		desktopNodeOwners.Delete(a)
		nativeMultihopOwners.Delete(a)
		activeMultihopGraphs.Delete(a)
		activeDNSRuntimeIdentities.Delete(a)
		sessionTrackers.Delete(a)
		homeExitProofs.Delete(a)
		strategyLocks.Delete(a)
		mtuSuspensions.Delete(a)
	})
	return f
}

func TestNativeMultihopFailureStopBoundary(t *testing.T) {
	// The original child supplied the exact stopped receipt before this wrapper
	// boundary executes; no process/protection success is inferred from this stub.
}

func (f *nativeMultihopFailureFixture) connect() *httptest.ResponseRecorder {
	body, _ := json.Marshal(multihopConnectRequest{EntryID: "entry", ExitID: "exit", EntryMode: "wg", ExitMode: "shadowsocks", Base: "wg", Execution: "local"})
	response := httptest.NewRecorder()
	f.a.nativeMultihopConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(body)), f.driver)
	return response
}

func TestNativeMultihopFailedConnectCanDisconnect(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newNativeMultihopFailureFixture(t, policy)
			response := f.connect()
			if response.Code != http.StatusBadGateway || len(f.launches) != 1 {
				t.Fatal("actual failed graph was not reached", response.Code, response.Body.String())
			}
			failed := f.a.state
			if _, present := desktopNodeOwners.Load(f.a); present {
				t.Fatal("joined failed graph retained node owner")
			}
			if _, present := nativeMultihopOwners.Load(f.a); present {
				t.Fatal("joined failed graph retained runtime owner")
			}
			if _, present := getActiveMultihopGraph(f.a); present {
				t.Fatal("joined failed graph retained presentation graph")
			}
			history := sessionTrackerFor(f.a).snapshot(0)
			before, _ := os.ReadFile(f.release)
			disconnected := externalFailureDisconnect(f.a)
			after, err := os.ReadFile(f.release)
			if err != nil || len(after) <= len(before) {
				t.Fatal("explicit Disconnect bypassed protection release", err)
			}
			if disconnected.Code != http.StatusOK {
				t.Fatal("Disconnect after joined native multihop failure", disconnected.Code, disconnected.Body.String())
			}
			if failed.Mode != "off" || failed.LogicalMode != "" || failed.RuntimeMode != "" || failed.Base != "" || failed.Phase != "failed" || failed.LastError == "" || history.RequestedMode != "multihop" || history.Phase != "failed" || history.Error == nil {
				t.Fatal("joined native failure lost off identity or requested history", failed, history)
			}
			if f.a.profiles.Profiles[0].KillSwitchPolicy != policy {
				t.Fatal("failure altered saved protection policy")
			}
		})
	}
}

func TestNativeMultihopFailedConnectRetainsExactCleanupGraph(t *testing.T) {
	f := newNativeMultihopFailureFixture(t, "on-connect")
	var original *nativeMultihopRuntime
	var graph activeMultihopGraph
	var marker string
	f.proof = func(launch *desktopNodeLaunch) error {
		value, _ := nativeMultihopOwners.Load(f.a)
		original = value.(*nativeMultihopRuntime)
		graph, _ = getActiveMultihopGraph(f.a)
		marker = filepath.Join(launch.directory, "unowned-replacement-file")
		if err := os.WriteFile(marker, []byte("retain this exact workspace"), 0600); err != nil {
			return err
		}
		return errors.New("modeled proof refusal before partial private cleanup")
	}
	response := f.connect()
	if response.Code != http.StatusInternalServerError || len(f.launches) != 1 || f.a.cmd != nil {
		t.Fatal("partial private cleanup was not reached", response.Code, response.Body.String())
	}
	launch := f.launches[0]
	owner, present := desktopNodeOwners.Load(f.a)
	retained, found := nativeMultihopOwners.Load(f.a)
	current, currentOK := getActiveMultihopGraph(f.a)
	if !present || owner != launch || !found || retained != original || !currentOK || current != graph || f.a.state.Mode != "multihop" || f.a.state.RuntimeMode != original.selection.ExitMode || f.a.state.RouterID != original.selection.Exit.ID || f.a.state.Phase != "failed" || !strings.Contains(f.a.state.LastError, "runtime cleanup failed") {
		t.Fatal("partial native cleanup lost complete original graph identity", f.a.state)
	}
	if !launch.nodeStopAcknowledged || !desktopNodeProcessExited(launch) {
		t.Fatal("private cleanup failure was confused with unjoined original process")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	retry := externalFailureDisconnect(f.a)
	if retry.Code != http.StatusOK || f.a.state.Mode != "off" {
		t.Fatal("exact original native cleanup retry failed", retry.Code, retry.Body.String())
	}
	if _, present := nativeMultihopOwners.Load(f.a); present {
		t.Fatal("retry retained graph owner")
	}
}

func TestNativeMultihopFailedConnectCanStartNewGraph(t *testing.T) {
	for _, policy := range []string{"on-connect", "always"} {
		t.Run(policy, func(t *testing.T) {
			f := newNativeMultihopFailureFixture(t, policy)
			if failed := f.connect(); failed.Code != http.StatusBadGateway {
				t.Fatal(failed.Code, failed.Body.String())
			}
			f.proof = func(*desktopNodeLaunch) error { return nil }
			next := f.connect()
			if next.Code != http.StatusOK || len(f.launches) != 2 || !f.a.state.Connected || f.launches[0] == f.launches[1] {
				t.Fatal("new native graph reused failed runtime", next.Code, next.Body.String())
			}
			if stopped := externalFailureDisconnect(f.a); stopped.Code != http.StatusOK {
				t.Fatal(stopped.Code, stopped.Body.String())
			}
		})
	}
}

func TestNativeMultihopHeldStopChild(t *testing.T) {
	hold := os.Getenv("ROUTERVPN_MULTIHOP_STOP_HOLD")
	if hold == "" {
		return
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(hold); err == nil {
			TestMTUStopChildFixture(t)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("held child did not receive its bounded release")
}

func TestNativeMultihopFailedConnectPreservesReplacementDuringCleanup(t *testing.T) {
	f := newNativeMultihopFailureFixture(t, "on-connect")
	f.hold = filepath.Join(t.TempDir(), "allow-stopped")
	replacement := exec.Command("replacement-not-started")
	replaced := make(chan error, 1)
	f.proof = func(launch *desktopNodeLaunch) error {
		go func() {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(filepath.Join(launch.directory, "stop.json")); err == nil {
					tracker := sessionTrackerFor(f.a)
					tracker.declareRequest("replacement-request", "replacement-base")
					f.a.mu.Lock()
					f.a.cmd = replacement
					f.a.state = state{Mode: "replacement-mode", LogicalMode: "replacement-logical", RuntimeMode: "replacement-runtime", RouterID: "replacement-node", Phase: "replacement-phase", LastError: "replacement-error", Connected: true}
					f.a.mu.Unlock()
					replaced <- os.WriteFile(f.hold, []byte("release original child"), 0600)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			replaced <- errors.New("original Stop request was not observed")
		}()
		return errors.New("modeled proof failure with concurrent owner replacement")
	}
	response := f.connect()
	if err := <-replaced; err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusConflict {
		t.Fatal("stale cleanup completion adopted replacement", response.Code, response.Body.String())
	}
	f.a.mu.Lock()
	actual, command := f.a.state, f.a.cmd
	f.a.mu.Unlock()
	history := sessionTrackerFor(f.a).snapshot(0)
	if command != replacement || actual.Mode != "replacement-mode" || actual.RouterID != "replacement-node" || actual.Phase != "replacement-phase" || actual.LastError != "replacement-error" || !actual.Connected || history.RequestedMode != "replacement-request" || history.Error != nil {
		t.Fatal("stale cleanup changed replacement state or history", actual, history)
	}
}
