package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Keep the explicit controller lifetime separate from the real connection
// transaction. Its returned finish is the exact closure used by public Connect,
// not a manually cleared app slot or cancellation of the native host lifetime.
func prepareDesktopExecutionOperationSessionModel(t *testing.T, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainExecutionSession, context.Context, func()) {
	t.Helper()
	f := newDesktopNodeChainOwnedFixture(t, 2)
	f.executionModel = &desktopExecutionOwnedModel{winner: winner}
	f.a.mu.Lock()
	f.a.connectionContext, f.a.connectionCancel = nil, nil
	f.a.state.Mode, f.a.state.Phase = "off", "off"
	f.a.mu.Unlock()
	caller, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	operation, finishOperation, err := f.a.beginConnectionOperationContext(caller)
	if err != nil {
		t.Fatal(err)
	}
	finish := sync.OnceFunc(finishOperation)
	t.Cleanup(finish)
	request := &desktopNodeChainExecutionRequest{capture: f.capture, native: f.selection.Native, requested: "auto"}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(operation, f.capture, f.selection, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	f.launch = launch
	session := &desktopNodeChainExecutionSession{app: f.a, launch: launch, execution: launch.chain.execution, selection: f.selection}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if err := session.Close(ctx); err != nil {
			t.Error("retained status fixture did not join original child", err)
		}
	})
	return f, session, operation, finish
}

func startDesktopExecutionOperationStatusModel(t *testing.T, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainExecutionSession, context.Context, func(), *http.ServeMux) {
	t.Helper()
	f, session, operation, finish := prepareDesktopExecutionOperationSessionModel(t, winner)
	t.Setenv("HOMEVPN_PORTABLE", "0")
	if err := session.startContext(operation); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	f.a.state.Connected, f.a.state.Phase = true, "connected"
	f.a.mu.Unlock()
	sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{
		ID: "retained-execution-status-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
	mux := http.NewServeMux()
	registerDesktopMultihopRoutes(mux, f.a)
	return f, session, operation, finish, mux
}

func getRetainedExecutionStatus(ctx context.Context, mux *http.ServeMux) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil).WithContext(ctx))
	return response
}

// The modeled child executes shipping staging, adoption and native registry
// methods. The registered GET and actual operation finish are production code;
// this is not an installed native OS or complete public Connect acceptance gate.
func TestNativeRegisteredExecutionStatusSurvivesOriginalOperationFinish(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, session, operation, finish, mux := startDesktopExecutionOperationStatusModel(t, winner)
			before := cloneRouterProfileStore(f.a.profiles)
			f.a.mu.Lock()
			err := session.execution.publicationCurrentLocked(operation, f.a, f.launch, f.selection)
			f.a.mu.Unlock()
			if err != nil || getRetainedExecutionStatus(operation, mux).Code != http.StatusOK {
				t.Fatal("original active execution operation is not publishable and observable", err)
			}
			finish()
			if !errors.Is(operation.Err(), context.Canceled) || f.a.connectionContext != nil || f.a.connectionCancel != nil || f.operation.Err() != nil {
				t.Fatal("real handler finish did not retire only its original operation")
			}
			caller, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			if err := session.Current(caller); err != nil {
				t.Fatal("handler finish retired the original native lifetime", err)
			}
			response := getRetainedExecutionStatus(caller, mux)
			var value struct {
				Connected bool   `json:"connected"`
				Execution string `json:"execution"`
			}
			var fields map[string]json.RawMessage
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || json.Unmarshal(response.Body.Bytes(), &fields) != nil ||
				!value.Connected || value.Execution != winner || fields["ordered_capture"] != nil || fields["ordered_nodes"] != nil {
				t.Fatalf("completed handler lost retained execution status: %d %s", response.Code, response.Body.String())
			}
			f.a.mu.Lock()
			err = session.execution.publicationCurrentLocked(caller, f.a, f.launch, f.selection)
			f.a.mu.Unlock()
			if err == nil || !reflect.DeepEqual(before, f.a.profiles) || f.starts != 1 {
				t.Fatal("retained observation admitted late publication, changed profiles or repeated startup")
			}
		})
	}
}

func TestNativeRetainedExecutionStatusRefusesChangedOriginalOwner(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, session, _, finish, mux := startDesktopExecutionOperationStatusModel(t, winner)
			finish()
			owner, execution, graph := session.native, session.execution, *session.graph
			for _, fault := range []string{"cancelled-caller", "missing-operation", "replacement-operation", "cancel-intent", "closing", "source", "observed-source", "graph", "registry", "command", "missing-proof"} {
				t.Run(fault, func(t *testing.T) {
					caller, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					switch fault {
					case "cancelled-caller":
						cancel()
					case "missing-operation":
						original := execution.operation
						execution.operation = nil
						defer func() { execution.operation = original }()
					case "replacement-operation":
						f.a.connectionContext = caller
						defer func() { f.a.connectionContext = nil }()
					case "cancel-intent":
						f.a.connectionCancelIntent = execution.operation
						defer func() { f.a.connectionCancelIntent = nil }()
					case "closing":
						f.a.closing = true
						defer func() { f.a.closing = false }()
					case "source":
						original := cloneRouterProfileStore(f.a.profiles)
						f.a.profiles.Profiles[0].APIToken = "changed-retained-source"
						defer func() { f.a.profiles = original }()
					case "observed-source":
						original, observe := cloneRouterProfileStore(f.a.profiles), owner.networkIdentityContext
						owner.networkIdentityContext = func(ctx context.Context) (string, error) {
							value, err := observe(ctx)
							f.a.mu.Lock()
							f.a.profiles.Profiles[0].APIToken = "changed-after-native-observation"
							f.a.mu.Unlock()
							return value, err
						}
						defer func() { f.a.profiles, owner.networkIdentityContext = original, observe }()
					case "graph":
						changed := graph
						changed.Started = changed.Started.Add(time.Second)
						activeMultihopGraphs.Store(f.a, changed)
						defer activeMultihopGraphs.Store(f.a, graph)
					case "registry":
						nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
						defer nativeMultihopOwners.Store(f.a, owner)
					case "command":
						f.a.cmd = exec.Command("replacement-retained-status-command")
						defer func() { f.a.cmd = f.launch.command }()
					case "missing-proof":
						proof := owner.execution
						owner.execution = nil
						defer func() { owner.execution = proof }()
					}
					before := cloneRouterProfileStore(f.a.profiles)
					response := getRetainedExecutionStatus(caller, mux)
					if response.Code != http.StatusConflict || strings.TrimSpace(response.Body.String()) != "ordered native route changed or is not ready for measurement" {
						t.Fatalf("retained status accepted changed original authority %s: %d %s", fault, response.Code, response.Body.String())
					}
					if fault != "observed-source" && !reflect.DeepEqual(before, f.a.profiles) {
						t.Fatal("refused retained status changed saved profiles")
					}
				})
			}
		})
	}
}
