//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Uses the original explicit Windows controller/child/kernel models to execute
// shipping source, proof, owner and status code. No installed OS proof is claimed.
func orderedPublicPerformanceOwner(t *testing.T, family string) *desktopNodeChainOwnedFixture {
	t.Helper()
	a, selection := orderedPerformanceFamilySelection(t, family)
	f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
	f.stagePublish(t)
	if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, f.launch); err != nil {
		t.Fatal(err)
	}
	if err := proveDesktopNodeChainContext(f.operation, f.a, f.selection, f.launch.command); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	f.a.state.Connected, f.a.state.Phase = true, "connected"
	f.a.mu.Unlock()
	sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "original-public-performance-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}})
	t.Setenv("HOMEVPN_PORTABLE", "0")
	return f
}

func TestNativeRegisteredOrderedStatusReturnsOriginalPerformanceCapture(t *testing.T) {
	for _, family := range []string{"ordinary", "socks5", "http-connect", "https-connect"} {
		t.Run(family, func(t *testing.T) {
			f := orderedPublicPerformanceOwner(t, family)
			before := cloneRouterProfileStore(f.a.profiles)
			identity, expected, count, err := captureOrderedPerformanceContext(f.operation, f.a)
			if err != nil || len(expected) != 64 || count != 3 || identity.Ordered == nil {
				t.Fatal("original modeled Performance owner did not capture", err)
			}
			mux := http.NewServeMux()
			registerDesktopMultihopRoutes(mux, f.a)
			get := func(ctx context.Context) *httptest.ResponseRecorder {
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil).WithContext(ctx))
				return response
			}
			response := get(f.operation)
			var value struct {
				Capture   string `json:"ordered_capture"`
				Nodes     int    `json:"ordered_nodes"`
				Connected bool   `json:"connected"`
				Supported bool   `json:"ordered_nodes_supported"`
			}
			var fields map[string]json.RawMessage
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &value) != nil || json.Unmarshal(response.Body.Bytes(), &fields) != nil ||
				value.Capture != expected || value.Nodes != count || !value.Connected || value.Supported != nativeNodeChainPlatformSupported() || fields["ordered_nodes_supported"] == nil {
				t.Fatal("registered native status omitted its original Performance capture", family, response.Code)
			}
			if !reflect.DeepEqual(before, f.a.profiles) {
				t.Fatal("public Performance status changed original profiles")
			}
			// Disconnected status cannot expose the last connected receipt.
			f.a.mu.Lock()
			f.a.state.Connected = false
			f.a.mu.Unlock()
			response = get(f.operation)
			fields = nil
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &fields) != nil || fields["ordered_capture"] != nil || fields["ordered_nodes"] != nil {
				t.Fatal("disconnected public status replayed an old Performance capture")
			}
		})
	}
}

func TestNativeRegisteredOrderedStatusRejectsChangedOrCancelledOwner(t *testing.T) {
	for _, family := range []string{"ordinary", "socks5", "http-connect", "https-connect"} {
		t.Run(family, func(t *testing.T) {
			f := orderedPublicPerformanceOwner(t, family)
			mux := http.NewServeMux()
			registerDesktopMultihopRoutes(mux, f.a)
			original, _ := nativeMultihopOwners.Load(f.a)
			graph, _ := getActiveMultihopGraph(f.a)
			tracker, _ := sessionTrackers.Load(f.a)
			for _, fault := range []string{"cancelled", "missing-owner", "replaced-owner", "graph", "missing-graph", "zero-graph", "session", "held-ready"} {
				t.Run(fault, func(t *testing.T) {
					before := cloneRouterProfileStore(f.a.profiles)
					ctx, cancel := context.WithCancel(f.operation)
					defer cancel()
					switch fault {
					case "cancelled":
						cancel()
					case "missing-owner":
						nativeMultihopOwners.Delete(f.a)
						defer nativeMultihopOwners.Store(f.a, original)
					case "replaced-owner":
						nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
						defer nativeMultihopOwners.Store(f.a, original)
					case "missing-graph":
						activeMultihopGraphs.Delete(f.a)
						defer activeMultihopGraphs.Store(f.a, graph)
					case "zero-graph":
						changed := graph
						changed.ChainNodes = 0
						activeMultihopGraphs.Store(f.a, changed)
						defer activeMultihopGraphs.Store(f.a, graph)
					case "graph":
						changed := graph
						changed.SourceSHA = strings.Repeat("e", 64)
						activeMultihopGraphs.Store(f.a, changed)
						defer activeMultihopGraphs.Store(f.a, graph)
					case "session":
						sessionTrackers.Store(f.a, &sessionTracker{a: f.a, session: &connectionSession{ID: "replaced", Connected: false}})
						defer sessionTrackers.Store(f.a, tracker)
					case "held-ready":
						var deadlineCancel context.CancelFunc
						ctx, deadlineCancel = context.WithTimeout(ctx, 50*time.Millisecond)
						defer deadlineCancel()
						f.launch.chain.mu.Lock()
						defer f.launch.chain.mu.Unlock()
					}
					request := httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil).WithContext(ctx)
					response := httptest.NewRecorder()
					started := time.Now()
					mux.ServeHTTP(response, request)
					if response.Code != http.StatusConflict || strings.TrimSpace(response.Body.String()) != "ordered native route changed or is not ready for measurement" ||
						request.Context() != ctx || !reflect.DeepEqual(before, f.a.profiles) || time.Since(started) > time.Second {
						t.Fatal("registered native status accepted an invalid original Performance owner", family, fault, response.Code)
					}
				})
			}
		})
	}
}

// The execution/session fixtures run the actual captured preparation, child
// adoption, graph publication and owner registry with explicit native models.
// A Compare winner labeled Local still owns a different execution adjunct.
func TestNativeRegisteredExecutionStatusPreservesWinnerWithoutGenericPerformance(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, session := prepareDesktopExecutionSessionModel(t, winner)
			t.Setenv("HOMEVPN_PORTABLE", "0")
			if err := session.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := session.Close(context.Background()); err != nil {
					t.Error("original modeled execution did not join", err)
				}
			})
			owner := session.native
			graph, ok := getActiveMultihopGraph(f.a)
			if !ok || owner == nil || owner.execution == nil || f.launch.chain.execution == nil ||
				owner.execution.currentContext(f.operation, f.launch, graph) != nil || graph.Execution != winner || f.launch.chain.ready != nil {
				t.Fatal("execution fixture lost its actual retained adoption")
			}
			f.a.mu.Lock()
			f.a.state.Connected, f.a.state.Phase = true, "connected"
			f.a.mu.Unlock()
			tracker := &sessionTracker{a: f.a, session: &connectionSession{ID: "original-execution-performance-session", Connected: true, Phase: "connected", PathProof: "passed", RouterID: f.selection.Control.ID}}
			sessionTrackers.Store(f.a, tracker)
			identity := speedLabPathIdentity{Tracker: tracker, SessionID: tracker.session.ID,
				StateToken: mtuStateSnapshotToken(f.a.state), RouterID: f.a.state.RouterID,
				Graph: graph, GraphOK: true, Ordered: owner, Command: f.launch.command, Network: owner.network}
			// This is the Windows registry branch: no platform snapshot may hide
			// the retained execution adjunct behind a Local winner label.
			f.a.mu.Lock()
			err := validateOrderedPerformanceOwnerLocked(f.a, identity, nil)
			f.a.mu.Unlock()
			if err == nil {
				t.Fatal("adopted execution acquired generic Local Performance owner", winner)
			}
			captured, err := captureMTUNodeChainSnapshotContext(f.operation, owner)
			if err != nil || captured.Execution != owner.execution || orderedPerformanceSnapshotTarget(captured) != "" {
				t.Fatal("adopted execution acquired generic Local policy target", winner, err)
			}
			if _, token, count, err := captureOrderedPerformanceContext(f.operation, f.a); err == nil || token != "" || count != 0 {
				t.Fatal("adopted execution exposed unsupported generic Performance rows")
			}
			mux := http.NewServeMux()
			registerDesktopMultihopRoutes(mux, f.a)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil).WithContext(f.operation))
			var fields map[string]json.RawMessage
			var value struct {
				Connected bool   `json:"connected"`
				Execution string `json:"execution"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &fields) != nil || json.Unmarshal(response.Body.Bytes(), &value) != nil ||
				!value.Connected || value.Execution != winner || fields["ordered_capture"] != nil || fields["ordered_nodes"] != nil {
				t.Fatal("registered native status lost its authenticated execution winner", winner, response.Code)
			}
		})
	}
}

// Every fault enters the actual registered route using the same adopted child.
// Restore the original associations before joined cleanup; no native verdict is
// inferred from these explicit controller/process models.
func TestNativeRegisteredExecutionStatusRejectsLostAuthority(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, session := prepareDesktopExecutionSessionModel(t, winner)
			t.Setenv("HOMEVPN_PORTABLE", "0")
			if err := session.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := session.Close(context.Background()); err != nil {
					t.Error("original modeled execution did not join", err)
				}
			})
			f.a.mu.Lock()
			f.a.state.Connected, f.a.state.Phase = true, "connected"
			f.a.mu.Unlock()
			owner, proof, execution := session.native, session.native.execution, f.launch.chain.execution
			graph, ok := getActiveMultihopGraph(f.a)
			if !ok || owner == nil || proof == nil || execution == nil || session.Current(f.operation) != nil {
				t.Fatal("original execution fixture is not current")
			}
			mux := http.NewServeMux()
			registerDesktopMultihopRoutes(mux, f.a)
			for _, fault := range []string{"cancelled", "missing-owner", "missing-proof", "missing-execution", "foreign-proof", "graph", "missing-graph", "zero-graph", "physical", "source", "command", "held-execution", "observed-state", "observed-registry", "observed-graph", "observed-proof"} {
				t.Run(fault, func(t *testing.T) {
					ctx, cancel := context.WithCancel(f.operation)
					defer cancel()
					switch fault {
					case "cancelled":
						cancel()
					case "missing-owner":
						nativeMultihopOwners.Delete(f.a)
						defer nativeMultihopOwners.Store(f.a, owner)
					case "missing-proof":
						owner.execution = nil
						defer func() { owner.execution = proof }()
					case "missing-execution":
						f.launch.chain.execution = nil
						defer func() { f.launch.chain.execution = execution }()
					case "foreign-proof":
						owner.execution = &desktopNodeChainExecutionProof{execution: &desktopNodeChainExecutionLaunch{}}
						defer func() { owner.execution = proof }()
					case "missing-graph":
						activeMultihopGraphs.Delete(f.a)
						defer activeMultihopGraphs.Store(f.a, graph)
					case "zero-graph":
						changed := graph
						changed.ChainNodes = 0
						activeMultihopGraphs.Store(f.a, changed)
						defer activeMultihopGraphs.Store(f.a, graph)
					case "graph":
						changed := graph
						changed.Started = changed.Started.Add(time.Second)
						activeMultihopGraphs.Store(f.a, changed)
						defer activeMultihopGraphs.Store(f.a, graph)
					case "physical":
						original := f.network.Load()
						f.network.Store("replacement-physical-network")
						defer f.network.Store(original)
					case "source":
						original := cloneRouterProfileStore(f.a.profiles)
						f.a.profiles.Profiles[1].Endpoint = "192.0.2.251"
						defer func() { f.a.profiles = original }()
					case "command":
						f.a.cmd = exec.Command("replacement-status-command")
						defer func() { f.a.cmd = f.launch.command }()
					case "held-execution":
						var deadlineCancel context.CancelFunc
						ctx, deadlineCancel = context.WithTimeout(ctx, 50*time.Millisecond)
						defer deadlineCancel()
						execution.mu.Lock()
						defer execution.mu.Unlock()
					default:
						observer, state := owner.networkIdentityContext, f.a.state
						owner.networkIdentityContext = func(call context.Context) (string, error) {
							value, err := observer(call)
							f.a.mu.Lock()
							switch fault {
							case "observed-state":
								f.a.state.Phase = "disconnecting"
							case "observed-registry":
								nativeMultihopOwners.Store(f.a, &nativeMultihopRuntime{})
							case "observed-graph":
								changed := graph
								changed.Started = changed.Started.Add(time.Second)
								activeMultihopGraphs.Store(f.a, changed)
							case "observed-proof":
								// Equal inert proof bytes are still a replacement of
								// the exact pointer captured before observation.
								copied := *proof
								owner.execution = &copied
							}
							f.a.mu.Unlock()
							return value, err
						}
						defer func() {
							owner.networkIdentityContext, owner.execution = observer, proof
							f.a.state = state
							nativeMultihopOwners.Store(f.a, owner)
							activeMultihopGraphs.Store(f.a, graph)
						}()
					}
					before := cloneRouterProfileStore(f.a.profiles)
					request := httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil).WithContext(ctx)
					response := httptest.NewRecorder()
					started := time.Now()
					mux.ServeHTTP(response, request)
					if response.Code != http.StatusConflict || strings.TrimSpace(response.Body.String()) != "ordered native route changed or is not ready for measurement" ||
						request.Context() != ctx || !reflect.DeepEqual(before, f.a.profiles) || time.Since(started) > time.Second {
						t.Fatal("registered native status accepted lost execution authority", winner, fault, response.Code)
					}
				})
			}
		})
	}
}
