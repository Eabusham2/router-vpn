package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"router-vpn/internal/mobilemultihop"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Real public decoder, operation, compiler, staged controller and owner methods;
// native process records and kernel state use the existing explicit model.
func TestDesktopImportedTrioExecutionPublicConnectUsesOriginalChild(t *testing.T) {
	testDesktopImportedExecutionPublicConnect(t, []int{3})
}

// Each new public lifecycle runs within the original per-root 120-second budget.
// The old trio root retains all three original choices unchanged.
func TestDesktopImportedPrefixExecutionPublic4Server(t *testing.T) {
	testDesktopImportedExecutionPublicConnect(t, []int{4}, desktopImportedExecutionChoice{"server", "server"})
}

func TestDesktopImportedPrefixExecutionPublic4CompareLocal(t *testing.T) {
	testDesktopImportedExecutionPublicConnect(t, []int{4}, desktopImportedExecutionChoice{"auto", "local"})
}

func TestDesktopImportedPrefixExecutionPublic4CompareServer(t *testing.T) {
	testDesktopImportedExecutionPublicConnect(t, []int{4}, desktopImportedExecutionChoice{"auto", "server"})
}

func TestDesktopImportedPrefixExecutionPublic8Server(t *testing.T) {
	testDesktopImportedExecutionPublicConnect(t, []int{8}, desktopImportedExecutionChoice{"server", "server"})
}

func TestDesktopImportedPrefixExecutionPublic8CompareLocal(t *testing.T) {
	testDesktopImportedExecutionPublicConnect(t, []int{8}, desktopImportedExecutionChoice{"auto", "local"})
}

func TestDesktopImportedPrefixExecutionPublic8CompareServer(t *testing.T) {
	testDesktopImportedExecutionPublicConnect(t, []int{8}, desktopImportedExecutionChoice{"auto", "server"})
}

type desktopImportedExecutionChoice struct{ requested, winner string }

func testDesktopImportedExecutionPublicConnect(t *testing.T, counts []int, selected ...desktopImportedExecutionChoice) {
	choices := selected
	if len(choices) == 0 {
		choices = []desktopImportedExecutionChoice{{"server", "server"}, {"auto", "local"}, {"auto", "server"}}
	}
	if (runtime.GOOS != "linux" && runtime.GOOS != "windows") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("execution product retains its independent installed platform admission")
	}
	for _, count := range counts {
		for _, choice := range choices {
			t.Run(fmt.Sprintf("%d-%s-%s", count, choice.requested, choice.winner), func(t *testing.T) {
				capturedApp, capturedLaunch := desktopImportedPrefixExecutionLaunchFixture(t, count, "windows", "2022-blake3-aes-256-gcm", 32)
				f := newDesktopNodeChainOwnedFixtureWith(t, capturedApp, capturedLaunch.chain.selection)
				a := f.a
				f.executionModel = &desktopExecutionOwnedModel{winner: choice.winner}
				a.connectionContext, a.connectionCancel = nil, nil
				a.state.Mode, a.state.Phase = "off", "off"
				t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(a); desktopComparisons.Delete(a) })
				release, err := a.holdCapturedMTU(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				opened := 0
				runtime := &desktopOrderedExecutionRuntime{
					capture: func(ctx context.Context, owner *app, selection multihopSelection, modes []string) (multihopSelection, error) {
						if owner != a || !reflect.DeepEqual(nodeChainSelectedReferences(selection.Nodes), nodeChainSelectedReferences(f.selection.Nodes)) || !reflect.DeepEqual(modes, []string{f.selection.ExitMode}) {
							return selection, errors.New("public capture changed original full graph")
						}
						return f.selection, ctx.Err()
					},
					prepare: func(ctx context.Context, owner *app, selection multihopSelection, requested string) (*desktopNodeChainExecutionSession, error) {
						opened++
						if owner != a || selection.Native != f.selection.Native || requested != choice.requested {
							return nil, errors.New("public open changed original selection")
						}
						request := &desktopNodeChainExecutionRequest{capture: f.capture, native: selection.Native, requested: requested}
						launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(ctx, f.capture, selection, nil, request)
						if err != nil {
							return nil, err
						}
						f.launch = launch
						session := &desktopNodeChainExecutionSession{app: a, launch: launch, execution: launch.chain.execution, selection: selection}
						return session, ctx.Err()
					},
				}
				q := orderedPublicRequest(t, a, nodeChainSelectedReferences(f.selection.Nodes))
				q.Execution = choice.requested
				raw, err := json.Marshal(q)
				if err != nil {
					t.Fatal(err)
				}
				response := httptest.NewRecorder()
				a.nativeMultihopConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(raw)), nativeMultihopConnectRuntime{execution: runtime})
				if response.Code != http.StatusOK {
					t.Fatalf("public Connect %d: %s", response.Code, response.Body.String())
				}
				owner, err := a.desktopOrderedExecutionOwner()
				if err != nil || owner == nil {
					t.Fatal("public route lost execution owner", err)
				}
				if opened != 1 || f.starts != 1 || !a.state.Connected || owner.session.graph.Execution != choice.winner || a.connectionContext != nil {
					t.Fatal("public transaction replayed Compare or lost original operation completion")
				}
				if err := owner.session.Current(context.Background()); err != nil {
					t.Fatal("request completion revoked retained native connection", err)
				}
				if count > 3 {
					// A positive synchronous status read cannot assume that the
					// fixture's background receipt observer is idle. Stop and join
					// only this captured watcher; retain its live native owner.
					watchDone := desktopOwnedNodeMonitorDone(f.launch)
					joinContext, cancelJoin := context.WithTimeout(context.Background(), 15*time.Second)
					joinErr := stopDesktopOwnedNodeMonitor(joinContext, f.launch)
					if joinErr == nil && watchDone != nil {
						joinErr = joinDesktopOwnedNodeMonitorStop(joinContext, a, watchDone)
					}
					cancelJoin()
					if joinErr != nil || owner.session.Current(context.Background()) != nil {
						t.Fatal("original fixture watcher did not join with native owner retained", joinErr)
					}
				}
				mux := http.NewServeMux()
				registerDesktopMultihopRoutes(mux, a)
				if count == 8 && choice.requested == "server" {
					execution := owner.session.execution
					blocked := httptest.NewRecorder()
					func() {
						execution.mu.Lock()
						defer execution.mu.Unlock()
						err := owner.session.native.execution.currentLocked(f.launch, *owner.session.graph)
						if err == nil || err.Error() != "ordered execution receipt is already being observed" {
							t.Fatal("held original receipt bypassed its observation guard", err)
						}
						mux.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil))
					}()
					if blocked.Code != http.StatusConflict || strings.TrimSpace(blocked.Body.String()) != "ordered native route changed or is not ready for measurement" {
						t.Fatal("held original receipt published public status", blocked.Code, blocked.Body.String())
					}
				}
				status := httptest.NewRecorder()
				mux.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/multihop/status", nil))
				var observed map[string]any
				if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &observed) != nil || observed["connected"] != true || observed["execution"] != choice.winner {
					t.Fatalf("public execution status lost actual child winner: %d %s", status.Code, status.Body.String())
				}
				allowed, ok := observed["ordered_executions"].([]any)
				if !ok || !reflect.DeepEqual(allowed, []any{"local", "server", "auto"}) {
					t.Fatal("status lost explicit product execution capabilities")
				}
				var body map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body["requested_execution"] != choice.requested || body["execution"] != choice.winner || len(body["nodes"].([]any)) != count {
					t.Fatal("public response relabelled request/winner or dropped middle nodes")
				}
				var nativeSource mobilemultihop.NodeChainSource
				if json.Unmarshal([]byte(owner.session.execution.preparation.LocalSource()), &nativeSource) != nil || nativeSource.Schema != 2 || len(nativeSource.Nodes) != count || nativeSource.IdentitySources[count-2] != "" {
					t.Fatal("public execution omitted original imported member")
				}
				var capturedSource mobilemultihop.NodeChainSource
				capturedInput, capturedErr := capturedLaunch.chain.policy.OriginalChain().LaunchInput()
				if capturedErr != nil || json.Unmarshal([]byte(capturedInput), &capturedSource) != nil || !reflect.DeepEqual(nativeSource, capturedSource) {
					t.Fatal("public execution substituted imported credentials")
				}
				stop, err := a.captureDesktopRetainedStop()
				if err != nil {
					t.Fatal(err)
				}
				if err := stop.Retire(context.Background(), owner.session.launch.command, false); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func prepareDesktopImportedExecutionModel(t *testing.T, requested, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainExecutionSession) {
	t.Helper()
	return prepareDesktopImportedPrefixExecutionModel(t, 3, requested, winner)
}

func prepareDesktopImportedPrefixExecutionModel(t *testing.T, count int, requested, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainExecutionSession) {
	t.Helper()
	a, captured := desktopImportedPrefixExecutionLaunchFixture(t, count, "windows", "2022-blake3-aes-256-gcm", 32)
	f := newDesktopNodeChainOwnedFixtureWith(t, a, captured.chain.selection)
	f.executionModel = &desktopExecutionOwnedModel{winner: winner}
	request := &desktopNodeChainExecutionRequest{capture: f.capture, native: f.selection.Native, requested: requested}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, f.selection, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	f.launch = launch
	return f, &desktopNodeChainExecutionSession{app: a, launch: launch, execution: launch.chain.execution, selection: f.selection}
}

func TestDesktopImportedTrioExecutionRestoreRetainsChosenSource(t *testing.T) {
	testDesktopImportedExecutionRestore(t, 3)
}

func TestDesktopImportedPrefixExecutionRestoreRetainsChosenSource(t *testing.T) {
	for _, count := range []int{4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) { testDesktopImportedExecutionRestore(t, count) })
	}
}

func testDesktopImportedExecutionRestore(t *testing.T, count int) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, s := prepareDesktopImportedPrefixExecutionModel(t, count, "auto", winner)
			if err := s.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			restore, err := s.CaptureRestore(f.operation)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows"); err == nil {
				t.Fatal("unjoined imported owner restored")
			}
			held := errors.New("original imported child still held")
			f.processes[0].closeErr = held
			if err := restore.retireContext(context.Background()); !errors.Is(err, held) || s.launch.ownedNode.retired {
				t.Fatal("failed imported join discarded owner", err)
			}
			f.processes[0].closeErr = nil
			if err := restore.retireContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			<-f.pulseDone
			next, owner, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows")
			if err != nil {
				t.Fatal(err)
			}
			last, present, err := owner.preparation.DesktopLast()
			if err != nil || !present || last.Execution() != winner || last.Target() != mobilemultihop.Targets[1] || f.starts != 1 {
				t.Fatal("imported restore repeated Compare or lost selected choice", err)
			}
			if owner.preparation.LocalSource() != s.execution.preparation.LocalSource() || next.chain.selection.Native != s.selection.Native || next.chain.policy.Metadata().RestoredMTU != f.live.MTU {
				t.Fatal("restore replaced imported source, captured native authority or MTU")
			}
		})
	}
}

func TestDesktopImportedTrioExecutionRefusesMissingOrForeignNativeMiddle(t *testing.T) {
	for _, fault := range []string{"omitted", "foreign"} {
		t.Run(fault, func(t *testing.T) {
			f, s := prepareDesktopImportedExecutionModel(t, "auto", "server")
			replacement := ""
			if fault == "foreign" {
				_, other := desktopImportedExecutionLaunchFixture(t, "windows", "2022-blake3-aes-128-gcm", 16)
				raw, err := other.chain.policy.OriginalChain().LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				var source mobilemultihop.NodeChainSource
				if json.Unmarshal([]byte(raw), &source) != nil {
					t.Fatal("foreign fixture source")
				}
				replacement = source.Nodes[1]
			}
			f.executionModel.importedSourceOverride = &replacement
			if err := s.startContext(f.operation); err == nil {
				t.Fatal("omitted or foreign imported native source acquired original execution")
			}
			if f.starts != 0 || desktopOwnedNodeProcess(s.launch) != nil || f.a.state.Connected {
				t.Fatal("changed imported source created a process or published Connected")
			}
			if err := s.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
