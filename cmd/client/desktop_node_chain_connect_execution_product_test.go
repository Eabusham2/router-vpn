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
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Real public decoder, operation, compiler, staged controller and owner methods;
// native process records and kernel state use the existing explicit model.
func TestDesktopCONNECTTrioExecutionPublicConnectUsesOriginalChild(t *testing.T) {
	if (runtime.GOOS != "linux" && runtime.GOOS != "windows") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("execution product retains its independent installed platform admission")
	}
	for _, protocol := range []string{"http-connect", "https-connect"} {
		count := 3
		for _, choice := range []struct{ requested, winner string }{{"server", "server"}, {"auto", "local"}, {"auto", "server"}} {
			t.Run(fmt.Sprintf("%s-%s-%s", protocol, choice.requested, choice.winner), func(t *testing.T) {
				capturedApp, capturedLaunch := desktopCONNECTProductLaunchFixture(t, "wg", protocol)
				// Register before the fixture: its original watcher/process must
				// join before these registries are removed, including Fatal paths.
				t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(capturedApp); desktopComparisons.Delete(capturedApp) })
				f := newDesktopNodeChainOwnedFixtureWith(t, capturedApp, capturedLaunch.chain.selection)
				a := f.a
				f.executionModel = &desktopExecutionOwnedModel{winner: choice.winner}
				a.connectionContext, a.connectionCancel = nil, nil
				a.state.Mode, a.state.Phase = "off", "off"
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
				// The modeled child shares this process with its real parent
				// watcher. Join only that captured watcher before a synchronous
				// positive status assertion; live native Current remains required.
				watchDone := desktopOwnedNodeMonitorDone(f.launch)
				joinContext, cancelJoin := context.WithTimeout(context.Background(), 15*time.Second)
				joinErr := stopDesktopOwnedNodeMonitor(joinContext, f.launch)
				if joinErr == nil && watchDone != nil {
					joinErr = joinDesktopOwnedNodeMonitorStop(joinContext, a, watchDone)
				}
				cancelJoin()
				if joinErr != nil || owner.session.Current(context.Background()) != nil {
					t.Fatal("captured fixture watcher did not join with original owner retained", joinErr)
				}
				mux := http.NewServeMux()
				registerDesktopMultihopRoutes(mux, a)
				if protocol == "https-connect" && choice.requested == "auto" && choice.winner == "server" {
					// The same actual locked observation must still refuse an
					// in-flight receipt, and the public handler must not publish it.
					execution := owner.session.execution
					blocked := httptest.NewRecorder()
					func() {
						execution.mu.Lock()
						defer execution.mu.Unlock()
						err := owner.session.native.execution.currentLocked(f.launch, *owner.session.graph)
						if err == nil || err.Error() != "ordered execution receipt is already being observed" {
							t.Fatal("held original execution receipt bypassed locked refusal", err)
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
				allowed, ok := observed["ordered_connect_trio_executions"].([]any)
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
				if json.Unmarshal([]byte(owner.session.execution.preparation.LocalSource()), &nativeSource) != nil || nativeSource.Schema != 4 || len(nativeSource.Nodes) != 3 || nativeSource.IdentitySources[1] != "" {
					t.Fatal("public execution omitted original imported member")
				}
				var capturedSource mobilemultihop.NodeChainSource
				capturedInput, capturedErr := capturedLaunch.chain.connectPolicy.OriginalSource()
				var capturedRaw string
				if capturedErr == nil {
					capturedRaw, capturedErr = capturedInput.Source()
				}
				if capturedErr != nil || json.Unmarshal([]byte(capturedRaw), &capturedSource) != nil || nativeSource.Nodes[1] != capturedSource.Nodes[1] {
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

// The actual private catalog and Local compiler are retained. Only process and
// Windows kernel observations are modeled by the existing owner fixture.
func desktopCONNECTProductApp(t *testing.T, mode, protocol string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopCONNECTCaptureFixture(t, mode, "password", "off")
	if protocol == "http-connect" {
		middle := &a.profiles.Profiles[1]
		proxy := *middle.External.HTTPSConnect
		proxy.TLSServerName = ""
		middle.External.Protocol, middle.External.HTTPSConnect, middle.External.HTTPConnect = protocol, nil, &proxy
		nodes[1].Mode = protocol
	}
	a.profiles.Profiles[2].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
	return a, nodes
}
func desktopCONNECTProductLaunchFixture(t *testing.T, mode, protocol string) (*app, *desktopNodeLaunch) {
	t.Helper()
	a, nodes := desktopCONNECTProductApp(t, mode, protocol)
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "windows")
	if err != nil {
		t.Fatal(err)
	}
	return a, launch
}

func TestDesktopCONNECTTrioExecutionSelectionBounds(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, choice := range []string{"server", "auto"} {
				t.Run(protocol+"/"+mode+"/"+choice, func(t *testing.T) {
					a, nodes := desktopCONNECTProductApp(t, mode, protocol)
					s, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, choice)
					if err != nil || !desktopCONNECTTrioExecutionMembers(s.Nodes, choice) {
						t.Fatal("original typed trio refused", err)
					}
					if _, err := resolveDesktopNodeChainCONNECTMembers(a.profiles.Profiles[2], a.profiles.Profiles, nodes, choice); err == nil {
						t.Fatal("Local-only capture admitted execution")
					}
					for _, fault := range []string{"long", "final-layer", "entry-layer", "wrong-final", "paired-middle", "duplicate-proof", "credentials", "hostname"} {
						altered := cloneDesktopNodeChainMembers(s.Nodes)
						switch fault {
						case "long":
							altered = append(altered[:1], append([]desktopNodeChainMember{altered[0]}, altered[1:]...)...)
						case "final-layer":
							altered[2].Profile.StartLayer = "aes-256-gcm"
						case "entry-layer":
							altered[0].Profile.StartLayer = "unsupported"
						case "wrong-final":
							altered[2].Mode = "hysteria2"
						case "paired-middle":
							altered[1].Profile.NodeKind = "router-vpn"
						case "duplicate-proof":
							altered[2].Profile.NodeProofID = altered[0].Profile.NodeProofID
						case "credentials", "hostname":
							proxy := altered[1].Profile.External.HTTPConnect
							if protocol == "https-connect" {
								proxy = altered[1].Profile.External.HTTPSConnect
							}
							if fault == "credentials" {
								proxy.Password = ""
							} else {
								proxy.Host = "proxy.example"
								altered[1].Profile.Endpoint = proxy.Host
							}
						}
						if desktopCONNECTTrioExecutionMembers(altered, choice) {
							t.Fatal("foreign CONNECT execution admitted", fault)
						}
					}
				})
			}
		}
	}
}

func prepareDesktopCONNECTExecutionModel(t *testing.T, requested, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainExecutionSession) {
	t.Helper()
	a, captured := desktopCONNECTProductLaunchFixture(t, "wg", "https-connect")
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

func TestDesktopCONNECTTrioExecutionRestoreRetainsChosenSource(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, s := prepareDesktopCONNECTExecutionModel(t, "auto", winner)
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
			last, present, err := owner.preparation.CONNECTDesktopLast()
			if err != nil || !present || last.Execution() != winner || last.Target() != mobilemultihop.Targets[1] || f.starts != 1 {
				t.Fatal("imported restore repeated Compare or lost selected choice", err)
			}
			_, nextMeta, _, nextErr := next.chain.connectPolicy.PhysicalReadValidated()
			if nextErr != nil {
				t.Fatal(nextErr)
			}
			if owner.preparation.LocalSource() != s.execution.preparation.LocalSource() || next.chain.selection.Native != s.selection.Native || nextMeta.RestoredMTU != f.live.MTU {
				t.Fatal("restore replaced imported source, captured native authority or MTU")
			}
		})
	}
}
