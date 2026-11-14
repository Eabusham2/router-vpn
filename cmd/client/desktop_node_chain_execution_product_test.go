package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"router-vpn/internal/common"
	"runtime"
	"testing"
	"time"
)

// Explicit controller/child/kernel models execute real staging, adoption,
// publication and Stop. Installed native OS acceptance remains separate.
func TestDesktopOrderedExecutionProductPublishesChildAndStopsExactOwner(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, s := prepareDesktopExecutionSessionModel(t, winner)
			t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(f.a) })
			if err := s.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			owner, err := f.a.retainDesktopOrderedExecution(s)
			if err != nil {
				t.Fatal(err)
			}
			before := cloneRouterProfileStore(f.a.profiles)
			if err := f.a.publishDesktopOrderedExecution(f.operation, s, true); err != nil {
				t.Fatal(err)
			}
			if !f.a.state.Connected || f.a.state.Phase != "connected" || s.graph.Execution != winner || f.starts != 1 {
				t.Fatal("controller did not publish the original child winner once")
			}
			for _, member := range s.selection.Nodes {
				old, _ := profileByID(before.Profiles, member.Profile.ID)
				now, _ := profileByID(f.a.profiles.Profiles, member.Profile.ID)
				if now.UseCount != old.UseCount+1 || now.LastUsedAt == "" {
					t.Fatal("omitted captured member usage")
				}
			}
			result, err := s.Result(f.operation)
			if err != nil || !reflect.DeepEqual(result, f.executionModel.ready.Progress.Comparison) {
				t.Fatal("controller repeated or replaced child Compare", err)
			}
			stop, err := f.a.captureDesktopRetainedStop()
			if err != nil {
				t.Fatal(err)
			}
			captured, ok := stop.(*desktopOrderedExecutionStop)
			if !ok || captured.owner != owner {
				t.Fatal("public Stop did not retain typed execution owner")
			}
			joined := errors.New("original child join is still pending")
			f.processes[0].closeErr = joined
			if err := stop.Retire(context.Background(), s.launch.command, false); !errors.Is(err, joined) {
				t.Fatal("lost original cleanup failure", err)
			}
			if current, _ := f.a.desktopOrderedExecutionOwner(); current != owner || s.closed {
				t.Fatal("failed join dropped retained execution")
			}
			f.processes[0].closeErr = nil
			if err := stop.Retire(context.Background(), s.launch.command, false); err != nil {
				t.Fatal(err)
			}
			if current, _ := f.a.desktopOrderedExecutionOwner(); current != nil || !s.closed || f.a.cmd != nil || f.a.state.Connected {
				t.Fatal("retired owner remained Connected")
			}
		})
	}
}

func TestDesktopOrderedExecutionProductStopCannotBorrowReplacement(t *testing.T) {
	f, s := prepareDesktopExecutionSessionModel(t, "server")
	t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(f.a) })
	if err := s.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.retainDesktopOrderedExecution(s); err != nil {
		t.Fatal(err)
	}
	stop, err := f.a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal(err)
	}
	replacement := &exec.Cmd{}
	f.a.cmd = replacement
	if err := stop.Retire(context.Background(), replacement, true); err == nil || f.processes[0].closed || f.a.cmd != replacement {
		t.Fatal("captured Stop retired or relabelled replacement")
	}
	f.a.cmd = s.launch.command
	if err := stop.Retire(context.Background(), s.launch.command, false); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopOrderedExecutionProductRestoreRequiresRetainedIntent(t *testing.T) {
	for _, ordinaryClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "retained-intent", true: "ordinary-close"}[ordinaryClose], func(t *testing.T) {
			f, s := prepareDesktopExecutionSessionModel(t, "local")
			t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(f.a) })
			if err := s.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			owner, err := f.a.retainDesktopOrderedExecution(s)
			if err != nil {
				t.Fatal(err)
			}
			capture, err := s.CaptureRestore(f.operation)
			if err != nil {
				t.Fatal(err)
			}
			saved := &desktopOrderedExecutionRestore{owner: owner, capture: capture}
			if ordinaryClose {
				if err := s.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := saved.retire(context.Background()); err == nil || capture.retired {
					t.Fatal("ordinary Close minted restore authority")
				}
				return
			}
			if err := saved.retire(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !s.closed || !capture.retired || s.restoreNext != nil || f.starts != 1 {
				t.Fatal("pre-test retirement constructed a successor early")
			}
			if err := saved.retire(context.Background()); err != nil {
				t.Fatal("retained retirement was not idempotent", err)
			}
		})
	}
}

func TestDesktopOrderedExecutionChoicesKeepProxyNativeAdmissionClosed(t *testing.T) {
	for _, requested := range []string{"local", "server", "auto"} {
		nodes := []common.MultihopNodeSelection{{ID: "first", Mode: "wg"}, {ID: "last", Mode: "shadowsocks"}}
		if err := desktopOrderedExecutionSelection(nodes, requested); err != nil {
			t.Fatal(requested, err)
		}
		hysteria := []common.MultihopNodeSelection{nodes[0], {ID: "last", Mode: "hysteria2"}}
		if err := desktopOrderedExecutionSelection(hysteria, requested); (err == nil) != (requested == "local") {
			t.Fatal("unsupported final acquired Server/Compare admission", requested, err)
		}
		for _, mode := range []string{"socks5", "http-connect", "https-connect"} {
			proxy := []common.MultihopNodeSelection{nodes[0], {ID: "middle", Mode: mode}, nodes[1]}
			err := desktopOrderedExecutionSelection(proxy, requested)
			if (err == nil) != (requested == "local") {
				t.Fatal("proxy execution admission changed", mode, requested, err)
			}
		}
	}
}

// The registered public decoder/operation/dispatcher reaches the real product
// transaction. Only installed source acquisition and native child startup use
// the same explicit controller/kernel model as the parent ownership tests.
func TestDesktopOrderedExecutionPublicConnectUsesChildOnly(t *testing.T) {
	if (runtime.GOOS != "linux" && runtime.GOOS != "windows") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("execution product retains its independent installed platform admission")
	}
	for _, count := range []int{2, 3, 8} {
		for _, choice := range []struct{ requested, winner string }{{"server", "server"}, {"auto", "local"}, {"auto", "server"}} {
			t.Run(fmt.Sprintf("%d-%s-%s", count, choice.requested, choice.winner), func(t *testing.T) {
				f := newDesktopNodeChainOwnedFixture(t, count)
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
				mux := http.NewServeMux()
				registerDesktopMultihopRoutes(mux, a)
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

func TestDesktopOrderedExecutionDisconnectRetainsExactReleaseAfterChildJoin(t *testing.T) {
	f, s := prepareDesktopExecutionSessionModel(t, "server")
	t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(f.a) })
	if err := s.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	owner, err := f.a.retainDesktopOrderedExecution(s)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := f.a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal(err)
	}
	f.kernel.closeFail = true
	if err := stop.Retire(context.Background(), s.launch.command, true); err == nil {
		t.Fatal("failed protection release reported success")
	}
	if !s.closed || !f.processes[0].closed || owner.slot.retirement == nil || f.a.nodeProtection != owner.slot {
		t.Fatal("release failure lost joined child or exact original slot")
	}
	capturedRelease := owner.slot.retirement
	replacement := &desktopNodeProtectionSlot{}
	f.a.nodeProtection = replacement
	retry, err := f.a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.Retire(context.Background(), nil, true); err == nil || f.a.nodeProtection != replacement || owner.slot.retirement != capturedRelease {
		t.Fatal("late Disconnect released replacement protection")
	}
	f.a.nodeProtection = owner.slot
	f.kernel.closeFail = false
	retry, err = f.a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.Retire(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	}
	if retained, _ := f.a.desktopOrderedExecutionOwner(); retained != nil || f.a.nodeProtection != nil || f.kernel.releases != 1 {
		t.Fatal("retry reacquired release or kept terminal owner")
	}
}

// Model only the captured platform Stop callback. The session still executes
// its shipping post-join cleanup, and a cancelled completion must be retried
// without retiring the original native transaction a second time.
type desktopOrderedExecutionStopFunc func(context.Context, *exec.Cmd, bool) error

func (stop desktopOrderedExecutionStopFunc) Retire(ctx context.Context, command *exec.Cmd, disconnect bool) error {
	return stop(ctx, command, disconnect)
}

func TestDesktopOrderedExecutionNativeJoinCompletionRetry(t *testing.T) {
	f, s := prepareDesktopExecutionSessionModel(t, "server")
	t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(f.a) })
	if err := s.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	owner, err := f.a.retainDesktopOrderedExecution(s)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	owner.stop = desktopOrderedExecutionStopFunc(func(ctx context.Context, command *exec.Cmd, disconnect bool) error {
		calls++
		if command != s.launch.command || !disconnect {
			return errors.New("changed captured platform Stop intent")
		}
		if err := closeDesktopNodeChainLaunch(ctx, f.a, s.launch); err != nil {
			return err
		}
		cancel()
		return nil
	})
	stop, err := f.a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal(err)
	}
	if err := stop.Retire(ctx, s.launch.command, true); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancelled completion", err)
	}
	if calls != 1 || !owner.nativeRetired || s.closed || !f.processes[0].closed {
		t.Fatal("cancelled completion lost joined native owner")
	}
	if current, _ := f.a.desktopOrderedExecutionOwner(); current != owner {
		t.Fatal("cancelled completion dropped cleanup registry")
	}
	replacement := &exec.Cmd{}
	original := f.a.cmd
	f.a.cmd = replacement
	if _, err := f.a.captureDesktopRetainedStop(); err == nil {
		t.Fatal("completion retry adopted replacement command")
	}
	f.a.cmd = original
	retry, err := f.a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal(err)
	}
	if err := retry.Retire(context.Background(), original, true); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !s.closed {
		t.Fatal("completion retry repeated native retirement or remained open")
	}
	if current, _ := f.a.desktopOrderedExecutionOwner(); current != nil {
		t.Fatal("completed retry retained registry")
	}
}

func TestDesktopOrderedExecutionPreparationCleanupKeepsPriorOwner(t *testing.T) {
	f, original := prepareDesktopExecutionSessionModel(t, "server")
	t.Cleanup(func() {
		desktopOrderedExecutionOwners.Delete(f.a)
		desktopOrderedExecutionPreparations.Delete(f.a)
	})
	if err := original.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	owner, err := f.a.retainDesktopOrderedExecution(original)
	if err != nil {
		t.Fatal(err)
	}
	request := &desktopNodeChainExecutionRequest{capture: f.capture, native: f.selection.Native, requested: "auto"}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, f.selection, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	prepared := &desktopNodeChainExecutionSession{app: f.a, launch: launch, execution: launch.chain.execution, selection: f.selection}
	command, slot, state := f.a.cmd, f.a.nodeProtection, f.a.state
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.a.retireDesktopOrderedExecutionPreparation(cancelled, prepared); !errors.Is(err, context.Canceled) {
		t.Fatal("failed preparation cleanup did not retain its exact cancellation", err)
	}
	pending, found := desktopOrderedExecutionPreparations.Load(f.a)
	if current, _ := f.a.desktopOrderedExecutionOwner(); !found || pending != prepared || current != owner || f.a.cmd != command || f.a.nodeProtection != slot || f.a.state != state || original.closed || f.processes[0].closed {
		t.Fatal("unentered cleanup replaced or retired the prior working owner")
	}
	// An entered session cannot borrow the preparation cleanup registry.
	if err := f.a.retireDesktopOrderedExecutionPreparation(context.Background(), original); err == nil {
		t.Fatal("preparation cleanup adopted a started session")
	}
	captured, err := f.a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal("public Stop could not retry pending preparation first", err)
	}
	if _, remains := desktopOrderedExecutionPreparations.Load(f.a); remains || !prepared.closed || original.closed || f.a.cmd != command || f.a.nodeProtection != slot || f.a.state != state || f.processes[0].closed {
		t.Fatal("pending cleanup touched prior command/protection or failed to join")
	}
	stop, ok := captured.(*desktopOrderedExecutionStop)
	if !ok || stop.owner != owner {
		t.Fatal("pending cleanup substituted captured original Stop")
	}
	if err := stop.Retire(context.Background(), command, false); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopOrderedExecutionPreStartFailureKeepsOriginalChild(t *testing.T) {
	for _, fault := range []string{"preflight", "guard", "stop", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f, original := prepareDesktopExecutionSessionModel(t, "server")
			t.Cleanup(func() {
				desktopOrderedExecutionOwners.Delete(f.a)
				desktopOrderedExecutionPreparations.Delete(f.a)
			})
			if err := original.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			owner, err := f.a.retainDesktopOrderedExecution(original)
			if err != nil {
				t.Fatal(err)
			}
			operation, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.a.mu.Lock()
			f.a.connectionContext, f.a.connectionCancel = operation, cancel
			command, slot := f.a.cmd, f.a.nodeProtection
			f.a.mu.Unlock()
			cause := errors.New("original pre-start failure")
			if fault == "stop" {
				owner.stop = desktopOrderedExecutionStopFunc(func(context.Context, *exec.Cmd, bool) error { return cause })
			}
			var prepared *desktopNodeChainExecutionSession
			driver := &desktopOrderedExecutionRuntime{
				capture: captureNativeMultihopForAppContext,
				prepare: func(ctx context.Context, a *app, selection multihopSelection, requested string) (*desktopNodeChainExecutionSession, error) {
					request := &desktopNodeChainExecutionRequest{capture: f.capture, native: selection.Native, requested: requested}
					launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(ctx, f.capture, selection, nil, request)
					if err != nil {
						return nil, err
					}
					prepared = &desktopNodeChainExecutionSession{app: a, launch: launch, execution: launch.chain.execution, selection: selection}
					switch fault {
					case "preflight":
						return prepared, cause
					case "guard":
						launch.chain.input += " "
					case "cancel":
						cancel()
					}
					return prepared, nil
				},
			}
			if _, err := f.a.connectDesktopOrderedExecutionWithRuntime(operation, f.selection, "auto", false, driver); err == nil {
				t.Fatal("failed preparation entered a replacement child")
			}
			if prepared == nil || !prepared.closed || prepared.launch.command != nil || f.starts != 1 || f.processes[0].closed || original.closed || f.a.cmd != command || f.a.nodeProtection != slot {
				t.Fatal("pre-start failure did not join only its unused successor")
			}
			if current, _ := f.a.desktopOrderedExecutionOwner(); current != owner {
				t.Fatal("pre-start failure replaced prior cleanup ownership")
			}
			if _, remains := desktopOrderedExecutionPreparations.Load(f.a); remains {
				t.Fatal("successful unentered cleanup retained pending authority")
			}
			owner.stop = nil
			if err := original.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDesktopOrderedExecutionPendingPreparationKeepsStopCallerBudget(t *testing.T) {
	f, prepared := prepareDesktopExecutionSessionModel(t, "server")
	t.Cleanup(func() { desktopOrderedExecutionPreparations.Delete(f.a) })
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.a.retireDesktopOrderedExecutionPreparation(cancelled, prepared); err == nil {
		t.Fatal("cancelled preparation cleanup unexpectedly completed")
	}
	if _, err := f.a.captureDesktopRetainedStopContext(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("pending Stop discarded its canceled original caller", err)
	}
	command, slot := &exec.Cmd{}, f.a.nodeProtection
	f.a.cmd = command
	prepared.mu.Lock()
	ctx, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	done := make(chan error, 1)
	go func() { _, err := f.a.captureDesktopRetainedStopContext(ctx); done <- err }()
	select {
	case err := <-done:
		prepared.mu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("pending preparation lost original Stop deadline", err)
		}
	case <-time.After(time.Second):
		prepared.mu.Unlock()
		<-done // Join the actual held call before failing the bounded fixture.
		t.Fatal("pending preparation replaced the original Stop caller budget")
	}
	pending, exists := desktopOrderedExecutionPreparations.Load(f.a)
	if !exists || pending != prepared || prepared.closed || f.a.cmd != command || f.a.nodeProtection != slot {
		t.Fatal("expired Stop changed pending or previous ownership")
	}
	if err := f.a.retirePendingDesktopOrderedExecutionPreparation(context.Background()); err != nil || !prepared.closed || f.a.cmd != command || f.a.nodeProtection != slot {
		t.Fatal("fresh exact retry did not join only its pending preparation", err)
	}
	if _, err := f.a.retainDesktopOrderedExecution(prepared); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(f.a) })
	f.a.mu.Lock()
	captureCtx, captureCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer captureCancel()
	captured := make(chan error, 1)
	go func() { _, err := f.a.captureDesktopRetainedStopContext(captureCtx); captured <- err }()
	select {
	case err := <-captured:
		f.a.mu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("original owner capture lost its Stop caller deadline", err)
		}
	case <-time.After(time.Second):
		f.a.mu.Unlock()
		<-captured
		t.Fatal("original owner capture blocked beyond its Stop caller budget")
	}
}

func TestDesktopOrderedExecutionRetirementKeepsCallerBudget(t *testing.T) {
	f, original := prepareDesktopExecutionSessionModel(t, "server")
	t.Cleanup(func() {
		desktopOrderedExecutionOwners.Delete(f.a)
		speedLabTemporaryOwners.Delete(f.a)
	})
	if err := original.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	owner, err := f.a.retainDesktopOrderedExecution(original)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := f.a.captureDesktopRetainedStop()
	if err != nil {
		t.Fatal(err)
	}
	stop, ok := captured.(*desktopOrderedExecutionStop)
	if !ok {
		t.Fatal("missing exact execution Stop")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stop.Retire(cancelled, original.launch.command, false); !errors.Is(err, context.Canceled) {
		t.Fatal("retirement discarded original caller cancellation", err)
	}
	for _, stage := range []string{"retire", "restore-lookup"} {
		t.Run(stage, func(t *testing.T) {
			if stage == "restore-lookup" {
				// Only force the real lookup to reach its app lock. No synthetic
				// temporary owner can pass the later original-owner checks.
				speedLabTemporaryOwners.Store(f.a, &speedLabTemporaryOwner{})
				defer speedLabTemporaryOwners.Delete(f.a)
			}
			f.a.mu.Lock()
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if stage == "retire" {
					done <- stop.Retire(ctx, original.launch.command, false)
				} else {
					_, err := f.a.speedLabOrderedExecutionRestore(ctx, owner)
					done <- err
				}
			}()
			select {
			case err := <-done:
				f.a.mu.Unlock()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("retirement lookup lost original caller deadline", err)
				}
			case <-time.After(time.Second):
				f.a.mu.Unlock()
				<-done
				t.Fatal("execution retirement exceeded its original caller budget")
			}
			if current, _ := f.a.desktopOrderedExecutionOwner(); current != owner || original.closed || f.processes[0].closed || f.a.cmd != original.launch.command {
				t.Fatal("expired retirement lost exact child or cleanup owner")
			}
		})
	}
	if err := stop.Retire(context.Background(), original.launch.command, false); err != nil {
		t.Fatal(err)
	}
}
