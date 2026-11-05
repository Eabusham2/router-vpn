//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"router-vpn/internal/mobilemtu"
	"router-vpn/internal/standardengine"
	"strings"
	"syscall"
	"testing"
	"time"
)

func standardMTURunFixture(t *testing.T) (context.Context, *linuxStandardServiceMTU, *standardengine.OperationFile, standardengine.OperationRun) {
	t.Helper()
	ctx, m, child := standardMTUAdmissionPair(t)
	if err := child.AcknowledgeLaunch(ctx, m.ready); err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	run := standardengine.OperationRun{CaptureSHA256: m.native.captureSHA, ID: strings.Repeat("d", 32), WorkDeadlineNS: deadline.UnixNano(), CleanupBudgetNS: int64(standardengine.OperationRunCleanupLimit), Original: m.current, OriginalMTU: 1500}
	return ctx, m, child, run
}

func TestLinuxStandardMTURunServiceKeepsOriginalClock(t *testing.T) {
	for _, name := range []string{"original", "changed-reader", "changed-MTU", "expired-admission", "one-clock", "cleanup-only", "child-closure", "lost-begin-fence", "failed-admission-recovery"} {
		t.Run(name, func(t *testing.T) {
			ctx, m, child, run := standardMTURunFixture(t)
			q := &linuxStandardServiceMTURequest{Run: &run}
			switch name {
			case "failed-admission-recovery":
				run.WorkDeadlineNS = time.Now().Add(-time.Second).UnixNano()
				if _, e := m.runRequest(ctx, "mtu-run-begin", q); e == nil || m.run == nil {
					t.Fatal("test did not retain failed admission pointer", e)
				}
				response, e := m.runRequest(ctx, "mtu-run-close", q)
				if e != nil || response.RunRetained || response.RunState != standardengine.OperationRunClosed || m.run != nil {
					t.Fatal("unsubmitted admission remained falsely pending", response, e)
				}
				if _, e = m.runRequest(ctx, "mtu-run-begin", q); e == nil {
					t.Fatal("delayed failed run was admitted")
				}
				next := run
				next.ID = strings.Repeat("e", 32)
				deadline, _ := ctx.Deadline()
				next.WorkDeadlineNS = deadline.UnixNano()
				if response, e = m.runRequest(ctx, "mtu-run-begin", &linuxStandardServiceMTURequest{Run: &next}); e != nil || !response.RunRetained {
					t.Fatal("known absent prior run prevented next admission", response, e)
				}
				return
			case "changed-reader":
				run.Original.InitialReceiptSHA256 = strings.Repeat("f", 64)
			case "changed-MTU":
				run.OriginalMTU = 1400
			case "expired-admission":
				run.WorkDeadlineNS = time.Now().Add(-time.Second).UnixNano()
			case "lost-begin-fence":
				response, err := m.runRequest(ctx, "mtu-run-close", q)
				if err != nil || response.RunRetained || response.RunState != standardengine.OperationRunClosed {
					t.Fatal("unsubmitted run could not be permanently fenced", response, err)
				}
				if _, err = m.runRequest(ctx, "mtu-run-begin", q); err == nil {
					t.Fatal("delayed Begin acquired a run after its close")
				}
				if retained, err := m.native.operations.OperationRunRetained(ctx, run); err != nil || retained {
					t.Fatal("rejection invented native admission", retained, err)
				}
				return
			}
			response, err := m.runRequest(ctx, "mtu-run-begin", q)
			if name == "changed-reader" || name == "changed-MTU" || name == "expired-admission" {
				if err == nil {
					t.Fatal("changed original run admitted")
				}
				return
			}
			if err != nil || !response.RunRetained || response.RunState != standardengine.OperationRunOpen || response.CleanupDeadlineNS != 0 {
				t.Fatal("actual FD11 run admission", response, err)
			}
			if name == "original" {
				return
			}
			if name == "child-closure" {
				response, err = m.runRequest(ctx, "mtu-run-close", q)
				if err != nil || response.RunState != standardengine.OperationRunClosing {
					t.Fatal("parent fabricated child closure", response, err)
				}
				if err = child.AcknowledgeOperationRunClosure(ctx, run); err != nil {
					t.Fatal(err)
				}
				response, err = m.runRequest(ctx, "mtu-run-status", q)
				if err != nil || response.RunState != standardengine.OperationRunClosed {
					t.Fatal("actual child closure not retained", response, err)
				}
				return
			}
			response, err = m.runRequest(ctx, "mtu-run-cleanup", q)
			if err != nil || response.CleanupDeadlineNS == 0 {
				t.Fatal("missing original cleanup clock", response, err)
			}
			first := response.CleanupDeadlineNS
			response, err = m.runRequest(ctx, "mtu-run-cleanup", q)
			if err != nil || response.CleanupDeadlineNS != first {
				t.Fatal("cleanup allowance renewed", response, err)
			}
			if name == "cleanup-only" {
				command := &linuxStandardServiceMTURequest{Run: &run, MTU: 1400, DeadlineNS: first - 1}
				if m.bindRunCommand(ctx, command) == nil {
					t.Fatal("work resumed after cleanup activation")
				}
				command.CleanupOnly = true
				if m.bindRunCommand(ctx, command) == nil {
					t.Fatal("cleanup changed captured original MTU")
				}
				command.MTU = run.OriginalMTU
				if err = m.bindRunCommand(ctx, command); err != nil {
					t.Fatal("exact original restore refused", err)
				}
			}
		})
	}
}

// The exchange is an explicit transport model over the real original FD11
// files and a real authenticated peer. It grants no TUN/measurement success.
func TestLinuxStandardMTURunProviderRetainsOriginalAuthority(t *testing.T) {
	for _, name := range []string{"held-launch-lock", "native-clock-first", "foreign-token", "changed-clock", "cancelled-finalizer", "expired-while-closing", "unjoined-close", "pending-observer"} {
		t.Run(name, func(t *testing.T) {
			parent, m, child, wire := standardMTURunFixture(t)
			peer, _, _ := linuxStandardPeerFixture(t)
			epoch := &linuxStandardRequestEpoch{}
			launch := &linuxStandardServiceLaunch{peer: peer, prepared: &linuxLegacyStandardExitOwner{requestEpoch: epoch}}
			owner := &linuxStandardServiceMTUOwner{launch: launch}
			work, cancelWork := context.WithCancel(parent)
			defer cancelWork()
			ctx, finish, err := mobilemtu.WithOperationContextProvider(work, time.Second, standardengine.OperationRunCleanupLimit, owner.cleanupDeadlineContext)
			if err != nil {
				t.Fatal(err)
			}
			defer finish()
			deadline, _ := mobilemtu.OperationWorkDeadline(ctx)
			wire.WorkDeadlineNS = deadline.UnixNano()
			if _, err = m.runRequest(ctx, "mtu-run-begin", &linuxStandardServiceMTURequest{Run: &wire}); err != nil {
				t.Fatal(err)
			}
			retained := &linuxStandardMTUClientRun{wire: wire, operation: ctx, epoch: epoch}
			owner.run.Store(retained)
			changedClock := false
			closingObserved := false
			launch.exchange = func(call context.Context, q linuxStandardServiceRequest, _ *os.File, _ func()) (linuxStandardServiceResponse, error) {
				response, err := m.runRequest(call, q.Action, q.MTU)
				if err == nil && q.Action == "mtu-run-close" && name == "expired-while-closing" && !closingObserved {
					closingObserved = true
					cancelWork()
				}
				if err == nil && q.Action == "mtu-run-close" && (name == "cancelled-finalizer" || name == "expired-while-closing" && call.Err() == nil) && response.RunState == standardengine.OperationRunClosing {
					if e := child.AcknowledgeOperationRunClosure(call, wire); e != nil {
						t.Fatal(e)
					}
				}
				if err == nil && changedClock && response.CleanupDeadlineNS != 0 {
					response.CleanupDeadlineNS++
				}
				return linuxStandardServiceResponse{MTU: response, authenticatedPeer: peer}, err
			}
			retained.captureTransport(launch)
			switch name {
			case "foreign-token":
				other, end, e := mobilemtu.WithOperationContext(parent, time.Second, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				defer end()
				if _, e = owner.cleanupDeadlineContext(other); e == nil {
					t.Fatal("foreign token acquired run cleanup")
				}
				return
			case "native-clock-first":
				original, cancel := context.WithTimeout(parent, 200*time.Millisecond)
				defer cancel()
				actual, e := child.ActivateOperationRunCleanup(original, wire)
				if e != nil {
					t.Fatal(e)
				}
				cleanup, e := mobilemtu.OperationCleanupContext(ctx)
				if e != nil {
					t.Fatal(e)
				}
				observed, _ := cleanup.Deadline()
				if !observed.Equal(actual) {
					t.Fatal("parent renewed original native clock", observed, actual)
				}
				return
			case "cancelled-finalizer", "expired-while-closing":
				if name == "cancelled-finalizer" {
					cancelWork()
				}
				if e := owner.finishRunContext(ctx); e != nil || !retained.closed.Load() {
					t.Fatal("original cleanup did not join actual child closure", e)
				}
				if _, state, e := m.native.operations.ReadOperationRun(parent); e != nil || state != standardengine.OperationRunClosed {
					t.Fatal("finalizer fabricated closure", state, e)
				}
				return
			case "unjoined-close":
				original, cancel := context.WithTimeout(parent, 200*time.Millisecond)
				defer cancel()
				if _, e := child.ActivateOperationRunCleanup(original, wire); e != nil {
					t.Fatal(e)
				}
				if e := owner.finishRunContext(ctx); !errors.Is(e, context.DeadlineExceeded) || retained.closed.Load() {
					t.Fatal("parent fabricated unjoined native closure", e)
				}
				if _, state, e := m.native.operations.ReadOperationRun(parent); e != nil || state != standardengine.OperationRunClosing {
					t.Fatal("lost original pending closure", state, e)
				}
				return
			case "pending-observer":
				epoch.mtuTransition = &linuxStandardControllerMTUTransition{}
				if e := owner.finishRunContext(ctx); e == nil || retained.closed.Load() {
					t.Fatal("run closed before original observer settled", e)
				}
				return
			}
			if name == "held-launch-lock" {
				launch.mu.Lock()
				defer launch.mu.Unlock()
			}
			cleanup, e := mobilemtu.OperationCleanupContext(ctx)
			if e != nil {
				t.Fatal("provider could not activate original clock", e)
			}
			first, _ := cleanup.Deadline()
			if name == "changed-clock" {
				changedClock = true
				if _, e = owner.cleanupDeadlineContext(ctx); e == nil {
					t.Fatal("changed shared clock accepted")
				}
			} else if again, e := mobilemtu.OperationCleanupContext(ctx); e != nil || again != cleanup {
				t.Fatal("provider recreated cleanup context", e)
			}
			actual, present, e := child.OperationRunCleanupDeadline(parent, wire)
			if e != nil || !present || !actual.Equal(first) {
				t.Fatal("provider did not retain actual shared FD11 deadline", actual, first, e)
			}
		})
	}
}

func TestLinuxStandardMTURunOwnerUsesOriginalWireAndChild(t *testing.T) {
	for _, scenario := range []string{"original", "lost-begin-ack", "repeat-run", "cancel-during-finalizer"} {
		t.Run(scenario, func(t *testing.T) {
			service, f, launch, observer, ctx := linuxStandardControllerEpochFixture(t)
			if err := launch.CaptureMTUExit(f.exit); err != nil {
				t.Fatal(err)
			}
			if err := launch.Start(ctx); err != nil {
				t.Fatal(err)
			}
			// Activation and route effects are modeled. Startup/run packets cross the
			// actual original authenticated controller/service socket and FD11 files.
			activation := &linuxStandardServiceMonitor{owner: launch, ctx: ctx, operation: ctx}
			linuxStandardServiceMonitors.Store(launch, activation)
			defer linuxStandardServiceMonitors.Delete(launch)
			f.a.mu.Lock()
			f.a.state.Connected = true
			f.a.state.Phase = "connected"
			f.a.state.RouterID = launch.request.RouterID
			f.a.mu.Unlock()
			owner := &linuxStandardServiceMTUOwner{launch: launch, connection: ctx, activation: activation, exitRaw: launch.mtuExitRaw, retained: true}
			launch.mtuOwner = owner
			native := service.session.owner.native
			device, inode := native.operations.Identity()
			fd, err := syscall.Dup(int(native.operations.File().Fd()))
			if err != nil {
				t.Fatal(err)
			}
			child, err := standardengine.CaptureOperationFile(os.NewFile(uintptr(fd), "modeled-native-run-closure"), device, inode, standardengine.OperationSize, standardengine.OperationLayout, native.captureSHA)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := child.Close(ctx); err != nil {
					t.Error(err)
				}
			}()
			exchange := launch.exchange
			lost := false
			runParent, stopRun := context.WithCancel(ctx)
			defer stopRun()
			launch.exchange = func(call context.Context, q linuxStandardServiceRequest, directory *os.File, before func()) (linuxStandardServiceResponse, error) {
				response, e := exchange(call, q, directory, before)
				if e == nil && q.Action == "mtu-run-close" && response.MTU != nil && response.MTU.RunState == standardengine.OperationRunClosing {
					if e = child.AcknowledgeOperationRunClosure(call, *q.MTU.Run); e != nil {
						t.Fatal(e)
					}
					if scenario == "cancel-during-finalizer" {
						stopRun()
					}

				}
				if e == nil && q.Action == "mtu-run-begin" && scenario == "lost-begin-ack" && !lost {
					lost = true
					return linuxStandardServiceResponse{}, context.DeadlineExceeded
				}
				return response, e
			}
			workCalls := 0
			execute := func(call context.Context) error {
				workCalls++
				if _, err := owner.CaptureContext(call); err != nil {
					return err
				}
				run := owner.run.Load()
				deadline, e := mobilemtu.OperationWorkDeadline(call)
				if e != nil || run == nil || run.wire.WorkDeadlineNS != deadline.UnixNano() || !mobilemtu.SameOperationContext(call, run.operation) {
					return errors.New("run lost original accepted operation")
				}
				return nil
			}
			err = owner.RunOperationContext(runParent, "captured-operation", execute)
			if scenario == "lost-begin-ack" {
				if err == nil || workCalls != 0 || !lost {
					t.Fatal("lost admission acknowledgement permitted work", workCalls, err)
				}
			} else if scenario == "cancel-during-finalizer" {
				if !errors.Is(err, context.Canceled) || workCalls != 1 {
					t.Fatal("late finalizer cancellation was hidden", workCalls, err)
				}
			} else if err != nil || workCalls != 1 {
				t.Fatal("actual run failed", workCalls, err)
			}
			first := owner.run.Load()
			if first == nil || !first.closed.Load() || owner.pending != nil || launch.prepared.requestEpoch.observer != observer {
				t.Fatal("original run did not close before result")
			}
			actual, state, e := native.operations.ReadOperationRun(ctx)
			if e != nil || actual != first.wire || state != standardengine.OperationRunClosed {
				t.Fatal("returned before actual original child closure", actual, state, e)
			}
			if scenario == "repeat-run" {
				if err = owner.RunOperationContext(ctx, "next-captured-operation", execute); err != nil {
					t.Fatal(err)
				}
				next := owner.run.Load()
				if next == first || next.wire.ID == first.wire.ID || next.wire.Original != first.wire.Original || !next.closed.Load() || workCalls != 2 {
					t.Fatal("repeat run replaced reader or reused authority")
				}
			}
		})
	}
}

func TestLinuxStandardMTURunPublicCancelKeepsCommit(t *testing.T) {
	for _, phase := range []string{"before-commit", "committed", "expired-observation"} {
		t.Run(phase, func(t *testing.T) {
			a := &app{}
			id := mtuViewIdentity{Session: "original-service", Profile: "original-profile", Native: true}
			request := strings.Repeat("a", 32)
			ctx, operation, err := beginMTUViewOperation(a, context.Background(), mtuViewRequest{Request: request}, id)
			if err != nil {
				t.Fatal(err)
			}
			defer operation.cancel()
			defer mtuViewSlots.Delete(a)
			calls := 0
			operation.cancelCaptured = func(call context.Context) error {
				calls++
				if phase == "committed" {
					return mobilemtu.ErrOperationCommitted
				}
				if phase == "expired-observation" {
					return context.DeadlineExceeded
				}
				return nil
			}
			response := httptest.NewRecorder()
			cancelRequest := httptest.NewRequest(http.MethodPost, "/api/mtu/cancel", strings.NewReader(`{"request_id":"`+request+`","session_id":"`+id.Session+`"}`))
			if phase == "expired-observation" {
				control, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer stop()
				cancelRequest = cancelRequest.WithContext(control)
				operation.mu.Lock()
			}
			a.cancelDesktopMTURoute(response, cancelRequest)
			if phase == "expired-observation" {
				operation.mu.Unlock()
			}
			wantCalls := 1
			if phase == "expired-observation" {
				wantCalls = 0
			}
			if calls != wantCalls {
				t.Fatal("public Cancel bypassed original native decision")
			}
			switch phase {
			case "before-commit":
				if response.Code != http.StatusOK || !errors.Is(ctx.Err(), context.Canceled) || !strings.Contains(response.Body.String(), "canceling") {
					t.Fatal("uncommitted Cancel did not signal original work", response.Code, response.Body.String())
				}
			case "committed":
				if response.Code != http.StatusOK || ctx.Err() != nil || !strings.Contains(response.Body.String(), `"committed":true`) || strings.Contains(response.Body.String(), "rollback") {
					t.Fatal("committed Cancel canceled winner or promised rollback", response.Code, response.Body.String())
				}
			case "expired-observation":
				if response.Code != http.StatusConflict || ctx.Err() != nil {
					t.Fatal("expired cancellation read retired healthy operation", response.Code, ctx.Err())
				}
			}
		})
	}
}
