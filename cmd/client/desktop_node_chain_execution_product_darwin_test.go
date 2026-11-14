//go:build darwin

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"testing"
	"time"
)

// The published original source, installed parent/session, private workspace
// and captured Stop run here. Child ACK and PF replies are explicit boundary
// models, so these tests do not replace installed native acceptance.
func macOSExecutionProductStopFixture(t *testing.T) (*desktopMacOSNodeChainHost, *desktopNodeChainExecutionSession, *[]string) {
	t.Helper()
	h, actions := macOSExecutionRetirementFixture(t)
	h.baselineRun = func(ctx context.Context, parent *desktopMacOSSessionCapture, selection desktopMacOSNodeChainSelection,
		action string, expected *desktopMacOSNodeChainReceipt, _ func()) (*desktopMacOSNodeChainReceipt, error) {
		if parent != h.parent || selection != h.selection || expected != h.baseline || !h.nativeRetired {
			return nil, errors.New("execution product PF boundary lost original authority or native join")
		}
		value := *expected
		switch action {
		case "retire":
			value.Phase = "held"
		case "release":
			value.Phase, value.Baseline = "retired", desktopMacOSBaselineProof{}
		default:
			return nil, errors.New("execution product PF boundary received an unrelated action")
		}
		*actions = append(*actions, action)
		return &value, ctx.Err()
	}
	h.process.nativeAcknowledged, h.process.nativeStopped = true, true
	// Session.Close checks this original application association; it grants no
	// native Current, process, graph or source-replay authority.
	h.launch.chain.capture = &desktopNodeChainHostCapture{app: h.parent.app}
	s := &desktopNodeChainExecutionSession{app: h.parent.app, launch: h.launch, execution: h.execution, selection: h.launch.chain.selection}
	t.Cleanup(func() {
		if h.process != nil {
			h.process.nativeAcknowledged, h.process.nativeStopped = true, true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := h.Close(ctx); err != nil {
			t.Error("original execution product fixture did not join", err)
		}
	})
	return h, s, actions
}

func TestDesktopMacOSExecutionProductStopKeepsOriginalOwnerAndIntent(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, disconnect := range []bool{false, true} {
			name := map[bool]string{false: "started", true: "partial"}[partial] + "/" + map[bool]string{false: "replacement", true: "disconnect"}[disconnect]
			t.Run(name, func(t *testing.T) {
				h, s, actions := macOSExecutionProductStopFixture(t)
				if partial {
					// PF/workspace ownership precedes process and graph publication.
					h.process, h.launch.command, s.app.cmd = nil, nil, nil
				}
				stop, err := h.runtime.captureExecutionProductStop(context.Background(), s)
				captured, exact := stop.(*desktopMacOSNodeChainStopCapture)
				if err != nil || !exact || captured.host != h || captured.command != s.launch.command ||
					captured.operation != s.app.connectionContext || len(*actions) != 0 || h.nativeRetired {
					t.Fatal("execution product Stop did not retain its original untouched owner", err)
				}
				if err := stop.Retire(context.Background(), s.launch.command, disconnect); err != nil {
					t.Fatal("original execution product Stop could not retire", err)
				}
				action, phase := "retire", "held"
				if disconnect {
					action, phase = "release", "retired"
				}
				if !h.closed || !h.nativeRetired || !h.workspaceRetired || !h.baselineRetired || h.baseline.Phase != phase ||
					h.baseline.Baseline.Present == disconnect || !reflect.DeepEqual(*actions, []string{action}) ||
					h.parent.session.nodeChain != nil || s.app.cmd != nil {
					t.Fatal("execution product Stop changed original disconnect or retained-deny intent", *actions)
				}
				terminal, err := h.runtime.captureExecutionProductStop(context.Background(), s)
				_, held := terminal.(*desktopMacOSExecutionProtectionStop)
				if err != nil || !s.closed || disconnect && terminal != nil || !disconnect && !held || !reflect.DeepEqual(*actions, []string{action}) {
					t.Fatal("closed execution host lost its exact terminal protection disposition", err)
				}
			})
		}
	}
}

func TestDesktopMacOSExecutionProductStopRejectsForeignOwners(t *testing.T) {
	for _, fault := range []string{"app", "launch", "execution", "platform", "host-runtime", "preparation", "physical", "native-selection", "session-slot", "command"} {
		t.Run(fault, func(t *testing.T) {
			h, s, actions := macOSExecutionProductStopFixture(t)
			platform := h.runtime
			switch fault {
			case "app":
				s.app = &app{}
			case "launch":
				s.launch = &desktopNodeLaunch{chain: h.launch.chain, command: h.launch.command}
			case "execution":
				s.execution = &desktopNodeChainExecutionLaunch{}
			case "platform":
				platform = &desktopNodeChainPlatformRuntime{host: h, registered: true}
			case "host-runtime":
				h.runtime = &desktopNodeChainPlatformRuntime{host: h, registered: true}
				defer func() { h.runtime = platform }()
			case "preparation":
				original := h.executionPreparation
				h.executionPreparation = nil
				defer func() { h.executionPreparation = original }()
			case "physical":
				original := h.executionPhysical
				h.executionPhysical = nil
				defer func() { h.executionPhysical = original }()
			case "native-selection":
				s.selection.Native = nil
			case "session-slot":
				h.parent.session.nodeChain = &desktopNodeChainPlatformRuntime{}
				defer func() { h.parent.session.nodeChain = platform }()
			case "command":
				s.app.cmd = &exec.Cmd{}
				defer func() { s.app.cmd = h.launch.command }()
			}
			if stop, err := platform.captureExecutionProductStop(context.Background(), s); err == nil || stop != nil || h.nativeRetired || h.closed || len(*actions) != 0 {
				t.Fatal("execution product Stop accepted a substituted original association", fault, err)
			}
		})
	}
}

func TestDesktopMacOSExecutionProductStopCancellationKeepsCallerBudget(t *testing.T) {
	for _, held := range []string{"session", "parent", "host", "app"} {
		t.Run(held, func(t *testing.T) {
			h, s, actions := macOSExecutionProductStopFixture(t)
			var unlock func()
			switch held {
			case "session":
				s.mu.Lock()
				unlock = s.mu.Unlock
			case "parent":
				<-h.parent.parent.gate
				unlock = func() { h.parent.parent.gate <- struct{}{} }
			case "host":
				<-h.gate
				unlock = func() { h.gate <- struct{}{} }
			case "app":
				s.app.mu.Lock()
				unlock = s.app.mu.Unlock
			}
			var once sync.Once
			release := func() { once.Do(unlock) }
			defer release()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, joined := make(chan struct{}), make(chan error, 1)
			go func() {
				close(entered)
				stop, err := h.runtime.captureExecutionProductStop(ctx, s)
				if stop != nil {
					err = errors.Join(err, errors.New("cancelled product capture returned active authority"))
				}
				joined <- err
			}()
			<-entered
			cancel()
			select {
			case err := <-joined:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("execution product capture lost original caller cancellation", err)
				}
			case <-time.After(time.Second):
				release()
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Fatal("cancelled execution product capture did not join after bounded cleanup")
				}
				t.Fatal("execution product capture replaced caller cancellation with standalone Stop budget")
			}
			if h.closed || h.nativeRetired || len(*actions) != 0 {
				t.Fatal("cancelled execution product capture mutated retained cleanup ownership")
			}
		})
	}
}

func TestDesktopMacOSExecutionProductStopRetainsFailedJoinAndReplacement(t *testing.T) {
	for _, fault := range []string{"native-ack", "command", "operation", "session"} {
		t.Run(fault, func(t *testing.T) {
			h, s, actions := macOSExecutionProductStopFixture(t)
			stop, err := h.runtime.captureExecutionProductStop(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			originalCommand, originalOperation := s.app.cmd, s.app.connectionContext
			restore := func() {
				h.process.nativeAcknowledged, h.process.nativeStopped = true, true
				s.app.cmd, s.app.connectionContext, h.parent.session.nodeChain = originalCommand, originalOperation, h.runtime
			}
			defer restore()
			switch fault {
			case "native-ack":
				h.process.nativeAcknowledged, h.process.nativeStopped = false, false
			case "command":
				s.app.cmd = &exec.Cmd{}
			case "operation":
				replacement, cancel := context.WithCancel(context.Background())
				defer cancel()
				s.app.connectionContext = replacement
			case "session":
				h.parent.session.nodeChain = &desktopNodeChainPlatformRuntime{}
			}
			if err := stop.Retire(context.Background(), originalCommand, false); err == nil || h.closed || h.nativeRetired ||
				h.baselineRetired || h.workspaceRetired || len(*actions) != 0 {
				t.Fatal("execution product Stop lost failed original retirement or adopted a replacement", fault, err)
			}
			if _, err := os.Stat(h.launch.directory); err != nil {
				t.Fatal("failed execution product retirement removed the original workspace", err)
			}
			restore()
			if err := stop.Retire(context.Background(), originalCommand, false); err != nil || !h.closed ||
				!h.baseline.Baseline.Present || !reflect.DeepEqual(*actions, []string{"retire"}) {
				t.Fatal("same original captured execution Stop could not retry under retained deny", err)
			}
		})
	}
}

func TestDesktopMacOSExecutionProductStopProvesJoinedCleanupBeforeAbsence(t *testing.T) {
	for _, stage := range []string{"unregistered", "registered", "staged"} {
		t.Run("unpublished-"+stage, func(t *testing.T) {
			h, s, actions := macOSExecutionProductStopFixture(t)
			// Constructor/preflight/stage can return this exact partial owner
			// before Start publishes a parent slot or enters PF/native work.
			h.entered, h.published, h.baselineEntered, h.baseline = false, false, false, nil
			h.process, h.launch.command, s.app.cmd, h.parent.session.nodeChain = nil, nil, nil, nil
			if stage != "staged" {
				if err := cleanupDesktopNodeLaunch(h.launch); err != nil {
					t.Fatal(err)
				}
				h.staged, h.stageDirectory, h.stageInfo = false, "", nil
				h.launch.directory, h.launch.directoryRoot, h.launch.directoryInfo = "", nil, nil
			}
			if stage == "unregistered" {
				h.runtime.registered = false
				delete(h.parent.session.dependents, h)
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if err := s.Close(cancelled); !errors.Is(err, context.Canceled) || h.closed || s.closed {
				t.Fatal("cancelled partial cleanup fabricated a completed owner", err)
			}
			stop, err := h.runtime.captureExecutionProductStop(context.Background(), s)
			captured, exact := stop.(*desktopMacOSExecutionUnpublishedStop)
			if err != nil || !exact || captured.host != h || captured.session != s || h.closed || h.nativeRetired || len(*actions) != 0 {
				t.Fatal("unpublished original cleanup was not retained for bounded retry", err)
			}
			// Capture cannot authorize a replacement command, then the same
			// captured original transaction must remain available for retry.
			s.app.cmd = &exec.Cmd{}
			err = stop.Retire(context.Background(), nil, true)
			s.app.cmd = nil
			if err == nil || h.nativeRetired || h.closed || len(*actions) != 0 {
				t.Fatal("unpublished Stop adopted a replacement command", err)
			}
			if err := stop.Retire(context.Background(), nil, true); err != nil || !h.closed || !s.closed ||
				!h.nativeRetired || !h.workspaceRetired || len(*actions) != 0 {
				t.Fatal("original unpublished owner could not join its exact cleanup", err)
			}
			if stop, err := h.runtime.captureExecutionProductStop(context.Background(), s); err != nil || stop != nil {
				t.Fatal("joined unpublished owner did not prove its final absence", err)
			}
		})
	}
	for _, baseline := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-baseline", true: "released-on-connect"}[baseline], func(t *testing.T) {
			h, s, actions := macOSExecutionProductStopFixture(t)
			if !baseline {
				h.baselineEntered, h.baseline = false, nil
			}
			if err := s.Close(context.Background()); err != nil {
				t.Fatal("actual failed-start session cleanup did not join", err)
			}
			if !s.closed || !h.closed || !h.nativeRetired || !h.workspaceRetired || h.parent.session.nodeChain != nil {
				t.Fatal("session closure substituted for original terminal native cleanup")
			}
			before := append([]string{}, (*actions)...)
			stop, err := h.runtime.captureExecutionProductStop(context.Background(), s)
			if err != nil || stop != nil || !reflect.DeepEqual(before, *actions) {
				t.Fatal("joined released execution could not hand off its exact empty owner", err)
			}
		})
	}
	t.Run("native-joined-session-cancelled", func(t *testing.T) {
		h, s, actions := macOSExecutionProductStopFixture(t)
		if err := h.Close(context.Background()); err != nil || s.closed {
			t.Fatal("native-only retirement did not preserve unfinished session bookkeeping", err)
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if err := s.Close(cancelled); !errors.Is(err, context.Canceled) || s.closed {
			t.Fatal("cancelled session cleanup fabricated completion", err)
		}
		if stop, err := h.runtime.captureExecutionProductStop(context.Background(), s); err != nil || stop != nil || !s.closed ||
			!reflect.DeepEqual(*actions, []string{"release"}) {
			t.Fatal("fresh captured Stop could not finish already joined session bookkeeping", err)
		}
	})
}

func TestDesktopMacOSExecutionProductStopRetainsTerminalProtectionUntilDisconnect(t *testing.T) {
	h, s, actions := macOSExecutionProductStopFixture(t)
	if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	stop, err := h.runtime.captureExecutionProductStop(context.Background(), s)
	captured, exact := stop.(*desktopMacOSExecutionProtectionStop)
	if err != nil || !exact || captured.host != h || captured.session != s || captured.receipt != h.baseline ||
		h.baseline.Phase != "held" || !h.baseline.Baseline.Present {
		t.Fatal("closed execution discarded its original held protection transaction", err)
	}
	if err := stop.Retire(context.Background(), nil, false); err != nil || !h.baseline.Baseline.Present || h.baseline.Phase != "held" {
		t.Fatal("replacement Stop opened the original retained deny baseline", err)
	}
	original, receipt := h.baselineRun, h.baseline
	h.baselineRun = func(context.Context, *desktopMacOSSessionCapture, desktopMacOSNodeChainSelection,
		string, *desktopMacOSNodeChainReceipt, func()) (*desktopMacOSNodeChainReceipt, error) {
		return nil, errors.New("original guarded PF retirement remains pending")
	}
	if err := stop.Retire(context.Background(), nil, true); err == nil || h.baseline != receipt || captured.receipt != receipt || !h.baseline.Baseline.Present {
		t.Fatal("failed final Disconnect discarded the exact retained protection receipt")
	}
	h.baselineRun = original
	if err := stop.Retire(context.Background(), nil, true); err != nil || h.baseline.Baseline.Present || h.baseline.Phase != "retired" ||
		!reflect.DeepEqual(*actions, []string{"retire", "retire", "release"}) {
		t.Fatal("final Disconnect could not settle its original joined protection transaction", err)
	}
	if stop, err := h.runtime.captureExecutionProductStop(context.Background(), s); err != nil || stop != nil {
		t.Fatal("released terminal execution failed its exact absence handoff", err)
	}
}

func TestDesktopMacOSExecutionProductStopRejectsFalseTerminalAbsence(t *testing.T) {
	for _, fault := range []string{"native-progress", "workspace-progress", "native-ack", "process-close", "process-join", "workspace-replacement", "baseline-progress", "baseline-phase", "baseline-capture", "controller", "command", "registry", "graph", "parent-slot", "parent-dependent"} {
		t.Run(fault, func(t *testing.T) {
			h, s, actions := macOSExecutionProductStopFixture(t)
			if err := s.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			before := append([]string(nil), (*actions)...)
			switch fault {
			case "native-progress":
				h.nativeRetired = false
				defer func() { h.nativeRetired = true }()
			case "workspace-progress":
				h.workspaceRetired = false
				defer func() { h.workspaceRetired = true }()
			case "native-ack":
				h.process.nativeAcknowledged = false
				defer func() { h.process.nativeAcknowledged = true }()
			case "process-close":
				h.process.closed = false
				defer func() { h.process.closed = true }()
			case "process-join":
				original := h.process.joined
				h.process.joined = make(chan struct{})
				defer func() { h.process.joined = original }()
			case "workspace-replacement":
				if err := os.Mkdir(h.stageDirectory, 0700); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(h.stageDirectory)
			case "baseline-progress":
				h.baselineRetired = false
				defer func() { h.baselineRetired = true }()
			case "baseline-phase":
				h.baseline.Phase = "active"
				defer func() { h.baseline.Phase = "retired" }()
			case "baseline-capture":
				original := h.baseline.Capture
				h.baseline.Capture.Source = "replacement"
				defer func() { h.baseline.Capture = original }()
			case "controller":
				s.app.localController = &ownedDesktopController{}
				defer func() { s.app.localController = h.parent.controller }()
			case "command":
				s.app.cmd = &exec.Cmd{}
				defer func() { s.app.cmd = nil }()
			case "registry":
				nativeMultihopOwners.Store(s.app, &nativeMultihopRuntime{})
				defer nativeMultihopOwners.Delete(s.app)
			case "graph":
				activeMultihopGraphs.Store(s.app, activeMultihopGraph{ChainNodes: 3})
				defer activeMultihopGraphs.Delete(s.app)
			case "parent-slot":
				h.parent.session.nodeChain = &desktopNodeChainPlatformRuntime{}
				defer func() { h.parent.session.nodeChain = nil }()
			case "parent-dependent":
				h.parent.session.dependents[h] = struct{}{}
				defer delete(h.parent.session.dependents, h)
			}
			if stop, err := h.runtime.captureExecutionProductStop(context.Background(), s); err == nil || stop != nil || !reflect.DeepEqual(before, *actions) {
				t.Fatal("closed session fabricated native absence from incomplete or foreign authority", fault, err)
			}
		})
	}
	for _, fault := range []string{"command", "operation", "receipt"} {
		t.Run("retained-"+fault, func(t *testing.T) {
			h, s, actions := macOSExecutionProductStopFixture(t)
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			stop, err := h.runtime.captureExecutionProductStop(context.Background(), s)
			if err != nil || stop == nil {
				t.Fatal(err)
			}
			originalOperation, originalReceipt := s.app.connectionContext, h.baseline
			defer func() { s.app.cmd, s.app.connectionContext, h.baseline = nil, originalOperation, originalReceipt }()
			switch fault {
			case "command":
				s.app.cmd = &exec.Cmd{}
			case "operation":
				replacement, cancel := context.WithCancel(context.Background())
				defer cancel()
				s.app.connectionContext = replacement
			case "receipt":
				copy := *h.baseline
				h.baseline = &copy
			}
			if err := stop.Retire(context.Background(), nil, true); err == nil || !reflect.DeepEqual(*actions, []string{"retire"}) {
				t.Fatal("terminal protection Stop adopted a replacement after capture", fault, err)
			}
		})
	}
}
