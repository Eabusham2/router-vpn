package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func prepareDesktopExecutionSessionModel(t *testing.T, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainExecutionSession) {
	t.Helper()
	f := newDesktopNodeChainOwnedFixture(t, 2)
	f.executionModel = &desktopExecutionOwnedModel{winner: winner}
	request := &desktopNodeChainExecutionRequest{capture: f.capture, native: f.selection.Native, requested: "auto"}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, f.selection, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	f.launch = launch
	f.onStart = func(_ context.Context, _ *desktopImportedOwnedProcess) {
		if _, exists := getActiveMultihopGraph(f.a); exists {
			t.Error("published a graph before child selection and fresh proof")
		}
		if _, exists := nativeMultihopOwners.Load(f.a); exists {
			t.Error("published native graph owner before child selection")
		}
	}
	return f, &desktopNodeChainExecutionSession{app: f.a, launch: launch, execution: launch.chain.execution, selection: f.selection}
}

// Runs real staging/start/adoption/registry/retirement methods with an explicit
// child/controller/kernel model. It does not claim native encrypted acceptance.
func TestDesktopNodeChainExecutionSessionOwnsChildResultAndRetirement(t *testing.T) {
	for _, winner := range []string{"local", "server"} {
		t.Run(winner, func(t *testing.T) {
			f, s := prepareDesktopExecutionSessionModel(t, winner)
			if err := s.startContext(f.operation); err != nil {
				t.Fatal(err)
			}
			if err := s.startContext(f.operation); err == nil || f.starts != 1 {
				t.Fatal("repeated child comparison/start")
			}
			result, err := s.Result(f.operation)
			if err != nil {
				t.Fatal(err)
			}
			if result.Winner == nil || string(result.Winner.Execution) != winner || !reflect.DeepEqual(result, f.executionModel.ready.Progress.Comparison) {
				t.Fatal("parent replaced native comparison result")
			}
			result.Winner.Transport = "changed-return-value"
			result.Measurements[0].Failure = "changed-return-value"
			again, err := s.Result(f.operation)
			if err != nil || !reflect.DeepEqual(again, f.executionModel.ready.Progress.Comparison) {
				t.Fatal("returned comparison aliases native receipt", err)
			}
			cancelled, cancel := context.WithCancel(f.operation)
			cancel()
			if err := s.Close(cancelled); err == nil || f.processes[0].closed {
				t.Fatal("cancelled cleanup changed child", err)
			}
			cause := errors.New("exact join pending")
			f.processes[0].closeErr = cause
			if err := s.Close(context.Background()); !errors.Is(err, cause) || s.closed {
				t.Fatal("failed join lost session", err)
			}
			if _, err := os.Stat(f.launch.directory); err != nil {
				t.Fatal("failed join removed private workspace", err)
			}
			f.processes[0].closeErr = nil
			if err := s.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !s.closed || !f.processes[0].closed || f.a.cmd != nil {
				t.Fatal("joined session retained original publication")
			}
			for _, registry := range []interface{ Load(any) (any, bool) }{&desktopNodeOwners, &nativeMultihopOwners, &activeMultihopGraphs, &activeDNSRuntimeIdentities} {
				if _, found := registry.Load(f.a); found {
					t.Fatal("joined session retained original registry")
				}
			}
			if _, err := os.Stat(f.launch.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("joined exact workspace not removed", err)
			}
			if err := s.Close(context.Background()); err != nil {
				t.Fatal("idempotent close failed", err)
			}
		})
	}
}

func TestDesktopNodeChainExecutionSessionCleanupKeepsReplacementPublications(t *testing.T) {
	f, s := prepareDesktopExecutionSessionModel(t, "server")
	if err := s.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	// Replacement registry publication is independent of the original native
	// join fixture. Its process/protection are never discovered or passed Close.
	replacement := &desktopNodeLaunch{command: exec.Command("replacement")}
	graph := *s.graph
	graph.Started = graph.Started.Add(time.Second)
	native := &nativeMultihopRuntime{launch: replacement, graph: graph}
	dns := activeDNSRuntimeIdentity{ProfileID: f.selection.Exit.ID, RuntimeID: f.selection.ExitMode, Config: "replacement/sing-box.json", ImportedEntry: true}
	f.a.mu.Lock()
	f.a.cmd = replacement.command
	desktopNodeOwners.Store(f.a, replacement)
	nativeMultihopOwners.Store(f.a, native)
	activeMultihopGraphs.Store(f.a, graph)
	activeDNSRuntimeIdentities.Store(f.a, dns)
	f.a.mu.Unlock()
	if err := s.Current(f.operation); err == nil {
		t.Fatal("replacement retained old Current")
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.a.cmd != replacement.command {
		t.Fatal("old close erased new command")
	}
	for _, pair := range []struct{ got, want any }{{loadExecutionRegistry(&desktopNodeOwners, f.a), replacement}, {loadExecutionRegistry(&nativeMultihopOwners, f.a), native}, {loadExecutionRegistry(&activeMultihopGraphs, f.a), graph}, {loadExecutionRegistry(&activeDNSRuntimeIdentities, f.a), dns}} {
		if !reflect.DeepEqual(pair.got, pair.want) {
			t.Fatal("old close erased replacement publication")
		}
	}
}

func loadExecutionRegistry(registry interface{ Load(any) (any, bool) }, a *app) any {
	value, _ := registry.Load(a)
	return value
}

func TestDesktopNodeChainExecutionSessionRestoresOnlyCapturedChoice(t *testing.T) {
	f, s := prepareDesktopExecutionSessionModel(t, "server")
	if err := s.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	capture, err := s.CaptureRestore(f.operation)
	if err != nil {
		t.Fatal(err)
	}
	foreign := desktopNodeChainExecutionRestore{app: capture.app, launch: &desktopNodeLaunch{}, execution: capture.execution}
	if _, _, err := s.prepareRestoreContext(f.operation, &foreign); err == nil || f.processes[0].closed {
		t.Fatal("foreign restore joined original child", err)
	}
	firstSession := f.launch.mtuSession
	firstDirectory := f.launch.directory
	next, _, err := s.prepareRestoreContext(f.operation, capture)
	if err != nil {
		t.Fatal(err)
	}
	if !s.closed || !capture.retired || !f.processes[0].closed || next.launch.mtuSession == firstSession {
		t.Fatal("restore bypassed joined original lifetime")
	}
	if _, err := os.Stat(firstDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restore retained original private workspace", err)
	}
	saved, present, err := next.execution.preparation.DesktopLast()
	if err != nil || !present || saved.Execution() != capture.last.Execution() || saved.Target() != capture.last.Target() || next.launch.chain.policy.Metadata().RestoredMTU != capture.mtu.MTU {
		t.Fatal("restore did not retain exact winner/target/MTU", err)
	}
	if again, _, err := s.prepareRestoreContext(f.operation, capture); err == nil || again != next {
		t.Fatal("same capture constructed a second successor")
	}
	f.launch = next.launch
	if err := next.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	if f.starts != 2 {
		t.Fatal("restore replayed more than one captured child")
	}
	result, err := next.Result(f.operation)
	if err != nil || result.Winner == nil || string(result.Winner.Execution) != saved.Execution() || result.Target != saved.Target() {
		t.Fatal("restored child changed selected result", err)
	}
	if err := next.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopNodeChainExecutionSessionPartialStartupCleanup(t *testing.T) {
	for _, phase := range []string{"prepared", "staged"} {
		t.Run(phase, func(t *testing.T) {
			f, s := prepareDesktopExecutionSessionModel(t, "server")
			if phase == "staged" {
				if err := stageOwnedNativeMultihopInputsContext(f.operation, f.a, f.selection, s.launch); err != nil {
					t.Fatal(err)
				}
			}
			directory := s.launch.directory
			replacement := &desktopNodeLaunch{command: exec.Command("replacement-after-partial-construction")}
			graph := activeMultihopGraph{Execution: "local", Started: time.Now()}
			native := &nativeMultihopRuntime{launch: replacement, graph: graph}
			dns := activeDNSRuntimeIdentity{ProfileID: f.selection.Exit.ID, RuntimeID: f.selection.ExitMode, Config: "replacement/sing-box.json", ImportedEntry: true}
			f.a.mu.Lock()
			f.a.cmd = replacement.command
			desktopNodeOwners.Store(f.a, replacement)
			nativeMultihopOwners.Store(f.a, native)
			activeMultihopGraphs.Store(f.a, graph)
			activeDNSRuntimeIdentities.Store(f.a, dns)
			f.a.mu.Unlock()
			if err := s.Close(context.Background()); err != nil {
				t.Fatal("partial original retirement failed", err)
			}
			if f.starts != 0 || !s.closed || f.a.cmd != replacement.command {
				t.Fatal("partial cleanup created child or erased replacement")
			}
			for _, pair := range []struct{ got, want any }{{loadExecutionRegistry(&desktopNodeOwners, f.a), replacement}, {loadExecutionRegistry(&nativeMultihopOwners, f.a), native}, {loadExecutionRegistry(&activeMultihopGraphs, f.a), graph}, {loadExecutionRegistry(&activeDNSRuntimeIdentities, f.a), dns}} {
				if !reflect.DeepEqual(pair.got, pair.want) {
					t.Fatal("partial cleanup erased unrelated publication")
				}
			}
			if directory != "" {
				if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("partial exact workspace remained", err)
				}
			}
			if err := s.Close(context.Background()); err != nil {
				t.Fatal("partial cleanup not idempotent", err)
			}
		})
	}
}

func TestDesktopNodeChainExecutionSessionChangedSourceStillJoinsOriginalChild(t *testing.T) {
	f, s := prepareDesktopExecutionSessionModel(t, "server")
	if err := s.startContext(f.operation); err != nil {
		t.Fatal(err)
	}
	asset := f.selection.Native.chain.assets[0]
	directory, err := nativeGeneratedDir(f.selection.Native.root, asset.id, asset.mode)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) == 0 {
		t.Fatal("missing original generated asset", err)
	}
	path := filepath.Join(directory, entries[0].Name())
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Current(f.operation); err == nil {
		t.Fatal("changed source retained Current")
	}
	if _, err := s.CaptureRestore(f.operation); err == nil {
		t.Fatal("changed source granted a new restore capture")
	}
	err = s.Close(context.Background())
	if !f.processes[0].closed {
		t.Fatal("changed source prevented original child join", err)
	}
	if err != nil {
		// Native protection may refuse a terminal receipt after an unrelated
		// source change. That refusal must retain the workspace/parent for retry.
		if s.closed {
			t.Fatal("failed retirement fabricated terminal cleanup", err)
		}
		if _, statErr := os.Stat(f.launch.directory); statErr != nil {
			t.Fatal("failed receipt removed original workspace", statErr)
		}
	}
}
