package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func startDesktopExecutionOwnedModel(t *testing.T) *desktopNodeChainOwnedFixture {
	t.Helper()
	f := newDesktopNodeChainOwnedFixture(t, 2)
	f.executionModel = &desktopExecutionOwnedModel{winner: "server"}
	request := &desktopNodeChainExecutionRequest{capture: f.capture, native: f.selection.Native, requested: "auto"}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, f.selection, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	f.launch = launch
	if err := stageOwnedNativeMultihopCommandContext(f.operation, f.a, f.selection, launch); err != nil {
		t.Fatal(err)
	}
	f.a.mu.Lock()
	err = f.a.publishDesktopNodeChainStartLocked(f.operation, launch, f.selection)
	f.a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := startDesktopOwnedNodeChainLaunch(f.operation, f.operation, f.a, launch); err != nil {
		t.Fatal(err)
	}
	if _, err := publishDesktopMultihopPlatformGraph(f.operation, f.a, launch, f.selection, "server"); err != nil {
		t.Fatal(err)
	}
	if err := bindNativeMultihopRuntimeContext(f.operation, f.a, launch, f.selection, f.capture.network); err != nil {
		t.Fatal(err)
	}
	return f
}

// The actual original parent Current/Close paths execute against explicit
// child/controller/kernel models. A replacement is never made cleanup authority.
func TestDesktopNodeChainExecutionStaleOperationCannotMutateReplacement(t *testing.T) {
	for _, fault := range []string{"cancelled-caller", "replacement-operation", "replacement-runtime"} {
		t.Run(fault, func(t *testing.T) {
			f := startDesktopExecutionOwnedModel(t)
			original := f.launch
			graph, _ := getActiveMultihopGraph(f.a)
			raw, _ := nativeMultihopOwners.Load(f.a)
			originalNative := raw.(*nativeMultihopRuntime)
			operation, cancel := context.WithCancel(context.Background())
			defer cancel()
			replacement := &desktopNodeLaunch{command: exec.Command("replacement-native-command")}
			replacementProcess := &desktopImportedOwnedProcess{closeErr: errors.New("replacement process must never close")}
			replacement.ownedNode = &desktopOwnedNodeRuntime{process: replacementProcess}
			replacementGraph := graph
			replacementGraph.Started = graph.Started.Add(time.Second)
			replacementNative := &nativeMultihopRuntime{launch: replacement, graph: replacementGraph}
			replacementTarget := *f.kernel.target
			replacementTarget.Capture.SessionID = strings.Repeat("b", 32)
			replacementTarget.BaselineSHA256 = strings.Repeat("c", 64)
			f.a.mu.Lock()
			if fault != "cancelled-caller" {
				f.a.connectionContext = operation
			}
			if fault == "replacement-runtime" {
				f.a.cmd = replacement.command
				desktopNodeOwners.Store(f.a, replacement)
				nativeMultihopOwners.Store(f.a, replacementNative)
				activeMultihopGraphs.Store(f.a, replacementGraph)
				f.kernel.target = &replacementTarget
			}
			f.a.mu.Unlock()
			caller := context.Background()
			if fault == "cancelled-caller" {
				cancelled, revoke := context.WithCancel(f.operation)
				revoke()
				caller = cancelled
			}
			currentErr := desktopNodeChainCurrent(caller, f.a, original)
			if fault == "replacement-operation" {
				// A completed request is not the active runtime's lifetime.
				if currentErr != nil {
					t.Fatal("new request invalidated still-owned runtime", currentErr)
				}
			} else if currentErr == nil {
				t.Fatal("cancelled caller or replaced runtime kept native Current")
			}
			if _, err := publishDesktopMultihopPlatformGraph(caller, f.a, original, f.selection, "server"); err == nil {
				t.Fatal("late chosen graph publication succeeded")
			}
			if err := bindNativeMultihopRuntimeContext(caller, f.a, original, f.selection, f.capture.network); err == nil {
				t.Fatal("late native owner replaced retained publication")
			}
			if fault == "cancelled-caller" {
				if err := closeDesktopNodeChainLaunch(caller, f.a, original); err == nil || f.processes[0].closed || !f.kernel.locked {
					t.Fatal("cancelled Close mutated the live captured child", err)
				}
			}
			err := closeDesktopNodeChainLaunch(context.Background(), f.a, original)
			if !f.processes[0].closed {
				t.Fatal("stale source lost exact original child cleanup", err)
			}
			<-f.pulseDone
			if fault == "replacement-runtime" {
				if err == nil || original.ownedNode.retired || !f.kernel.locked || f.kernel.target == nil || *f.kernel.target != replacementTarget || replacementProcess.closes != 0 || replacementProcess.closed {
					t.Fatal("old Close changed replacement protection/process or fabricated retirement", err)
				}
				current, _ := nativeMultihopOwners.Load(f.a)
				node, _ := desktopNodeOwners.Load(f.a)
				after, _ := getActiveMultihopGraph(f.a)
				if current != replacementNative || node != replacement || f.a.cmd != replacement.command || after != replacementGraph || f.a.connectionContext != operation {
					t.Fatal("stale observation/Close mutated replacement ownership")
				}
			} else {
				if err != nil || !original.ownedNode.retired || f.kernel.locked {
					t.Fatal("cancelled original owner failed exact native retirement", err)
				}
				current, _ := nativeMultihopOwners.Load(f.a)
				if current != originalNative {
					t.Fatal("native retirement fabricated a different parent graph")
				}
				if fault == "replacement-operation" && f.a.connectionContext != operation {
					t.Fatal("old Close changed replacement operation")
				}
			}
		})
	}
}
