package main

import (
	"context"
	"os/exec"
	"testing"
)

// This exercises the final app-lock guard with original captured source and
// operation objects. Process/native proof remains outside this model boundary.
func TestDesktopNodeChainExecutionPublicationRequiresOriginalOperation(t *testing.T) {
	for _, fault := range []string{"original", "omitted-operation", "replacement-operation", "cancelled-operation", "replacement-command", "changed-source", "foreign-app"} {
		t.Run(fault, func(t *testing.T) {
			f := newDesktopNodeChainOwnedFixture(t, 2)
			request := &desktopNodeChainExecutionRequest{capture: f.capture, native: f.selection.Native, requested: "auto"}
			launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, f.selection, nil, request)
			if err != nil {
				t.Fatal(err)
			}
			f.launch = launch
			launch.command = exec.Command("original-owned-command")
			f.a.cmd = launch.command
			e := launch.chain.execution
			a := f.a
			switch fault {
			case "omitted-operation":
				e.operation = nil
			case "replacement-operation":
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f.a.connectionContext = ctx
			case "cancelled-operation":
				f.cancel()
			case "replacement-command":
				f.a.cmd = exec.Command("replacement-owned-command")
			case "changed-source":
				f.a.profiles.Profiles[0].APIToken = "replacement"
			case "foreign-app":
				a = &app{}
			}
			a.mu.Lock()
			err = e.publicationCurrentLocked(context.Background(), a, launch, f.selection)
			a.mu.Unlock()
			if (err == nil) != (fault == "original") {
				t.Fatal("wrong captured publication admission", err)
			}
		})
	}
}
