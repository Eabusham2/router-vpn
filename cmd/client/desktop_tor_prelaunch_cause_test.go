package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestDesktopTorPrelaunchRejectedOriginalCallerKeepsCauseAndCleanup(t *testing.T) {
	for _, cause := range []string{"cancelled", "deadline", "missing"} {
		t.Run(cause, func(t *testing.T) {
			a, prepared := desktopTorPreparedFixture(t, clientTorBridge)
			owner := desktopTorPreparedOwner(t, a, prepared)
			owner.command = exec.Command(os.Args[0], "-test.run=^TestStartupExternalProcessFixture$")
			owner.command.Env = envWithValue(os.Environ(), "ROUTERVPN_STARTUP_EXTERNAL_CHILD", "cleanup")
			var caller context.Context
			var expected error
			switch cause {
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				caller, expected = ctx, context.Canceled
			case "deadline":
				ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
				defer cancel()
				caller, expected = ctx, context.DeadlineExceeded
			}
			checked := false
			err := owner.startContext(caller, func() error {
				checked = true
				return nil
			})
			if !errors.Is(err, errTorPrelaunchRejected) || checked {
				t.Fatal("missing or expired original caller entered prelaunch admission", err, checked)
			}
			if expected != nil {
				if !errors.Is(err, expected) || !errors.Is(err, errConnectionOperationCancelled) {
					t.Fatal("expired Tor prelaunch lost its original cause or connection cancellation identity", err)
				}
			} else if errors.Is(err, errConnectionOperationCancelled) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("missing Tor caller manufactured an original cancellation", err)
			}
			if owner.command.Process != nil || a.cmd != nil || a.state.Connected || !owner.retired {
				t.Fatal("rejected Tor caller started a child or lost owned input retirement")
			}
			if _, exists := desktopNodeOwners.Load(a); exists {
				t.Fatal("rejected Tor caller retained native launch authority")
			}
			if _, exists := activeDNSRuntimeIdentities.Load(a); exists {
				t.Fatal("rejected Tor caller retained its prepared DNS identity")
			}
			if _, err := os.Stat(prepared.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected Tor caller retained its unused private inputs", err)
			}
			if err := owner.cleanup(); err != nil {
				t.Fatal("rejected Tor caller cleanup lost its original idempotent owner", err)
			}
		})
	}
}
