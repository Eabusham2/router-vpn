package main

import (
	"context"
	"errors"
	"testing"
)

type desktopExecutionRestoreCloseModel struct {
	expected *desktopNodeChainExecutionLaunch
	calls    int
	failure  error
}

func (m *desktopExecutionRestoreCloseModel) closeForExecutionRestore(ctx context.Context, e *desktopNodeChainExecutionLaunch) error {
	m.calls++
	if e != m.expected {
		return errors.New("model received another captured execution")
	}
	return errors.Join(m.failure, ctx.Err())
}

// Capability dispatch model only: the actual Darwin inherited owner separately
// proves joined child/PF/utun retention and the physical deny baseline.
func TestDesktopNodeChainExecutionRestoreKeepsRetainedCloseIntent(t *testing.T) {
	for _, fault := range []string{"retained-darwin", "missing-darwin", "failed-retained", "foreign-execution", "foreign-launch", "cancelled", "linux-fallback", "windows-fallback"} {
		t.Run(fault, func(t *testing.T) {
			target := "darwin"
			if fault == "linux-fallback" {
				target = "linux"
			}
			if fault == "windows-fallback" {
				target = "windows"
			}
			launch, e := desktopExecutionAttachedFixture(t, target)
			model := &desktopExecutionRestoreCloseModel{expected: e}
			var retained desktopNodeChainExecutionRestoreCloser = model
			ctx := context.Background()
			fallback := 0
			switch fault {
			case "missing-darwin", "linux-fallback", "windows-fallback":
				retained = nil
			case "failed-retained":
				model.failure = errors.New("retained close has not joined")
			case "foreign-execution":
				_, e = desktopExecutionAttachedFixture(t, target)
			case "foreign-launch":
				launch = &desktopNodeLaunch{chain: launch.chain}
			case "cancelled":
				call, cancel := context.WithCancel(ctx)
				cancel()
				ctx = call
			}
			err := closeDesktopNodeChainExecutionRestoreCapability(ctx, launch, e, retained, func(context.Context) error { fallback++; return nil })
			positive := fault == "retained-darwin" || fault == "linux-fallback" || fault == "windows-fallback"
			if (err == nil) != positive {
				t.Fatal("wrong restore close admission", err)
			}
			wantRetained := 0
			if fault == "retained-darwin" || fault == "failed-retained" {
				wantRetained = 1
			}
			wantFallback := 0
			if fault == "linux-fallback" || fault == "windows-fallback" {
				wantFallback = 1
			}
			if model.calls != wantRetained || fallback != wantFallback {
				t.Fatal("restore borrowed ordinary Disconnect or another captured owner", model.calls, fallback)
			}
		})
	}
}
