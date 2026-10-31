package main

import (
	"context"
	"os/exec"
	"testing"
)

func TestSpeedLabFallbackReleaseRequiresCapturedTransaction(t *testing.T) {
	for _, change := range []string{"live", "test-cancelled", "intent-cancelled", "operation", "runtime", "not-mutated", "restored", "invalid-owner"} {
		t.Run(change, func(t *testing.T) {
			intent, cancelIntent := context.WithCancel(context.Background())
			defer cancelIntent()
			operation, cancelTest := context.WithCancel(intent)
			defer cancelTest()
			command := &exec.Cmd{Path: "captured-runtime-not-executed"}
			owner := &speedLabTemporaryOwner{intent: intent, cancelIntent: cancelIntent, test: operation,
				cancelTest: cancelTest, current: operation, runtime: command, mutated: true}
			a := &app{connectionContext: operation, cmd: command}
			speedLabTemporaryOwners.Store(a, owner)
			defer speedLabTemporaryOwners.Delete(a)
			switch change {
			case "test-cancelled":
				cancelTest()
			case "intent-cancelled":
				cancelIntent() // explicit Stop still belongs to the outer test owner
			case "operation":
				a.connectionContext = context.Background()
			case "runtime":
				a.cmd = &exec.Cmd{Path: "replacement-runtime-not-executed"}
			case "not-mutated":
				owner.mutated = false
			case "restored":
				owner.restored = true
			case "invalid-owner":
				speedLabTemporaryOwners.Store(a, "not the captured owner")
			}
			originalCurrent, originalRuntime := owner.current, owner.runtime
			originalMutated, originalRestored := owner.mutated, owner.restored
			originalCommand, originalContext := a.cmd, a.connectionContext
			deferred, err := a.speedLabDefersFallbackRelease(operation)
			valid := change == "live" || change == "test-cancelled" || change == "intent-cancelled"
			if !deferred || (err == nil) != valid {
				t.Fatal("fallback cleanup accepted a replaced or completed temporary transaction", change, deferred, err)
			}
			if owner.current != originalCurrent || owner.runtime != originalRuntime || owner.mutated != originalMutated ||
				owner.restored != originalRestored || a.cmd != originalCommand || a.connectionContext != originalContext {
				t.Fatal("fallback ownership check changed a captured or replacement connection")
			}
		})
	}
}
