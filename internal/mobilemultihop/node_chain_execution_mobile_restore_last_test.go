package mobilemultihop

import (
	"context"
	"testing"
	"time"
)

// Compose the actual shared runtime, proof I/O, authenticated Manager and
// typed effective-MTU projection. Only the native reader/retirement boundary
// is the existing explicit component double; the bridge separately requires
// its original daemon Instance.Close receipt before replacement construction.
func TestMobileNodeChainExecutionLastAfterEffectiveMTURestore(t *testing.T) {
	original, reader, ctx := nodeChainExecutionReadbackFixture(t, "ios", "auto", true)
	before := original.runtime.Progress()
	if before.Execution != "local" {
		t.Fatal("fixture must retain a proved Compare Local result")
	}
	originalLast, err := original.runtime.CaptureLastContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := original.runtime.CaptureMobileRestoreContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodeChainExecutionReadbackRetire(t, original, reader, ctx)
	prep, err := capture.NewPreparationContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := original.runtime.projection.preparation
	if prep.Source() != ordinary.Source() || prep.LocalSource() != ordinary.LocalSource() || prep.ConfigSHA256() == ordinary.ConfigSHA256() {
		t.Fatal("effective MTU restore relabeled original source or actual config")
	}
	projection, err := prep.BindExecution(original.runtime.projection.policy)
	if err != nil {
		t.Fatal(err)
	}
	next := cloneNodeChainExecutionRuntimeEngine(original.engine)
	next.projection = projection
	next.identity.ConfigSHA256 = projection.ConfigSHA256()
	restored, err := NewMobileNodeChainExecutionRestoreRuntime(ctx, capture, projection, next)
	if err != nil {
		t.Fatal(err)
	}
	restored.testTLS = original.trust
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := restored.CloseContext(cleanup); err != nil {
			t.Error(err)
		}
	})
	if err := restored.Run(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err := restored.CaptureLastContext(ctx)
	if err != nil {
		t.Fatal("proved typed restore lost durable Last", err)
	}
	if saved.JSON() != originalLast.JSON() || saved.Execution() != before.Execution || saved.Target() != before.Comparison.Target ||
		saved.ValidatePreparation(prep) != nil || saved.ValidatePreparation(ordinary) != nil {
		t.Fatal("Last after typed restore changed logical intent or concrete winner")
	}
	reopened, err := ParseNodeChainExecutionPreparation(ordinary.Source())
	if err != nil || reopened.ConfigSHA256() != ordinary.ConfigSHA256() || reopened.ConfigSHA256() == prep.ConfigSHA256() {
		t.Fatal("ordinary Last preparation borrowed opaque effective MTU", err)
	}
	if _, err := ParseNodeChainExecutionLast(saved.JSON(), reopened); err != nil {
		t.Fatal("durable Last could not bind original ordinary source", err)
	}
	if _, err := reopened.MobileRestoreReadback(); err == nil {
		t.Fatal("ordinary Last source fabricated native restore authority")
	}
	next.mu.Lock()
	selections := len(next.selections)
	next.mu.Unlock()
	if selections != 1 || !restored.Progress().Ready || restored.Progress().Execution != "local" {
		t.Fatal("typed restore reran Compare while capturing Last", selections)
	}
}
