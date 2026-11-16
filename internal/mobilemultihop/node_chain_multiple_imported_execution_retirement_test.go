package mobilemultihop

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type multipleImportedRetiredTestEngine struct {
	*nodeChainExecutionRuntimeEngine
	joined   atomic.Bool
	calls    atomic.Int32
	failure  atomic.Bool
	onSecond func()
}

func (e *multipleImportedRetiredTestEngine) MultipleImportedExecutionRetiredContext(ctx context.Context, original *NodeChain) error {
	if e.calls.Add(1) == 2 && e.onSecond != nil {
		e.onSecond()
	}
	if !e.joined.Load() || e.failure.Load() {
		return errors.New("original native joined receipt unavailable")
	}
	return e.nodeChainExecutionRuntimeEngine.MultipleImportedExecutionRetiredContext(ctx, original)
}

type multipleImportedNoRetirement struct {
	NodeChainExecutionEngine
	source *nodeChainExecutionRuntimeEngine
}

func (e *multipleImportedNoRetirement) ObserveMultipleImportedExecutionContext(ctx context.Context, c *NodeChain) error {
	return e.source.ObserveMultipleImportedExecutionContext(ctx, c)
}
func (e *multipleImportedNoRetirement) SelectionEpochContext(ctx context.Context) (uint64, error) {
	return e.source.SelectionEpochContext(ctx)
}
func TestNodeChainMultipleImportedExecutionRetirementRefusals(t *testing.T) {
	for _, fault := range []string{"unjoined-native", "failed-native", "missing-native-interface", "old-engine", "old-session", "second-retirement-failure", "cancelled-retirement"} {
		t.Run(fault, func(t *testing.T) {
			f := multipleImportedExecutionRuntimeFixture(t, multipleImportedServerLayouts[1], "server")
			old := &multipleImportedRetiredTestEngine{nodeChainExecutionRuntimeEngine: f.engine}
			f.runtime.engine = old
			if fault == "missing-native-interface" {
				f.runtime.engine = &multipleImportedNoRetirement{NodeChainExecutionEngine: f.engine, source: f.engine}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err != nil {
				t.Fatal(err)
			}
			capture, err := f.runtime.CaptureRestoreContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.runtime.CloseContext(ctx); err != nil {
				t.Fatal(err)
			}
			next := cloneNodeChainExecutionRuntimeEngine(f.engine)
			f.engine.mu.Lock()
			f.engine.alive = false
			f.engine.mu.Unlock()
			old.joined.Store(true)
			switch fault {
			case "unjoined-native":
				old.joined.Store(false)
			case "failed-native":
				old.failure.Store(true)
			case "old-engine":
				next.identity.EngineID = capture.identity.EngineID
			case "old-session":
				next.identity.SessionID = capture.identity.SessionID
			case "second-retirement-failure":
				old.onSecond = func() { old.failure.Store(true) }
			case "cancelled-retirement":
				old.onSecond = cancel
			}
			restored, err := NewNodeChainExecutionRestoreRuntime(capture, next)
			if err != nil {
				t.Fatal("fixture restore construction", err)
			}
			restored.testTLS = f.trust
			if err = restored.Run(ctx); err == nil {
				t.Fatal("unjoined original native owner admitted")
			}
			next.mu.Lock()
			opens := next.opens
			next.mu.Unlock()
			if opens != 0 {
				t.Fatal("restore proof failure opened application")
			}
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer closeCancel()
			if err := restored.CloseContext(closeCtx); err != nil {
				t.Fatal("failed restore cleanup", err)
			}
		})
	}
}
