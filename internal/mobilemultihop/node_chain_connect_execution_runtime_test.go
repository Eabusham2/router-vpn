package mobilemultihop

import (
	"context"
	"testing"
	"time"
)

// The original HTTP/TLS lease, Manager, proofs and comparison execute. Only
// native routing/registry/DNS and remote worker observations are modeled by
// the existing fixture; this is not encrypted native acceptance.
func TestNodeChainCONNECTExecutionRuntimeOriginalProofsAndStop(t *testing.T) {
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			f := newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionFixtureSource(t, execution))
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err != nil {
				t.Fatal("original typed execution", err)
			}
			if !f.runtime.Progress().Ready {
				t.Fatal("typed runtime not ready")
			}
			if _, err := f.runtime.CaptureRestoreContext(ctx); err != nil {
				t.Fatal("original restore receipt", err)
			}
			if err := f.runtime.CloseContext(ctx); err != nil {
				t.Fatal("joined original stop", err)
			}
			f.runner.mu.Lock()
			defer f.runner.mu.Unlock()
			if len(f.runner.workers) == 0 {
				t.Fatal("missing actual Manager acquisition")
			}
			for _, worker := range f.runner.workers {
				if worker.Alive() {
					t.Fatal("original worker survived joined stop")
				}
			}
		})
	}
}
func TestNodeChainCONNECTExecutionRuntimeRefusesUnprovedOriginal(t *testing.T) {
	for _, fault := range []string{"public", "dns", "final", "foreign-source"} {
		t.Run(fault, func(t *testing.T) {
			f := newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionFixtureSource(t, "server"))
			switch fault {
			case "public":
				f.engine.wrongPublic = true
			case "dns":
				f.engine.failDNS = true
			case "final":
				f.engine.wrongPrefix = 2
			case "foreign-source":
				original := f.runtime.projection.preparation.connect.source
				fresh, err := NewNodeChainCONNECTSource(original.sourceJSON)
				if err != nil {
					t.Fatal(err)
				}
				f.runtime.projection.preparation.connect.source = fresh
				defer func() { f.runtime.projection.preparation.connect.source = original }()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := f.runtime.Run(ctx); err == nil {
				t.Fatal("unproved CONNECT execution admitted", fault)
			}
			f.engine.mu.Lock()
			opened := f.engine.open || f.engine.opens != 0
			f.engine.mu.Unlock()
			if opened || f.runtime.Progress().Ready {
				t.Fatal("failed proof opened application", fault)
			}
		})
	}
}

func TestNodeChainCONNECTExecutionRestoreKeepsOriginalChoice(t *testing.T) {
	testNodeChainExecutionRestoreKeepsWinner(t, newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionFixtureSource(t, "auto")))
}

type connectExecutionMissingObserver struct {
	NodeChainExecutionEngine
	NodeChainExecutionSelectionEpochEngine
}

func TestNodeChainCONNECTExecutionMissingNativeObserverRefusedBeforeDiscovery(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixtureFromSource(t, connectExecutionFixtureSource(t, "server"))
	missing := connectExecutionMissingObserver{f.engine, f.engine}
	if _, err := NewNodeChainExecutionRuntime(f.runtime.projection, missing); err == nil {
		t.Fatal("typed runtime acquired without original native observer")
	}
	if _, err := NewNodeChainExecutionDiscoveryOwner(f.runtime.projection.preparation, missing); err == nil {
		t.Fatal("typed discovery acquired without original native observer")
	}
}
