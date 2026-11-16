package mobilemultihop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func multipleImportedExecutionLatencyFixture(t *testing.T, layout nodeChainImportedLayout, execution string) (*nodeChainExecutionRuntimeFixture, *nodeChainExecutionMeasurementTestOwner, *NodeChainExecutionMeasurement, *NodeChainExecutionLatency) {
	t.Helper()
	f := multipleImportedExecutionRuntimeFixture(t, layout, execution)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	if execution == "auto" {
		f.engine.localDelay = time.Millisecond
		f.engine.serverDelay = 200 * time.Millisecond
	}
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
	measurement, err := f.runtime.NewHopMeasurementContext(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := measurement.Close(); err != nil {
			t.Error(err)
		}
	})
	facade := executionFiftyFacade(t, measurement)
	return f, owner, measurement, facade
}
func TestNodeChainMultipleImportedExecutionSelectedCapture(t *testing.T) {
	for _, index := range []int{1, 2, 5} {
		for _, execution := range []string{"server", "auto"} {
			layout := multipleImportedServerLayouts[index]
			t.Run(layout.name+"/"+execution, func(t *testing.T) {
				f, _, measurement, facade := multipleImportedExecutionLatencyFixture(t, layout, execution)
				var capture struct {
					Schema     int                                        `json:"schema"`
					Source     string                                     `json:"source_sha256"`
					Config     string                                     `json:"config_sha256"`
					Generation string                                     `json:"generation_sha256"`
					Execution  string                                     `json:"selected_execution"`
					Nodes      []nodeChainExecutionLatencyHop             `json:"nodes"`
					Multiple   *nodeChainExecutionLatencyMultipleImported `json:"multiple_imported"`
				}
				if err := json.Unmarshal([]byte(facade.CaptureJSON()), &capture); err != nil {
					t.Fatal(err)
				}
				p := f.runtime.projection
				selected := f.runtime.Progress().Execution
				identity, err := measurement.engine.IdentityContext(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256([]byte(identity))
				if capture.Schema != 1 || capture.Source != p.SourceSHA256() || capture.Config != p.ConfigSHA256() || capture.Generation != hex.EncodeToString(digest[:]) || capture.Execution != selected || len(capture.Nodes) != layout.count || capture.Multiple == nil || capture.Multiple.Schema != 6 || capture.Multiple.OriginalSourceSHA256 != p.preparation.local.SourceSHA256() {
					t.Fatal("typed selected source/generation identity changed", capture)
				}
				expected, _, err := p.ImportedPublicMeasurementCaptures(selected)
				if err != nil || len(expected) != len(capture.Multiple.Public) {
					t.Fatal("complete selected inventory", err)
				}
				for i, original := range expected {
					record := capture.Multiple.Public[i]
					if record.Position != original.Position || record.Tag != original.Tag || record.SourceSHA256 != original.SourceSHA256 {
						t.Fatal("foreign positional capture")
					}
				}
				proofs, _ := p.ProofInventory(selected)
				for i, node := range capture.Nodes {
					want := "private-node"
					if p.policy.importedPublicAt(i) {
						want = "public-path"
					}
					if node.Position != i || node.NodeID != proofs[i].ProfileID || node.Kind != want {
						t.Fatal("original selected kind/position", node)
					}
				}
			})
		}
	}
}
func TestNodeChainMultipleImportedExecutionSelectedCaptureRefusals(t *testing.T) {
	for _, fault := range []string{"original-owner", "selected-epoch", "measurement-owner", "source-copy", "projection-copy", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f, owner, measurement, facade := multipleImportedExecutionLatencyFixture(t, multipleImportedServerLayouts[1], "server")
			// The running source is immutable and its watch/Stop callbacks may
			// still read it. Corrupt only a detached borrowing capture; never
			// rewrite the original source underneath those owned callbacks.
			useDetachedProjection := func(projection *NodeChainExecutionProjection) {
				original := measurement.engine.projection
				measurement.engine.projection = projection
				// This facade has not started a measurement worker. Restore only
				// its idle borrowed field before the original measurement closes.
				t.Cleanup(func() { measurement.engine.projection = original })
			}
			switch fault {
			case "original-owner":
				preparation := *f.runtime.projection.preparation
				binding := *preparation.multiple
				preparation.multiple = &binding
				binding.self, binding.preparation = &binding, &preparation
				if err := preparation.validateCapture(); err != nil {
					t.Fatal("otherwise-identical detached control must validate", err)
				}
				binding.owners = nil
				if preparation.validateCapture() == nil {
					t.Fatal("detached preparation borrowed a missing original registry")
				}
				projection := *f.runtime.projection
				projection.preparation = &preparation
				useDetachedProjection(&projection)
			case "selected-epoch":
				f.engine.mu.Lock()
				f.engine.epoch++
				f.engine.mu.Unlock()
			case "measurement-owner":
				owner.mu.Lock()
				owner.runtime = nil
				owner.mu.Unlock()
			case "source-copy":
				preparation := *f.runtime.projection.preparation
				if preparation.validateCapture() == nil {
					t.Fatal("equal-content preparation borrowed the original binding")
				}
				projection := *f.runtime.projection
				projection.preparation = &preparation
				useDetachedProjection(&projection)
			case "projection-copy":
				projection := *f.runtime.projection
				if projection.Source() != f.runtime.projection.Source() || projection.Config() != f.runtime.projection.Config() {
					t.Fatal("projection-copy control changed captured content")
				}
				useDetachedProjection(&projection)
			case "cancel":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if v, e := measurement.NewLatencyBenchmarkContext(ctx, func(c context.Context) error { return c.Err() }); v != nil || e == nil {
					t.Fatal("cancelled facade")
				}
				return
			}
			if facade.CaptureJSON() != "" {
				t.Fatal("stale original selected source produced capture")
			}
		})
	}
}
func TestNodeChainMultipleImportedExecutionLegacyCaptureUnchanged(t *testing.T) {
	f := newNodeChainExecutionRuntimeFixture(t, "server")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := f.runtime.Run(ctx); err != nil {
		t.Fatal(err)
	}
	owner := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
	measurement, err := f.runtime.NewHopMeasurementContext(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer measurement.Close()
	facade := executionFiftyFacade(t, measurement)
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(facade.CaptureJSON()), &fields) != nil || len(fields) != 6 {
		t.Fatal("legacy capture shape widened")
	}
	for _, name := range []string{"schema", "source_sha256", "config_sha256", "generation_sha256", "selected_execution", "nodes"} {
		if _, ok := fields[name]; !ok {
			t.Fatal("legacy capture lost field")
		}
	}
	if !reflect.DeepEqual(f.runtime.projection.policy.localProofs, f.runtime.projection.policy.local.ProofInventory()) {
		t.Fatal("legacy source replaced")
	}
}
