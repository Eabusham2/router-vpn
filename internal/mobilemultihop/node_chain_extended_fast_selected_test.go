package mobilemultihop

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNodeChainExtendedFastSelectedOriginalPlatforms(t *testing.T) {
	for _, count := range []int{9, 16} {
		layout := extendedSelectedLayout(count)
		for _, execution := range []string{"server", "auto"} {
			for _, target := range []string{"", "android", "ios"} {
				t.Run(fmt.Sprintf("%d/%s/%s", count, execution, target), func(t *testing.T) {
					original, prep, source := multipleImportedExecutionFixture(t, layout, "awg2-fast", "", execution, target)
					policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
					if err != nil {
						t.Fatal(err)
					}
					projection, err := prep.BindExecution(policy)
					if err != nil {
						t.Fatal(err)
					}
					bound, err := projection.MTUPlan()
					if err != nil {
						t.Fatal(err)
					}
					if _, err := projection.PlanForMTU(projection.Config(), bound.Original); err != nil {
						t.Fatal(err)
					}
					if prep.ExtendedOriginalNodeCount() != count || !original.extendedFastSelectedSource() {
						t.Fatal("lost original Fast platform source")
					}
					last := original.importedNodes.members[count-2]
					original.importedNodes.members[count-2] = original.importedNodes.members[count-3]
					if original.extendedFastSelectedSource() || prep.ExtendedOriginalNodeCount() != 0 || projection.validateCapture() == nil {
						t.Fatal("foreign late member retained selected Fast authority")
					}
					original.importedNodes.members[count-2] = last
				})
			}
			for _, target := range []string{"linux", "windows", "darwin"} {
				t.Run(fmt.Sprintf("%d/%s/desktop-%s", count, execution, target), func(t *testing.T) {
					original, _, source := multipleImportedExecutionFixture(t, layout, "awg2-fast", "", execution, "")
					native, err := NewDesktopNodeChainPolicy(original, strings.Repeat("c", 32), target, 0)
					if err != nil {
						t.Fatal(err)
					}
					prep, err := NewDesktopNodeChainMultipleImportedExecutionPreparation(native, execution)
					if err != nil {
						t.Fatal(err)
					}
					policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
					if err != nil {
						t.Fatal(err)
					}
					projection, err := prep.BindExecution(policy)
					if err != nil {
						t.Fatal(err)
					}
					bound, err := projection.MTUPlan()
					if err != nil {
						t.Fatal(err)
					}
					if _, err := projection.PlanForMTU(projection.Config(), bound.Original); err != nil {
						t.Fatal(err)
					}
					reopened, err := ParseDesktopNodeChainMultipleImportedExecutionPreparation(prep.Source())
					if err != nil || reopened.ConfigSHA256() != prep.ConfigSHA256() || reopened.ExtendedOriginalNodeCount() != count {
						t.Fatal("Fast native source failed exact reopen", err)
					}
					foreign, err := NewDesktopNodeChainPolicy(original, strings.Repeat("d", 32), target, 0)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := projection.PlanForMTU(foreign.Config(), bound.Original); err == nil {
						t.Fatal("another original native owner supplied the selected Fast TUN")
					}
				})
			}
		}
	}
}

// Native owners are the explicit existing runtime doubles. The canonical
// encrypted worker and complete Box checks retain their independent gates.
func TestNodeChainExtendedFastSelectedOriginal(t *testing.T) {
	for _, count := range []int{9, 16} {
		layout := extendedSelectedLayout(count)
		for _, requested := range []struct{ mode, winner string }{{"server", "server"}, {"auto", "server"}, {"auto", "local"}} {
			t.Run(fmt.Sprintf("%d/%s/%s", count, requested.mode, requested.winner), func(t *testing.T) {
				_, preparation, source := multipleImportedExecutionFixture(t, layout, "awg2-fast", "", requested.mode, "")
				f := newNodeChainExecutionRuntimeFixtureFromPreparation(t, source, preparation)
				if requested.mode == "auto" {
					if requested.winner == "local" {
						f.engine.serverDelay = 200 * time.Millisecond
					} else {
						f.engine.localDelay = 200 * time.Millisecond
					}
				}
				ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
				defer stop()
				if err := f.runtime.Run(ctx); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := f.runtime.CloseContext(ctx); err != nil {
						t.Error(err)
					}
				}()
				assertMultipleImportedExecutionProgress(t, f)
				before := f.runtime.Progress()
				if before.Execution != requested.winner {
					t.Fatalf("got %q, want originally measured %q", before.Execution, requested.winner)
				}
				projection := f.runtime.projection
				original, err := projection.preparation.OriginalMultipleImportedSource()
				if err != nil || original.ExtendedLocalNodeCount() != count || projection.preparation.ExtendedOriginalNodeCount() != count || projection.preparation.ExtendedOriginalStatusLimit() != original.ExtendedLocalStatusLimit() {
					t.Fatal("original capture", err)
				}
				for i, member := range projection.policy.source.Server.Members[:count-2] {
					if member.SourceSHA256 != original.importedSSMemberAt(i+1).source {
						t.Fatal("changed original private source", i+1)
					}
				}
				if !original.extendedFastSelectedSource() || projection.policy.source.Server.EntryMode != "awg2-fast" {
					t.Fatal("selected execution lost its original Fast packet owner")
				}
				plan, err := projection.MTUPlan()
				if err != nil {
					t.Fatal(err)
				}
				bound, err := projection.PlanForMTU(projection.Config(), plan.Original)
				if err != nil || bound.Ceiling != plan.Ceiling || len(plan.Prefixes) != count {
					t.Fatal("live Fast MTU", err)
				}
				for _, size := range bound.Candidates(plan.Ceiling) {
					config, err := bound.Config(size)
					if err != nil {
						t.Fatal(err)
					}
					actual, err := projection.PlanForMTU(config, size)
					if err != nil || actual.Ceiling != plan.Ceiling {
						t.Fatal("Fast TUN readback changed original ceiling", err)
					}
				}
				if _, err := projection.PlanForMTU(projection.Config(), plan.Ceiling+1); err == nil {
					t.Fatal("above-bound Fast TUN was admitted")
				}
				o := &nodeChainExecutionMeasurementTestOwner{runtime: f.runtime}
				m, err := f.runtime.NewHopMeasurementContext(ctx, o)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := m.Close(); err != nil {
						t.Error(err)
					}
				}()
				raw, err := m.SelectedCaptureContext(ctx)
				if err != nil || original.ValidateMultipleImportedLatencyCapture(raw) != nil {
					t.Fatal("selected receipt lost original source", err)
				}
				pub, _, err := projection.ImportedPublicMeasurementCaptures(before.Execution)
				if err != nil || len(pub) != count-2 || original.ValidateMultipleImportedLatencyCapture(strings.Replace(raw, pub[len(pub)-1].SourceSHA256, strings.Repeat("f", 64), 1)) == nil {
					t.Fatal("late source identity escaped validation", err)
				}
				after := f.runtime.Progress()
				if after.Execution != before.Execution || !reflect.DeepEqual(before.Comparison, after.Comparison) {
					t.Fatal("reading a selected capture repeated comparison")
				}
			})
		}
	}
}
