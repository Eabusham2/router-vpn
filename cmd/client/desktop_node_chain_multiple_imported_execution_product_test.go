package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// Only the child process and kernel are modeled. The shipping parent performs
// its actual complete-source staging, typed adoption, readiness and restoration.
func prepareDesktopMultipleImportedExecutionModel(t *testing.T, layout desktopIndependentImportedLayout, requested, winner string) (*desktopNodeChainOwnedFixture, *desktopNodeChainExecutionSession) {
	t.Helper()
	a, nodes := desktopIndependentImportedFixture(t, layout, "wg", "off")
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[layout.count-1], a.profiles.Profiles, nodes, requested)
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newDesktopNodeChainOwnedFixtureWith(t, a, selection)
	f.executionModel = &desktopExecutionOwnedModel{winner: winner}
	request := &desktopNodeChainExecutionRequest{capture: f.capture, native: selection.Native, requested: requested}
	launch, err := prepareDesktopOwnedNodeChainLaunchForPurposeAndExecution(f.operation, f.capture, selection, nil, request)
	if err != nil {
		t.Fatal(err)
	}
	f.launch = launch
	return f, &desktopNodeChainExecutionSession{app: a, launch: launch, execution: launch.chain.execution, selection: selection}
}

func TestDesktopMultipleImportedExecutionParentSelectionAndRestore(t *testing.T) {
	for _, index := range []int{1, 2, 4} {
		for _, choice := range [][2]string{{"server", "server"}, {"auto", "local"}, {"auto", "server"}} {
			layout := desktopIndependentImportedLayouts[index]
			t.Run(fmt.Sprintf("%s/%s/%s", layout.name, choice[0], choice[1]), func(t *testing.T) {
				f, session := prepareDesktopMultipleImportedExecutionModel(t, layout, choice[0], choice[1])
				if err := session.startContext(f.operation); err != nil {
					t.Fatal(err)
				}
				execution := session.execution
				if execution.multiplePhysical == nil || execution.ready == nil || execution.ready.Kind != "routervpn-node-chain-multiple-imported-execution-ready-v1" || execution.ready.Progress.Execution != choice[1] || len(execution.ready.Progress.Prefixes) != layout.count {
					t.Fatal("parent lost complete selected schema-six readiness")
				}
				public, _, err := execution.projection.ImportedPublicMeasurementCaptures(choice[1])
				if err != nil || len(public) != len(layout.positions) {
					t.Fatal("selected public inventory", err)
				}
				for i, position := range layout.positions {
					row := execution.ready.Progress.Prefixes[position]
					if public[i].Position != position || row.Kind != "public-path" || row.Label != "Cumulative path through imported hop to public HTTPS edge" || !row.Proven {
						t.Fatal("parent borrowed another imported position")
					}
				}
				restore, err := session.CaptureRestore(f.operation)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows"); err == nil {
					t.Fatal("unjoined multiple imported owner restored")
				}
				if err := restore.retireContext(context.Background()); err != nil {
					t.Fatal(err)
				}
				<-f.pulseDone
				next, resumed, err := restore.newLaunchContext(f.operation, strings.Repeat("b", 32), "windows")
				if err != nil {
					t.Fatal(err)
				}
				last, present, err := resumed.preparation.MultipleImportedDesktopLast()
				if err != nil || !present || last.Execution() != choice[1] || last.Target() != mobilemultihop.Targets[1] || f.starts != 1 || resumed.multiplePhysical == nil || resumed.preparation.LocalSource() != execution.preparation.LocalSource() || next.chain.selection.Native != session.selection.Native {
					t.Fatal("restore changed original route, choice or measurement target", err)
				}
				_, meta, _, err := next.chain.policy.PhysicalReadValidated()
				if err != nil || meta.RestoredMTU != f.live.MTU {
					t.Fatal("restore lost actual captured MTU", err)
				}
			})
		}
	}
}
