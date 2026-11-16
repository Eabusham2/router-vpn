//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// Actual parent/PF receipt/child retirement methods execute; PF commands and
// child acknowledgment remain the existing explicit boundary models.
func TestMacOSPairedSSExecutionRetirementKeepsOriginalPhysicalOwner(t *testing.T) {
	for _, fault := range []string{"original", "missing-host", "foreign-child", "foreign-preparation"} {
		t.Run(fault, func(t *testing.T) {
			h, actions := macOSExecutionRetirementFixtureWith(t, func(t *testing.T) (*app, *desktopNodeLaunch) {
				return desktopNodeChainLaunchFixture(t, 4, "darwin")
			})
			if h.executionPhysical == nil || h.executionCONNECTPhysical != nil || h.executionSOCKSPhysical != nil || h.executionOpenVPNPhysical != nil || h.process.executionPhysical != h.executionPhysical {
				t.Fatal("paired SS retirement borrowed imported physical authority")
			}
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || h.closed || h.nativeRetired || len(*actions) != 0 {
				t.Fatal("child exit substituted for paired SS cleanup acknowledgment", err)
			}
			if _, err := os.Stat(h.launch.directory); err != nil {
				t.Fatal("unjoined paired SS child lost private source", err)
			}
			h.process.nativeAcknowledged, h.process.nativeStopped = true, true
			physical, child, preparation := h.executionPhysical, h.process.executionPhysical, h.process.execution
			switch fault {
			case "missing-host":
				h.executionPhysical = nil
			case "foreign-child":
				h.process.executionPhysical = &mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy{}
			case "foreign-preparation":
				replay, err := mobilemultihop.ParseDesktopNodeChainExecutionPreparation(preparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				h.process.execution = replay
			}
			if fault != "original" {
				if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || h.closed || len(*actions) != 0 {
					t.Fatal("foreign paired SS owner acquired original PF retirement", err)
				}
				h.executionPhysical, h.process.executionPhysical, h.process.execution = physical, child, preparation
			}
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err != nil || !h.closed || !h.nativeRetired || !h.workspaceRetired || !h.baselineRetired || h.baseline.Phase != "held" || !h.baseline.Baseline.Present || !reflect.DeepEqual(*actions, []string{"retire"}) {
				t.Fatal("paired SS retirement lost joined owner or retained deny", err)
			}
		})
	}
}

// Real Darwin public admission must reach the original captured preparation.
// The deliberate preparation refusal proves dispatch without claiming a child
// or kernel connection; installed PF/TUN/provider evidence remains separate.
func TestMacOSPairedSSExecutionPublicPreparationKeepsCapturedSource(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, choice := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, choice), func(t *testing.T) {
				a, launch := desktopNodeChainLaunchFixture(t, count, "darwin")
				selected := launch.chain.selection
				captures, prepares := 0, 0
				driver := &desktopOrderedExecutionRuntime{
					capture: func(ctx context.Context, owner *app, selection multihopSelection, modes []string) (multihopSelection, error) {
						captures++
						if owner != a || !reflect.DeepEqual(nodeChainSelectedReferences(selection.Nodes), nodeChainSelectedReferences(selected.Nodes)) || !reflect.DeepEqual(modes, []string{"shadowsocks"}) {
							return selection, errors.New("foreign paired SS capture")
						}
						return selected, ctx.Err()
					},
					prepare: func(ctx context.Context, owner *app, selection multihopSelection, requested string) (*desktopNodeChainExecutionSession, error) {
						prepares++
						if owner != a || selection.Native != selected.Native || requested != choice || ctx.Err() != nil {
							t.Error("Darwin public preparation replaced original paired SS owner")
						}
						return nil, errors.New("deliberate original native preparation boundary")
					},
				}
				request := orderedPublicRequest(t, a, nodeChainSelectedReferences(selected.Nodes))
				request.Execution = choice
				raw, err := json.Marshal(request)
				if err != nil {
					t.Fatal(err)
				}
				response := httptest.NewRecorder()
				a.nativeMultihopConnectOwned(response, httptest.NewRequest(http.MethodPost, "/api/multihop/connect", bytes.NewReader(raw)), nativeMultihopConnectRuntime{execution: driver})
				if response.Code != http.StatusBadGateway || captures != 1 || prepares != 1 || a.cmd != nil || a.state.Connected {
					t.Fatalf("Darwin paired SS admission did not preserve its bounded original preparation: status=%d captures=%d prepares=%d %s", response.Code, captures, prepares, response.Body.String())
				}
			})
		}
	}
}

func TestMacOSPairedSSExecutionAdmissionRemainsBounded(t *testing.T) {
	t.Setenv("ROUTERVPN_MULTIHOP_ENGINE", "native")
	if nativeDesktopOrderedExecutionPlatformSupported() {
		t.Fatal("generic Darwin capability was widened")
	}
	for _, count := range []int{2, 4, 8} {
		_, launch := desktopNodeChainLaunchFixture(t, count, "darwin")
		members := launch.chain.selection.Nodes
		if !desktopPairedSSExecutionMembers(members, "server") || !nativeDesktopOrderedExecutionSelectionPlatformSupported(members, "server") {
			t.Fatal("original paired SS refused")
		}
		foreign := cloneDesktopNodeChainMembers(members)
		foreign[len(foreign)-1].Mode = "openvpn"
		if desktopPairedSSExecutionMembers(foreign, "server") || nativeDesktopOrderedExecutionSelectionPlatformSupported(foreign, "server") {
			t.Fatal("paired SS capability admitted unrelated final")
		}
		foreign = cloneDesktopNodeChainMembers(members)
		foreign[0].Profile.NodeProofID = ""
		if desktopPairedSSExecutionMembers(foreign, "auto") || nativeDesktopOrderedExecutionSelectionPlatformSupported(foreign, "auto") {
			t.Fatal("paired SS capability admitted missing original identity")
		}
	}
}
