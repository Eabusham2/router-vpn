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
func TestMacOSHysteriaExecutionRetirementKeepsOriginalPhysicalOwner(t *testing.T) {
	for _, fault := range []string{"original", "missing-host", "foreign-child", "foreign-preparation"} {
		t.Run(fault, func(t *testing.T) {
			h, actions := macOSExecutionRetirementFixtureWith(t, func(t *testing.T) (*app, *desktopNodeLaunch) {
				return desktopHysteriaExecutionLaunchFixture(t, 4, "darwin", "", 0)
			})
			if h.executionPhysical == nil || h.executionCONNECTPhysical != nil || h.executionSOCKSPhysical != nil || h.executionOpenVPNPhysical != nil || h.process.executionPhysical != h.executionPhysical {
				t.Fatal("paired Hysteria retirement borrowed imported physical authority")
			}
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || h.closed || h.nativeRetired || len(*actions) != 0 {
				t.Fatal("child exit substituted for Hysteria cleanup acknowledgment", err)
			}
			if _, err := os.Stat(h.launch.directory); err != nil {
				t.Fatal("unjoined Hysteria child lost private source", err)
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
					t.Fatal("foreign Hysteria owner acquired original PF retirement", err)
				}
				h.executionPhysical, h.process.executionPhysical, h.process.execution = physical, child, preparation
			}
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err != nil || !h.closed || !h.nativeRetired || !h.workspaceRetired || !h.baselineRetired || h.baseline.Phase != "held" || !h.baseline.Baseline.Present || !reflect.DeepEqual(*actions, []string{"retire"}) {
				t.Fatal("paired Hysteria retirement lost joined owner or retained deny", err)
			}
		})
	}
}

func TestMacOSHysteriaExecutionAdmissionRemainsBounded(t *testing.T) {
	t.Setenv("ROUTERVPN_MULTIHOP_ENGINE", "native")
	_, launch := desktopHysteriaExecutionLaunchFixture(t, 4, "darwin", "", 0)
	members := launch.chain.selection.Nodes
	if !desktopHysteriaExecutionMembers(members, "server") || !nativeDesktopOrderedExecutionSelectionPlatformSupported(members, "server") {
		t.Fatal("original paired Hysteria refused")
	}
	// Selection is still checked independently of the platform capability hint.
	changed := cloneDesktopNodeChainMembers(members)
	changed[len(changed)-1].Mode = "shadowsocks"
	if desktopHysteriaExecutionMembers(changed, "server") || nativeDesktopOrderedExecutionSelectionPlatformSupported(changed, "server") {
		t.Fatal("Hysteria capability admitted unrelated paired SS")
	}
	changed = cloneDesktopNodeChainMembers(members)
	changed[len(changed)-1].Profile.StartLayer = "aes-256-gcm"
	if desktopHysteriaExecutionMembers(changed, "server") {
		t.Fatal("Hysteria capability admitted final Start Layer")
	}
}

// Real Darwin public admission must reach the original captured preparation.
// The deliberate preparation refusal proves dispatch without claiming a child
// or kernel connection; installed PF/TUN/provider evidence remains separate.
func TestMacOSHysteriaExecutionPublicPreparationKeepsCapturedSource(t *testing.T) {
	for _, count := range []int{2, 4, 8} {
		for _, choice := range []string{"server", "auto"} {
			t.Run(fmt.Sprintf("%d/%s", count, choice), func(t *testing.T) {
				a, launch := desktopHysteriaExecutionLaunchFixture(t, count, "darwin", "", 0)
				selected := launch.chain.selection
				captures, prepares := 0, 0
				driver := &desktopOrderedExecutionRuntime{
					capture: func(ctx context.Context, owner *app, selection multihopSelection, modes []string) (multihopSelection, error) {
						captures++
						if owner != a || !reflect.DeepEqual(nodeChainSelectedReferences(selection.Nodes), nodeChainSelectedReferences(selected.Nodes)) || !reflect.DeepEqual(modes, []string{"hysteria2"}) {
							return selection, errors.New("foreign Hysteria capture")
						}
						return selected, ctx.Err()
					},
					prepare: func(ctx context.Context, owner *app, selection multihopSelection, requested string) (*desktopNodeChainExecutionSession, error) {
						prepares++
						if owner != a || selection.Native != selected.Native || requested != choice || ctx.Err() != nil {
							t.Error("Darwin public preparation replaced original Hysteria owner")
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
					t.Fatalf("Darwin Hysteria admission did not preserve its bounded original preparation: status=%d captures=%d prepares=%d %s", response.Code, captures, prepares, response.Body.String())
				}
			})
		}
	}
}
