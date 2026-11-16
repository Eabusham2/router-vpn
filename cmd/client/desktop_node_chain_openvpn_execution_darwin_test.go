//go:build darwin

package main

import (
	"context"
	"os"
	"reflect"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func macOSOpenVPNExecutionRetirementFixture(t *testing.T) (*desktopMacOSNodeChainHost, *[]string) {
	return macOSExecutionRetirementFixtureWith(t, func(t *testing.T) (*app, *desktopNodeLaunch) {
		a, _, launch, _, _ := desktopOpenVPNExecutionLaunchFixtureWithProtection(t, 4, "darwin", "auto", "on-connect")
		return a, launch
	})
}

func TestMacOSOpenVPNExecutionRetirementKeepsOriginalPhysicalOwner(t *testing.T) {
	for _, fault := range []string{"original", "missing-host", "mixed-host", "foreign-child", "mixed-child", "foreign-preparation"} {
		t.Run(fault, func(t *testing.T) {
			h, actions := macOSOpenVPNExecutionRetirementFixture(t)
			if h.executionOpenVPNPhysical == nil || h.executionPhysical != nil || h.executionCONNECTPhysical != nil || h.executionSOCKSPhysical != nil || h.process.executionOpenVPNPhysical != h.executionOpenVPNPhysical {
				t.Fatal("OpenVPN retirement fixture borrowed another physical family")
			}
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || h.closed || h.nativeRetired || len(*actions) != 0 {
				t.Fatal("OpenVPN exit substituted for native cleanup acknowledgment", err)
			}
			if _, err := os.Stat(h.launch.directory); err != nil {
				t.Fatal("unjoined OpenVPN child lost its original private source", err)
			}
			h.process.nativeAcknowledged, h.process.nativeStopped = true, true
			physical, child, preparation := h.executionOpenVPNPhysical, h.process.executionOpenVPNPhysical, h.process.execution
			switch fault {
			case "missing-host":
				h.executionOpenVPNPhysical = nil
			case "mixed-host":
				h.executionCONNECTPhysical = &mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy{}
			case "foreign-child":
				h.process.executionOpenVPNPhysical = &mobilemultihop.DesktopNodeChainOpenVPNExecutionPhysicalPolicy{}
			case "mixed-child":
				h.process.executionPhysical = &mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy{}
			case "foreign-preparation":
				copy, err := mobilemultihop.ParseDesktopNodeChainOpenVPNExecutionPreparation(preparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				h.process.execution = copy
			}
			if fault != "original" {
				if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || h.closed || len(*actions) != 0 {
					t.Fatal("foreign OpenVPN owner acquired original PF retirement", err)
				}
				h.executionOpenVPNPhysical, h.process.executionOpenVPNPhysical, h.process.execution = physical, child, preparation
				h.executionCONNECTPhysical, h.process.executionPhysical = nil, nil
			}
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err != nil || !h.closed || !h.nativeRetired || !h.workspaceRetired || !h.baselineRetired || h.baseline.Phase != "held" || !h.baseline.Baseline.Present || !reflect.DeepEqual(*actions, []string{"retire"}) {
				t.Fatal("original OpenVPN joined restoration did not retain deny protection", err)
			}
		})
	}
}
