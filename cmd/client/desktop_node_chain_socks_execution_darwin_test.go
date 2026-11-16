//go:build darwin

package main

import (
	"context"
	"os"
	"reflect"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

func macOSSOCKSExecutionRetirementFixture(t *testing.T) (*desktopMacOSNodeChainHost, *[]string) {
	return macOSExecutionRetirementFixtureWith(t, func(t *testing.T) (*app, *desktopNodeLaunch) {
		a, _, launch := desktopSOCKSParentFixture(t, "awg2-strong")
		return a, launch
	})
}

func TestMacOSSOCKSExecutionRetirementKeepsOriginalPhysicalOwner(t *testing.T) {
	for _, fault := range []string{"original", "missing-host", "mixed-host", "foreign-child", "mixed-child", "foreign-preparation"} {
		t.Run(fault, func(t *testing.T) {
			h, actions := macOSSOCKSExecutionRetirementFixture(t)
			if h.executionSOCKSPhysical == nil || h.executionPhysical != nil || h.executionCONNECTPhysical != nil || h.process.executionSOCKSPhysical != h.executionSOCKSPhysical {
				t.Fatal("SOCKS retirement fixture borrowed another physical family")
			}
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || h.closed || h.nativeRetired || len(*actions) != 0 {
				t.Fatal("SOCKS exit substituted for native cleanup acknowledgment", err)
			}
			if _, err := os.Stat(h.launch.directory); err != nil {
				t.Fatal("unjoined SOCKS child lost its original private source", err)
			}
			h.process.nativeAcknowledged, h.process.nativeStopped = true, true
			physical, child, preparation := h.executionSOCKSPhysical, h.process.executionSOCKSPhysical, h.process.execution
			switch fault {
			case "missing-host":
				h.executionSOCKSPhysical = nil
			case "mixed-host":
				h.executionCONNECTPhysical = &mobilemultihop.DesktopNodeChainCONNECTExecutionPhysicalPolicy{}
			case "foreign-child":
				h.process.executionSOCKSPhysical = &mobilemultihop.DesktopNodeChainSOCKSExecutionPhysicalPolicy{}
			case "mixed-child":
				h.process.executionPhysical = &mobilemultihop.DesktopNodeChainExecutionPhysicalPolicy{}
			case "foreign-preparation":
				copy, err := mobilemultihop.ParseDesktopNodeChainSOCKSExecutionPreparation(preparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				h.process.execution = copy
			}
			if fault != "original" {
				if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err == nil || h.closed || len(*actions) != 0 {
					t.Fatal("foreign SOCKS owner acquired original PF retirement", err)
				}
				h.executionSOCKSPhysical, h.process.executionSOCKSPhysical, h.process.execution = physical, child, preparation
				h.executionCONNECTPhysical, h.process.executionPhysical = nil, nil
			}
			if err := h.runtime.closeForExecutionRestore(context.Background(), h.execution); err != nil || !h.closed || !h.nativeRetired || !h.workspaceRetired || !h.baselineRetired || h.baseline.Phase != "held" || !h.baseline.Baseline.Present || !reflect.DeepEqual(*actions, []string{"retire"}) {
				t.Fatal("original SOCKS joined restoration did not retain deny protection", err)
			}
		})
	}
}
