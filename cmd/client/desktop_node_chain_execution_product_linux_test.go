//go:build linux

package main

import (
	"context"
	"testing"
)

func TestDesktopOrderedExecutionUnenteredLinuxPreparationCanRetire(t *testing.T) {
	for _, withHost := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-host", true: "before-session"}[withHost], func(t *testing.T) {
			a := &app{}
			capture := &desktopNodeChainHostCapture{app: a}
			platform := &desktopNodeChainPlatformRuntime{capture: capture}
			chain := &desktopNodeChainLaunch{capture: capture, platform: platform}
			execution := &desktopNodeChainExecutionLaunch{original: chain}
			chain.execution = execution
			launch := &desktopNodeLaunch{chain: chain}
			if withHost {
				platform.host = &desktopLinuxNodeHost{launch: launch, gate: make(chan struct{}, 1)}
				platform.host.gate <- struct{}{}
			}
			s := &desktopNodeChainExecutionSession{app: a, launch: launch, execution: execution}
			t.Cleanup(func() { desktopOrderedExecutionOwners.Delete(a) })
			if _, err := a.retainDesktopOrderedExecution(s); err != nil {
				t.Fatal(err)
			}
			if _, err := platform.captureExecutionProductStop(context.Background(), s); err == nil {
				t.Fatal("unjoined preparation inferred absence")
			}
			if err := s.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			stop, err := a.captureDesktopRetainedStop()
			if err != nil {
				t.Fatal("joined unentered preparation cannot retry Stop", err)
			}
			if stop != nil {
				t.Fatal("unentered preparation invented native Stop authority")
			}
			if current, _ := a.desktopOrderedExecutionOwner(); current != nil {
				t.Fatal("unentered preparation retained permanent cleanup owner")
			}
			if platform.registered || platform.session != nil || launch.command != nil || launch.directory != "" {
				t.Fatal("preparation created native or workspace authority")
			}
		})
	}
}

func TestDesktopOrderedExecutionUnenteredLinuxRefusesEnteredOrReplacedOwner(t *testing.T) {
	for _, mutation := range []string{"stage", "start", "transaction", "registered", "foreign-app"} {
		t.Run(mutation, func(t *testing.T) {
			a := &app{}
			capture := &desktopNodeChainHostCapture{app: a}
			platform := &desktopNodeChainPlatformRuntime{capture: capture}
			chain := &desktopNodeChainLaunch{capture: capture, platform: platform}
			launch := &desktopNodeLaunch{chain: chain}
			platform.host = &desktopLinuxNodeHost{launch: launch, gate: make(chan struct{}, 1)}
			platform.host.gate <- struct{}{}
			s := &desktopNodeChainExecutionSession{app: a, launch: launch, closed: true}
			switch mutation {
			case "stage":
				platform.host.stageEntered = true
			case "start":
				platform.host.startEntered = true
			case "transaction":
				platform.host.transaction = &desktopLinuxNodeTransaction{}
			case "registered":
				platform.registered = true
			case "foreign-app":
				capture.app = &app{}
			}
			if _, err := platform.captureExecutionProductStop(context.Background(), s); err == nil {
				t.Fatal("nil process inferred unentered native absence")
			}
		})
	}
}
