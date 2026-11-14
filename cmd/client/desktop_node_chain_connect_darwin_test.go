//go:build darwin

package main

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func desktopMacOSCONNECTRetirementFixture(t *testing.T) (*desktopMacOSNodeChainHost, *[]string) {
	return desktopMacOSNodeChainRetirementFixtureWith(t, func(t *testing.T) (*app, *desktopNodeLaunch) {
		a, _, launch := desktopCONNECTParentFixture(t, "awg2-strong")
		return a, launch
	})
}
func TestDesktopMacOSCONNECTRetirementRequiresOriginalNativeAcknowledgment(t *testing.T) {
	h, actions := desktopMacOSCONNECTRetirementFixture(t)
	child := &desktopMacOSProcess{parent: h.parent, command: h.launch.command, gate: make(chan struct{}, 1), joined: make(chan struct{})}
	child.gate <- struct{}{}
	child.started.Store(true)
	close(child.joined)
	h.process = child
	if err := h.Close(context.Background()); err == nil || h.closed || h.nativeRetired || h.baselineRetired || h.workspaceRetired || len(*actions) != 0 {
		t.Fatal("typed child exit bypassed native acknowledgment", err)
	}
	if _, err := os.Stat(h.launch.directory); err != nil {
		t.Fatal("unacknowledged typed owner lost original workspace", err)
	}
	child.nativeAcknowledged, child.nativeStopped = true, true
	if err := h.Close(context.Background()); err != nil || !h.closed || !reflect.DeepEqual(*actions, []string{"release"}) || h.parent.session.nodeChain != nil || h.parent.app.cmd != nil {
		t.Fatal("typed original acknowledgment did not complete exact joined retirement", err)
	}
}
func TestDesktopMacOSCONNECTRetirementRejectsForeignPolicy(t *testing.T) {
	h, actions := desktopMacOSCONNECTRetirementFixture(t)
	original := h.launch.chain.connectPolicy
	_, _, other := desktopCONNECTParentFixture(t, "awg2-strong")
	h.launch.chain.connectPolicy = other.chain.connectPolicy
	if err := h.Close(context.Background()); err == nil || h.closed || len(*actions) != 0 {
		t.Fatal("typed cleanup adopted foreign concrete policy")
	}
	h.launch.chain.connectPolicy = original
	if err := h.Close(context.Background()); err != nil || !h.closed {
		t.Fatal("original typed cleanup could not retry", err)
	}
}
