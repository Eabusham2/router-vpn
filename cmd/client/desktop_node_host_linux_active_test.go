//go:build linux

package main

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobilemultihop"
)

func TestDesktopLinuxNodeActivationProof(t *testing.T) {
	now := time.Now()
	started := now.Add(-2 * time.Second)
	ready := mobilemultihop.DesktopNodeReadyRecord{InterfaceName: "router-vpn", InterfaceIndex: 12, MTU: 1400}
	live := desktopNodeMTURecord{Interface: "router-vpn", Index: 12, MTU: 1400, Reader: 1, Heartbeat: now.UnixMilli()}
	proof := desktopLinuxNodeProof{ready: ready, live: live, provedAt: now.Add(-time.Millisecond), elapsed: 20 * time.Millisecond}
	if err := validateDesktopLinuxNodeActivationProof(&proof, ready, live, started, now, 5); err != nil {
		t.Fatal("fresh captured proof comparison was rejected", err)
	}
	for _, scenario := range []string{"absent", "historical-clock", "historical-start", "historical-now", "stale", "future", "before-start",
		"zero-elapsed", "negative-elapsed", "unbounded-elapsed", "impossible-elapsed", "unbounded-deadline", "changed-ready", "changed-live", "active-mtu", "failed-reader"} {
		t.Run(scenario, func(t *testing.T) {
			copy, r, m, begin, current, seconds := proof, ready, live, started, now, 5
			selected := &copy
			switch scenario {
			case "absent":
				selected = nil
			case "historical-clock":
				copy.provedAt = copy.provedAt.Round(0)
			case "historical-start":
				begin = begin.Round(0)
			case "historical-now":
				current = current.Round(0)
			case "stale":
				begin, copy.provedAt = now.Add(-time.Minute), now.Add(-31*time.Second)
			case "future":
				copy.provedAt = now.Add(time.Millisecond)
			case "before-start":
				copy.provedAt = started.Add(-time.Millisecond)
			case "zero-elapsed":
				copy.elapsed = 0
			case "negative-elapsed":
				copy.elapsed = -time.Millisecond
			case "unbounded-elapsed":
				begin, copy.elapsed = now.Add(-time.Minute), 6*time.Second
			case "impossible-elapsed":
				copy.elapsed = 3 * time.Second
			case "unbounded-deadline":
				seconds = 301
			case "changed-ready":
				r.DNSConfigSHA256 = "replacement"
			case "changed-live":
				m.Path = "replacement"
			case "active-mtu":
				copy.live.Active, m.Active = true, true
			case "failed-reader":
				copy.live.Failure, m.Failure = "reader failed", "reader failed"
			}
			if err := validateDesktopLinuxNodeActivationProof(selected, r, m, begin, current, seconds); err == nil {
				t.Fatal("activation accepted a stale, impossible or replaced captured proof")
			}
		})
	}
	live.Heartbeat++
	if err := validateDesktopLinuxNodeActivationProof(&proof, ready, live, started, now, 5); err != nil {
		t.Fatal("the original reader's advancing heartbeat changed proof ownership", err)
	}
}

// This is a comparison-only model. It never invokes Activate, reports a
// successful native Current, creates a process, or claims a routed TUN proof.
// The assembled native gate separately exercises those original owners.
func linuxNodeActivationCaptureModel(t *testing.T) (*desktopLinuxNodeHost, context.CancelFunc) {
	t.Helper()
	h, profile := linuxHostProofFixture(t)
	operation, finish := context.WithCancel(context.Background())
	lifetime, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.operation = operation
	h.parent = &desktopLinuxNodeParentCapture{lifetime: lifetime}
	h.launch.command = &exec.Cmd{}
	h.process = &desktopLinuxNodeProcess{parent: h.parent, ctx: lifetime, command: h.launch.command, joined: make(chan struct{})}
	h.process.started.Store(true)
	h.network, h.revision = "captured-network", desktopOwnedNodeProfileToken(profile)
	meta := h.policy.Metadata()
	h.selection = linuxprotection.NodeSelection{SessionID: meta.SessionID, SourceSHA256: meta.SourceSHA256,
		ConfigSHA256: meta.ConfigSHA256, Policy: meta.KillSwitchPolicy, HomeLAN: meta.HomeLANAccess}
	h.transaction = &desktopLinuxNodeTransaction{parent: h.parent, process: h.process, policy: h.policy, operation: operation,
		selection: h.selection, network: h.network, revision: h.revision, profileID: h.launch.profileID, options: h.options}
	now := time.Now()
	h.ready = &mobilemultihop.DesktopNodeReadyRecord{}
	h.proof = &desktopLinuxNodeProof{ready: *h.ready, provedAt: now.Add(-time.Millisecond), elapsed: time.Millisecond}
	h.activation = &desktopLinuxNodeActivation{host: h, parent: h.parent, operation: operation, process: h.process,
		transaction: h.transaction, policy: h.policy, launch: h.launch, selection: h.selection, network: h.network,
		revision: h.revision, options: h.options, proof: *h.proof, activatedAt: now, lifetime: lifetime, cancel: cancel}
	return h, finish
}

func TestDesktopLinuxNodeActivationRetainsCapturedLifetime(t *testing.T) {
	h, finish := linuxNodeActivationCaptureModel(t)
	defer finish()
	if err := h.activation.matches(h); err != nil {
		t.Fatal("captured owner comparison failed before request completion", err)
	}
	finish()
	if h.operation.Err() != context.Canceled || h.activation.lifetime.Err() != nil || h.activation.matches(h) != nil {
		t.Fatal("startup cancellation invalidated the separately captured activation lifetime")
	}
	h.revokeActivationLocked()
	if h.activation.lifetime.Err() != context.Canceled || h.activation.matches(h) == nil {
		t.Fatal("original retirement did not revoke its retained activation")
	}
}

func TestDesktopLinuxNodeActivationRejectsChangedCapture(t *testing.T) {
	for _, scenario := range []string{"host", "parent", "operation", "process", "transaction", "policy", "launch", "selection", "network", "profile", "options", "ready", "proof", "activation-time",
		"transaction-profile", "transaction-network", "transaction-parent", "command", "unstarted", "retiring", "joined", "controller-ended"} {
		t.Run(scenario, func(t *testing.T) {
			h, finish := linuxNodeActivationCaptureModel(t)
			defer finish()
			active := h.activation
			switch scenario {
			case "host":
				active.host = &desktopLinuxNodeHost{}
			case "parent":
				h.parent = &desktopLinuxNodeParentCapture{}
			case "operation":
				h.operation = context.Background()
			case "process":
				h.process = &desktopLinuxNodeProcess{}
			case "transaction":
				h.transaction = &desktopLinuxNodeTransaction{}
			case "policy":
				h.policy = nil
			case "launch":
				h.launch = &desktopNodeLaunch{}
			case "selection":
				h.selection.HomeLAN = !h.selection.HomeLAN
			case "network":
				h.network += "replacement"
			case "profile":
				h.revision += "replacement"
			case "options":
				h.options[0] = !h.options[0]
			case "ready":
				h.ready.InterfaceIndex++
			case "proof":
				h.proof.elapsed++
			case "activation-time":
				active.activatedAt = active.activatedAt.Add(time.Minute)
			case "transaction-profile":
				h.transaction.profileID += "replacement"
			case "transaction-network":
				h.transaction.network += "replacement"
			case "transaction-parent":
				h.transaction.parent = &desktopLinuxNodeParentCapture{}
			case "command":
				h.process.command = &exec.Cmd{}
			case "unstarted":
				h.process.started.Store(false)
			case "retiring":
				h.process.retiring.Store(true)
			case "joined":
				close(h.process.joined)
			case "controller-ended":
				active.cancel()
			}
			if active.matches(h) == nil {
				t.Fatal("active comparison accepted a replacement or retired original owner")
			}
		})
	}
}

func TestDesktopLinuxNodeConnectedCannotCreateActivation(t *testing.T) {
	a := &app{state: state{Connected: true, Phase: "connected"}}
	h := &desktopLinuxNodeHost{gate: make(chan struct{}, 1), parent: &desktopLinuxNodeParentCapture{app: a}}
	h.gate <- struct{}{}
	if err := h.Current(context.Background()); err == nil || !a.state.Connected || h.activation != nil {
		t.Fatal("presentation state supplied an absent native activation capability")
	}
}
