//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

func TestDesktopLinuxNodeMTUReadbackComparison(t *testing.T) {
	before := desktopNodeMTURecord{Schema: 1, Session: strings.Repeat("a", 32), Config: strings.Repeat("b", 64), Path: strings.Repeat("c", 64),
		Generation: 2, Request: strings.Repeat("d", 32), Lease: strings.Repeat("e", 32), Active: true, Reader: 2,
		Interface: "router-vpn", Index: 12, MTU: 1376, Heartbeat: time.Now().UnixMilli()}
	fresh := before
	fresh.Heartbeat++
	if !sameDesktopNodeMTUReadback(before, fresh) {
		t.Fatal("the original heartbeat changed the captured native reader")
	}
	for _, scenario := range []string{"schema", "session", "config", "path", "generation", "request", "lease", "active", "restored", "expired", "reader", "interface", "index", "mtu", "failure"} {
		t.Run(scenario, func(t *testing.T) {
			copy := fresh
			switch scenario {
			case "schema":
				copy.Schema++
			case "session":
				copy.Session += "x"
			case "config":
				copy.Config += "x"
			case "path":
				copy.Path += "x"
			case "generation":
				copy.Generation++
			case "request":
				copy.Request += "x"
			case "lease":
				copy.Lease += "x"
			case "active":
				copy.Active = false
			case "restored":
				copy.Restored = true
			case "expired":
				copy.Expired = true
			case "reader":
				copy.Reader++
			case "interface":
				copy.Interface += "x"
			case "index":
				copy.Index++
			case "mtu":
				copy.MTU++
			case "failure":
				copy.Failure = "rejected"
			}
			if sameDesktopNodeMTUReadback(before, copy) {
				t.Fatal("Linux MTU readback accepted another native lease or reader")
			}
		})
	}
}

// Comparison-only owner model. It cannot pass host.Current, create a lease,
// mutate a TUN, authenticate a child or produce a native retirement receipt.
func linuxNodeMTUComparisonModel(t *testing.T) *desktopLinuxNodeMTUOwner {
	t.Helper()
	h, finish := linuxNodeActivationCaptureModel(t)
	t.Cleanup(finish)
	meta := h.policy.Metadata()
	h.launch.mtuSession, h.launch.configSHA256 = meta.SessionID, meta.ConfigSHA256
	initial := desktopNodeMTURecord{Schema: 1, Session: meta.SessionID, Config: meta.ConfigSHA256,
		Path: strings.Repeat("c", 64), Interface: "router-vpn", Index: 12, MTU: 1376, Reader: 1}
	s := &desktopLinuxNodeSession{parent: h.parent, active: h}
	s.journal = &desktopLinuxNodeJournal{parent: h.parent}
	h.transaction.journal = s.journal
	owner := &desktopLinuxNodeMTUOwner{host: h, session: s, activation: h.activation, process: h.process, transaction: h.transaction,
		launch: h.launch, initial: initial, native: &desktopNodeMTUOwner{launch: h.launch, record: initial}}
	h.mtu = owner
	return owner
}

func TestDesktopLinuxNodeMTUOriginalOwnerComparison(t *testing.T) {
	for _, scenario := range []string{"valid", "host-lease", "activation", "process", "transaction", "launch", "native-launch", "session-parent", "process-parent",
		"transaction-parent", "journal", "transaction-process", "policy", "selection", "runtime-options", "saved-options", "transaction-options", "transaction-saved-options", "command", "session", "config", "path", "interface", "launch-session", "launch-config"} {
		t.Run(scenario, func(t *testing.T) {
			owner := linuxNodeMTUComparisonModel(t)
			h := owner.host
			switch scenario {
			case "host-lease":
				h.mtu = &desktopLinuxNodeMTUOwner{}
			case "activation":
				h.activation = &desktopLinuxNodeActivation{}
			case "process":
				h.process = &desktopLinuxNodeProcess{}
			case "transaction":
				h.transaction = &desktopLinuxNodeTransaction{}
			case "launch":
				h.launch = &desktopNodeLaunch{}
			case "native-launch":
				owner.native.launch = &desktopNodeLaunch{}
			case "session-parent":
				owner.session.parent = &desktopLinuxNodeParentCapture{}
			case "process-parent":
				owner.process.parent = &desktopLinuxNodeParentCapture{}
			case "transaction-parent":
				owner.transaction.parent = &desktopLinuxNodeParentCapture{}
			case "journal":
				owner.transaction.journal = &desktopLinuxNodeJournal{}
			case "transaction-process":
				owner.transaction.process = &desktopLinuxNodeProcess{}
			case "policy":
				h.policy = nil
			case "selection":
				h.selection.HomeLAN = !h.selection.HomeLAN
			case "runtime-options":
				h.options[0] = !h.options[0]
			case "saved-options":
				h.savedOptions[0] = !h.savedOptions[0]
			case "transaction-options":
				owner.transaction.options[0] = !owner.transaction.options[0]
			case "transaction-saved-options":
				owner.transaction.savedOptions[0] = !owner.transaction.savedOptions[0]
			case "command":
				owner.process.command = &exec.Cmd{}
			case "session":
				owner.native.record.Session += "x"
			case "config":
				owner.native.record.Config += "x"
			case "path":
				owner.native.record.Path += "x"
			case "interface":
				owner.native.record.Interface += "x"
			case "launch-session":
				owner.launch.mtuSession += "x"
			case "launch-config":
				owner.launch.configSHA256 += "x"
			}
			if err := owner.originalLocked(); (err == nil) != (scenario == "valid") {
				t.Fatal("Linux MTU cleanup changed its original owner comparison", scenario, err)
			}
		})
	}
	owner := linuxNodeMTUComparisonModel(t)
	owner.host.activation.cancel()
	owner.host.closing = true
	if owner.originalLocked() != nil || owner.activation.matches(owner.host) == nil {
		t.Fatal("retiring the old activation erased its separate original cleanup comparison")
	}
}

func TestDesktopLinuxNodeMTUCaptureRefusesPartialOwnerAndFallback(t *testing.T) {
	for _, scenario := range []string{"cancelled", "partial-session", "foreign-parent", "lost-controller"} {
		t.Run(scenario, func(t *testing.T) {
			a, snapshot := newMTUTransactionFixture(t)
			controller := &ownedDesktopController{}
			p := &desktopLinuxNodeParent{controller: controller, gate: make(chan struct{}, 1)}
			p.gate <- struct{}{}
			controller.nodeParent, a.localController = p, controller
			parent := &desktopLinuxNodeParentCapture{app: a, controller: controller, parent: p, lifetime: context.Background()}
			s := &desktopLinuxNodeSession{gate: make(chan struct{}, 1), parent: parent}
			s.gate <- struct{}{}
			p.session = s
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "cancelled":
				cancel()
			case "foreign-parent":
				s.parent = &desktopLinuxNodeParentCapture{}
			case "lost-controller":
				parent.controller = &ownedDesktopController{}
			}
			entered := false
			handled, err := withDesktopLinuxNodeMTUHost(ctx, a, func(*desktopLinuxNodeSession, *desktopLinuxNodeHost) error { entered = true; return nil })
			if !handled || err == nil || entered {
				t.Fatal("partial Linux MTU ownership abandoned its handled failure", handled, err, entered)
			}
			if _, handled, err := openDesktopPlatformMTUOwner(a, snapshot, mtuLiveSnapshot{nodeRecord: &desktopNodeMTURecord{}}, strings.Repeat("a", 32), &exec.Cmd{}); !handled || err == nil {
				t.Fatal("unproved Linux original capture fell through to a legacy kernel writer")
			}
		})
	}
	if _, handled, err := openDesktopPlatformMTUOwner(&app{}, mtuRetestSnapshot{}, mtuLiveSnapshot{nodeRecord: &desktopNodeMTURecord{}}, "", nil); !handled || err == nil {
		t.Fatal("a disappeared captured Linux host fell back to an ambient interface")
	}
}

func TestDesktopLinuxNodeMTUFamilyRetainsPrivateTarget(t *testing.T) {
	for _, test := range []struct {
		name, host string
		family     int
	}{
		{"default-v4", "", 4}, {"private-v4", "192.168.50.133", 4}, {"private-v6", "[fd77::1]", 6},
		{"hostname", "node.example.test", 0}, {"public", "1.1.1.1", 0}, {"invalid", "invalid", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			family, err := desktopLinuxMTUFamily(mtuRetestSnapshot{Profile: common.RouterProfile{DAITAHost: test.host}})
			if (err == nil) != (test.family != 0) || family != test.family {
				t.Fatal("Linux MTU target used ambient resolution or another captured family", family, err)
			}
		})
	}
}

func TestDesktopLinuxNodeMTUSnapshotRetainsAutoPolicyAndRuntime(t *testing.T) {
	for _, scenario := range []string{"auto", "different-saved-runtime", "fixed", "manual", "source-profile", "mode", "node", "saved-options", "runtime-options", "disconnected"} {
		t.Run(scenario, func(t *testing.T) {
			a, snapshot := newMTUTransactionFixture(t)
			h := &desktopLinuxNodeHost{parent: &desktopLinuxNodeParentCapture{app: a},
				launch: &desktopNodeLaunch{profileID: snapshot.Profile.ID, mode: snapshot.Mode}, revision: desktopOwnedNodeProfileToken(snapshot.Profile)}
			switch scenario {
			case "different-saved-runtime":
				snapshot.State.Jumbo, h.options[1] = true, true
				a.state = snapshot.State
				snapshot.StateToken = mtuStateSnapshotToken(snapshot.State)
			case "fixed", "manual":
				snapshot.Profile.MTUPolicy, snapshot.Profile.ManualMTU = scenario, 1376
				a.profiles.Profiles[0] = snapshot.Profile
				snapshot.ProfileToken = mtuProfileSnapshotToken(snapshot.Profile)
				h.revision = desktopOwnedNodeProfileToken(snapshot.Profile)
			case "source-profile":
				snapshot.Profile.AdGuardIPv4 = "192.168.50.134"
			case "mode":
				snapshot.Mode = "wg"
			case "node":
				snapshot.State.RouterID = "different-node"
			case "saved-options":
				snapshot.Profile.JumboTUN = true
				a.profiles.Profiles[0] = snapshot.Profile
				snapshot.ProfileToken = mtuProfileSnapshotToken(snapshot.Profile)
			case "runtime-options":
				snapshot.State.Jumbo = true
				a.state = snapshot.State
				snapshot.StateToken = mtuStateSnapshotToken(snapshot.State)
			case "disconnected":
				snapshot.State.Connected = false
			}
			if err := validateDesktopLinuxMTUSnapshot(h, snapshot); (err == nil) != (scenario == "auto" || scenario == "different-saved-runtime") {
				t.Fatal("Linux MTU snapshot confused saved fixed policy or another runtime with Auto authority", scenario, err)
			}
		})
	}
}

func TestDesktopLinuxNodeMTURetirementRetainsUndischargedLease(t *testing.T) {
	// This is a refusal test, not a simulated successful native retirement.
	// No process has been created; even that does not erase a retained lease
	// whose original capture cannot currently prove checked cleanup.
	h := &desktopLinuxNodeHost{}
	owner := &desktopLinuxNodeMTUOwner{host: h}
	h.mtu = owner
	if err := h.retireLocked(context.Background(), false); err == nil || h.mtu != owner || owner.closed {
		t.Fatal("Linux host discarded an undischarged original MTU lease before retirement")
	}
}

func TestDesktopLinuxNodeMTUStopRejectsUnadmittedCleanup(t *testing.T) {
	// Refusal-only models: none can prove a native parent or retire an engine.
	// They require cancellation/replacement/drain guards before that authority
	// is even entered. Actual successful fallback belongs to the real-TUN gate.
	for _, scenario := range []string{"no-failure", "cancelled-hold", "deadline-hold", "cancelled-call", "registry", "command", "held-retest", "undrained"} {
		t.Run(scenario, func(t *testing.T) {
			native := linuxNodeMTUComparisonModel(t)
			command := native.process.command
			a := &app{cmd: command}
			outer := &mtuLiveOwner{a: a, command: command, kernel: native, stopped: true}
			mtuLiveOwners.Store(a, outer)
			t.Cleanup(func() { mtuLiveOwners.Delete(a) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failed := errors.New("captured native cleanup remains unresolved")
			want := "bounded original teardown capture"
			switch scenario {
			case "no-failure":
				failed = nil
			case "cancelled-hold":
				failed = context.Canceled
			case "deadline-hold":
				failed = context.DeadlineExceeded
			case "cancelled-call":
				cancel()
			case "registry":
				mtuLiveOwners.Store(a, &mtuLiveOwner{})
				want = "replacement lease or command"
			case "command":
				command = &exec.Cmd{}
				want = "replacement lease or command"
			case "held-retest":
				lock := mtuRetestLockFor(a)
				lock.Lock()
				defer lock.Unlock()
				want = "waiting for its captured Retest operation"
			case "undrained":
				outer.stopped = false
				want = "preceded original request drain"
			}
			handled, err := prepareDesktopPlatformMTUStop(ctx, a, command, nil, outer, false, failed)
			if !handled || err == nil || !strings.Contains(err.Error(), want) || native.host.mtu != native || native.closed ||
				native.host.closing || native.activation.lifetime.Err() != nil || native.transaction.stopRequested.Load() || a.cmd != native.process.command {
				t.Fatal("Linux MTU fallback crossed an unadmitted captured teardown boundary", scenario, handled, err)
			}
		})
	}
}
