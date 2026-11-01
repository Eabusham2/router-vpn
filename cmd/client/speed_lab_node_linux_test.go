//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

// Only the native policy/TUN read is modeled. The original activation,
// session/host gates, app selection, cancellation and final owner comparisons
// are the shipping path. These tests do not create an installed TUN or claim
// a successful native Activate/Current operation.
type linuxSpeedLabPathFixture struct {
	a      *app
	p      *desktopLinuxNodeParent
	s      *desktopLinuxNodeSession
	h      *desktopLinuxNodeHost
	finish context.CancelFunc
	reads  int
	live   desktopNodeMTURecord
}

func newLinuxSpeedLabPathFixture(t *testing.T) *linuxSpeedLabPathFixture {
	t.Helper()
	h, finish := linuxNodeActivationCaptureModel(t)
	t.Cleanup(finish)
	profile, err := h.capturedProofProfile()
	if err != nil {
		t.Fatal(err)
	}
	meta := h.policy.Metadata()
	h.launch.mode = meta.Mode
	h.network = physicalNetworkIdentity()
	h.transaction.network, h.activation.network = h.network, h.network
	// The source parser normalizes its complete profile. This model stores
	// that exact normalized profile as the original saved application input.
	h.revision = desktopOwnedNodeProfileToken(profile)
	h.transaction.revision, h.activation.revision = h.revision, h.revision
	h.options = [3]bool{profile.DAITAEnabled, profile.JumboTUN, profile.SocksEnabled}
	h.savedOptions, h.transaction.options, h.transaction.savedOptions = h.options, h.options, h.options
	h.activation.options, h.activation.savedOptions = h.options, h.options
	h.gate = make(chan struct{}, 1)
	h.gate <- struct{}{}
	h.ready.SessionID, h.ready.SourceSHA256, h.ready.ConfigSHA256 = meta.SessionID, meta.SourceSHA256, meta.ConfigSHA256
	h.ready.InterfaceName, h.ready.InterfaceIndex, h.ready.MTU = "router-vpn", 37, 1400
	h.proof.ready = *h.ready
	h.activation.proof = *h.proof
	a := &app{cfg: common.ClientConfig{
		ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"),
		ModesFile:    filepath.Join(linuxOwnedControllerRoot, "modes.json"),
		ScriptsDir:   filepath.Join(linuxOwnedControllerRoot, "modes"),
		StateFile:    filepath.Join(linuxOwnedControllerRoot, "state.json")},
		profiles: common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}},
		cmd:      h.launch.command, state: state{Connected: true, Phase: "connected", RouterID: profile.ID,
			Mode: meta.Mode, RuntimeMode: meta.Mode, DAITA: h.options[0], Jumbo: h.options[1], Socks: h.options[2]}}
	p := &desktopLinuxNodeParent{gate: make(chan struct{}, 1), ctx: h.parent.lifetime, cancel: h.activation.cancel, complete: true,
		dependents: make(map[ownedDesktopNodeParent]struct{})}
	p.gate <- struct{}{}
	controller := &ownedDesktopController{nodeParent: p}
	p.controller, a.localController = controller, controller
	h.parent.app, h.parent.controller, h.parent.parent = a, controller, p
	s := &desktopLinuxNodeSession{gate: make(chan struct{}, 1), parent: h.parent, active: h,
		journal: &desktopLinuxNodeJournal{parent: h.parent}}
	s.gate <- struct{}{}
	p.session, p.dependents[s], p.dependents[h] = s, struct{}{}, struct{}{}
	h.transaction.journal = s.journal
	f := &linuxSpeedLabPathFixture{a: a, p: p, s: s, h: h, finish: finish,
		live: desktopNodeMTURecord{Interface: "router-vpn", Index: 37, MTU: 1400, Reader: 1}}
	sessionTrackers.Store(a, &sessionTracker{a: a, session: &connectionSession{
		ID: "captured-linux-measurement", Connected: true, Phase: "connected", PathProof: "passed", RouterID: profile.ID}})
	t.Cleanup(func() { sessionTrackers.Delete(a); desktopNodeOwners.Delete(a) })
	return f
}

func (f *linuxSpeedLabPathFixture) read(ctx context.Context, h *desktopLinuxNodeHost) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error) {
	f.reads++
	if ctx.Err() != nil || h != f.h {
		return mobilemultihop.DesktopNodeReadyRecord{}, desktopNodeMTURecord{}, errors.New("modeled read selected another native owner")
	}
	for _, gate := range []chan struct{}{f.s.gate, f.h.gate} {
		select {
		case <-gate:
			gate <- struct{}{}
			return mobilemultihop.DesktopNodeReadyRecord{}, desktopNodeMTURecord{}, errors.New("native observation ran without its original gates")
		default:
		}
	}
	return *h.ready, f.live, nil
}

func (f *linuxSpeedLabPathFixture) capture(t *testing.T) *desktopLinuxNodePath {
	t.Helper()
	path, handled, err := captureDesktopLinuxNodePathWith(context.Background(), f.a, f.h.launch.command, f.read)
	if err != nil || !handled || path == nil || path.session != f.s || path.host != f.h || path.activation != f.h.activation ||
		path.transaction != f.h.transaction || path.process != f.h.process || path.journal != f.s.journal ||
		path.ready != *f.h.ready || f.reads != 1 {
		t.Fatal("Linux Speed Lab did not capture the original activated path", handled, f.reads, err)
	}
	return path
}

func TestSpeedLabLinuxRetainsActivatedPath(t *testing.T) {
	for _, scenario := range []string{"original", "request-finished", "smart-phase", "runtime-options", "display-only", "live-mtu"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLinuxSpeedLabPathFixture(t)
			if scenario == "runtime-options" {
				f.h.options = [3]bool{!f.h.options[0], !f.h.options[1], !f.h.options[2]}
				f.h.transaction.options, f.h.activation.options = f.h.options, f.h.options
				f.a.state.DAITA, f.a.state.Jumbo, f.a.state.Socks = f.h.options[0], f.h.options[1], f.h.options[2]
			}
			path := f.capture(t)
			switch scenario {
			case "request-finished":
				f.finish()
			case "smart-phase":
				f.a.state.Phase = "smart:simplify:shadowsocks"
			case "display-only":
				f.a.profiles.Profiles[0].Name = "Renamed display label"
				f.a.profiles.Profiles[0].UseCount++
			case "live-mtu":
				f.live.MTU, f.live.Reader, f.live.Heartbeat = 1300, 2, time.Now().UnixMilli()
			}
			if err := validateDesktopLinuxNodePathWith(context.Background(), f.a, path, f.read); err != nil || f.reads != 2 {
				t.Fatal("same original native path was not observed after its independent state change", f.reads, err)
			}
			if _, exists := desktopNodeOwners.Load(f.a); exists {
				t.Fatal("Linux path capture installed a competing legacy process owner")
			}
			if err := f.s.enter(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := f.h.enter(context.Background()); err != nil {
				t.Fatal(err)
			}
			ready, live, err := path.currentLockedWith(context.Background(), f.read)
			f.h.gate <- struct{}{}
			f.s.gate <- struct{}{}
			if err != nil || ready != path.ready || live != f.live || f.reads != 3 {
				t.Fatal("sealed restoration did not receive the actual observed reader", ready, live, err)
			}
		})
	}
}

func TestSpeedLabLinuxRejectsChangedPath(t *testing.T) {
	for _, scenario := range []string{"command", "session-host", "parent-session", "controller", "host-parent", "activation", "process", "transaction",
		"journal", "launch", "policy", "host-registration", "session-registration", "parent-stopping", "app-closing", "duplicate-owner",
		"profile", "dns", "mtu", "ipv6", "saved-options", "runtime-options", "network", "ready", "joined", "retiring", "cancelled-lifetime", "external", "multihop"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLinuxSpeedLabPathFixture(t)
			path := f.capture(t)
			switch scenario {
			case "command":
				f.a.cmd = &exec.Cmd{}
			case "session-host":
				f.s.active = &desktopLinuxNodeHost{}
			case "parent-session":
				f.p.session = &desktopLinuxNodeSession{}
			case "controller":
				f.a.localController = &ownedDesktopController{}
			case "host-parent":
				f.h.parent = &desktopLinuxNodeParentCapture{}
			case "activation":
				f.h.activation = &desktopLinuxNodeActivation{}
			case "process":
				f.h.process = &desktopLinuxNodeProcess{}
			case "transaction":
				f.h.transaction = &desktopLinuxNodeTransaction{}
			case "journal":
				f.s.journal = &desktopLinuxNodeJournal{}
			case "launch":
				f.h.launch = &desktopNodeLaunch{}
			case "policy":
				f.h.policy = nil
			case "host-registration":
				delete(f.p.dependents, f.h)
			case "session-registration":
				delete(f.p.dependents, f.s)
			case "parent-stopping":
				f.p.stopping = true
			case "app-closing":
				f.a.closing = true
			case "duplicate-owner":
				desktopNodeOwners.Store(f.a, f.h.launch)
			case "profile":
				f.a.profiles.Profiles[0].APIToken += "-replacement"
			case "dns":
				f.a.profiles.Profiles[0].AdGuardIPv4 = "192.168.50.134"
			case "mtu":
				f.a.profiles.Profiles[0].ManualMTU++
			case "ipv6":
				f.a.profiles.Profiles[0].IPv6Mode = "off"
			case "saved-options":
				f.a.profiles.Profiles[0].DAITAEnabled = !f.a.profiles.Profiles[0].DAITAEnabled
			case "runtime-options":
				f.a.state.Jumbo = !f.a.state.Jumbo
			case "network":
				f.h.network += "-replacement"
			case "ready":
				f.h.ready.SourceSHA256 += "-replacement"
			case "joined":
				close(f.h.process.joined)
			case "retiring":
				f.h.process.retiring.Store(true)
			case "cancelled-lifetime":
				f.h.activation.cancel()
			case "external":
				f.a.state.Mode = "external-node"
			case "multihop":
				f.a.state.Mode = "multihop"
			}
			if err := validateDesktopLinuxNodePathWith(context.Background(), f.a, path, f.read); err == nil || f.reads != 1 {
				t.Fatal("Linux Speed Lab used a replacement or stale owner for observation", scenario, f.reads, err)
			}
		})
	}
}

func TestSpeedLabLinuxBracketsNativeRead(t *testing.T) {
	for _, scenario := range []string{"failure", "changed-record", "command-during-read", "profile-during-read", "session-during-read", "cancel-during-read", "missing-reader"} {
		t.Run(scenario, func(t *testing.T) {
			for _, stage := range []string{"capture", "result"} {
				t.Run(stage, func(t *testing.T) {
					f := newLinuxSpeedLabPathFixture(t)
					var path *desktopLinuxNodePath
					if stage == "result" {
						path = f.capture(t)
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					read := func(ctx context.Context, h *desktopLinuxNodeHost) (mobilemultihop.DesktopNodeReadyRecord, desktopNodeMTURecord, error) {
						r, live, err := f.read(ctx, h)
						switch scenario {
						case "failure":
							err = errors.New("modeled actual policy/TUN observation failed")
						case "changed-record":
							r.SourceSHA256 += "-replacement"
						case "command-during-read":
							f.a.cmd = &exec.Cmd{}
						case "profile-during-read":
							f.a.profiles.Profiles[0].APIToken += "-replacement"
						case "session-during-read":
							f.s.active = &desktopLinuxNodeHost{}
						case "cancel-during-read":
							cancel()
						}
						return r, live, err
					}
					if scenario == "missing-reader" {
						read = nil
					}
					var err error
					if stage == "capture" {
						var handled bool
						path, handled, err = captureDesktopLinuxNodePathWith(ctx, f.a, f.a.cmd, read)
						if !handled || path != nil {
							t.Fatal("failed Linux observation returned a path or borrowed a generic one")
						}
					} else {
						err = validateDesktopLinuxNodePathWith(ctx, f.a, path, read)
					}
					if err == nil {
						t.Fatal("Linux Speed Lab accepted a failed, changed, cancelled or omitted native observation")
					}
				})
			}
		})
	}
}

func TestSpeedLabLinuxRejectsOmittedOrMixedIdentity(t *testing.T) {
	for _, scenario := range []string{"omitted", "unproved-capture", "external", "tor", "node", "graph", "entry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLinuxSpeedLabPathFixture(t)
			path := f.capture(t)
			identity := speedLabPathIdentity{SessionID: "captured-linux-measurement", StateToken: mtuStateSnapshotToken(f.a.state),
				RouterID: f.a.state.RouterID, Command: f.a.cmd, Network: f.h.network, ProfileToken: desktopOwnedNodeProfileToken(f.a.profiles.Profiles[0]),
				Options: f.h.options, Linux: path}
			switch scenario {
			case "omitted":
				identity.Linux = nil
				identity.ProfileToken = liveMeasurementProfileToken(f.a.profiles.Profiles[0])
			case "unproved-capture":
				f.h.activation = nil
				if _, _, err := captureSpeedLabIdentity(f.a); err == nil {
					t.Fatal("Connected created an unproved Linux measurement identity")
				}
			case "external":
				identity.External = &desktopNodeLaunch{external: &desktopExternalRuntime{}}
			case "tor":
				identity.Tor = &desktopNodeLaunch{}
			case "node":
				identity.Node = f.h.launch
			case "graph":
				identity.GraphOK = true
			case "entry":
				identity.TorEntry = &desktopTorPredecessorCapture{}
			}
			err := validateSpeedLabIdentity(f.a, identity)
			mixed := scenario != "omitted" && scenario != "unproved-capture"
			if err == nil || scenario == "omitted" && !strings.Contains(err.Error(), "omitted its retained Linux") ||
				mixed && !strings.Contains(err.Error(), "mixes") {
				t.Fatal("generic Speed Lab accepted an omitted, unproved or mixed Linux identity", scenario, err)
			}
		})
	}
}

func TestSpeedLabLinuxCaptureCannotFallThrough(t *testing.T) {
	for _, scenario := range []string{"legacy", "unused-parent", "missing-retained-session", "wrong-parent", "unproved-empty-session", "missing-session-gate", "missing-host-gate", "foreign-session", "cancelled", "foreign-app"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLinuxSpeedLabPathFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "legacy":
				f.a.localController = nil
			case "unused-parent":
				f.p.session = nil
				clear(f.p.dependents)
			case "missing-retained-session":
				f.p.session = nil
			case "wrong-parent":
				f.a.localController.nodeParent = &desktopLinuxNodeSession{}
			case "unproved-empty-session":
				f.s.active = nil
				f.p.complete = false
			case "missing-session-gate":
				f.s.gate = nil
			case "missing-host-gate":
				f.h.gate = nil
			case "foreign-session":
				f.s.parent = &desktopLinuxNodeParentCapture{}
			case "cancelled":
				cancel()
			case "foreign-app":
				f.s.parent.app = &app{}
			}
			path, handled, err := captureDesktopLinuxNodePathWith(ctx, f.a, f.a.cmd, f.read)
			legacy := scenario == "legacy" || scenario == "unused-parent"
			if path != nil || handled == legacy || (err == nil) != legacy || f.reads != 0 {
				t.Fatal("partial Linux owner became a generic path or another native owner", scenario, handled, f.reads, err)
			}
		})
	}
}

func TestSpeedLabLinuxGateCancellation(t *testing.T) {
	for _, scenario := range []string{"session", "host", "parent"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLinuxSpeedLabPathFixture(t)
			path := f.capture(t)
			gate := f.s.gate
			if scenario == "host" {
				gate = f.h.gate
			} else if scenario == "parent" {
				gate = f.p.gate
			}
			<-gate
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- validateDesktopLinuxNodePathWith(ctx, f.a, path, f.read) }()
			cancel()
			select {
			case err := <-done:
				if err == nil || f.reads != 1 {
					t.Fatal("cancelled gate wait admitted a native observation", err, f.reads)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("cancelled gate wait was not joined")
			}
			gate <- struct{}{}
			if err := validateDesktopLinuxNodePathWith(context.Background(), f.a, path, f.read); err != nil || f.reads != 2 {
				t.Fatal("cancelled observation stole the original gate or owner", err, f.reads)
			}
		})
	}
}
