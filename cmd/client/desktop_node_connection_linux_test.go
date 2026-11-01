//go:build linux

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopLinuxPublicSelectionStaysBounded(t *testing.T) {
	profile := common.RouterProfile{NodeKind: "router-vpn", KillSwitch: true, KillSwitchPolicy: "on-connect"}
	a := &app{}
	for _, mode := range []string{"wg", "awg2-fast", "wg-pq", "hysteria2", "reality-vision", "ss-v2ray", "split", "max", "naive-h2", "tor", "openvpn", "smart-auto", "shadowsocks"} {
		if got := a.desktopLinuxNodeConnectionSelected(profile, mode); got != (mode == "shadowsocks") {
			t.Fatal("Linux public dispatcher changed an unrelated graph", mode, got)
		}
	}
	for _, policy := range []string{"off", "on-connect", "always", "malformed"} {
		profile.KillSwitchPolicy = policy
		if got := a.desktopLinuxNodeConnectionSelected(profile, "shadowsocks"); got != (policy != "off") {
			t.Fatal("missing protection validation became a legacy fallback", policy, got)
		}
	}
	profile.KillSwitchPolicy = "on-connect"
	a.nodeConnectionHost = &desktopNodeConnectionHost{}
	if a.desktopLinuxNodeConnectionSelected(profile, "shadowsocks") {
		t.Fatal("Linux dispatcher replaced the separately captured platform host")
	}
}

func TestDesktopLinuxPublicPreflightRejectsBeforeStop(t *testing.T) {
	for _, scenario := range []string{"cover-runtime", "start-aes", "start-whitening", "malformed-layer", "external", "unknown-policy", "missing-controller", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOMEVPN_ROOT", root)
			profile := common.RouterProfile{ID: "original", Endpoint: "198.51.100.8", NodeKind: "router-vpn", KillSwitch: true, KillSwitchPolicy: "on-connect"}
			operation, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &app{connectionContext: operation, connectionCancel: cancel,
				cfg: common.ClientConfig{ScriptsDir: filepath.Join(root, "modes")},
				modes: []common.Mode{{ID: "shadowsocks", Name: "Original Shadowsocks", DAITASupported: true, JumboSupported: true,
					Command: []string{"this-legacy-fallback-must-never-start"}}},
				state: state{Connected: true, Phase: "connected", Mode: "original", RuntimeMode: "original", RouterID: "previous"},
				cmd:   &exec.Cmd{}}
			expected := "supported protected Shadowsocks graph and exact Start Layer"
			switch scenario {
			case "cover-runtime":
				a.state.DAITA = true    // Saved false remains independent from this actual selection.
				expected = "Linux Node" // Requested cover still requires the installed captured native owner.
			case "start-aes":
				profile.StartLayer = common.StartLayerAES256GCM
				expected = "Linux Node" // Capability is not permission to bypass its missing native owner.
			case "start-whitening":
				profile.StartLayer = common.StartLayerAES256GCMXOR
				expected = "Linux Node"
			case "malformed-layer":
				profile.StartLayer = "aes-256-gcm-xor"
			case "external":
				profile.NodeKind = "external"
			case "unknown-policy":
				profile.KillSwitchPolicy = "malformed"
			case "missing-controller":
				expected = "Linux Node"
			case "cancelled":
				cancel()
			}
			a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
			before, command, profiles := a.state, a.cmd, cloneRouterProfileStore(a.profiles)
			transition := &modeAttemptTransition{}
			a.operationMu.Lock()
			err := a.startModeAttempt("shadowsocks", true, transition)
			a.operationMu.Unlock()
			if err == nil || transition.StopBegun || a.state != before || a.cmd != command || !reflect.DeepEqual(a.profiles, profiles) {
				t.Fatal("Linux public preflight changed its original connection before rejecting unsupported launch", err)
			}
			if scenario == "cancelled" {
				if !errors.Is(err, errConnectionOperationCancelled) {
					t.Fatal("public Linux cancellation lost the shared operation sentinel", err)
				}
			} else if !strings.Contains(err.Error(), expected) {
				t.Fatal("public Linux preflight did not reach its intended rejection", err, expected)
			}
			if _, exists := desktopNodeOwners.Load(a); exists {
				t.Fatal("rejected Linux launch installed a legacy runtime owner")
			}
		})
	}
}

// The parent fixture models only existing native-read observations. This test
// exercises the final app-lock comparison without claiming an installed TUN.
func TestDesktopLinuxPublicPreflightCannotAdoptReplacement(t *testing.T) {
	for _, scenario := range []string{"original", "command", "phase", "controller", "operation", "cancelled", "cancel-intent", "profile", "saved-options", "selected-node", "legacy-owner", "closing"} {
		t.Run(scenario, func(t *testing.T) {
			f, _ := linuxSealedRestoreFixture(t, false)
			operation, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.a.connectionContext = operation
			capture := &desktopLinuxNodeConnectPreflight{app: f.a, controller: f.a.localController, operation: operation,
				command: f.a.cmd, state: f.a.state, host: f.h, session: f.s}
			switch scenario {
			case "command":
				f.a.cmd = &exec.Cmd{}
			case "phase":
				f.a.state.Phase = "replacement"
			case "controller":
				f.a.localController = &ownedDesktopController{}
			case "operation":
				f.a.connectionContext = context.Background()
			case "cancelled":
				cancel()
			case "cancel-intent":
				f.a.connectionCancelIntent = operation
			case "profile":
				f.a.profiles.Profiles[0].APIToken += "replacement"
			case "saved-options":
				f.a.profiles.Profiles[0].DAITAEnabled = true
			case "selected-node":
				f.a.profiles.SelectedID = "replacement"
			case "legacy-owner":
				desktopNodeOwners.Store(f.a, f.h.launch)
			case "closing":
				f.a.closing = true
			}
			before, command := f.a.state, f.a.cmd
			f.a.mu.Lock()
			err := capture.currentAppLocked()
			f.a.mu.Unlock()
			if (err == nil) != (scenario == "original") || f.a.state != before || f.a.cmd != command {
				t.Fatal("Linux final preflight accepted or changed a replacement connection", err)
			}
		})
	}
}

func TestDesktopLinuxLegacyTransitionNeverCreatesOwnership(t *testing.T) {
	a := &app{}
	if err := a.guardDesktopLinuxNodeLegacyTransition(); err != nil || a.localController != nil {
		t.Fatal("an unrelated legacy app acquired Linux ownership", err)
	}
	f := newLinuxSpeedLabPathFixture(t)
	before, command, session, host := f.a.state, f.a.cmd, f.p.session, f.s.active
	if err := f.a.guardDesktopOwnedNodeTransition(nil); err == nil || f.a.state != before || f.a.cmd != command || f.p.session != session || f.s.active != host {
		t.Fatal("legacy preflight accepted or changed a retained Linux source", err)
	}
}
