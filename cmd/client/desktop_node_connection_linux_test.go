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
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong", "wg-pq", "hysteria2", "reality-vision", "ss-v2ray", "split", "max", "naive-h2", "tor", "openvpn", "smart-auto", "shadowsocks"} {
		if got := a.desktopLinuxNodeConnectionSelected(profile, mode); got != (mode == "shadowsocks" || mode == "wg" || mode == "awg2-fast" || mode == "awg2-strong" || mode == "hysteria2") {
			t.Fatal("Linux public dispatcher changed an unrelated graph", mode, got)
		}
	}
	for _, mode := range []string{"shadowsocks", "wg", "awg2-fast", "awg2-strong", "hysteria2"} {
		for _, policy := range []string{"off", "on-connect", "always", "malformed"} {
			profile.KillSwitchPolicy = policy
			if got := a.desktopLinuxNodeConnectionSelected(profile, mode); got != (policy != "off") {
				t.Fatal("missing protection validation became a legacy fallback", mode, policy, got)
			}
		}
	}
	profile.KillSwitchPolicy = "on-connect"
	a.nodeConnectionHost = &desktopNodeConnectionHost{}
	for _, mode := range []string{"shadowsocks", "wg", "awg2-fast", "awg2-strong", "hysteria2"} {
		if a.desktopLinuxNodeConnectionSelected(profile, mode) {
			t.Fatal("Linux dispatcher replaced the separately captured platform host", mode)
		}
	}
}

func TestDesktopLinuxPublicPreflightRejectsBeforeStop(t *testing.T) {
	for _, scenario := range []string{"cover-runtime", "start-aes", "start-whitening", "malformed-layer", "external", "unknown-policy", "missing-controller", "cancelled", "wg-plain", "wg-aes", "wg-whitening", "wg-cancelled", "hysteria2-plain", "hysteria2-aes", "hysteria2-whitening", "hysteria2-cancelled", "awg2-fast-plain", "awg2-fast-aes", "awg2-fast-whitening", "awg2-fast-cancelled", "awg2-strong-plain", "awg2-strong-aes", "awg2-strong-whitening", "awg2-strong-cancelled"} {
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
			mode := "shadowsocks"
			if strings.HasPrefix(scenario, "wg-") {
				mode = "wg"
				a.modes[0].ID = mode
			}
			if strings.HasPrefix(scenario, "hysteria2-") {
				mode = "hysteria2"
				a.modes[0].ID = mode
			}
			for _, candidate := range []string{"awg2-fast", "awg2-strong"} {
				if strings.HasPrefix(scenario, candidate+"-") {
					mode, a.modes[0].ID = candidate, candidate
				}
			}
			expected := "supported protected graph and exact Start Layer"
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
			case "wg-plain", "hysteria2-plain", "awg2-fast-plain", "awg2-strong-plain":
				expected = "Linux Node"
			case "hysteria2-aes", "wg-aes":
				profile.StartLayer = common.StartLayerAES256GCM
				expected = "Linux Node"
			case "hysteria2-whitening", "wg-whitening":
				profile.StartLayer = common.StartLayerAES256GCMXOR
				expected = "Linux Node"
			case "awg2-fast-aes", "awg2-strong-aes":
				profile.StartLayer = common.StartLayerAES256GCM
			case "awg2-fast-whitening", "awg2-strong-whitening":
				profile.StartLayer = common.StartLayerAES256GCMXOR
			case "cancelled", "wg-cancelled", "hysteria2-cancelled", "awg2-fast-cancelled", "awg2-strong-cancelled":
				cancel()
			}
			a.profiles = common.RouterProfileStore{SelectedID: profile.ID, Profiles: []common.RouterProfile{profile}}
			before, command, profiles := a.state, a.cmd, cloneRouterProfileStore(a.profiles)
			transition := &modeAttemptTransition{}
			a.operationMu.Lock()
			err := a.startModeAttempt(mode, true, transition)
			a.operationMu.Unlock()
			if err == nil || transition.StopBegun || a.state != before || a.cmd != command || !reflect.DeepEqual(a.profiles, profiles) {
				t.Fatal("Linux public preflight changed its original connection before rejecting unsupported launch", err)
			}
			if scenario == "cancelled" || scenario == "wg-cancelled" || scenario == "hysteria2-cancelled" || scenario == "awg2-fast-cancelled" || scenario == "awg2-strong-cancelled" {
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
