//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemtu"
)

// This comparison model exercises the final application adoption boundary.
// It has no real process, interface, native receipt or activation authority;
// the installed-host cases execute those separate production prerequisites.
func TestDesktopLinuxMTUViewRechecksCompleteAppCapture(t *testing.T) {
	for _, name := range []string{"valid", "different-saved-runtime", "missing-profile", "same-id-dns", "same-id-mtu-policy", "same-id-key",
		"saved-option", "runtime-option", "controller", "controller-parent", "parent-record", "private-roots", "command",
		"disconnected", "phase", "node", "mode", "closing", "duplicate-legacy", "empty-session", "foreign-profile", "native-identity", "ended-parent"} {
		t.Run(name, func(t *testing.T) {
			profile := common.RouterProfile{ID: "original-view-node", DNSMode: "home", AdGuardIPv4: "192.168.50.133", MTUPolicy: "fixed", ManualMTU: 1376}
			command := &exec.Cmd{}
			parent := &desktopLinuxNodeParent{}
			controller := &ownedDesktopController{nodeParent: parent}
			lifetime, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &app{localController: controller, cmd: command, profiles: common.RouterProfileStore{Profiles: []common.RouterProfile{profile}, SelectedID: profile.ID},
				cfg: common.ClientConfig{ProfilesFile: filepath.Join(linuxOwnedControllerRoot, "routers.json"), ModesFile: filepath.Join(linuxOwnedControllerRoot, "modes.json"),
					ScriptsDir: filepath.Join(linuxOwnedControllerRoot, "modes"), StateFile: filepath.Join(linuxOwnedControllerRoot, "state.json")},
				state: state{Connected: true, Phase: "connected", RouterID: profile.ID, RuntimeMode: "shadowsocks"}}
			h := &desktopLinuxNodeHost{parent: &desktopLinuxNodeParentCapture{app: a, parent: parent, controller: controller, lifetime: lifetime},
				launch: &desktopNodeLaunch{profileID: profile.ID, mode: "shadowsocks"}, process: &desktopLinuxNodeProcess{command: command},
				revision: desktopOwnedNodeProfileToken(profile)}
			identity := mtuViewIdentity{Session: "original-view-session", Profile: profile.ID}
			switch name {
			case "different-saved-runtime":
				h.options = [3]bool{true, true, true}
				a.state.DAITA, a.state.Jumbo, a.state.Socks = true, true, true
			case "missing-profile":
				a.profiles.Profiles = nil
			case "same-id-dns":
				a.profiles.Profiles[0].AdGuardIPv4 = "192.168.50.134"
			case "same-id-mtu-policy":
				a.profiles.Profiles[0].MTUPolicy = "auto"
			case "same-id-key":
				a.profiles.Profiles[0].APIToken = "replacement-private-reference"
			case "saved-option":
				a.profiles.Profiles[0].DAITAEnabled = true
			case "runtime-option":
				a.state.DAITA = true
			case "controller":
				a.localController = &ownedDesktopController{nodeParent: parent}
			case "controller-parent":
				controller.nodeParent = &desktopLinuxNodeParent{}
			case "parent-record":
				parent.record.Generation = "replacement"
			case "private-roots":
				a.cfg.ProfilesFile += ".replacement"
			case "command":
				a.cmd = &exec.Cmd{}
			case "disconnected":
				a.state.Connected = false
			case "phase":
				a.state.Phase = "starting"
			case "node":
				a.state.RouterID = "replacement"
			case "mode":
				a.state.RuntimeMode = "replacement"
			case "closing":
				a.closing = true
			case "duplicate-legacy":
				desktopNodeOwners.Store(a, h.launch)
				defer desktopNodeOwners.Delete(a)
			case "empty-session":
				identity.Session = ""
			case "foreign-profile":
				identity.Profile = "replacement"
			case "native-identity":
				identity.Native = true
			case "ended-parent":
				cancel()
			}
			a.mu.Lock()
			err := desktopLinuxMTUViewAppCurrentLocked(a, h, identity)
			a.mu.Unlock()
			want := name == "valid" || name == "different-saved-runtime"
			if (err == nil) != want {
				t.Fatal("MTU status accepted a replaced complete application capture or confused saved/runtime options", err)
			}
		})
	}
}

func TestDesktopLinuxMTUViewKeepsLiveReadbackSeparateFromMeasuredResults(t *testing.T) {
	for _, name := range []string{"auto-idle", "fixed-idle", "pending-without-view", "running-view", "canceling-view", "completed-view", "restored-view", "changed-value", "changed-value-request", "later-lease", "later-lease-request", "unknown-request", "foreign-session"} {
		t.Run(name, func(t *testing.T) {
			view := desktopLinuxMTUView{identity: mtuViewIdentity{Session: "original-session", Profile: "original-profile"}, live: desktopNodeMTURecord{MTU: 1376}, auto: true}
			request, session := "", view.identity.Session
			wantCode, wantPhase := http.StatusOK, "idle"
			wantAllowed, wantRequested, wantRunning, wantMeasured, wantRestored := true, false, false, false, false
			wantSource := "live-captured-interface"
			if name == "running-view" || name == "canceling-view" || name == "completed-view" || name == "restored-view" || strings.HasPrefix(name, "changed-value") || strings.HasPrefix(name, "later-lease") {
				view.hasOperation = true
				view.operation = mobilemtu.Status{Request: strings.Repeat("a", 32), Phase: "complete", EffectiveMTU: 1376, Source: "measured-path", Complete: true, Measured: true}
			}
			switch name {
			case "fixed-idle":
				view.auto, wantAllowed = false, false
			case "pending-without-view":
				view.busy, wantRunning, wantPhase = true, true, "busy"
			case "running-view", "canceling-view":
				view.busy, view.operation.Running = true, true
				view.operation.EffectiveMTU = 9000 // A saved/provisional result cannot replace live readback.
				view.operation.Phase = "measuring"
				if name == "canceling-view" {
					view.operation.Phase = "canceling"
				}
				wantRequested, wantRunning, wantPhase = true, true, view.operation.Phase
				request = view.operation.Request
			case "completed-view":
				wantRequested, wantMeasured, wantPhase, wantSource = true, true, "complete", "measured-path"
				request = view.operation.Request
			case "restored-view":
				view.operation.Measured, view.operation.Restored = false, true
				view.operation.Phase, view.operation.Source = "restored", "restored-captured-interface"
				wantRequested, wantRestored, wantPhase, wantSource = true, true, "restored", view.operation.Source
			case "changed-value", "changed-value-request":
				view.operation.EffectiveMTU = 9000
				if name == "changed-value-request" {
					request, wantCode = view.operation.Request, http.StatusConflict
				}
			case "later-lease", "later-lease-request":
				view.busy, wantRunning, wantPhase = true, true, "busy"
				if name == "later-lease-request" {
					request, wantCode = view.operation.Request, http.StatusNotFound
				}
			case "unknown-request":
				request, wantCode = strings.Repeat("b", 32), http.StatusNotFound
			case "foreign-session":
				session, wantCode = "replacement-session", http.StatusConflict
			}
			response := httptest.NewRecorder()
			writeDesktopLinuxMTUCapturedView(response, view, request, session)
			if response.Code != wantCode {
				t.Fatalf("wrong status for captured readback: %d %s", response.Code, response.Body.String())
			}
			if wantCode != http.StatusOK {
				return
			}
			var actual struct {
				Session   string           `json:"session_id"`
				Profile   string           `json:"profile_id"`
				Requested bool             `json:"requested"`
				Waiting   bool             `json:"waiting_commit"`
				Allowed   *bool            `json:"optimization_allowed"`
				Status    mobilemtu.Status `json:"status"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &actual); err != nil {
				t.Fatal(err)
			}
			if actual.Session != view.identity.Session || actual.Profile != view.identity.Profile || actual.Allowed == nil || *actual.Allowed != wantAllowed || actual.Requested != wantRequested || actual.Waiting || actual.Status.EffectiveMTU != 1376 || actual.Status.Source != wantSource || actual.Status.Phase != wantPhase || actual.Status.Running != wantRunning || actual.Status.Measured != wantMeasured || actual.Status.Restored != wantRestored {
				t.Fatal("native status changed its current interface, policy, or measurement evidence", response.Body.String())
			}
			if wantRunning && actual.Status.Complete || !wantRequested && actual.Status.Request != "" {
				t.Fatal("native readback invented completion or adopted an unrelated view token", response.Body.String())
			}
		})
	}
}

func TestDesktopLinuxMTUViewDoesNotCreateNativeOwnership(t *testing.T) {
	for _, name := range []string{"ordinary-path", "cancelled", "foreign-parent"} {
		t.Run(name, func(t *testing.T) {
			a := &app{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "cancelled" {
				cancel()
			}
			if name == "foreign-parent" {
				a.localController = &ownedDesktopController{nodeParent: &desktopLinuxNodeSession{}}
			}
			_, handled, err := captureDesktopLinuxMTUView(ctx, a, "")
			if name == "ordinary-path" {
				if handled || err != nil {
					t.Fatal("legacy path adopted native ownership", handled, err)
				}
			} else if !handled || err == nil {
				t.Fatal("invalid native request fell through to saved measurement", handled, err)
			}
			if a.localController != nil {
				if _, ok := a.localController.nodeParent.(*desktopLinuxNodeSession); !ok {
					t.Fatal("status created or replaced a native parent")
				}
			}
		})
	}
}
