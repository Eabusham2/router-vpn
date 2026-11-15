//go:build go1.25

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"router-vpn/internal/mobilemultihop"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Public handlers retain the original compiler, source, protection journal and
// restoration. The existing fixture doubles only process/WFP/network boundaries.
func TestDesktopSingleNodeOffPublicTemporaryRestoresOriginalOwner(t *testing.T) {
	for _, direction := range []string{"router-external-router", "external-router-external"} {
		t.Run(direction, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy := "off"
				f := newDesktopWindowsExternalFixture(t, policy)
				a := f.base.a
				if f.base.profile.KillSwitchPolicy != "off" || !desktopOwnedNodeModeEligible(f.base.profile, "wg") {
					t.Fatal("single Router Off did not select original retained owner")
				}
				protocol := "https-connect"
				routerFirst := strings.HasPrefix(direction, "router-")
				var original *desktopNodeLaunch
				if routerFirst {
					response := httptest.NewRecorder()
					a.connect(response, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"wg"}`)))
					if response.Code != http.StatusOK {
						t.Fatal("original Router connect", response.Code, response.Body.String())
					}
					original = f.base.children[0].launch
				} else {
					original = f.connect(t, protocol)
				}
				deadline := time.Now().Add(time.Second)
				var originalIdentity speedLabPathIdentity
				for {
					identity, _, err := captureSpeedLabIdentity(a)
					if err == nil {
						originalIdentity = identity
						break
					} else if !time.Now().Before(deadline) {
						t.Fatal("original session observation", err)
					}
					time.Sleep(100 * time.Millisecond)
				}
				// Connected publication precedes the original DNS result's guarded
				// adoption. Join that exact worker within the same observation budget;
				// synctest.Wait alone can return while adoption sleeps on a lock timer.
				observation, stopObservation := context.WithDeadline(context.Background(), deadline)
				err := waitDesktopSpeedLabDNSObservation(observation, originalIdentity)
				stopObservation()
				if err != nil {
					t.Fatal("original DNS observation did not join", err)
				}
				var source []byte
				if original.ownedNode != nil {
					source = bytes.Clone(original.ownedNode.source)
				} else {
					source = bytes.Clone(original.external.source)
				}
				privateBefore, err := os.ReadFile(a.cfg.ProfilesFile)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				request := speedLabRequest{Scope: "temporary", DurationMode: "custom", MinSeconds: 1, MaxSeconds: 1}
				if routerFirst {
					request.Topology, request.NodeID, request.Execution = "external", f.profiles[protocol].ID, "local"
					f.onAdmit = func(child *desktopWindowsExternalChild) error {
						if child.launch.external != nil {
							cancel()
							return context.Canceled
						}
						return nil
					}
				} else {
					request.Topology, request.NodeID, request.Mode = "router", f.base.profile.ID, "wg"
					f.base.onHTTP = func(child *desktopNodeConnectionChild) { cancel() }

				}
				body, _ := json.Marshal(request)
				response := httptest.NewRecorder()
				a.speedLabRun(response, httptest.NewRequest(http.MethodPost, "/api/speed-lab/run", bytes.NewReader(body)).WithContext(ctx))

				if response.Code != http.StatusConflict || ctx.Err() == nil || !a.state.Connected || len(f.children) != 3 {
					t.Fatal("cancelled public test did not restore its original typed host", direction, response.Code, response.Body.String(), a.state, len(f.children))
				}
				trial, restored := f.children[1], f.children[2]
				if f.children[0].target.Policy != "off" || trial.target.Policy != "off" || restored.target.Policy != "off" {
					t.Fatal("all-Off succession changed captured policy")
				}

				if restored.attempt.transfer.Predecessor == nil || *restored.attempt.transfer.Predecessor != trial.target || restored.launch.command == original.command || restored.Alive() != nil {
					t.Fatal("restoration reused an old predecessor or child")
				}
				if routerFirst {
					if restored.launch.ownedNode == nil || restored.launch.external != nil || restored.launch.ownedNode.host != original.ownedNode.host || !bytes.Equal(source, restored.launch.ownedNode.source) {
						t.Fatal("Router restoration acquired external proof identity or reselected its host/source")
					}
				} else {
					if restored.launch.ownedNode != nil || restored.launch.external == nil || restored.launch.external.windowsHost != original.external.windowsHost ||
						!bytes.Equal(source, restored.launch.external.source) || restored.launch.external.selection != "local" || restored.launch.external.windows.policy.Metadata().Protocol != f.profiles[protocol].External.Protocol {
						t.Fatal("ordinary restoration acquired Router proof identity or reselected its host/source/winner")
					}
					if mtu, err := captureDesktopMTURestore(restored.launch); err != nil || mtu != 1360 {
						t.Fatal("restored external live MTU changed", mtu, err)
					}
				}
				privateAfter, err := os.ReadFile(a.cfg.ProfilesFile)
				if err != nil || !bytes.Equal(privateBefore, privateAfter) || a.connectionContext != nil {
					t.Fatal("temporary succession changed saved private source or retained the operation", err)
				}
			})
		})
	}
}

func TestDesktopSingleNodeOffPublicJoinRetainsOriginalSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newDesktopNodeConnectionFixture(t, "off", "")
		connected := httptest.NewRecorder()
		f.a.connect(connected, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"wg"}`)))
		if connected.Code != http.StatusOK || len(f.children) != 1 {
			t.Fatal("Off public connect lost retained source", connected.Code, connected.Body.String())
		}
		child := f.children[0]
		source := bytes.Clone(child.launch.ownedNode.source)
		child.mu.Lock()
		child.closeErr = errors.New("original native endpoint remains held")
		child.mu.Unlock()
		failed := httptest.NewRecorder()
		f.a.disconnect(failed, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
		retained, ok := desktopNodeOwners.Load(f.a)
		if failed.Code < 400 || !ok || retained != child.launch || f.a.nodeProtection == nil || f.a.nodeProtection.active != child.launch.ownedNode.attempt || f.kernel.target == nil || f.kernel.target.Policy != "off" || !f.kernel.locked || !bytes.Equal(source, child.launch.ownedNode.source) {
			t.Fatal("Off failed join discarded original isolated owner", failed.Code, failed.Body.String())
		}
		blocked := httptest.NewRecorder()
		f.a.connect(blocked, httptest.NewRequest(http.MethodPost, "/api/connect", strings.NewReader(`{"mode":"awg2-fast"}`)))
		if blocked.Code < 400 || len(f.children) != 1 {
			t.Fatal("Off failed join admitted replacement", blocked.Code, blocked.Body.String())
		}
		child.mu.Lock()
		child.closeErr = nil
		child.mu.Unlock()
		joined := httptest.NewRecorder()
		f.a.disconnect(joined, httptest.NewRequest(http.MethodPost, "/api/disconnect", nil))
		if joined.Code != http.StatusOK || f.a.cmd != nil || f.a.nodeProtection != nil || f.kernel.target != nil || f.kernel.locked {
			t.Fatal("Off successful original join retained native authority", joined.Code, joined.Body.String())
		}
		if _, ok := desktopNodeOwners.Load(f.a); ok {
			t.Fatal("Off successful cleanup retained source registry")
		}
	})
}

// The public dispatcher admits every actual raw NodeProfile mode, while an
// unrelated catalog transport cannot acquire this native source owner.
func TestDesktopSingleNodeOffCatalogHasCompleteRetainedCoverage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "configs", "client", "modes.json"))
	var modes []struct {
		ID string `json:"id"`
	}
	if err != nil || json.Unmarshal(raw, &modes) != nil {
		t.Fatal("cannot read actual shipping mode catalog", err)
	}
	seen := map[string]bool{}
	for _, mode := range modes {
		if !mobilemultihop.NodeProfileMode(mode.ID) {
			continue
		}
		if seen[mode.ID] {
			t.Fatal("duplicate raw node mode", mode.ID)
		}
		seen[mode.ID] = true
		for _, layer := range []string{"", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			if !mobilemultihop.DesktopNodePhysicalGraphSupported(mode.ID, layer) {
				t.Fatal("single Node Off would lose an original raw mode", mode.ID, layer)
			}
		}
	}
	if len(seen) != 19 {
		t.Fatal("raw catalog mode inventory changed without retained Off coverage", len(seen))
	}
}

func TestDesktopSingleNodeOffPreparationSealsBeforePreviousStop(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			f := newDesktopOwnedNodePreparationFixture(t, mode)
			f.profile.KillSwitch, f.profile.KillSwitchPolicy = false, "off"
			f.a.profiles.Profiles[0] = cloneRouterProfile(f.profile)
			command, state := f.a.cmd, f.a.state
			launch, err := f.prepare(mode, f.verify, f.lookup)
			if err != nil || launch == nil || launch.ownedNode == nil {
				t.Fatal("fresh Off capture failed retained preparation", err)
			}
			defer clearSpeedLabRestorePlan(speedLabRestorePlan{native: launch})
			if launch.ownedNode.policy.Metadata().KillSwitchPolicy != "off" || f.a.cmd != command || f.a.state != state || f.a.nodeProtection != nil || f.lookupCalls != 0 {
				t.Fatal("Off preparation changed prior runtime or captured policy")
			}
			for _, fault := range []string{"credential", "protection"} {
				changed := cloneRouterProfile(f.profile)
				if fault == "credential" {
					changed.APIToken += "replacement"
				} else {
					changed.KillSwitchPolicy = "always"
					changed.KillSwitch = true
				}
				if err := validateDesktopOwnedNodeSourceProfile(changed, launch.endpoint, string(launch.ownedNode.source)); err == nil {
					t.Fatal("Off original source accepted replacement profile", fault)
				}
			}
		})
	}
}
