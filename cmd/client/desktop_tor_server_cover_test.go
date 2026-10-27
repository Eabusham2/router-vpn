package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobiletor"
)

// Exercise the actual public connect and profile-save paths. The process
// fixture supplies native lifecycle receipts; native Box tests separately
// enforce the requested cover before producing those receipts.
func TestDesktopTorServerCoverPublicConnectionKeepsCapturedRate(t *testing.T) {
	for _, mode := range []string{"tor", "tor-bridge"} {
		t.Run(mode, func(t *testing.T) {
			f := speedLabTorPipelineFixture(t)
			f.unified = true
			f.a.mu.Lock()
			p := &f.a.profiles.Profiles[0]
			if mode == "tor" {
				p.External = &common.ExternalNodeConfig{Protocol: "tor"}
			}
			p.MultihopExecution, p.DAITAEnabled, p.DAITARateKbps = "server", true, 64
			id := p.ID
			f.a.mu.Unlock()
			direct := false
			response := f.request(t, externalProfileConnectRequest{ProfileID: id, Direct: &direct, Execution: "server"})
			if response.Code != http.StatusOK {
				t.Fatal("public Server connection discarded cover", response.Code, response.Body.String())
			}
			check := func() {
				t.Helper()
				source, err := os.ReadFile(filepath.Join(f.launch.directory, "tor-profile.json"))
				if err != nil {
					t.Fatal(err)
				}
				var captured common.RouterProfile
				if json.Unmarshal(source, &captured) != nil || !captured.DAITAEnabled || captured.DAITARateKbps != 64 || captured.MultihopExecution != "server" {
					t.Fatal("actual private launch input lost saved cover selection")
				}
				raw, err := os.ReadFile(filepath.Join(f.launch.directory, "tor-capture.json"))
				if err != nil {
					t.Fatal(err)
				}
				input, err := mobiletor.DecodeDesktopBridgeCapture(string(source), string(raw), f.launch.directory)
				if err != nil || input.Policy().ServerPolicy().Padding() != (mobiletor.TorPaddingPolicy{Enabled: true, RateKbps: 64}) {
					t.Fatal("public connection did not compile actual Server cover", err)
				}
			}
			check()
			if err := f.a.stopModeWithIntent(true); err != nil {
				t.Fatal(err)
			}
			response = postSetup(t, f.a, "/api/connection-profile/setup/save", map[string]any{"name": "Server cover", "mode": "external", "multihop_enabled": false})
			var saved struct {
				Profile connectionProfileRecord `json:"profile"`
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &saved) != nil {
				t.Fatal("complete cover profile could not be saved", response.Code, response.Body.String())
			}
			f.a.mu.Lock()
			f.a.profiles.Profiles[0].DAITAEnabled, f.a.profiles.Profiles[0].DAITARateKbps = false, 192
			f.a.mu.Unlock()
			response = desktopTorProfileRequest(t, f, "/api/connection-profile/load", map[string]any{"id": saved.Profile.ID})
			if response.Code != http.StatusOK || !f.a.profiles.Profiles[0].DAITAEnabled || f.a.profiles.Profiles[0].DAITARateKbps != 64 {
				t.Fatal("complete profile Load discarded cover policy", response.Code, response.Body.String())
			}
			response = f.request(t, externalProfileConnectRequest{ProfileID: id, Direct: &direct, Execution: "server"})
			if response.Code != http.StatusOK {
				t.Fatal("restored cover profile could not reconnect", response.Code, response.Body.String())
			}
			check()
		})
	}
}
