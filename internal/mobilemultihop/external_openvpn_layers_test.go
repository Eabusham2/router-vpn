package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func externalOpenVPNLayerMapFixture(t *testing.T, mode string) (string, string) {
	t.Helper()
	source, capture := externalOpenVPNMappedExecutionFixture(t)
	captured := externalTestRead(t, capture)
	profile := captured["profile"].(map[string]any)
	profile["start_layer"] = mode
	external := profile["external"].(map[string]any)
	layers := map[string]any{}
	for index, host := range []string{"203.0.113.20", "203.0.113.21"} {
		layers[host] = map[string]any{"mode": mode, "api": "http://10.93.0.1:8787", "transport": map[string]any{"type": "shadowsocks", "tag": "saved-start", "server": host, "server_port": float64(8388 + 2*index), "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('c'+index)), 32)))}}
	}
	external["openvpn_start_layers"] = layers
	return source, externalTestJSON(t, captured)
}

func TestOpenVPNMappedLayersCompileOriginalRemoteIdentityAndBoundMTURetest(t *testing.T) {
	for _, mode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run(mode+"/"+execution, func(t *testing.T) {
				source, capture := externalOpenVPNLayerMapFixture(t, mode)
				captured := externalTestRead(t, capture)
				profile := captured["profile"].(map[string]any)
				profile["multihop_execution"] = execution
				prepared, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, captured), "")
				if err != nil {
					t.Fatal(err)
				}
				policy, err := NewExternalPolicy(source, prepared)
				if err != nil {
					t.Fatal(err)
				}
				graph := externalTestRead(t, policy.Config())
				tag := LocalTag
				if execution == "local" {
					tag = ExternalFinalTag
				}
				endpoint := externalTestFind(t, graph, tag)
				original := externalTestFind(t, externalTestRead(t, source), ExternalFinalTag)
				mapping := externalTestFind(t, graph, multihoprelay.OpenVPNStartLayerMapTag)
				if !reflect.DeepEqual(endpoint["servers"], original["servers"]) || endpoint["detour"] != multihoprelay.OpenVPNStartLayerMapTag || mapping["detour"] != "entry-wg" || mapping["mode"] != mode || !reflect.DeepEqual(mapping["layers"], profile["external"].(map[string]any)["openvpn_start_layers"]) {
					t.Fatal("mapped graph changed provider tuple, entry or host-specific private policy")
				}
				if endpoint["mtu"] != float64(1382) {
					t.Fatal("mapped graph omitted worst per-host layer overhead", endpoint["mtu"])
				}
				for _, key := range []string{"openvpn_start_layers", "provider_identity", "password", "10.93.0.1"} {
					if strings.Contains(policy.Metadata(), key) {
						t.Fatal("private mapped policy leaked in public metadata")
					}
				}
			})
		}
	}
}

func TestOpenVPNMappedLayersCompareAndRestoreKeepExactProvedOwner(t *testing.T) {
	mappedOpenVPNTargets(t)
	for _, mode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, restored := range []string{"", "local", "server"} {
			t.Run(mode+"/"+restored, func(t *testing.T) {
				source, capture := externalOpenVPNLayerMapFixture(t, mode)
				r, e := externalExecutionCapturedRequest(t, source, capture, restored)
				if _, err := r.Run(); err != nil {
					t.Fatal(err, r.ProgressJSON())
				}
				want := restored
				if want == "" {
					var progress Progress
					if json.Unmarshal([]byte(r.ProgressJSON()), &progress) != nil || len(progress.Measurements) != 2 {
						t.Fatal("missing actual comparison measurements")
					}
					best := 1e300
					for _, row := range progress.Measurements {
						if !row.Eligible || row.ScoreMS == nil || *row.ScoreMS != (row.LastNodeMS+row.ExternalMS)/2 {
							t.Fatal("mapped candidate changed exact average formula")
						}
						if *row.ScoreMS < best {
							best = *row.ScoreMS
							want = string(row.Candidate.Execution)
						}
					}
				}
				if r.Execution() != want || !r.Healthy() {
					t.Fatal("wrong mapped candidate retained")
				}
				if err := r.VerifyCurrentPath(); err != nil {
					t.Fatal(err)
				}
				e.mu.Lock()
				for tag, addresses := range e.nodeDials {
					wantAddress := "203.0.113.20:443"
					if tag == ServerTag {
						wantAddress = "203.0.113.21:9443"
					}
					for _, address := range addresses {
						if address != wantAddress {
							t.Error("probe used private service collision instead of original host", tag)
						}
					}
				}
				if restored == "" {
					winnerTag := LocalTag
					if want == "server" {
						winnerTag = ServerTag
					}
					if len(e.probeTargets[LocalTag]) < 2 || len(e.probeTargets[ServerTag]) < 2 || len(e.probeTargets[winnerTag]) < 4 || e.probeTargets[LocalTag][1] != e.probeTargets[ServerTag][1] || e.probeTargets[winnerTag][1] != e.probeTargets[winnerTag][3] {
						t.Error("Compare changed shared external endpoint or skipped winner reproof")
					}
				}
				before := len(e.leaseRequests)
				e.mu.Unlock()
				tag := LocalTag
				if want == "server" {
					tag = ServerTag
				}
				mappedOpenVPNChange(e, tag)
				if r.VerifyCurrentPath() == nil || r.Healthy() {
					t.Fatal("new provider generation retained old mapped proof")
				}
				e.mu.Lock()
				after := len(e.leaseRequests)
				e.mu.Unlock()
				if after != before {
					t.Fatal("measurement path check acquired another candidate")
				}
			})
		}
	}
}

func TestOpenVPNMappedLayersRequireActualV6CapabilityAndExactSavedMode(t *testing.T) {
	mappedOpenVPNTargets(t)
	for _, capability := range []string{"missing", "claimed"} {
		t.Run(capability, func(t *testing.T) {
			source, capture := externalOpenVPNLayerMapFixture(t, "aes-256-gcm")
			captured := externalTestRead(t, capture)
			captured["profile"].(map[string]any)["multihop_execution"] = "server"
			r, e := externalExecutionCapturedRequest(t, source, externalTestJSON(t, captured), "")
			e.mu.Lock()
			e.badOpenVPNLayerCapability = capability
			e.mu.Unlock()
			if _, err := r.Run(); err == nil || r.Healthy() {
				t.Fatal("old server advertised unsupported per-host encryption")
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			for _, request := range e.leaseRequests {
				if request.ExternalAttempt != "" {
					t.Fatal("invalid capability acquired a lease")
				}
			}
		})
	}
	for _, mode := range []string{"", "off", "aes-256-gcm+xor-whitening"} {
		source, capture := externalOpenVPNLayerMapFixture(t, "aes-256-gcm")
		captured := externalTestRead(t, capture)
		captured["profile"].(map[string]any)["start_layer"] = mode
		if _, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, captured), ""); err == nil {
			t.Fatal("selected mode silently changed mapped encryption")
		}
	}
}
