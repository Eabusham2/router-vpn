package mobilemultihop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

func externalOpenVPNServerProfile(t *testing.T, external map[string]any) map[string]any {
	t.Helper()
	profile := predecessorCopy(external["openvpn"].(map[string]any))
	profile["username"], profile["password"] = "independent-server-user", "independent-server-password"
	return map[string]any{"protocol": "openvpn", "openvpn": profile, "pairing_private_key": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))}
}

func externalOpenVPNExecutionFixture(t *testing.T, selection, layer string) (string, string) {
	t.Helper()
	source, raw := externalExecutionProtocolFixture(t, "hysteria2", selection, layer)
	graph, capture := externalTestRead(t, source), externalTestRead(t, raw)
	profile := capture["profile"].(map[string]any)
	old := profile["external"].(map[string]any)
	config := "client\nremote 203.0.113.20 1194 udp\nremote 203.0.113.20 443 tcp\nremote-random\nauth-user-pass\npeer-fingerprint " + strings.Repeat("a", 64) + "\nverify-x509-name provider.example name\ntun-mtu 1500\nmssfix 1400\n"
	owned := nativeopenvpn.Profile{Config: config, Username: "exact-local-user", Password: "exact-local-password"}
	external := map[string]any{"protocol": "openvpn", "expected_public_ip": old["expected_public_ip"], "response_probe": old["response_probe"], "openvpn": map[string]any{"config": config, "username": owned.Username, "password": owned.Password}}
	if layer != "" {
		external["start_layer"] = old["start_layer"]
		if layer == "aes-256-gcm+xor-whitening" {
			external["start_layer"].(map[string]any)["transport"].(map[string]any)["server_port"] = float64(8389)
		}
	}
	server := externalOpenVPNServerProfile(t, external)
	public, err := multihoprelay.ExternalOpenVPNServerDescriptor(server)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(public)
	var descriptor map[string]any
	_ = json.Unmarshal(encoded, &descriptor)
	external["openvpn_pairing"] = map[string]any{"private_key": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), "server": descriptor}
	profile["external"], profile["multihop_exit_mode"], capture["protocol"] = external, "openvpn", "openvpn"
	entry := externalTestFind(t, graph, "entry-wg")
	entry["mtu"] = float64(1600)
	entryProfile := capture["entry"].(map[string]any)
	entryProfile["mtu_policy"], entryProfile["manual_mtu"] = "fixed", float64(1600)
	endpoint, err := nativeopenvpn.CompileProfile(owned, ExternalFinalTag, "entry-wg")
	if err != nil {
		t.Fatal(err)
	}
	graph["outbounds"] = []any{}
	graph["endpoints"] = []any{entry, endpoint}
	return externalTestJSON(t, graph), externalTestJSON(t, capture)
}

func TestOpenVPNExternalExecutionCapturesDistinctServerPolicyAndProvedRestoration(t *testing.T) {
	for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, execution := range []string{"local", "server", "auto"} {
			for _, restored := range []string{"", "local", "server"} {
				if restored != "" && execution != "auto" && restored != execution {
					continue
				}
				t.Run(layer+"/"+execution+"/"+restored, func(t *testing.T) {
					source, capture := externalOpenVPNExecutionFixture(t, execution, layer)
					prepared, err := PrepareExternalExecutionCapture(source, capture, restored)
					if err != nil {
						t.Fatal(err)
					}
					policy, err := NewExternalPolicy(source, prepared)
					if err != nil {
						t.Fatal(err)
					}
					graph := externalTestRead(t, policy.Config())
					tag := LocalTag
					if execution == "local" && restored == "" {
						tag = ExternalFinalTag
					}
					local := externalTestFind(t, graph, tag)
					if local["type"] != "openvpn-client" || local["system"] != false || local["username"] != "exact-local-user" || local["password"] != "exact-local-password" || local["server"] != nil {
						t.Fatal("compiled Local endpoint lost original provider identity or multiremote shape")
					}
					wantHost, wantMTU := "203.0.113.20", float64(1440)
					if layer != "" {
						wantHost, wantMTU = "10.93.0.1", 1382
					}
					remotes := local["servers"].([]any)
					if len(remotes) != 2 || remotes[0].(map[string]any)["server"] != wantHost || remotes[1].(map[string]any)["server"] != wantHost || local["mtu"] != wantMTU {
						t.Fatal("OpenVPN remote list or per-hop/layer MTU bound changed")
					}
					meta := externalTestRead(t, policy.Metadata())
					if meta["configured_mtu"] != float64(1280) || meta["entry_mtu"] != float64(1600) || meta["udp_available"] != true || meta["dns_detour"] != ExternalFinalTag || meta["entry_proof"] != "required" {
						t.Fatal("OpenVPN candidates lost selected DNS, UDP or captured entry policy")
					}
					if tag == LocalTag {
						want := execution
						if restored != "" {
							want = restored
						}
						if policy.capture.Execution.Selection != want || policy.capture.Profile["multihop_execution"] != execution {
							t.Fatal("restoration reran Compare or changed saved choice")
						}
						exit, err := externalRelaySelection(policy.capture)
						if err != nil || multihoprelay.ValidateExternalRequest(exit, policy.capture.Execution.Request) != nil {
							t.Fatal("captured OpenVPN lease lost owned authentication")
						}
					}
					for _, secret := range []string{"provider_identity", "pairing_public_key", "exact-local-password", "independent-server-user"} {
						if strings.Contains(policy.Metadata(), secret) {
							t.Fatal("private OpenVPN pairing data entered metadata")
						}
					}
				})
			}
		}
	}
}

func TestOpenVPNExternalExecutionProofRunsChallengeAndRepeatedWinnerWithoutCredentialReuse(t *testing.T) {
	previous := Targets
	Targets = []string{"http://1.1.1.1/public-a", "http://1.0.0.1/public-b"}
	defer func() { Targets = previous }()
	for _, restored := range []string{"", "local", "server"} {
		t.Run(restored, func(t *testing.T) {
			source, capture := externalOpenVPNExecutionFixture(t, "auto", "aes-256-gcm+xor-whitening")
			request, engine := externalExecutionCapturedRequest(t, source, capture, restored)
			if _, err := request.Run(); err != nil {
				t.Fatal(err)
			}
			want := restored
			if want == "" {
				want = "server"
			}
			if !request.Healthy() || request.Execution() != want {
				t.Fatal("OpenVPN proof did not retain selected execution")
			}
			engine.mu.Lock()
			attempts := append([]multihoprelay.Request{}, engine.leaseRequests...)
			engine.mu.Unlock()
			seen := map[string]bool{}
			for _, q := range attempts {
				if q.ExternalAttempt == "" || q.ExternalEpoch == "" || q.ExternalPeer != "10.77.0.2" {
					t.Fatal("OpenVPN acquisition lacked authenticated entry challenge")
				}
				seen[q.ExternalAttempt] = true
			}
			if restored == "" && len(seen) != 2 || restored == "server" && len(seen) != 1 || restored == "local" && len(seen) != 0 {
				t.Fatal("trial/restored execution did not retain exact fresh acquisition lifecycle")
			}
			if err := request.Close(); err != nil {
				t.Fatal(err)
			}
			for _, q := range attempts {
				if _, err := engine.manager.Create(context.Background(), netip.MustParseAddr("10.77.0.2"), q); err == nil {
					t.Fatal("retired native OpenVPN proof recreated a provider session")
				}
			}
		})
	}
}

func TestOpenVPNExternalExecutionRejectsChangedPairingAndUnsafeMTUBeforeOpening(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"missing pairing": func(c map[string]any) {
			delete(c["profile"].(map[string]any)["external"].(map[string]any), "openvpn_pairing")
		},
		"changed provider identity": func(c map[string]any) {
			c["profile"].(map[string]any)["external"].(map[string]any)["openvpn_pairing"].(map[string]any)["server"].(map[string]any)["provider_identity"].(map[string]any)["username"] = "exact-local-user"
		},
		"fixed server interface exceeded": func(c map[string]any) {
			p := c["profile"].(map[string]any)
			p["mtu_policy"], p["manual_mtu"] = "fixed", float64(1600)
		},
		"second remote not proved": func(c map[string]any) {
			p := c["profile"].(map[string]any)["external"].(map[string]any)["openvpn"].(map[string]any)
			p["config"] = strings.Replace(p["config"].(string), "203.0.113.20 443", "203.0.113.21 443", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			source, capture := externalOpenVPNExecutionFixture(t, "auto", "aes-256-gcm")
			selected := externalTestRead(t, capture)
			change(selected)
			if _, err := PrepareExternalExecutionCapture(source, externalTestJSON(t, selected), ""); err == nil {
				t.Fatal("unsafe or substituted provider capture accepted")
			}
		})
	}
	// Invalid imported pairings are rejected even for an ordinary Local request;
	// omitting pairing altogether remains valid Local behavior.
	source, capture := externalOpenVPNExecutionFixture(t, "local", "")
	selected := externalTestRead(t, capture)
	ext := selected["profile"].(map[string]any)["external"].(map[string]any)
	ext["openvpn_pairing"] = nil
	if _, err := NewExternalPolicy(source, externalTestJSON(t, selected)); err == nil {
		t.Fatal("invalid optional pairing was silently discarded")
	}
	delete(ext, "openvpn_pairing")
	if _, err := NewExternalPolicy(source, externalTestJSON(t, selected)); err != nil {
		t.Fatal("Local unnecessarily required pairing", err)
	}
}
