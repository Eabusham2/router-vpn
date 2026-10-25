package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/nativeopenvpn"
)

func desktopOpenVPNCreateFixture(t *testing.T, layer string) externalProfileCreateRequest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "fixtures", "external-openvpn-client.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Layers map[string]struct {
			External common.ExternalNodeConfig `json:"external"`
			Layer    string                    `json:"selected_layer"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	f, ok := fixtures.Layers[layer]
	if !ok || f.External.OpenVPN == nil || f.External.OpenVPNPairing == nil {
		t.Fatal("paired OpenVPN fixture missing")
	}
	return externalProfileCreateRequest{Name: "Captured OpenVPN", Protocol: "openvpn", ExpectedPublicIP: f.External.ExpectedPublicIP,
		OpenVPN: f.External.OpenVPN, OpenVPNPairing: f.External.OpenVPNPairing, ResponseProbe: f.External.ResponseProbe,
		StartLayer: f.Layer, StartLayerProvision: f.External.StartLayer}
}

func desktopOpenVPNCompileFixture(t *testing.T, request externalProfileCreateRequest) (common.RouterProfile, standardExit, *desktopNodeLaunch) {
	t.Helper()
	profile, err := externalProfileFromCreateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if profile.External.OpenVPN.Config != request.OpenVPN.Config || profile.External.OpenVPN.Username != request.OpenVPN.Username || profile.External.OpenVPN.Password != request.OpenVPN.Password {
		t.Fatal("native creation changed original OpenVPN text or literal credentials")
	}
	if profile.DNSMode != "home" || profile.DNSProtocol != "udp" || profile.DNSPort != 53 {
		t.Fatal("OpenVPN creation replaced the Home AdGuard default")
	}
	profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "tcp", "203.0.113.53", 5353
	profile.IPv6Mode, profile.MTUPolicy, profile.MultihopExecution = "off", "auto", "local"
	exit, err := standardExitFromExternalProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := compileDesktopExternalCaptured(context.Background(), profile, common.RouterProfile{}, exit, true, "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return profile, exit, launch
}

func TestTypedExternalOpenVPNPersistsOriginalAndRedactsPairing(t *testing.T) {
	for _, layer := range []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		t.Run(layer, func(t *testing.T) {
			request := desktopOpenVPNCreateFixture(t, layer)
			request.OpenVPN.Config = "\n# original native import\r\n" + request.OpenVPN.Config + "\r\n"
			private, err := json.Marshal(request.OpenVPNPairing)
			if err != nil {
				t.Fatal(err)
			}
			request.OpenVPNPairing, request.OpenVPNPairingJSON = nil, "\n"+string(private)+"\n"
			profile, _, launch := desktopOpenVPNCompileFixture(t, request)
			if !reflect.DeepEqual(launch.external.physicalEndpoints, []string{"203.0.113.20"}) {
				t.Fatal("same-host remote list changed physical ownership")
			}
			root := t.TempDir()
			a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}, profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion}, state: state{Mode: "off", Phase: "off"}}
			recorder := httptest.NewRecorder()
			a.externalProfileCreate(recorder, typedCreateRequest(t, request))
			if recorder.Code != http.StatusOK {
				t.Fatal("private OpenVPN creation failed", recorder.Code, recorder.Body.String())
			}
			encoded, err := os.ReadFile(a.cfg.ProfilesFile)
			if err != nil {
				t.Fatal(err)
			}
			var saved common.RouterProfileStore
			if err := json.Unmarshal(encoded, &saved); err != nil {
				t.Fatal(err)
			}
			if len(saved.Profiles) != 1 || !reflect.DeepEqual(saved.Profiles[0].External, profile.External) {
				t.Fatal("private persisted OpenVPN authority changed")
			}
			public := recorder.Body.String()
			if !strings.Contains(public, `"has_openvpn_pairing":true`) {
				t.Fatal("public OpenVPN readiness missing")
			}
			for _, secret := range []string{request.OpenVPN.Username, request.OpenVPN.Password, profile.External.OpenVPNPairing.PrivateKey, `"openvpn_pairing":`, `"provider_identity":`, `"transport":`, `"config":`} {
				if secret != "" && strings.Contains(public, secret) {
					t.Fatal("public profile exposed private OpenVPN material")
				}
			}
		})
	}
}

func TestTypedExternalOpenVPNKeepsLocalMultipleRemoteHosts(t *testing.T) {
	request := desktopOpenVPNCreateFixture(t, common.StartLayerOff)
	request.OpenVPNPairing, request.ResponseProbe = nil, nil
	request.OpenVPN.Config = strings.Replace(request.OpenVPN.Config, "remote 203.0.113.20 443 tcp", "remote 203.0.113.21 443 tcp", 1)
	profile, _, launch := desktopOpenVPNCompileFixture(t, request)
	if !reflect.DeepEqual(launch.external.physicalEndpoints, []string{"203.0.113.20", "203.0.113.21"}) {
		t.Fatal("Local failover lost a physical remote")
	}
	var graph map[string]any
	if json.Unmarshal(launch.config, &graph) != nil {
		t.Fatal("invalid graph")
	}
	endpoint := taggedRuntimeItem(graph["endpoints"].([]any), "custom-exit")
	if endpoint == nil || endpoint["system"] != false || len(endpoint["servers"].([]any)) != 2 || endpoint["server"] != nil {
		t.Fatal("Local failover was collapsed into a singleton or a separate TUN")
	}
	physical, err := desktopExternalPhysicalEndpoints(profile, common.RouterProfile{ID: "entry", Endpoint: "198.51.100.8"}, false, "198.51.100.8")
	if err != nil || !reflect.DeepEqual(physical, []string{"198.51.100.8"}) {
		t.Fatal("hopped exit opened physical provider exceptions", err)
	}
	for _, value := range desktopNativeEnvironment([]string{"HOMEVPN_NATIVE_ENDPOINTS_JSON=[\"8.8.8.8\"]"}, "/tmp/owned", "entry", "198.51.100.8") {
		if strings.HasPrefix(value, "HOMEVPN_NATIVE_ENDPOINTS_JSON=") {
			t.Fatal("inherited endpoint list crossed native staging")
		}
	}
}

func TestTypedExternalOpenVPNRejectsAmbiguousOrForeignMaterial(t *testing.T) {
	fixture := desktopOpenVPNCreateFixture(t, common.StartLayerOff)
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeExternalProfileCreate(raw); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"duplicate": []byte(`{"protocol":"openvpn",` + string(raw[1:])),
		"unknown":   []byte(`{"config_path":"/tmp/private.ovpn",` + string(raw[1:])),
		"null":      []byte(`{"protocol":"openvpn","openvpn":null}`),
		"null-pair": []byte(`{"protocol":"openvpn","openvpn_pairing":null}`),
		"trailing":  append(append([]byte{}, raw...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeExternalProfileCreate(data); err == nil {
				t.Fatal("ambiguous private request accepted")
			}
		})
	}
	for name, change := range map[string]func(*externalProfileCreateRequest){
		"missing-profile": func(q *externalProfileCreateRequest) { q.OpenVPN = nil },
		"other-protocol":  func(q *externalProfileCreateRequest) { q.Protocol = "socks5"; q.Server = "203.0.113.20"; q.Port = 1080 },
		"duplicate-pairing": func(q *externalProfileCreateRequest) {
			q.OpenVPNPairingJSON = `{"private_key":"a","private_key":"b","server":{}}`
			q.OpenVPNPairing = nil
		},
		"two-representations": func(q *externalProfileCreateRequest) { q.OpenVPNPairingJSON = string(raw) },
		"script":              func(q *externalProfileCreateRequest) { q.OpenVPN.Config += "\nscript-security 2\nup /tmp/injected\n" },
		"file-auth": func(q *externalProfileCreateRequest) {
			q.OpenVPN.Config = strings.ReplaceAll(q.OpenVPN.Config, "auth-user-pass", "auth-user-pass /tmp/credentials")
		},
		"foreign-transport": func(q *externalProfileCreateRequest) { q.OpenVPNPairing.Server.Transport["server"] = "203.0.113.99" },
	} {
		t.Run(name, func(t *testing.T) {
			request := desktopOpenVPNCreateFixture(t, common.StartLayerOff)
			change(&request)
			if _, err := externalProfileFromCreateRequest(request); err == nil {
				t.Fatal("unsafe OpenVPN request accepted")
			}
		})
	}
}

// Consume JSON emitted by actual native Save handlers, including their original
// pairing editor bytes. No parallel serialization in this test can hide a UI
// parser that trims credentials or silently drops private pairing members.
func TestDesktopExternalOpenVPNFormPayload(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("run deploy/test_desktop_amnezia_forms.py with the platform form")
	}
	for _, layer := range []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		t.Run(layer, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(directory, "openvpn-"+layer+".json"))
			if err != nil {
				t.Fatal(err)
			}
			request, err := decodeExternalProfileCreate(raw)
			if err != nil {
				t.Fatal(err)
			}
			expected := desktopOpenVPNCreateFixture(t, layer)
			if request.Protocol != "openvpn" || request.StartLayer != layer || request.OpenVPNPairingJSON == "" || !reflect.DeepEqual(request.OpenVPN, expected.OpenVPN) {
				t.Fatal("native form changed original OpenVPN profile, credentials, layer or raw pairing")
			}
			profile, _, launch := desktopOpenVPNCompileFixture(t, request)
			if !reflect.DeepEqual(profile.External.OpenVPNPairing, expected.OpenVPNPairing) {
				t.Fatal("native form changed paired provider authority")
			}
			if export := os.Getenv("ROUTERVPN_DESKTOP_OPENVPN_GRAPHS"); export != "" {
				if err := os.WriteFile(filepath.Join(export, "form-"+layer+".json"), launch.config, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	t.Run("unpaired-local-multiremote", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(directory, "openvpn-local-multiremote.json"))
		if err != nil {
			t.Fatal(err)
		}
		request, err := decodeExternalProfileCreate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if request.Protocol != "openvpn" || request.OpenVPNPairing != nil || request.OpenVPNPairingJSON != "" || request.ResponseProbe != nil || request.StartLayerProvision != nil {
			t.Fatal("Local import acquired unrelated paired credentials or a layer")
		}
		_, _, launch := desktopOpenVPNCompileFixture(t, request)
		if len(launch.external.physicalEndpoints) < 2 {
			t.Fatal("native Local form lost the original physical remote list")
		}
		if export := os.Getenv("ROUTERVPN_DESKTOP_OPENVPN_GRAPHS"); export != "" {
			if err := os.WriteFile(filepath.Join(export, "form-local-multiremote.json"), launch.config, 0600); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestDesktopOpenVPNRetainsPairedExecutionAndRestoredWinner(t *testing.T) {
	for _, base := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, execution := range []string{"local", "server", "auto"} {
			t.Run(base+"/"+execution, func(t *testing.T) {
				request := desktopOpenVPNCreateFixture(t, common.StartLayerOff)
				request.OpenVPN.Config = strings.ReplaceAll(request.OpenVPN.Config, "1194 udp", "1194 tcp")
				server := *request.OpenVPN
				server.Username, server.Password = "independent-server", "server-private-secret"
				descriptor, err := nativeopenvpn.DescribePeer(server, testWGKey('r'))
				if err != nil {
					t.Fatal(err)
				}
				request.OpenVPNPairing.Server = descriptor
				profile, exit, _ := desktopOpenVPNCompileFixture(t, request)
				profile.MultihopExecution, profile.MultihopEntryMode = execution, base
				entry, files := viaEntryBaseFixture(t, base)
				entry.MTUPolicy, entry.ManualMTU = "manual", 1500
				launch, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				if launch.external.selection != execution || launch.external.predecessor == "" {
					t.Fatal("OpenVPN lost captured entry or execution")
				}
				chosen := "local"
				if execution != "local" {
					chosen = "server"
				}
				restored, err := compileSpeedLabExternalRestore(&speedLabExternalRestore{source: launch.external.source, predecessor: launch.external.predecessor, profile: launch.external.profile, entry: launch.external.entry, execution: chosen, network: "captured-network"}, exit)
				if err != nil {
					t.Fatal(err)
				}
				if restored.external.selection != chosen || restored.external.predecessor != launch.external.predecessor || restored.external.session == launch.external.session {
					t.Fatal("OpenVPN restoration reran comparison or changed its owned path")
				}
				if export := os.Getenv("ROUTERVPN_DESKTOP_OPENVPN_GRAPHS"); export != "" {
					if err := os.WriteFile(filepath.Join(export, base+"-"+execution+".json"), launch.config, 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
