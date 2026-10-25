package main

import (
	"bytes"
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
	"router-vpn/internal/mobilemultihop"
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

func desktopOpenVPNMultiHostCreateFixture(t *testing.T) externalProfileCreateRequest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "fixtures", "external-openvpn-multihost-client.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		External common.ExternalNodeConfig `json:"external"`
		Layer    string                    `json:"selected_layer"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.External.OpenVPN == nil || fixture.External.OpenVPNPairing == nil || len(fixture.External.OpenVPNResponseProbes) < 2 {
		t.Fatal("multi-host private fixture missing")
	}
	return externalProfileCreateRequest{Name: "Captured provider fallback", Protocol: "openvpn", ExpectedPublicIP: fixture.External.ExpectedPublicIP,
		OpenVPN: fixture.External.OpenVPN, OpenVPNPairing: fixture.External.OpenVPNPairing, OpenVPNResponseProbes: fixture.External.OpenVPNResponseProbes, StartLayer: fixture.Layer}
}

func desktopOpenVPNMappedLayerCreateFixture(t *testing.T, layer string) externalProfileCreateRequest {
	t.Helper()
	suffix := "aes"
	if layer == common.StartLayerAES256GCMXOR {
		suffix = "xor"
	} else if layer != common.StartLayerAES256GCM {
		t.Fatal("mapped layer fixture requires AES or AES plus XOR")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "fixtures", "external-openvpn-multihost-layered-"+suffix+"-client.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		External common.ExternalNodeConfig `json:"external"`
		Layer    string                    `json:"selected_layer"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || fixture.Layer != layer || len(fixture.External.OpenVPNStartLayers) != 2 {
		t.Fatal("mapped private layer fixture is invalid", err)
	}
	return externalProfileCreateRequest{Name: "Captured layered fallback", Protocol: "openvpn", ExpectedPublicIP: fixture.External.ExpectedPublicIP,
		OpenVPN: fixture.External.OpenVPN, OpenVPNPairing: fixture.External.OpenVPNPairing,
		OpenVPNResponseProbes: fixture.External.OpenVPNResponseProbes, OpenVPNStartLayers: fixture.External.OpenVPNStartLayers, StartLayer: fixture.Layer}
}

func TestTypedExternalOpenVPNMappedLayersPersistPrivately(t *testing.T) {
	for _, layer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		for _, rawEditor := range []bool{false, true} {
			request := desktopOpenVPNMappedLayerCreateFixture(t, layer)
			expected, err := json.Marshal(request.OpenVPNStartLayers)
			if err != nil {
				t.Fatal(err)
			}
			if rawEditor {
				request.OpenVPNStartLayers = nil
				request.OpenVPNStartLayersJSON = "\n" + string(expected) + "\n"
			}
			profile, err := externalProfileFromCreateRequest(request)
			if err != nil || profile.StartLayer != layer {
				t.Fatal("mapped layer creation failed", err)
			}
			actual, _ := json.Marshal(profile.External.OpenVPNStartLayers)
			if !bytes.Equal(expected, actual) || profile.External.StartLayer != nil || profile.External.ResponseProbe != nil {
				t.Fatal("captured private map or selected layer changed")
			}
			clone := common.CloneRouterProfile(profile)
			profile.External.OpenVPNStartLayers["203.0.113.21"].Transport["password"] = testWGKey('k')
			cloned, _ := json.Marshal(clone.External.OpenVPNStartLayers)
			if !bytes.Equal(cloned, expected) {
				t.Fatal("captured layer credentials alias another mutable node")
			}
			root := t.TempDir()
			a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}, profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion}, state: state{Mode: "off", Phase: "off"}}
			// Re-read the independent fixture after the deliberate alias mutation.
			request = desktopOpenVPNMappedLayerCreateFixture(t, layer)
			if rawEditor {
				request.OpenVPNStartLayers = nil
				request.OpenVPNStartLayersJSON = "\n" + string(expected) + "\n"
			}
			recorder := httptest.NewRecorder()
			a.externalProfileCreate(recorder, typedCreateRequest(t, request))
			if recorder.Code != http.StatusOK {
				t.Fatal("private layered node creation failed", recorder.Code, recorder.Body.String())
			}
			encoded, err := os.ReadFile(a.cfg.ProfilesFile)
			var saved common.RouterProfileStore
			if err != nil || json.Unmarshal(encoded, &saved) != nil || len(saved.Profiles) != 1 {
				t.Fatal("private layer map was not persisted", err)
			}
			persisted, _ := json.Marshal(saved.Profiles[0].External.OpenVPNStartLayers)
			if !bytes.Equal(persisted, expected) || saved.Profiles[0].StartLayer != layer {
				t.Fatal("persisted private layers differ from the captured selection")
			}
			options := httptest.NewRecorder()
			a.speedLabOptions(options, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil))
			for _, public := range []string{recorder.Body.String(), options.Body.String()} {
				if strings.Contains(public, "openvpn_start_layers") || strings.Contains(public, "openvpn_response_probes") {
					t.Fatal("private fallback maps escaped public metadata")
				}
				for _, provision := range saved.Profiles[0].External.OpenVPNStartLayers {
					if strings.Contains(public, provision.API) || strings.Contains(public, provision.Transport["password"].(string)) {
						t.Fatal("private layer API or credential escaped public metadata")
					}
				}
			}
		}
	}
}

func TestTypedExternalOpenVPNMappedLayersRejectAmbiguousInputs(t *testing.T) {
	for name, change := range map[string]func(*externalProfileCreateRequest){
		"dual-representation": func(q *externalProfileCreateRequest) {
			raw, _ := json.Marshal(q.OpenVPNStartLayers)
			q.OpenVPNStartLayersJSON = string(raw)
		},
		"legacy-provision": func(q *externalProfileCreateRequest) {
			q.StartLayerProvision = desktopOpenVPNCreateFixture(t, common.StartLayerAES256GCM).StartLayerProvision
		},
		"legacy-probe": func(q *externalProfileCreateRequest) {
			q.ResponseProbe = &common.ExternalResponseProbe{URL: "https://203.0.113.20/response"}
		},
		"partial-map": func(q *externalProfileCreateRequest) { delete(q.OpenVPNStartLayers, "203.0.113.21") },
		"foreign-host": func(q *externalProfileCreateRequest) {
			q.OpenVPNStartLayers["203.0.113.99"] = q.OpenVPNStartLayers["203.0.113.21"]
			delete(q.OpenVPNStartLayers, "203.0.113.21")
		},
		"foreign-transport": func(q *externalProfileCreateRequest) {
			q.OpenVPNStartLayers["203.0.113.21"].Transport["server"] = "203.0.113.99"
		},
		"wrong-key": func(q *externalProfileCreateRequest) {
			q.OpenVPNStartLayers["203.0.113.21"].Transport["password"] = "not-a-key"
		},
		"public-api": func(q *externalProfileCreateRequest) {
			value := q.OpenVPNStartLayers["203.0.113.21"]
			value.API = "http://203.0.113.21:8787"
			q.OpenVPNStartLayers["203.0.113.21"] = value
		},
		"mixed-mode": func(q *externalProfileCreateRequest) {
			value := q.OpenVPNStartLayers["203.0.113.21"]
			value.Mode = common.StartLayerAES256GCMXOR
			q.OpenVPNStartLayers["203.0.113.21"] = value
		},
		"off-selection":       func(q *externalProfileCreateRequest) { q.StartLayer = common.StartLayerOff },
		"different-selection": func(q *externalProfileCreateRequest) { q.StartLayer = common.StartLayerAES256GCMXOR },
		"no-response-map":     func(q *externalProfileCreateRequest) { q.OpenVPNResponseProbes = nil },
		"foreign-protocol": func(q *externalProfileCreateRequest) {
			q.Protocol = "socks5"
			q.OpenVPN = nil
			q.OpenVPNPairing = nil
			q.OpenVPNResponseProbes = nil
			q.Server = "203.0.113.20"
			q.Port = 1080
		},
		"raw-null": func(q *externalProfileCreateRequest) { q.OpenVPNStartLayers = nil; q.OpenVPNStartLayersJSON = "null" },
		"raw-trailing": func(q *externalProfileCreateRequest) {
			raw, _ := json.Marshal(q.OpenVPNStartLayers)
			q.OpenVPNStartLayers = nil
			q.OpenVPNStartLayersJSON = string(raw) + "{}"
		},
		"raw-duplicate-host": func(q *externalProfileCreateRequest) {
			raw, _ := json.Marshal(q.OpenVPNStartLayers)
			value, _ := json.Marshal(q.OpenVPNStartLayers["203.0.113.20"])
			q.OpenVPNStartLayers = nil
			q.OpenVPNStartLayersJSON = `{"203.0.113.20":` + string(value) + `,` + string(raw[1:])
		},
		"raw-oversized": func(q *externalProfileCreateRequest) {
			raw, _ := json.Marshal(q.OpenVPNStartLayers)
			q.OpenVPNStartLayers = nil
			q.OpenVPNStartLayersJSON = strings.Repeat(" ", nativeopenvpn.MaxStartLayersBytes) + string(raw)
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := desktopOpenVPNMappedLayerCreateFixture(t, common.StartLayerAES256GCM)
			change(&request)
			if _, err := externalProfileFromCreateRequest(request); err == nil {
				t.Fatal("ambiguous, foreign or inconsistent layer map accepted")
			}
		})
	}
	for _, field := range []string{"openvpn_start_layers", "openvpn_start_layers_json"} {
		if _, err := decodeExternalProfileCreate([]byte(`{"protocol":"openvpn","` + field + `":null}`)); err == nil {
			t.Fatal("explicit null map accepted")
		}
	}
	request := desktopOpenVPNMappedLayerCreateFixture(t, common.StartLayerAES256GCM)
	raw, _ := json.Marshal(request)
	for _, field := range []string{"start_layer_provision", "response_probe"} {
		if _, err := decodeExternalProfileCreate([]byte(`{"` + field + `":null,` + string(raw[1:]))); err == nil {
			t.Fatal("null legacy provision was collapsed beside a mapped layer")
		}
	}
}

func TestTypedExternalOpenVPNMultiHostMapPersistsPrivately(t *testing.T) {
	for _, rawEditor := range []bool{false, true} {
		request := desktopOpenVPNMultiHostCreateFixture(t)
		expected, err := json.Marshal(request.OpenVPNResponseProbes)
		if err != nil {
			t.Fatal(err)
		}
		if rawEditor {
			request.OpenVPNResponseProbes = nil
			request.OpenVPNResponseProbesJSON = "\n" + string(expected) + "\n"
		}
		profile, _, launch := desktopOpenVPNCompileFixture(t, request)
		if len(launch.external.physicalEndpoints) < 2 {
			t.Fatal("provider fallback lost its physical remotes")
		}
		captured, err := json.Marshal(profile.External.OpenVPNResponseProbes)
		if err != nil || !bytes.Equal(captured, expected) {
			t.Fatal("private response map changed", err)
		}
		clone := common.CloneRouterProfile(profile)
		for host, probe := range profile.External.OpenVPNResponseProbes {
			probe.ServerName = "mutated.example.test"
			profile.External.OpenVPNResponseProbes[host] = probe
			break
		}
		cloned, _ := json.Marshal(clone.External.OpenVPNResponseProbes)
		if !bytes.Equal(cloned, expected) {
			t.Fatal("captured response map aliases mutable node data")
		}
		root := t.TempDir()
		a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")}, profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion}, state: state{Mode: "off", Phase: "off"}}
		recorder := httptest.NewRecorder()
		a.externalProfileCreate(recorder, typedCreateRequest(t, request))
		if recorder.Code != http.StatusOK {
			t.Fatal("mapped private creation failed", recorder.Code, recorder.Body.String())
		}
		encoded, err := os.ReadFile(a.cfg.ProfilesFile)
		if err != nil {
			t.Fatal(err)
		}
		var saved common.RouterProfileStore
		if json.Unmarshal(encoded, &saved) != nil || len(saved.Profiles) != 1 {
			t.Fatal("private provider map was not persisted")
		}
		persisted, _ := json.Marshal(saved.Profiles[0].External.OpenVPNResponseProbes)
		if !bytes.Equal(persisted, expected) {
			t.Fatal("persisted provider map changed")
		}
		options := httptest.NewRecorder()
		a.speedLabOptions(options, httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil))
		for _, public := range []string{recorder.Body.String(), options.Body.String()} {
			if !strings.Contains(public, `"has_response_probe":true`) {
				t.Fatal("valid mapped probe readiness missing")
			}
			if strings.Contains(public, `"openvpn_response_probes"`) {
				t.Fatal("private map escaped public metadata")
			}
			for _, probe := range saved.Profiles[0].External.OpenVPNResponseProbes {
				if strings.Contains(public, probe.URL) || probe.ServerName != "" && strings.Contains(public, probe.ServerName) {
					t.Fatal("private provider proof endpoint escaped public metadata")
				}
			}
		}
	}
}

func TestTypedExternalOpenVPNMapRejectsAmbiguousInputs(t *testing.T) {
	for name, change := range map[string]func(*externalProfileCreateRequest){
		"dual-map": func(q *externalProfileCreateRequest) {
			raw, _ := json.Marshal(q.OpenVPNResponseProbes)
			q.OpenVPNResponseProbesJSON = string(raw)
		},
		"single-and-map": func(q *externalProfileCreateRequest) {
			q.ResponseProbe = &common.ExternalResponseProbe{URL: "https://203.0.113.20/proof"}
		},
		"partial-map": func(q *externalProfileCreateRequest) {
			for host := range q.OpenVPNResponseProbes {
				delete(q.OpenVPNResponseProbes, host)
				break
			}
		},
		"wrong-host": func(q *externalProfileCreateRequest) {
			for host, probe := range q.OpenVPNResponseProbes {
				probe.URL = "https://203.0.113.99/proof"
				q.OpenVPNResponseProbes[host] = probe
				break
			}
		},
		"raw-duplicate": func(q *externalProfileCreateRequest) {
			raw, _ := json.Marshal(q.OpenVPNResponseProbes)
			q.OpenVPNResponseProbes = nil
			q.OpenVPNResponseProbesJSON = `{"203.0.113.20":{"url":"https://203.0.113.20/proof"},` + string(raw[1:])
		},
		"foreign-protocol": func(q *externalProfileCreateRequest) {
			q.Protocol = "socks5"
			q.OpenVPN = nil
			q.OpenVPNPairing = nil
			q.Server = "203.0.113.20"
			q.Port = 1080
		},
		"raw-null": func(q *externalProfileCreateRequest) {
			q.OpenVPNResponseProbes = nil
			q.OpenVPNResponseProbesJSON = "null"
		},
		"raw-trailing": func(q *externalProfileCreateRequest) {
			raw, _ := json.Marshal(q.OpenVPNResponseProbes)
			q.OpenVPNResponseProbes = nil
			q.OpenVPNResponseProbesJSON = string(raw) + "{}"
		},
	} {
		t.Run(name, func(t *testing.T) {
			q := desktopOpenVPNMultiHostCreateFixture(t)
			change(&q)
			if _, err := externalProfileFromCreateRequest(q); err == nil {
				t.Fatal("ambiguous or foreign proof map accepted")
			}
		})
	}
	for _, field := range []string{"openvpn_response_probes", "openvpn_response_probes_json"} {
		if _, err := decodeExternalProfileCreate([]byte(`{"protocol":"openvpn","` + field + `":null}`)); err == nil {
			t.Fatal("null private map accepted")
		}
	}
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
	for suffix, layer := range map[string]string{"aes": common.StartLayerAES256GCM, "xor": common.StartLayerAES256GCMXOR} {
		t.Run("mapped-layer-"+suffix, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(directory, "openvpn-multihost-"+suffix+".json"))
			if err != nil {
				t.Fatal(err)
			}
			request, err := decodeExternalProfileCreate(raw)
			if err != nil {
				t.Fatal(err)
			}
			expected := desktopOpenVPNMappedLayerCreateFixture(t, layer)
			if request.Protocol != "openvpn" || request.StartLayer != layer || request.OpenVPNStartLayersJSON == "" || request.OpenVPNPairingJSON == "" || request.OpenVPNResponseProbesJSON == "" || request.StartLayerProvision != nil || request.ResponseProbe != nil || !reflect.DeepEqual(request.OpenVPN, expected.OpenVPN) {
				t.Fatal("native form lost the exact mapped layer, original source or private owners")
			}
			profile, _, launch := desktopOpenVPNCompileFixture(t, request)
			if !reflect.DeepEqual(profile.External.OpenVPNStartLayers, expected.OpenVPNStartLayers) || !reflect.DeepEqual(profile.External.OpenVPNResponseProbes, expected.OpenVPNResponseProbes) || !reflect.DeepEqual(profile.External.OpenVPNPairing, expected.OpenVPNPairing) {
				t.Fatal("native form changed a host's captured provision, proof endpoint or pairing")
			}
			var graph map[string]any
			if json.Unmarshal(launch.config, &graph) != nil {
				t.Fatal("native layer graph is invalid")
			}
			endpoint := taggedRuntimeItem(graph["endpoints"].([]any), "custom-exit")
			if endpoint == nil || endpoint["type"] != "openvpn-client" || endpoint["detour"] != "routervpn-exit-start-layer-map" || len(endpoint["servers"].([]any)) != 2 {
				t.Fatal("per-host layer mapping lost original remote identity")
			}
			mapper := taggedRuntimeItem(graph["outbounds"].([]any), "routervpn-exit-start-layer-map")
			if mapper == nil || mapper["type"] != "routervpn-openvpn-layer-map" {
				t.Fatal("captured native per-host mapper is missing")
			}
			if export := os.Getenv("ROUTERVPN_DESKTOP_OPENVPN_GRAPHS"); export != "" {
				if err := os.WriteFile(filepath.Join(export, "form-multihost-"+suffix+".json"), launch.config, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	t.Run("mapped-layer-duplicate", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(directory, "openvpn-multihost-duplicate-layer.json"))
		if err != nil {
			t.Fatal(err)
		}
		request, err := decodeExternalProfileCreate(raw)
		if err != nil {
			t.Fatal("raw native layer editor must reach strict map decoder", err)
		}
		if _, err := externalProfileFromCreateRequest(request); err == nil {
			t.Fatal("native form normalized duplicate host layers instead of rejecting them")
		}
	})
	t.Run("paired-multihost", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join(directory, "openvpn-multihost.json"))
		if err != nil {
			t.Fatal(err)
		}
		request, err := decodeExternalProfileCreate(raw)
		if err != nil {
			t.Fatal(err)
		}
		expected := desktopOpenVPNMultiHostCreateFixture(t)
		if request.Protocol != "openvpn" || request.OpenVPNPairingJSON == "" || request.OpenVPNResponseProbesJSON == "" || request.ResponseProbe != nil || request.StartLayerProvision != nil || request.StartLayer != common.StartLayerOff || !reflect.DeepEqual(request.OpenVPN, expected.OpenVPN) {
			t.Fatal("native form changed multi-host provider authority")
		}
		profile, _, launch := desktopOpenVPNCompileFixture(t, request)
		if !reflect.DeepEqual(profile.External.OpenVPNResponseProbes, expected.OpenVPNResponseProbes) || !reflect.DeepEqual(profile.External.OpenVPNPairing, expected.OpenVPNPairing) || len(launch.external.physicalEndpoints) < 2 {
			t.Fatal("native form lost captured provider remotes, response map or pairing")
		}
		bad, err := os.ReadFile(filepath.Join(directory, "openvpn-multihost-duplicate.json"))
		if err != nil {
			t.Fatal(err)
		}
		rejected, err := decodeExternalProfileCreate(bad)
		if err != nil {
			t.Fatal("raw editor request should reach strict private map decoder", err)
		}
		if _, err = externalProfileFromCreateRequest(rejected); err == nil {
			t.Fatal("duplicate remote map was silently normalized by the native form")
		}
		if export := os.Getenv("ROUTERVPN_DESKTOP_OPENVPN_GRAPHS"); export != "" {
			if err := os.WriteFile(filepath.Join(export, "form-multihost.json"), launch.config, 0600); err != nil {
				t.Fatal(err)
			}
		}
	})
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

func TestDesktopOpenVPNMappedLayersRestoreCapturedPathAndWinner(t *testing.T) {
	launches, restorations := 0, 0
	for _, base := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, entryLayer := range []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			for _, exitLayer := range []string{common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
				for _, execution := range []string{"local", "server", "auto"} {
					name := strings.Join([]string{base, entryLayer, exitLayer, execution}, "-")
					t.Run(name, func(t *testing.T) {
						request := desktopOpenVPNMappedLayerCreateFixture(t, exitLayer)
						profile, exit, _ := desktopOpenVPNCompileFixture(t, request)
						profile.MultihopEntryMode, profile.MultihopExecution = base, execution
						entry, files := viaEntryBaseFixture(t, base)
						entry.StartLayer, entry.MTUPolicy, entry.ManualMTU = entryLayer, "manual", 1500
						entry.SocksHost, entry.SocksPort, entry.SocksUsername, entry.SocksPassword = "10.77.0.1", 1080, "captured-entry", "captured-entry-secret"
						var start map[string][]byte
						if entryLayer != common.StartLayerOff {
							raw, err := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"type": "shadowsocks", "tag": "proxy", "server": entry.Endpoint, "server_port": 8388, "method": mobilemultihop.NativeStartLayerMethod, "password": testWGKey('s')}}})
							if err != nil {
								t.Fatal(err)
							}
							start = map[string][]byte{"sing-box.json": raw}
						}
						original, err := compileDesktopExternalCaptured(context.Background(), profile, entry, exit, false, "", files, start, nil)
						if err != nil {
							t.Fatal(err)
						}
						launches++
						privateBefore, _ := json.Marshal(original.external.profile.External)
						profile.External.OpenVPNStartLayers["203.0.113.21"].Transport["password"] = testWGKey('z')
						profile.DNSHost, profile.MTUPolicy, profile.ManualMTU = "203.0.113.99", "manual", 1281
						entry.StartLayer, entry.Endpoint = common.StartLayerOff, "198.51.100.99"
						privateAfter, _ := json.Marshal(original.external.profile.External)
						if !bytes.Equal(privateBefore, privateAfter) || original.external.entry.StartLayer != entryLayer || original.external.profile.DNSHost != "203.0.113.53" || original.external.profile.MTUPolicy != "auto" {
							t.Fatal("mutable selection replaced captured provider keys, entry, DNS or MTU")
						}
						var oldCapture map[string]any
						if json.Unmarshal(original.external.capture, &oldCapture) != nil {
							t.Fatal("invalid captured OpenVPN execution")
						}
						chosen := []string{execution}
						if execution == "auto" {
							chosen = []string{"local", "server"}
						}
						for _, winner := range chosen {
							saved := &speedLabExternalRestore{source: append([]byte(nil), original.external.source...), predecessor: original.external.predecessor, profile: cloneRouterProfile(original.external.profile), entry: cloneRouterProfile(original.external.entry), execution: winner, network: "captured-network", mtu: 1340}
							restored, err := compileSpeedLabExternalRestore(saved, exit)
							if err != nil {
								t.Fatal(err)
							}
							restorations++
							if restored.external.selection != winner || restored.external.profile.MultihopExecution != execution || restored.external.predecessor != original.external.predecessor || restored.external.session == original.external.session || restored.external.network != saved.network || restored.external.mtu == nil || restored.external.mtu.restoreMTU != 1340 || !bytes.Equal(restored.external.source, original.external.source) {
								t.Fatal("restoration changed its captured path, measurement ownership or proved winner")
							}
							var freshCapture map[string]any
							if json.Unmarshal(restored.external.capture, &freshCapture) != nil || !reflect.DeepEqual(oldCapture["profile"], freshCapture["profile"]) || !reflect.DeepEqual(oldCapture["entry"], freshCapture["entry"]) {
								t.Fatal("restoration changed provider map, original remotes, policy or entry credentials")
							}
							if execution != "local" {
								oldExecution, freshExecution := oldCapture["execution"].(map[string]any), freshCapture["execution"].(map[string]any)
								if freshExecution["selection"] != winner {
									t.Fatal("restoration reran Compare")
								}
								oldRequest, freshRequest := oldExecution["request"].(map[string]any), freshExecution["request"].(map[string]any)
								for _, key := range []string{"session_id", "listener_username", "listener_password"} {
									if oldRequest[key] == freshRequest[key] {
										t.Fatal("restoration reused a retired relay lease", key)
									}
								}
								fingerprint, ok := oldRequest["external_fingerprint"].(string)
								if !ok || len(fingerprint) != 64 || freshRequest["external_fingerprint"] != fingerprint || oldRequest["exit_start_layer"] != exitLayer || freshRequest["exit_start_layer"] != exitLayer {
									t.Fatal("restoration replaced the authenticated provider identity")
								}
							}
							if directory := os.Getenv("ROUTERVPN_DESKTOP_OPENVPN_GRAPHS"); directory != "" {
								if err := os.WriteFile(filepath.Join(directory, "mapped-"+name+"-restore-"+winner+".json"), restored.config, 0600); err != nil {
									t.Fatal(err)
								}
							}
						}
						if directory := os.Getenv("ROUTERVPN_DESKTOP_OPENVPN_GRAPHS"); directory != "" {
							if err := os.WriteFile(filepath.Join(directory, "mapped-"+name+".json"), original.config, 0600); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
	if launches != 54 || restorations != 72 {
		t.Fatal("mapped OpenVPN restoration matrix did not execute", launches, restorations)
	}
}
