package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
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
)

const desktopFormServerPublic = "bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg="

func TestDesktopExternalPacketFormPayload(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("run deploy/test_desktop_amnezia_forms.py with the platform form")
	}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, layer := range []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				raw, err := os.ReadFile(filepath.Join(directory, protocol+"-"+layer+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var request externalProfileCreateRequest
				if err := decodeRelayControlJSON(raw, &request); err != nil {
					t.Fatal(err)
				}
				if request.Protocol != protocol || request.StartLayer != layer || request.ServerPeer == nil || request.ServerPeer.PublicKey != desktopFormServerPublic || request.ServerPeer.MTU != 1360 || request.ServerPeer.PersistentKeepalive != 25 || !reflect.DeepEqual(request.ServerPeer.Addresses, []string{"10.66.0.3/32", "fd66::3/128"}) {
					t.Fatal("native packet form changed its separate public server descriptor")
				}
				profile, err := externalProfileFromCreateRequest(request)
				if err != nil {
					t.Fatal(err)
				}
				if profile.DNSMode != "home" || !reflect.DeepEqual(profile.External.ServerPeer, request.ServerPeer) {
					t.Fatal("native packet creation lost the selected DNS default or public descriptor")
				}
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				if exit.WGPrivateKey != testWGKey('p') || exit.WGPeerPublicKey != testWGKey('q') || !reflect.DeepEqual(exit.WGAddresses, []string{"10.66.0.2/32", "fd66::2/128"}) || exit.WGKeepalive != 17 || exit.WGMTU != 1280 {
					t.Fatal("server descriptor replaced the selected Local packet credentials")
				}
				public := publicProfileFor(profile)
				if public.External == nil || !public.External.HasServerPeer || !public.External.HasResponseProbe {
					t.Fatal("public eligibility flags lost the linked descriptor or probe")
				}
				publicJSON, err := json.Marshal(public)
				if err != nil {
					t.Fatal(err)
				}
				for _, private := range []string{desktopFormServerPublic, "10.66.0.3", "fd66::3", testWGKey('p'), testWGKey('q'), "node-response"} {
					if strings.Contains(string(publicJSON), private) {
						t.Fatal("public node response exposed packet descriptor or private connection data")
					}
				}
				var publicObject map[string]any
				if json.Unmarshal(publicJSON, &publicObject) != nil {
					t.Fatal("public node is not JSON")
				}
				if _, exists := publicObject["external"].(map[string]any)["server_peer"]; exists {
					t.Fatal("public view exposed the server descriptor instead of readiness only")
				}
				// The API owns a detached descriptor; editing a request does not
				// mutate a captured node that may already be preparing a path.
				request.ServerPeer.Addresses[0] = "10.99.0.3/32"
				if profile.External.ServerPeer.Addresses[0] != "10.66.0.3/32" {
					t.Fatal("created packet descriptor aliases the editable request")
				}
				profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "tcp", "203.0.113.53", 5353
				profile.IPv6Mode, profile.MTUPolicy, profile.EffectiveMTU = "on", "auto", 9000
				entry := common.RouterProfile{ID: "form-entry", NodeKind: "router-vpn", Endpoint: "198.51.100.20", NodeProofID: strings.Repeat("c", 64), RouterAPI: "http://10.77.0.1:8787", APIToken: "form-entry-private-token", AdGuardIPv4: "10.77.0.1", AdGuardIPv6: "fd77:77::1", IPv6Mode: "on", MTUPolicy: "auto", HomeLANAccess: true}
				wg := nativeWG{PrivateKey: testWGKey('c'), PublicKey: testWGKey('d'), Host: entry.Endpoint, Addresses: []string{"10.77.0.2/32", "fd77:77::2/128"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, Port: 51820, MTU: 1500}
				for _, execution := range []string{"local", "server", "auto"} {
					profile.MultihopExecution = execution
					graph, err := buildNativeStandardExitConfig(profile, wg, exit)
					if err != nil {
						t.Fatal(err)
					}
					launch, err := compileDesktopExternalGraph(graph, profile, entry, exit, false, "")
					if err != nil {
						t.Fatal(execution, err)
					}
					var compiled map[string]any
					if json.Unmarshal(launch.config, &compiled) != nil {
						t.Fatal("compiled packet form is not JSON")
					}
					tag := "custom-exit"
					if execution != "local" {
						tag = mobilemultihop.LocalTag
					}
					local := taggedRuntimeItem(compiled["endpoints"].([]any), tag)
					if local == nil || local["private_key"] != testWGKey('p') || !reflect.DeepEqual(local["address"], []any{"10.66.0.2/32", "fd66::2/128"}) {
						t.Fatal("compiled packet form lost its Local endpoint identity")
					}
					if execution != "local" {
						selector := taggedRuntimeItem(compiled["outbounds"].([]any), "custom-exit")
						server := taggedRuntimeItem(compiled["outbounds"].([]any), mobilemultihop.ServerTag)
						if selector == nil || selector["type"] != "selector" || server == nil || server["type"] != "socks" || server["detour"] != "entry-wg" {
							t.Fatal("native packet form did not compile its isolated authenticated Server candidate")
						}
					}
					var capture map[string]any
					if json.Unmarshal(launch.external.capture, &capture) != nil {
						t.Fatal("captured packet plan is not JSON")
					}
					capturedPeer := capture["profile"].(map[string]any)["external"].(map[string]any)["server_peer"].(map[string]any)
					if capturedPeer["public_key"] != desktopFormServerPublic || len(capturedPeer) != 4 {
						t.Fatal("native plan lost its independent public peer or gained server secrets")
					}
				}
			})
		}
	}
}

func TestDesktopPacketCreateKeepsDescriptorPrivateAndRejectsBorrowedOrSecretPeer(t *testing.T) {
	request := desktopAWGRequest()
	request.ServerPeer = &common.ExternalServerPeer{PublicKey: desktopFormServerPublic, Addresses: []string{"10.66.0.3/32", "fd66::3/128"}, MTU: 1360, PersistentKeepalive: 25}
	request.WGAddresses = []string{"10.66.0.2/32", "fd66::2/128"}
	profile, err := externalProfileFromCreateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !publicProfileFor(profile).External.HasServerPeer {
		t.Fatal("valid packet descriptor is absent from public eligibility")
	}
	storePath := filepath.Join(t.TempDir(), "profiles.json")
	a := &app{cfg: common.ClientConfig{ProfilesFile: storePath}, profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion}, state: state{Mode: "off", Phase: "off"}}
	response := httptest.NewRecorder()
	a.externalProfileCreate(response, typedCreateRequest(t, request))
	if response.Code != http.StatusOK || len(a.profiles.Profiles) != 1 || a.profiles.SelectedID != a.profiles.Profiles[0].ID {
		t.Fatal("valid packet form was not atomically saved and selected", response.Code)
	}
	persisted, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	var saved common.RouterProfileStore
	if json.Unmarshal(persisted, &saved) != nil || len(saved.Profiles) != 1 || !reflect.DeepEqual(saved.Profiles[0].External.ServerPeer, request.ServerPeer) || saved.Profiles[0].External.AmneziaWG.PrivateKey != request.WGPrivateKey {
		t.Fatal("private packet store lost the independent public descriptor or replaced Local credentials")
	}
	if !strings.Contains(response.Body.String(), `"has_server_peer":true`) || strings.Contains(response.Body.String(), `"server_peer":`) || strings.Contains(response.Body.String(), request.WGPrivateKey) {
		t.Fatal("packet create response omitted eligibility or exposed private profile fields")
	}
	for _, mutate := range []func(*externalProfileCreateRequest){
		func(q *externalProfileCreateRequest) { q.ServerPeer.Addresses[0] = q.WGAddresses[0] },
		func(q *externalProfileCreateRequest) {
			raw, _ := base64.StdEncoding.DecodeString(q.WGPrivateKey)
			key, _ := ecdh.X25519().NewPrivateKey(raw)
			q.ServerPeer.PublicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
		},
		func(q *externalProfileCreateRequest) { q.ServerPeer.MTU = 1279 },
		func(q *externalProfileCreateRequest) {
			q.Protocol = "socks5"
			q.AWGParameters = nil
			q.Username, q.Password = "u", "p"
		},
	} {
		raw, _ := json.Marshal(request)
		var changed externalProfileCreateRequest
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture clone failed")
		}
		mutate(&changed)
		if _, err := externalProfileFromCreateRequest(changed); err == nil {
			t.Fatal("create accepted borrowed, invalid or wrong-protocol server peer")
		}
	}
	for _, forbidden := range []string{"private_key", "preshared_key", "pre_shared_key", "command"} {
		raw, _ := json.Marshal(request)
		var object map[string]any
		_ = json.Unmarshal(raw, &object)
		object["server_peer"].(map[string]any)[forbidden] = "never-import-server-secret"
		raw, _ = json.Marshal(object)
		a := &app{cfg: common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "profiles.json")}, state: state{Mode: "off", Phase: "off"}}
		result := httptest.NewRecorder()
		a.externalProfileCreate(result, httptest.NewRequest(http.MethodPost, "/api/external-profile/create", bytes.NewReader(raw)))
		if result.Code != http.StatusBadRequest || len(a.profiles.Profiles) != 0 {
			t.Fatal("typed create accepted private or executable server-peer material")
		}
	}
}
