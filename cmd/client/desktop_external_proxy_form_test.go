package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/multihoprelay"
)

// Consume the payloads produced by the actual GTK, PowerShell and Swift Save
// handlers. This crosses the UI/controller boundary instead of recreating its
// serialization in Go, including literal credentials and private outer layers.
func TestDesktopExternalProxyFormPayload(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_EXTERNAL_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("run deploy/test_desktop_amnezia_forms.py with the platform form")
	}
	for _, protocol := range []string{"shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"} {
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
				if request.Protocol != protocol || request.StartLayer != layer || request.ResponseProbe == nil || request.ResponseProbe.URL != "https://203.0.113.60:8443/node-response" || request.ResponseProbe.ServerName != "external.example" {
					t.Fatal("native form changed its protocol, layer or same-server response endpoint")
				}
				profile, err := externalProfileFromCreateRequest(request)
				if err != nil {
					t.Fatal(err)
				}
				if profile.DNSMode != "home" || profile.DNSProtocol != "udp" || profile.DNSPort != 53 {
					t.Fatal("native creation replaced the Home AdGuard default")
				}
				exit, err := standardExitFromExternalProfile(profile)
				if err != nil {
					t.Fatal(err)
				}
				if exit.Protocol != protocol || exit.ResponseProbe == nil || *exit.ResponseProbe != *request.ResponseProbe || exit.Server != "203.0.113.60" || exit.ExpectedPublicIP != "203.0.113.60" {
					t.Fatal("native request lost its captured server, public identity or response probe")
				}
				if protocol == "socks5" || protocol == "http-connect" || protocol == "https-connect" {
					if exit.Username != " user literal " || exit.Password != " password literal " {
						t.Fatal("native creation changed literal proxy credential whitespace")
					}
				} else if exit.Secret != " private proxy secret " {
					t.Fatal("native creation changed the literal transport secret")
				}
				encoded, err := json.Marshal(profile.External)
				if err != nil {
					t.Fatal(err)
				}
				var external map[string]any
				if err := json.Unmarshal(encoded, &external); err != nil {
					t.Fatal(err)
				}
				var provision *multihoprelay.StartLayer
				if profile.External.StartLayer != nil {
					provision = &multihoprelay.StartLayer{Mode: profile.External.StartLayer.Mode, API: profile.External.StartLayer.API, Transport: profile.External.StartLayer.Transport}
				}
				paired, err := multihoprelay.ExternalSelection(profile.ID, protocol, external, provision)
				if err != nil || paired.External == nil || paired.External.ResponseProbe.URL != request.ResponseProbe.URL {
					t.Fatal("saved native form cannot enter the authenticated shared execution path", err)
				}
				// Direct has no home route. Explicitly selecting this fixture DNS
				// exercises the shipping graph compiler without inventing fallback.
				profile.DNSMode, profile.DNSProtocol, profile.DNSHost, profile.DNSPort = "custom", "tcp", "203.0.113.53", 5353
				profile.IPv6Mode, profile.MTUPolicy, profile.EffectiveMTU = "off", "auto", 9000
				profile.MultihopExecution = "local"
				graph, err := buildDirectStandardExitConfig(profile, exit)
				if err != nil {
					t.Fatal(err)
				}
				launch, err := compileDesktopExternalGraph(graph, profile, common.RouterProfile{}, exit, true, "")
				if err != nil {
					t.Fatal(err)
				}
				var compiled map[string]any
				if err := json.Unmarshal(launch.config, &compiled); err != nil {
					t.Fatal(err)
				}
				items := compiled["outbounds"].([]any)
				inner := taggedRuntimeItem(items, "custom-exit")
				outer := taggedRuntimeItem(items, multihoprelay.ExitStartLayerTag)
				if inner == nil {
					t.Fatal("native form lost its final transport")
				}
				if layer == common.StartLayerOff {
					if outer != nil || inner["server"] != "203.0.113.60" || exit.StartLayer != nil {
						t.Fatal("Off retained a private provision or changed the selected host")
					}
				} else {
					wantType := "shadowsocks"
					if layer == common.StartLayerAES256GCMXOR {
						wantType = "routervpn-aes-xor"
					}
					if outer == nil || outer["type"] != wantType || outer["server"] != "203.0.113.60" || outer["password"] != testWGKey(7) || inner["server"] != "10.77.0.1" || inner["detour"] != multihoprelay.ExitStartLayerTag {
						t.Fatal("native form encryption does not match the actual private native graph")
					}
				}
				dns := compiled["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
				if dns["type"] != "tcp" || dns["server"] != "203.0.113.53" || dns["server_port"] != float64(5353) || dns["detour"] != "custom-exit" {
					t.Fatal("native form graph changed the captured selected DNS")
				}
				if compiled["inbounds"].([]any)[0].(map[string]any)["mtu"] != float64(1280) {
					t.Fatal("native creation promoted cached MTU into a current-path result")
				}
				public, err := json.Marshal(publicProfileFor(profile))
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{" user literal ", " password literal ", " private proxy secret ", testWGKey(7), "10.77.0.1:8787", "node-response", "start_layer_provision"} {
					if strings.Contains(string(public), secret) || strings.Contains(string(launch.metadata), secret) {
						t.Fatal("public node or native proof metadata exposed private form material")
					}
				}
				// The backend must reject a misbound endpoint even when a native
				// client submits syntactically valid JSON directly.
				bad := request
				bad.ResponseProbe = &common.ExternalResponseProbe{URL: "https://203.0.113.61:8443/node-response", ServerName: "external.example"}
				if _, err := externalProfileFromCreateRequest(bad); err == nil {
					t.Fatal("native form bypassed the exact-server response endpoint binding")
				}
			})
		}
	}
}
