package main

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"router-vpn/internal/mobilemultihop"
)

// The native PowerShell, AppKit/Swift and GTK fixtures execute their shipping
// Save serialization and hand its actual JSON to this unchanged Go boundary.
func TestDesktopAmneziaFormPayload(t *testing.T) {
	directory := os.Getenv("ROUTERVPN_AWG_FORM_PAYLOADS")
	if directory == "" {
		t.Skip("run deploy/test_desktop_amnezia_forms.py with the platform form")
	}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		raw, err := os.ReadFile(filepath.Join(directory, protocol+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var request externalProfileCreateRequest
		if err := decodeRelayControlJSON(raw, &request); err != nil {
			t.Fatal(err)
		}
		if request.Protocol != protocol || request.WGKeepalive != 17 || request.WGMTU != 1280 || request.WGPrivateKey != testWGKey('p') || request.WGPeerPublicKey != testWGKey('q') {
			t.Fatal("native form changed the peer or protocol")
		}
		profile, err := externalProfileFromCreateRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		exit, err := standardExitFromExternalProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		if exit.Protocol != protocol || exit.WGKeepalive != 17 {
			t.Fatal("native form selection was lost in runtime translation")
		}
		if protocol == "wireguard" {
			if len(request.AWGParameters) != 0 || profile.External.AmneziaWG != nil || profile.External.WireGuard == nil {
				t.Fatal("ordinary WG form became AWG")
			}
			continue
		}
		if !reflect.DeepEqual(request.AWGParameters, desktopAWGRequest().AWGParameters) || !reflect.DeepEqual(exit.AWGParameters, request.AWGParameters) {
			t.Fatal("native form changed an exact provider parameter")
		}
		endpoint, err := desktopAmneziaEndpoint(exit, "")
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mobilemultihop.AmneziaRuntimeConfig(string(encoded)); err != nil {
			t.Fatal(err)
		}
		// Syntax-valid values still must pass actual native limits. UI input
		// parsing never replaces this authoritative controller validation.
		for _, change := range []func(map[string]string){
			func(p map[string]string) { p["jc"] = "129" },
			func(p map[string]string) { p["s4"] = "1281" },
			func(p map[string]string) { p["h1"] = "1" },
			func(p map[string]string) { p["h2"] = p["h1"] },
			func(p map[string]string) { p["h1"] = "19999999-10000000" },
		} {
			bad := request
			bad.AWGParameters = maps.Clone(request.AWGParameters)
			change(bad.AWGParameters)
			if _, err := externalProfileFromCreateRequest(bad); err == nil {
				t.Fatal("native form bypassed the actual AmneziaWG bounds")
			}
		}
	}
}
