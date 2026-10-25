package common

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/nativeopenvpn"
)

func externalOpenVPNMappedProfile(t *testing.T) RouterProfile {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/fixtures/external-openvpn-multihost-client.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		External ExternalNodeConfig `json:"external"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	p := externalOpenVPNPairedTestProfile(t, StartLayerOff)
	p.External = &fixture.External
	return p
}

func TestExternalOpenVPNResponseMapRoundtripAndCapturedCopy(t *testing.T) {
	p := externalOpenVPNMappedProfile(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var imported RouterProfile
	if err = json.Unmarshal(raw, &imported); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(imported.External.OpenVPNResponseProbes, p.External.OpenVPNResponseProbes) || !reflect.DeepEqual(imported.External.OpenVPNPairing, p.External.OpenVPNPairing) || *imported.External.OpenVPN != *p.External.OpenVPN {
		t.Fatal("private map, original remotes or independent pairing changed")
	}
	clone := CloneRouterProfile(p)
	p.External.OpenVPNResponseProbes["203.0.113.21"] = nativeopenvpn.ResponseEndpoint{URL: "https://203.0.113.22/foreign"}
	delete(p.External.OpenVPNResponseProbes, "203.0.113.20")
	if len(clone.External.OpenVPNResponseProbes) != 2 || clone.External.OpenVPNResponseProbes["203.0.113.21"].URL != "https://203.0.113.21/response" {
		t.Fatal("replacement profile mutated captured response map")
	}
	local := externalOpenVPNMappedProfile(t)
	local.External.OpenVPNPairing = nil
	if _, err = json.Marshal(local); err != nil {
		t.Fatal("Local multi-host map requires a server pairing", err)
	}
}

func TestExternalOpenVPNResponseMapRejectsAmbiguousPrivateImport(t *testing.T) {
	p := externalOpenVPNMappedProfile(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	good := string(raw)
	for name, bad := range map[string]string{
		"duplicate host": strings.Replace(good, `"openvpn_response_probes":{`, `"openvpn_response_probes":{"203.0.113.21":{"url":"https://203.0.113.21/foreign"},`, 1),
		"duplicate url":  strings.Replace(good, `"url":"https://203.0.113.21/response"`, `"url":"https://203.0.113.21/response","url":"https://203.0.113.21/changed"`, 1),
		"unknown field":  strings.Replace(good, `"url":"https://203.0.113.21/response"`, `"url":"https://203.0.113.21/response","insecure":true`, 1),
		"legacy null":    strings.Replace(good, `"external":{`, `"external":{"response_probe":null,`, 1),
		"layer null":     strings.Replace(good, `"external":{`, `"external":{"start_layer":null,`, 1),
		"null map":       strings.Replace(good, `"openvpn_response_probes":{`, `"openvpn_response_probes":null,"discarded":{`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == good {
				t.Fatal("negative mutation missed source")
			}
			var decoded RouterProfile
			if json.Unmarshal([]byte(bad), &decoded) == nil {
				t.Fatal("ambiguous map import accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*RouterProfile){
		"missing host": func(p *RouterProfile) { delete(p.External.OpenVPNResponseProbes, "203.0.113.21") },
		"foreign map": func(p *RouterProfile) {
			p.External.OpenVPNResponseProbes["203.0.113.22"] = nativeopenvpn.ResponseEndpoint{URL: "https://203.0.113.22/response"}
		},
		"first-host substitution": func(p *RouterProfile) {
			p.External.OpenVPNResponseProbes["203.0.113.21"] = nativeopenvpn.ResponseEndpoint{URL: "https://203.0.113.20/response"}
		},
		"changed original": func(p *RouterProfile) {
			p.External.OpenVPN.Config = strings.Replace(p.External.OpenVPN.Config, "203.0.113.21 443", "203.0.113.22 443", 1)
		},
		"mixed legacy": func(p *RouterProfile) {
			p.External.ResponseProbe = &ExternalResponseProbe{URL: "https://203.0.113.20/response"}
		},
		"selected layer": func(p *RouterProfile) { p.StartLayer = StartLayerAES256GCM },
	} {
		t.Run(name, func(t *testing.T) {
			p := externalOpenVPNMappedProfile(t)
			mutate(&p)
			if _, err := json.Marshal(p); err == nil {
				t.Fatal("unproved map policy serialized")
			}
		})
	}
}
