package common

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func externalAmneziaProfile() RouterProfile {
	return RouterProfile{ID: "imported-awg", NodeKind: "external", External: &ExternalNodeConfig{
		Protocol: "amneziawg", ExpectedPublicIP: "203.0.113.42",
		AmneziaWG: &ExternalAmneziaWGConfig{ExternalWireGuardConfig: ExternalWireGuardConfig{
			PrivateKey: testWGKey, PeerPublicKey: testWGKey, PresharedKey: testWGKey,
			Addresses: []string{"10.81.0.2/32", "fd81::2/128"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			Endpoint: "[2001:db8::81]:51820", DNS: []string{"9.9.9.9"}, MTU: 1380, PersistentKeepalive: 25,
		}, Parameters: map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32",
			"h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}},
	}}
}

func TestExternalAmneziaProfileRoundTripAndDetachedCapture(t *testing.T) {
	p := externalAmneziaProfile()
	before := unnormalizedProfileJSON(t, p)
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got RouterProfile
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.External.Protocol != "amneziawg" || got.External.WireGuard != nil || !reflect.DeepEqual(got.External.AmneziaWG, p.External.AmneziaWG) || got.Endpoint != "2001:db8::81" {
		t.Fatal("imported AmneziaWG parameters, peer, keepalive or endpoint changed")
	}
	if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) {
		t.Fatal("encoding changed the live imported node")
	}
	clone := copyProfileForJSON(p)
	clone.External.AmneziaWG.Parameters["s4"] = "64"
	clone.External.AmneziaWG.Addresses[0] = "10.1.0.1/32"
	clone.External.AmneziaWG.AllowedIPs[0] = "10.0.0.0/8"
	clone.External.AmneziaWG.DNS[0] = "1.1.1.1"
	if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) {
		t.Fatal("saved graph shares its parameters or address slices with the live node")
	}
}

func TestExternalAmneziaProfileRejectsDiscardedOrInvalidParameters(t *testing.T) {
	mutations := map[string]func(*ExternalAmneziaWGConfig){
		"missing":            func(a *ExternalAmneziaWGConfig) { delete(a.Parameters, "s4") },
		"unknown":            func(a *ExternalAmneziaWGConfig) { a.Parameters["i1"] = "unowned" },
		"noise budget":       func(a *ExternalAmneziaWGConfig) { a.Parameters["jc"] = "129" },
		"overlap":            func(a *ExternalAmneziaWGConfig) { a.Parameters["h2"] = a.Parameters["h1"] },
		"ordinary WG header": func(a *ExternalAmneziaWGConfig) { a.Parameters["h1"] = "1" },
		"whitespace":         func(a *ExternalAmneziaWGConfig) { a.Parameters["s4"] = " 32" },
		"wrong key":          func(a *ExternalAmneziaWGConfig) { a.PrivateKey = "invalid" },
		"missing routes":     func(a *ExternalAmneziaWGConfig) { a.AllowedIPs = nil },
		"bad keepalive":      func(a *ExternalAmneziaWGConfig) { a.PersistentKeepalive = 65536 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p := externalAmneziaProfile()
			mutate(p.External.AmneziaWG)
			if _, err := json.Marshal(p); err == nil {
				t.Fatal("invalid imported AmneziaWG policy was serialized")
			}
		})
	}
	p := externalAmneziaProfile()
	p.External.WireGuard = &p.External.AmneziaWG.ExternalWireGuardConfig
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("second protocol block was accepted")
	}
	p = externalAmneziaProfile()
	p.External.Protocol = "wireguard"
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("AmneziaWG silently relabeled WireGuard")
	}
	encoded, _ := json.Marshal(externalAmneziaProfile())
	var got RouterProfile
	if err := json.Unmarshal([]byte(strings.Replace(string(encoded), `"s4":"32"`, `"s4":32`, 1)), &got); err == nil {
		t.Fatal("numeric parameter replaced its exact imported string")
	}
}
