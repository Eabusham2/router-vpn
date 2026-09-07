package common

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
)

func unnormalizedProfileJSON(t *testing.T, p RouterProfile) []byte {
	t.Helper()
	body, err := json.Marshal(routerProfileWire(p))
	if err != nil { t.Fatal(err) }
	return body
}

func TestProfileMarshalNeverMutatesExternalPolicy(t *testing.T) {
	cases := []ExternalNodeConfig{
		{Protocol: " WireGuard ", ExpectedPublicIP: " 203.0.113.12 ", WireGuard: &ExternalWireGuardConfig{PrivateKey: testWGKey, PeerPublicKey: testWGKey, Endpoint: " vpn.example.test:51820 ", Addresses: []string{" 10.77.0.2/32 "}, AllowedIPs: []string{" 0.0.0.0/0 "}, DNS: []string{" 1.1.1.1 "}}},
		{Protocol: " SOCKS5 ", ExpectedPublicIP: " 203.0.113.12 ", SOCKS5: &ExternalSOCKS5Config{Host: " vpn.example.test ", Port: 1080}},
		{Protocol: " HTTP ", ExpectedPublicIP: " 203.0.113.12 ", HTTPConnect: &ExternalHTTPConnectConfig{Host: " vpn.example.test ", Port: 8080}},
		{Protocol: " HTTPS ", ExpectedPublicIP: " 203.0.113.12 ", HTTPSConnect: &ExternalHTTPConnectConfig{Host: " vpn.example.test ", Port: 443, TLSServerName: " vpn.example.test "}},
		{Protocol: " Shadowsocks ", ExpectedPublicIP: " 203.0.113.12 ", Shadowsocks: &ExternalShadowsocksConfig{Server: " vpn.example.test ", Port: 8388, Method: " aes-256-gcm ", Password: "test-password"}},
		{Protocol: " Hysteria2 ", ExpectedPublicIP: " 203.0.113.12 ", Hysteria2: &ExternalHysteria2Config{Server: " vpn.example.test ", Port: 443, TLSServerName: " vpn.example.test ", Password: "test-password"}},
		{Protocol: " OpenVPN ", ExpectedPublicIP: " 203.0.113.12 ", OpenVPN: &ExternalOpenVPNConfig{Config: "client\nremote vpn.example.test 1194 tcp\n"}},
		{Protocol: " Tor ", TorBridge: &ExternalTorBridgeConfig{Bridges: []string{validObfs4Bridge}}},
	}
	for _, ext := range cases {
		t.Run(ext.Protocol, func(t *testing.T) {
			p := RouterProfile{ID: "exit", NodeKind: "external", External: &ext}
			before := unnormalizedProfileJSON(t, p)
			body, err := json.Marshal(p)
			if err != nil { t.Fatal(err) }
			if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) {
				t.Fatal("serializing a profile mutated its live external policy")
			}
			var decoded RouterProfile
			if err := json.Unmarshal(body, &decoded); err != nil { t.Fatal(err) }
			if decoded.IPv6Mode != "on" || decoded.StartupMode != "smart-auto" || decoded.External == nil {
				t.Fatal("nonmutating output lost normalization or external settings")
			}
		})
	}
}

func TestProfileStoreMarshalDoesNotPartiallyNormalizeLiveProfiles(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false:"success", true:"failure"}[invalid], func(t *testing.T) {
			p := RouterProfile{ID:"home", NodeKind:" Router-VPN ", KillSwitchPolicy:" OFF "}
			store := RouterProfileStore{Profiles: []RouterProfile{p}}
			if invalid { store.Profiles = append(store.Profiles, p) }
			body, err := json.Marshal(store)
			if (err != nil) != invalid { t.Fatalf("unexpected serialization error: %v", err) }
			for _, current := range store.Profiles {
				if !reflect.DeepEqual(current, p) { t.Fatal("JSON output partially changed live profile defaults") }
			}
			if !invalid {
				var decoded RouterProfileStore
				if err := json.Unmarshal(body, &decoded); err != nil { t.Fatal(err) }
				if decoded.SelectedID != "home" || decoded.Profiles[0].KillSwitchPolicy != "off" { t.Fatal("normalized store output regressed") }
			}
		})
	}
	p := RouterProfile{ID:"bad", NodeKind:"external", External:&ExternalNodeConfig{Protocol:" SOCKS5 ", ExpectedPublicIP:"203.0.113.12", SOCKS5:&ExternalSOCKS5Config{Host:" proxy.example.test ", Port:1080, Username:"incomplete"}}}
	before := unnormalizedProfileJSON(t, p)
	if _, err := json.Marshal(p); err == nil { t.Fatal("invalid credentials accepted") }
	if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) { t.Fatal("failed encoding mutated external credentials") }
}

func TestProfileJSONCopiesEveryReferenceField(t *testing.T) {
	p := RouterProfile{External: &ExternalNodeConfig{WireGuard:&ExternalWireGuardConfig{Addresses:[]string{"address"}, AllowedIPs:[]string{"route"}, DNS:[]string{"dns"}}, OpenVPN:&ExternalOpenVPNConfig{}, Shadowsocks:&ExternalShadowsocksConfig{}, SOCKS5:&ExternalSOCKS5Config{}, HTTPConnect:&ExternalHTTPConnectConfig{}, HTTPSConnect:&ExternalHTTPConnectConfig{}, Hysteria2:&ExternalHysteria2Config{}, TorBridge:&ExternalTorBridgeConfig{Bridges:[]string{"bridge"}}}, CustomLayers:[]string{"layer"}, HomeLANCIDRs:[]string{"cidr"}, DNSResults:[]DNSBenchmarkResult{{Name:"measured"}}}
	cloned := copyProfileForJSON(p)
	var check func(reflect.Value, reflect.Value)
	check = func(a, b reflect.Value) {
		switch a.Kind() {
		case reflect.Struct:
			for i:=0; i<a.NumField(); i++ { check(a.Field(i), b.Field(i)) }
		case reflect.Pointer:
			if !a.IsNil() { if a.Pointer()==b.Pointer() { t.Fatal("JSON copy shares a nested pointer") }; check(a.Elem(), b.Elem()) }
		case reflect.Slice:
			if a.Len()>0 && a.Pointer()==b.Pointer() { t.Fatal("JSON copy shares a slice backing array") }
		}
	}
	if !reflect.DeepEqual(p, cloned) { t.Fatal("detaching references changed values") }
	check(reflect.ValueOf(p), reflect.ValueOf(cloned))
}

func TestProfileMarshalConcurrentReadersAreSideEffectFree(t *testing.T) {
	p := torProfile(" Tor ", validObfs4Bridge)
	before := unnormalizedProfileJSON(t, p)
	store := RouterProfileStore{SelectedID: p.ID, Profiles: []RouterProfile{p}}
	var workers sync.WaitGroup
	for i:=0; i<4; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); for n:=0; n<10; n++ {
			if _, err:=json.Marshal(p); err!=nil { t.Error(err) }
			if _, err:=json.Marshal(store); err!=nil { t.Error(err) }
		} }()
	}
	workers.Wait()
	if !bytes.Equal(before, unnormalizedProfileJSON(t, p)) { t.Fatal("concurrent encoders changed the source profile") }
}
