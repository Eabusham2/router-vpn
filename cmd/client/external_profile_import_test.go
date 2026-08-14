package main

import (
	"encoding/json"
	"testing"

	"router-vpn/internal/common"
)

func TestDecodeExternalImportDirectAndEnvelope(t *testing.T) {
	direct := []byte(`{
	  "schema_version":3,"id":"ext-wg","name":"External WG","node_kind":"external",
	  "endpoint":"203.0.113.8",
	  "external":{"protocol":"wireguard","expected_public_ip":"203.0.113.9","wireguard":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","peer_public_key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","addresses":["10.10.0.2/32"],"endpoint":"203.0.113.8:51820","allowed_ips":["0.0.0.0/0"]}}
	}`)
	p, err := decodeExternalImport(direct)
	if err != nil { t.Fatalf("direct external profile rejected: %v", err) }
	if p.ID != "ext-wg" || p.NodeKind != "external" { t.Fatalf("wrong direct profile: %+v", p) }

	var raw map[string]any
	if err := json.Unmarshal(direct, &raw); err != nil { t.Fatal(err) }
	envelope, _ := json.Marshal(map[string]any{"routerProfiles": []any{raw}, "selectedRouterID": "ext-wg"})
	p, err = decodeExternalImport(envelope)
	if err != nil { t.Fatalf("external envelope rejected: %v", err) }
	if p.ID != "ext-wg" { t.Fatalf("wrong envelope profile: %s", p.ID) }
}

func TestExternalImportNormalizationRejectsRouterVPNAdminFields(t *testing.T) {
	p := common.RouterProfile{
		SchemaVersion: 3,
		ID: "ext-test",
		Name: "Bad external",
		NodeKind: "external",
		Endpoint: "203.0.113.8",
		APIToken: "must-not-be-accepted",
		External: &common.ExternalNodeConfig{
			Protocol: "socks5",
			ExpectedPublicIP: "203.0.113.9",
			SOCKS5: &common.ExternalSOCKS5Config{Host: "203.0.113.8", Port: 1080},
		},
	}
	if err := common.NormalizeRouterProfile(&p); err == nil {
		t.Fatal("external profile with Router VPN API token unexpectedly accepted")
	}
}

func TestDecodeExternalImportRequiresUnambiguousSelection(t *testing.T) {
	payload := []byte(`{"routerProfiles":[
	 {"schema_version":3,"id":"a","node_kind":"external","external":{"protocol":"socks5","expected_public_ip":"203.0.113.1","socks5":{"host":"203.0.113.2","port":1080}}},
	 {"schema_version":3,"id":"b","node_kind":"external","external":{"protocol":"socks5","expected_public_ip":"203.0.113.3","socks5":{"host":"203.0.113.4","port":1080}}}
	]}`)
	if _, err := decodeExternalImport(payload); err == nil {
		t.Fatal("ambiguous multi-external import unexpectedly accepted")
	}
}
