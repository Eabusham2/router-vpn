package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

const (
	testWGPrivateKey    = "ERERERERERERERERERERERERERERERERERERERERERE="
	testWGPresharedKey  = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
	testWGPeerPublicKey = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
)

func privateHTTPTestProfile() common.RouterProfile {
	return common.RouterProfile{
		SchemaVersion: common.RouterProfileSchemaVersion,
		ID:            "ext-private-test",
		Name:          "External WG Test",
		NodeKind:      "external",
		Endpoint:      "203.0.113.8",
		RouterAPI:     "http://10.77.0.1:8787",
		APIToken:      "ROUTER_ADMIN_SECRET_DO_NOT_LEAK",
		SocksHost:     "10.77.0.1",
		SocksPort:     1080,
		SocksUsername: "SOCKS_USER_SECRET",
		SocksPassword: "SOCKS_PASSWORD_SECRET",
		DAITAHost:     "10.77.0.1",
		DAITAPort:     45999,
		NodeProofID:   strings.Repeat("a", 64),
		External: &common.ExternalNodeConfig{
			Protocol:         "wireguard",
			ExpectedPublicIP: "203.0.113.9",
			WireGuard: &common.ExternalWireGuardConfig{
				PrivateKey:    testWGPrivateKey,
				PresharedKey:  testWGPresharedKey,
				PeerPublicKey: testWGPeerPublicKey,
				Endpoint:      "203.0.113.8:51820",
				Addresses:     []string{"10.20.0.2/32"},
				AllowedIPs:    []string{"0.0.0.0/0"},
			},
		},
	}
}

func assertNoPrivateProfileSecrets(t *testing.T, body string) {
	t.Helper()
	for _, secret := range []string{
		"ROUTER_ADMIN_SECRET_DO_NOT_LEAK",
		"SOCKS_USER_SECRET",
		"SOCKS_PASSWORD_SECRET",
		testWGPrivateKey,
		testWGPresharedKey,
		strings.Repeat("a", 64),
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("private profile secret leaked in HTTP response: %q\n%s", secret, body)
		}
	}
	for _, privateField := range []string{`"api_token"`, `"socks_username"`, `"socks_password"`, `"private_key"`, `"preshared_key"`, `"node_proof_id"`} {
		if strings.Contains(body, privateField) {
			t.Fatalf("private profile field leaked in HTTP response: %s\n%s", privateField, body)
		}
	}
	if !strings.Contains(body, "203.0.113.9") || !strings.Contains(body, "external") {
		t.Fatalf("secret-free public external-node metadata was lost: %s", body)
	}
}

func TestProfilesHTTPUsesSecretFreeProjection(t *testing.T) {
	p := privateHTTPTestProfile()
	a := &app{profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: p.ID, Profiles: []common.RouterProfile{p}}}
	rr := httptest.NewRecorder()
	a.listProfiles(rr, httptest.NewRequest("GET", "/api/profiles", nil))
	if rr.Code != 200 {
		t.Fatalf("/api/profiles status = %d: %s", rr.Code, rr.Body.String())
	}
	assertNoPrivateProfileSecrets(t, rr.Body.String())
}

func TestInfoHTTPUsesSecretFreeProjection(t *testing.T) {
	p := privateHTTPTestProfile()
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: "/private/routers.json", Listen: "127.0.0.1:8788", HealthURL: "http://10.77.0.1:8787/health", AutoTestSeconds: 8},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: p.ID, Profiles: []common.RouterProfile{p}},
	}
	rr := httptest.NewRecorder()
	a.info(rr, httptest.NewRequest("GET", "/api/info", nil))
	if rr.Code != 200 {
		t.Fatalf("/api/info status = %d: %s", rr.Code, rr.Body.String())
	}
	assertNoPrivateProfileSecrets(t, rr.Body.String())
}
