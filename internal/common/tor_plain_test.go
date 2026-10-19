package common

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPlainTorRoundTripKeepsDynamicExitAndNoBridge(t *testing.T) {
	var profile RouterProfile
	if err := json.Unmarshal([]byte(`{"id":"ordinary-tor","node_kind":"external","external":{"protocol":"tor","expected_public_ip":""}}`), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Endpoint != "tor" || profile.External.Protocol != "tor" || profile.External.TorBridge != nil || profile.External.ExpectedPublicIP != "" {
		t.Fatal("ordinary Tor became a bridge or fixed exit", profile.External)
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var restored RouterProfile
	if json.Unmarshal(data, &restored) != nil || restored.External.Protocol != "tor" {
		t.Fatal("plain Tor did not persist")
	}
	for _, external := range []string{
		`{"protocol":"tor","expected_public_ip":"203.0.113.1"}`,
		`{"protocol":"tor","socks5":{"host":"203.0.113.1","port":443}}`,
		`{"protocol":"tor","tor_bridge":{"bridges":[]}}`,
	} {
		if json.Unmarshal([]byte(`{"id":"bad","node_kind":"external","external":`+external+`}`), &restored) == nil {
			t.Fatal("plain Tor accepted a fixed exit or another protocol", external)
		}
	}
}

func TestLegacyTorAliasPreservesImportedBridges(t *testing.T) {
	data := `{"id":"bridge","node_kind":"external","external":{"protocol":"tor","tor_bridge":{"bridges":["obfs4 203.0.113.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0"]}}}`
	var profile RouterProfile
	if err := json.Unmarshal([]byte(data), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.External.Protocol != "tor-bridge" || !strings.Contains(profile.External.TorBridge.Bridges[0], "cert=Y2VydA") {
		t.Fatal("legacy Tor bridge alias lost captured credentials")
	}
}
