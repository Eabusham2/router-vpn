package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

func desktopCapabilityFixture() multihoprelay.Capabilities {
	c := multihoprelay.Capabilities{NodeID: strings.Repeat("a", 64), Execution: "server", Exits: []multihoprelay.Capability{}}
	for i := 0; i < 64; i++ {
		c.Exits = append(c.Exits, multihoprelay.Capability{ID: strings.Repeat("x", 120) + fmt.Sprint(i), Mode: "awg2-pq", NodeID: strings.Repeat("b", 64), PublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("q", 32))), PQIdentity: strings.Repeat("c", 64), Layer: "aes-256-gcm"})
	}
	return c
}
func TestDesktopDiscoveryAcceptsFullCatalogAndPQPublicMetadata(t *testing.T) {
	c := desktopCapabilityFixture()
	raw, _ := json.Marshal(c)
	if len(raw) <= 8192 {
		t.Fatal("fixture below old bound")
	}
	var got multihoprelay.Capabilities
	if err := decodeRelayControlJSONBounded(raw, &got, multihoprelay.LeaseResponseLimit(http.MethodGet)); err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(c.NodeID); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got)
	if string(encoded) != string(raw) {
		t.Fatal("public PQ fields were lost")
	}
	if err := decodeRelayControlJSON(raw, &got); err == nil {
		t.Fatal("ordinary mutation response limit grew")
	}
}
func TestDesktopDiscoveryKeepsStrictJSONAndCatalogGuards(t *testing.T) {
	c := desktopCapabilityFixture()
	raw, _ := json.Marshal(c)
	for _, bad := range [][]byte{append([]byte(`{"node_id":"`+c.NodeID+`",`), raw[1:]...), append([]byte(`{"unknown":true,`), raw[1:]...), append(raw, []byte(`{}`)...), []byte("null"), append(raw, []byte(strings.Repeat(" ", multihoprelay.MaxCapabilitiesBytes))...)} {
		var value multihoprelay.Capabilities
		if decodeRelayControlJSONBounded(bad, &value, multihoprelay.MaxCapabilitiesBytes) == nil {
			t.Fatal("ambiguous or oversized discovery accepted")
		}
	}
	c.Exits = append(c.Exits, c.Exits[0])
	raw, _ = json.Marshal(c)
	var got multihoprelay.Capabilities
	if err := decodeRelayControlJSONBounded(raw, &got, multihoprelay.MaxCapabilitiesBytes); err != nil {
		t.Fatal(err)
	}
	if got.Validate(c.NodeID) == nil {
		t.Fatal("too many registry entries accepted")
	}
}
