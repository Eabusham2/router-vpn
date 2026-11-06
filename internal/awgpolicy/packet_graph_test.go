package awgpolicy

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEndpointEnvelopeRetainsPublicCarrierAndPrivateDestination(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	for _, row := range []struct {
		inner, outer      string
		overhead, control int
	}{
		{"10.1.0.1", "192.0.2.1", 118, 234},
		{"fd01::1", "192.0.2.1", 130, 246},
		{"10.1.0.1", "2001:db8::1", 138, 254},
		{"fd01::1", "2001:db8::1", 150, 266},
	} {
		endpoint := map[string]any{"type": "wireguard", "detour": "layer", "peers": []any{map[string]any{"address": row.inner}}}
		layer := map[string]any{"tag": "layer", "type": "shadowsocks", "method": "2022-blake3-aes-256-gcm", "password": key, "server": row.outer}
		e, err := EndpointEnvelope(endpoint, layer)
		if err != nil || e.DataOverhead != row.overhead || e.ControlMax != row.control {
			t.Fatal("wrong exact carrier envelope", row, e, err)
		}
		layer["password"] = key + ":" + key + ":" + key
		multi, err := EndpointEnvelope(endpoint, layer)
		if err != nil || multi.DataOverhead != e.DataOverhead+24 {
			t.Fatal("identity header request bound lost", multi, err)
		}
		for _, mutate := range []func(){func() { layer["password"] = "not-a-key" }, func() { layer["password"] = key; layer["method"] = "none" }, func() { layer["method"] = "2022-blake3-aes-256-gcm"; layer["tag"] = "foreign" }, func() { layer["tag"] = "layer"; layer["server"] = "example.invalid" }} {
			mutate()
			if _, err := EndpointEnvelope(endpoint, layer); err == nil {
				t.Fatal("unowned or malformed layer admitted")
			}
		}
	}
}
