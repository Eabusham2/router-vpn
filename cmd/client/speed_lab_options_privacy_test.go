package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestSpeedLabOptionsHideTorBridgeRelay(t *testing.T) {
	a := &app{
		profiles: common.RouterProfileStore{
			SchemaVersion: common.RouterProfileSchemaVersion,
			SelectedID:    "tor-private",
			Profiles: []common.RouterProfile{{
				SchemaVersion: common.RouterProfileSchemaVersion,
				ID:            "tor-private",
				Name:          "Tor Snowflake",
				NodeKind:      "external",
				Endpoint:      "203.0.113.77:443",
				External: &common.ExternalNodeConfig{
					Protocol: "tor-bridge",
					TorBridge: &common.ExternalTorBridgeConfig{
						Transport: "snowflake",
						Bridges:   []string{"Bridge snowflake 203.0.113.77:443 fingerprint=ABC url=https://broker.example/ front=front.example"},
					},
				},
			}},
		},
		state: state{Mode: "off", Phase: "off"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/speed-lab/options", nil)
	a.speedLabOptions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Speed Lab options status=%d body=%q", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "203.0.113.77:443") || strings.Contains(body, "Bridge snowflake") {
		t.Fatalf("Speed Lab options leaked Tor relay metadata: %s", body)
	}
	if !strings.Contains(body, `"external_protocol":"tor-bridge"`) || !strings.Contains(body, `"id":"tor-private"`) {
		t.Fatalf("Speed Lab options lost safe Tor node identity: %s", body)
	}
}
