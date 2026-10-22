package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func TestExternalRegistryOfflineLeaseMatchesPrivateRuntimeContract(t *testing.T) {
	exit := multihoprelay.Exit{ID: "external", Mode: "shadowsocks", Transport: map[string]any{"type": "shadowsocks", "tag": "exit", "server": "203.0.113.20", "server_port": 8388, "method": "aes-256-gcm", "password": "captured-private-secret"}, External: &multihoprelay.ExternalExit{ExpectedPublicIP: "203.0.113.88", ResponseProbe: multihoprelay.ResponseProbe{URL: "https://203.0.113.20/response", ServerName: "node.example"}}}
	lease, err := relayValidationLease(exit, "10.77.0.1", 26240, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if lease.EntryNodeID != strings.Repeat("a", 64) || lease.ExitNodeID != "" || multihoprelay.ValidateExternalRequest(exit, lease.Request) != nil {
		t.Fatal("offline check invented Router exit identity or omitted native authentication")
	}
	body, err := multihoprelay.Build(exit, netip.MustParseAddr("10.77.0.2"), lease)
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	if json.Unmarshal(body, &graph) != nil || graph["dns"] != nil {
		t.Fatal("offline plan overrode selected client DNS")
	}
	if _, err := relayValidationLease(exit, "10.77.0.1", 26240, ""); err == nil {
		t.Fatal("offline validation accepted missing entry identity")
	}
	lease.ExternalAuthentication = strings.Repeat("0", 64)
	if _, err := multihoprelay.Build(exit, netip.MustParseAddr("10.77.0.2"), lease); err == nil {
		t.Fatal("offline compiler accepted an unauthenticated private transport")
	}
}
