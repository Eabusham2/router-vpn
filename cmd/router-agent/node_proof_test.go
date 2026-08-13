package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidNodeIDRequiresLowercaseSHA256Hex(t *testing.T) {
	valid := strings.Repeat("a", 64)
	if !validNodeID(valid) {
		t.Fatal("valid lowercase SHA-256 node id was rejected")
	}
	for _, bad := range []string{
		"",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("A", 64),
		strings.Repeat("g", 64),
		"../" + strings.Repeat("a", 61),
	} {
		if validNodeID(bad) {
			t.Fatalf("invalid node id accepted: %q", bad)
		}
	}
}

func TestPrivateHealthReturnsExactNodeIdentity(t *testing.T) {
	nodeID := strings.Repeat("b", 64)
	s := &server{cfg: cfg{NodeID: nodeID}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://router/health", nil)
	s.health(rr, req)
	if rr.Code != 200 {
		t.Fatalf("health status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Fatalf("health ok=%v", body["ok"])
	}
	if body["node_id"] != nodeID {
		t.Fatalf("health node_id=%v want %s", body["node_id"], nodeID)
	}
	if body["proof"] != "router-vpn-private-agent-v1" {
		t.Fatalf("health proof=%v", body["proof"])
	}
}
