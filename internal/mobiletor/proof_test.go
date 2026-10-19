package mobiletor

import (
	"context"
	"strings"
	"testing"
)

func TestDynamicTorProofRequiresBothTorAndPublicIP(t *testing.T) {
	for _, text := range []string{`{"IsTor":false,"IP":"8.8.8.8"}`, `{"IP":"8.8.8.8"}`, `{"IsTor":true,"IP":"127.0.0.1"}`, `{"IsTor":true,"IP":"fd00::1"}`, `{"IsTor":true,"IP":"224.0.0.1"}`, `{"IsTor":false,"IsTor":true,"IP":"8.8.8.8"}`, `{"IsTor":true,"IP":"8.8.8.8"} {}`, `{"IsTor":true,"IP":"8.8.8.8","admin":"secret"}`} {
		if _, err := parseProof([]byte(text)); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("ambiguous, non-Tor or non-public proof accepted")
		}
	}
	if ip, err := parseProof([]byte(`{"IsTor":true,"IP":"2001:4860:4860::8888"}`)); err != nil || ip != "2001:4860:4860::8888" {
		t.Fatal(ip, err)
	}
	if _, err := Prove(context.Background(), "session", nil); err == nil {
		t.Fatal("proof fell back to default network")
	}
}
