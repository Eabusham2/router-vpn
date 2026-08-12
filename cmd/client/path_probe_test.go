package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestSelectedProfilePathProofOverridesLegacyConfigAndRequiresRouterProof(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer good.Close()

	a := &app{cfg: common.ClientConfig{HealthURL: "http://127.0.0.1:1/not-used", AutoTestSeconds: 1}}
	if _, err := a.testHealth(common.RouterProfile{PathProbeURL: good.URL}); err != nil {
		t.Fatalf("selected profile path proof should override legacy config URL: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("generic internet success"))
	}))
	defer bad.Close()
	if _, err := a.testHealth(common.RouterProfile{PathProbeURL: bad.URL}); err == nil || !strings.Contains(err.Error(), "proof response") {
		t.Fatalf("generic 2xx must not count as Router VPN path proof, got %v", err)
	}
}

func TestDefaultProfilePathProofIsPrivateRouterAgent(t *testing.T) {
	p := common.RouterProfile{}
	applyProfileDefaults(&p)
	if p.PathProbeURL != "http://10.77.0.1:8787/health" {
		t.Fatalf("unexpected default path proof URL: %q", p.PathProbeURL)
	}
}
