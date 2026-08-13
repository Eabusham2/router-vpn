package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-vpn/internal/common"
)

func TestSelectedProfilePathProofOverridesLegacyConfigAndRequiresExactNodeProof(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOMEVPN_ROOT", root)
	profile := common.RouterProfile{ID: "router-test"}
	expectedNodeID := writeTestWGIdentity(t, root, profile.ID)

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":%q}`, expectedNodeID, desktopNodeProofKind)
	}))
	defer good.Close()
	profile.PathProbeURL = good.URL

	a := &app{cfg: common.ClientConfig{HealthURL: "http://127.0.0.1:1/not-used", AutoTestSeconds: 1}}
	if _, err := a.testHealth(profile); err != nil {
		t.Fatalf("selected profile exact path proof should override legacy config URL: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer bad.Close()
	profile.PathProbeURL = bad.URL
	if _, err := a.testHealth(profile); err == nil {
		t.Fatal("generic ok=true must not count as exact Router VPN node path proof")
	}
}

func TestDefaultProfilePathProofIsPrivateRouterAgent(t *testing.T) {
	p := common.RouterProfile{}
	applyProfileDefaults(&p)
	if p.PathProbeURL != "http://10.77.0.1:8787/health" {
		t.Fatalf("unexpected default path proof URL: %q", p.PathProbeURL)
	}
}
