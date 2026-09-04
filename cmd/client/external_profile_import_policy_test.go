package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestExternalProfileImportPersistsRuntimeDNSPolicy(t *testing.T) {
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "routers.json")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion},
		state: state{Mode: "off", Phase: "off"},
	}
	// Home DNS belongs to Router VPN nodes only. External normalization strips
	// that inherited home policy, then externalRuntimePolicy must persist Rescue
	// DoH rather than waiting until Connect to substitute it transiently.
	payload := `{
	  "schema_version":4,
	  "id":"ext-socks",
	  "name":"External SOCKS",
	  "node_kind":"external",
	  "dns_mode":"home",
	  "dns_host":"10.77.0.1",
	  "external":{
	    "protocol":"socks5",
	    "expected_public_ip":"203.0.113.9",
	    "socks5":{"host":"203.0.113.8","port":1080}
	  }
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/external-profile/import", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	a.externalProfileImport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("external import status=%d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.profiles.Profiles) != 1 {
		t.Fatalf("saved external profiles=%d", len(a.profiles.Profiles))
	}
	p := a.profiles.Profiles[0]
	if p.DNSMode != "rescue" || p.DNSProtocol != "https" || p.DNSHost != "1.1.1.1" || p.DNSPort != 443 || p.DNSServerName != "cloudflare-dns.com" || p.DNSPath != "/dns-query" {
		t.Fatalf("external import persisted the wrong runtime DNS policy: %+v", p)
	}
	if p.RouterAPI != "" || p.AdGuardIPv4 != "" || p.AdGuardIPv6 != "" || p.SocksHost != "" || p.SocksUsername != "" || p.SocksPassword != "" {
		t.Fatalf("external import retained Router VPN home defaults: %+v", p)
	}
}
