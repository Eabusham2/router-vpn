package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestExternalProfileImportPersistsRuntimeDNSPolicy(t *testing.T) {
	for _, selection := range []string{"absent", "home"} {
		t.Run(selection, func(t *testing.T) { testExternalProfileImportDNSPolicy(t, selection) })
	}
}

func testExternalProfileImportDNSPolicy(t *testing.T, selection string) {
	a := &app{
		cfg:      common.ClientConfig{ProfilesFile: filepath.Join(t.TempDir(), "routers.json")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileSchemaVersion},
		state:    state{Mode: "off", Phase: "off"},
	}
	// A modern explicit Home choice survives import. A direct connection must
	// reject it without an owned Router VPN entry instead of changing the user's
	// selection. An absent policy retains the documented Rescue migration.
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
	if selection == "absent" {
		payload = strings.ReplaceAll(payload, `"dns_mode":"home",`, "")
		payload = strings.ReplaceAll(payload, `"dns_host":"10.77.0.1",`, "")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/external-profile/import", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	a.externalProfileImport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("external import status=%d body=%q", rr.Code, rr.Body.String())
	}
	a.mu.Lock()
	profiles := append([]common.RouterProfile(nil), a.profiles.Profiles...)
	a.mu.Unlock()
	if len(profiles) != 1 {
		t.Fatalf("saved external profiles=%d", len(profiles))
	}
	raw, err := os.ReadFile(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	var persisted common.RouterProfileStore
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Profiles) != 1 {
		t.Fatal("saved file lost imported profile")
	}
	for _, p := range []common.RouterProfile{profiles[0], persisted.Profiles[0]} {
		if selection == "absent" {
			if p.DNSMode != "rescue" || p.DNSProtocol != "https" || p.DNSHost != "1.1.1.1" || p.DNSPort != 443 || p.DNSServerName != "cloudflare-dns.com" || p.DNSPath != "/dns-query" {
				t.Fatalf("external import persisted the wrong absent-policy migration: %+v", p)
			}
		} else {
			if p.DNSMode != "home" || p.DNSHost != "10.77.0.1" {
				t.Fatalf("external import replaced explicit Home DNS: %+v", p)
			}
			exit, err := standardExitFromExternalProfile(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildDirectStandardExitConfig(p, exit); err == nil {
				t.Fatal("direct Home DNS compiled without an owned Router VPN entry")
			}
		}
		if p.RouterAPI != "" || p.AdGuardIPv4 != "" || p.AdGuardIPv6 != "" || p.SocksHost != "" || p.SocksUsername != "" || p.SocksPassword != "" {
			t.Fatalf("external import retained Router VPN home defaults: %+v", p)
		}
	}
}
