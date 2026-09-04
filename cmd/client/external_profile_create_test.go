package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

const createTestWGKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func createRequestFor(protocol string) externalProfileCreateRequest {
	q := externalProfileCreateRequest{
		Name:             "Typed " + protocol,
		Protocol:         protocol,
		ExpectedPublicIP: "8.8.8.8",
		Server:           "203.0.113.40",
		Port:             443,
	}
	switch protocol {
	case "wireguard":
		q.Server = "2001:4860:4860::8888"
		q.Port = 51820
		q.WGPrivateKey = createTestWGKey
		q.WGPeerPublicKey = createTestWGKey
		q.WGAddresses = []string{"10.55.0.2/32"}
		q.WGAllowedIPs = []string{"0.0.0.0/0", "::/0"}
		q.WGDNS = []string{"1.1.1.1"}
		q.WGMTU = 1380
	case "socks5":
		q.Port = 1080
		q.Username, q.Password = "proxy-user", "proxy-secret"
	case "http-connect":
		q.Port = 8080
		q.Username, q.Password = "http-user", "http-secret"
	case "https-connect":
		q.Username, q.Password = "https-user", "https-secret"
		q.TLSServerName = "proxy.example.com"
	case "shadowsocks":
		q.Port = 8388
		q.Method = "aes-256-gcm"
		q.Secret = "ss-secret"
	case "hysteria2":
		q.Port = 8443
		q.Secret = "hy-secret"
		q.TLSServerName = "hy.example.com"
	}
	return q
}

func TestTypedExternalProfileBuilderSupportsCommonNodeFamilies(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			p, err := externalProfileFromCreateRequest(createRequestFor(protocol))
			if err != nil {
				t.Fatal(err)
			}
			if p.NodeKind != "external" || p.External == nil || p.External.Protocol != protocol {
				t.Fatalf("typed node normalized incorrectly: %+v", p)
			}
			if p.External.ExpectedPublicIP != "8.8.8.8" {
				t.Fatalf("expected exit proof lost: %+v", p.External)
			}
			switch protocol {
			case "wireguard":
				if p.External.WireGuard == nil || p.External.WireGuard.Endpoint != "[2001:4860:4860::8888]:51820" {
					t.Fatalf("WireGuard IPv6 endpoint was not bracketed safely: %+v", p.External.WireGuard)
				}
			case "socks5":
				if p.External.SOCKS5 == nil || p.External.SOCKS5.Username != "proxy-user" || p.External.SOCKS5.Password != "proxy-secret" {
					t.Fatalf("SOCKS5 credentials lost: %+v", p.External.SOCKS5)
				}
			case "http-connect":
				if p.External.HTTPConnect == nil || p.External.HTTPConnect.Port != 8080 || p.External.HTTPConnect.TLSServerName != "" {
					t.Fatalf("HTTP CONNECT block wrong: %+v", p.External.HTTPConnect)
				}
			case "https-connect":
				if p.External.HTTPSConnect == nil || p.External.HTTPSConnect.TLSServerName != "proxy.example.com" || p.External.HTTPSConnect.Password != "https-secret" {
					t.Fatalf("HTTPS CONNECT TLS/auth lost: %+v", p.External.HTTPSConnect)
				}
			case "shadowsocks":
				if p.External.Shadowsocks == nil || p.External.Shadowsocks.Method != "aes-256-gcm" || p.External.Shadowsocks.Password != "ss-secret" {
					t.Fatalf("Shadowsocks block wrong: %+v", p.External.Shadowsocks)
				}
			case "hysteria2":
				if p.External.Hysteria2 == nil || p.External.Hysteria2.TLSServerName != "hy.example.com" || p.External.Hysteria2.Password != "hy-secret" {
					t.Fatalf("Hysteria2 block wrong: %+v", p.External.Hysteria2)
				}
			}
		})
	}
}

func TestTypedExternalProfileBuilderDelegatesSpecializedImports(t *testing.T) {
	for protocol, want := range map[string]string{
		"openvpn":    "hardened config import path",
		"tor-bridge": "dedicated censorship-circumvention builder",
	} {
		q := createRequestFor("socks5")
		q.Protocol = protocol
		if _, err := externalProfileFromCreateRequest(q); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s should delegate to specialized importer, got %v", protocol, err)
		}
	}
}

func TestTypedExternalProfileBuilderKeepsHTTPAndHTTPSDistinct(t *testing.T) {
	httpNode := createRequestFor("http-connect")
	httpNode.TLSServerName = "should-not-be-ignored.example"
	if _, err := externalProfileFromCreateRequest(httpNode); err == nil || !strings.Contains(err.Error(), "plain HTTP CONNECT") {
		t.Fatalf("plain HTTP CONNECT silently accepted TLS metadata: %v", err)
	}
	httpsNode := createRequestFor("https-connect")
	httpsNode.TLSServerName = ""
	if _, err := externalProfileFromCreateRequest(httpsNode); err == nil || !strings.Contains(err.Error(), "TLS server name") {
		t.Fatalf("HTTPS CONNECT accepted missing SNI: %v", err)
	}
}

func typedCreateRequest(t *testing.T, q externalProfileCreateRequest) *http.Request {
	t.Helper()
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPost, "/api/external-profile/create", bytes.NewReader(raw))
}

func TestTypedExternalProfileCreatePersistsSelectsAndRedactsResponse(t *testing.T) {
	root := t.TempDir()
	a := &app{
		cfg:      common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion},
		state:    state{Mode: "off", Phase: "off"},
	}
	q := createRequestFor("https-connect")
	recorder := httptest.NewRecorder()
	a.externalProfileCreate(recorder, typedCreateRequest(t, q))
	if recorder.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(a.profiles.Profiles) != 1 || a.profiles.SelectedID == "" || a.state.RouterID != a.profiles.SelectedID {
		t.Fatalf("new external node was not atomically selected: store=%+v state=%+v", a.profiles, a.state)
	}
	created := a.profiles.Profiles[0]
	if created.External == nil || created.External.HTTPSConnect == nil || created.External.HTTPSConnect.Password != "https-secret" {
		t.Fatalf("private persisted node lost credentials: %+v", created)
	}
	response := recorder.Body.String()
	for _, secret := range []string{"https-secret", "https-user"} {
		if strings.Contains(response, secret) {
			t.Fatalf("typed create response leaked %q: %s", secret, response)
		}
	}
	if !strings.Contains(response, `"protocol":"https-connect"`) || !strings.Contains(response, `"expected_public_ip":"8.8.8.8"`) {
		t.Fatalf("public create response lost node truth: %s", response)
	}
	info, err := os.Lstat(a.cfg.ProfilesFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().IsRegular() == false {
		t.Fatalf("profiles store is not a regular file: %v", info.Mode())
	}
}

func TestTypedExternalProfileCreateFailsClosedDuringLiveSession(t *testing.T) {
	root := t.TempDir()
	a := &app{
		cfg:      common.ClientConfig{ProfilesFile: filepath.Join(root, "routers.json")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion},
		state:    state{Connected: true, Mode: "wg", Phase: "connected", RouterID: "live"},
	}
	recorder := httptest.NewRecorder()
	a.externalProfileCreate(recorder, typedCreateRequest(t, createRequestFor("socks5")))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("live-session create status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(a.profiles.Profiles) != 0 || a.profiles.SelectedID != "" || a.state.RouterID != "live" {
		t.Fatalf("live-session create mutated state: store=%+v state=%+v", a.profiles, a.state)
	}
}

func TestTypedExternalProfileCreateRollsBackOnPersistenceFailure(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := common.RouterProfile{SchemaVersion: common.RouterProfileSchemaVersion, ID: "old-node", Name: "Old", NodeKind: "external", Endpoint: "203.0.113.9", External: &common.ExternalNodeConfig{Protocol: "socks5", ExpectedPublicIP: "8.8.4.4", SOCKS5: &common.ExternalSOCKS5Config{Host: "203.0.113.9", Port: 1080}}}
	a := &app{
		cfg: common.ClientConfig{ProfilesFile: filepath.Join(blocker, "routers.json")},
		profiles: common.RouterProfileStore{SchemaVersion: common.RouterProfileStoreVersion, SelectedID: old.ID, Profiles: []common.RouterProfile{old}},
		state: state{Mode: "off", Phase: "off", RouterID: old.ID},
	}
	recorder := httptest.NewRecorder()
	a.externalProfileCreate(recorder, typedCreateRequest(t, createRequestFor("socks5")))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("persistence failure status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(a.profiles.Profiles) != 1 || a.profiles.Profiles[0].ID != old.ID || a.profiles.SelectedID != old.ID || a.state.RouterID != old.ID {
		t.Fatalf("failed typed create left a half-adopted node: store=%+v state=%+v", a.profiles, a.state)
	}
}

func TestTypedExternalProfileCreateRejectsWrongMethod(t *testing.T) {
	a := &app{}
	recorder := httptest.NewRecorder()
	a.externalProfileCreate(recorder, httptest.NewRequest(http.MethodGet, "/api/external-profile/create", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET create status=%d", recorder.Code)
	}
}
