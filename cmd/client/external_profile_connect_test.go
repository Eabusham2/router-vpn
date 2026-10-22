package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestExternalRuntimePolicyDefaultsToHomeWithoutPublicSubstitution(t *testing.T) {
	p := common.RouterProfile{ID: "ext", Name: "External", NodeKind: "external", HomeLANAccess: false, KillSwitchPolicy: "always", External: &common.ExternalNodeConfig{Protocol: "socks5", ExpectedPublicIP: "203.0.113.101", SOCKS5: &common.ExternalSOCKS5Config{Host: "198.51.100.10", Port: 1080}}}
	policy, err := externalRuntimePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if policy.DNSMode != "home" || policy.DNSProtocol != "udp" || policy.DNSHost != "" || policy.DNSServerName != "" || policy.DNSPort != 53 {
		t.Fatalf("missing DNS choice was replaced: %+v", policy)
	}
	if policy.KillSwitchPolicy != "always" || policy.HomeLANAccess {
		t.Fatalf("network policy changed: %+v", policy)
	}
}

func TestExternalDNSPolicyUsesOnlyCapturedRouterEntryForHome(t *testing.T) {
	node, err := externalProfileFromCreateRequest(createRequestFor("shadowsocks"))
	if err != nil {
		t.Fatal(err)
	}
	entry := common.RouterProfile{ID: "owned-entry", NodeKind: "router-vpn", AdGuardIPv4: "192.168.50.133", AdGuardIPv6: "fd42:50::133"}
	policy, err := externalDNSPolicyForPath(node, entry, false)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := selectedStandardExitDNS(policy, false)
	if err != nil || dns["server"] != "192.168.50.133" || dns["detour"] != "entry-wg" {
		t.Fatalf("Home did not use captured entry: %v %#v", err, dns)
	}
	if node.AdGuardIPv4 != "" || node.DNSHost != "" {
		t.Fatal("runtime entry resolver leaked into the reusable external node")
	}
	entry.AdGuardIPv4 = ""
	policy, err = externalDNSPolicyForPath(node, entry, false)
	if err != nil {
		t.Fatal(err)
	}
	dns, err = selectedStandardExitDNS(policy, false)
	if err != nil || dns["server"] != "fd42:50::133" {
		t.Fatal("captured IPv6 Home resolver was lost")
	}
	for name, route := range map[string]struct {
		entry  common.RouterProfile
		direct bool
	}{
		"direct": {entry, true}, "missing-entry": {common.RouterProfile{}, false},
		"missing-adguard": {common.RouterProfile{ID: "no-dns", NodeKind: "router-vpn"}, false},
		"external-entry":  {node, false},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := externalDNSPolicyForPath(node, route.entry, route.direct); err == nil {
				t.Fatal("Home was silently replaced or fabricated")
			}
		})
	}
	// An explicitly saved encrypted Home policy survives entry resolution.
	node.DNSProtocol, node.DNSHost, node.DNSPort, node.DNSServerName, node.DNSPath = "https", "192.168.50.133", 8443, "home.example.test", "/private-dns"
	policy, err = externalDNSPolicyForPath(node, entry, false)
	if err != nil {
		t.Fatal(err)
	}
	dns, err = selectedStandardExitDNS(policy, false)
	if err != nil || dns["type"] != "https" || dns["server_port"] != 8443 || dns["path"] != "/private-dns" {
		t.Fatalf("encrypted Home parameters changed: %v %#v", err, dns)
	}
}

func TestExternalDNSPolicyExplicitRescueAndCustomStaySelected(t *testing.T) {
	node, err := externalProfileFromCreateRequest(createRequestFor("socks5"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"rescue", "custom", "doh", "dot"} {
		node.DNSMode, node.DNSProtocol, node.DNSHost, node.DNSPort, node.DNSServerName, node.DNSPath = mode, "tcp", "9.9.9.9", 53, "dns.quad9.net", "/dns-query"
		if mode == "doh" || mode == "rescue" {
			node.DNSProtocol = "https"
			node.DNSPort = 443
		}
		if mode == "dot" {
			node.DNSProtocol = "tls"
			node.DNSPort = 853
		}
		policy, err := externalDNSPolicyForPath(node, common.RouterProfile{}, true)
		if err != nil || policy.DNSHost != node.DNSHost || policy.DNSMode != mode || policy.DNSPort != node.DNSPort {
			t.Fatalf("explicit %s DNS changed: %v", mode, err)
		}
	}
}

func TestExternalDNSPreflightPreservesExistingConnection(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle DNS preflight", true: "active owner retained"}[active], func(t *testing.T) {
			a := externalConnectionTestApp(t, "socks5", false)
			a.profiles.Profiles[3].DNSMode = ""
			a.profiles.Profiles[3].DNSHost = ""
			a.state.Connected = active
			a.state.Phase = "off"
			if active {
				a.state.Phase = "connected"
			}
			a.state.RouterID = "existing-owner"
			before := a.state
			profiles := cloneRouterProfileStore(a.profiles)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/external-profile/connect", strings.NewReader(`{"profile_id":"external","direct":true}`))
			a.externalProfileConnect(w, r)
			wantStatus, wantMessage := http.StatusBadRequest, "Home AdGuard is selected"
			if active {
				wantStatus, wantMessage = http.StatusConflict, "disconnect before starting another connection"
			}
			if w.Code != wantStatus || !strings.Contains(w.Body.String(), wantMessage) {
				t.Fatalf("unexpected preflight response: %d %s", w.Code, w.Body.String())
			}
			if !reflect.DeepEqual(a.state, before) || !reflect.DeepEqual(a.profiles, profiles) {
				t.Fatal("rejected connection changed the captured session or saved profiles")
			}
		})
	}
}

func TestExternalRuntimePolicyPreservesExplicitDNS(t *testing.T) {
	p := common.RouterProfile{ID: "ext", Name: "External", NodeKind: "external", DNSMode: "custom", DNSProtocol: "udp", DNSHost: "9.9.9.9", DNSPort: 53, External: &common.ExternalNodeConfig{Protocol: "socks5", ExpectedPublicIP: "203.0.113.102", SOCKS5: &common.ExternalSOCKS5Config{Host: "198.51.100.11", Port: 1080}}}
	policy, err := externalRuntimePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if policy.DNSMode != "custom" || policy.DNSHost != "9.9.9.9" || policy.DNSPort != 53 {
		t.Fatalf("explicit DNS changed: %+v", policy)
	}
}

func TestExternalRuntimePolicyRejectsRouterVPNNode(t *testing.T) {
	if _, err := externalRuntimePolicy(common.RouterProfile{ID: "home"}); err == nil {
		t.Fatal("Router VPN node was accepted as external policy")
	}
}
