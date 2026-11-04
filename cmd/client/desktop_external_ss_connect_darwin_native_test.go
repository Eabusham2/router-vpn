//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"errors"
	"net/http"
	"router-vpn/internal/common"
	"strings"
	"testing"
)

var macOSExternalSSCONNECTCases = []string{
	"ss-entry-aes128-http",
	"ss-entry-aes128-http-always",
	"ss-entry-aes128-https",
	"ss-entry-aes128-https-always",
	"ss-entry-aes256-http",
	"ss-entry-aes256-http-always",
	"ss-entry-aes256-https",
	"ss-entry-aes256-https-always",
	"ss-entry-chacha-http",
	"ss-entry-chacha-http-always",
	"ss-entry-chacha-https",
	"ss-entry-chacha-https-always",
	"ss-entry-aes256-http-wrong-entry-key",
	"ss-entry-aes256-https-wrong-entry-method",
	"ss-entry-aes256-http-wrong-entry-public",
	"ss-entry-aes256-http-wrong-exit-username",
	"ss-entry-aes256-http-wrong-exit-key",
	"ss-entry-aes256-http-wrong-exit-address",
	"ss-entry-aes256-http-wrong-dns",
	"ss-entry-aes256-http-wrong-exit",
	"ss-entry-aes256-https-wrong-exit-username",
	"ss-entry-aes256-https-wrong-exit-key",
	"ss-entry-aes256-https-wrong-exit-server-name",
	"ss-entry-aes256-https-wrong-trust",
}

func macOSExternalSSCONNECTScenario(scenario string) (entry, protocol, fault string, found bool) {
	for _, candidate := range macOSExternalSSCONNECTCases {
		if candidate != scenario {
			continue
		}
		parts := strings.Split(scenario, "-")
		entry = macOSExternalSSEntryMethod(parts[2])
		protocol = "http-connect"
		if parts[3] == "https" {
			protocol = "https-connect"
		}
		if len(parts) > 4 && parts[4] != "always" {
			fault = strings.Join(parts[4:], "-")
		}
		return entry, protocol, fault, true
	}
	return "", "", "", false
}
func macOSExternalNativeSSCONNECTProfile(t *testing.T, p *macOSExternalNativePeer, exit *common.RouterProfile) *common.RouterProfile {
	t.Helper()
	exit.Endpoint = p.address.Addr().String()
	exit.MultihopEnabled, exit.MultihopEntryID, exit.MultihopExitID = true, macOSExternalNativeEntryID(p), exit.ID
	exit.MultihopExecution, exit.MultihopEntryMode = "local", ""
	exit.DNSProtocol = "tcp"
	entry := common.RouterProfile{ID: macOSExternalNativeEntryID(p), Name: "Original SS2022 CONNECT entry", NodeKind: "external", Endpoint: p.physical.String(), DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "203.0.113.53", DNSPort: 5353, IPv6Mode: "on", HomeLANAccess: true, StartLayer: common.StartLayerOff, MTUPolicy: "auto", External: &common.ExternalNodeConfig{Protocol: "shadowsocks", ExpectedPublicIP: "203.0.113.77", Shadowsocks: &common.ExternalShadowsocksConfig{Server: p.physical.String(), Port: int(p.entryAddress.Port()), Method: p.ssEntryMethod, Password: p.ssEntryPassword}}}
	proxy := exit.External.HTTPConnect
	if p.protocol == "https-connect" {
		proxy = exit.External.HTTPSConnect
	}
	switch p.fault {
	case "wrong-entry-key":
		entry.External.Shadowsocks.Password = macOSExternalNativeSSKey(t, p.ssEntryMethod)
	case "wrong-entry-method":
		entry.External.Shadowsocks.Method = macOSExternalSSEntryMethod("chacha")
	case "wrong-entry-public":
		entry.External.ExpectedPublicIP = "203.0.113.78"
	case "wrong-exit-username":
		proxy.Username += "-different"
	case "wrong-exit-key":
		proxy.Password += "-different"
	case "wrong-exit-server-name":
		proxy.TLSServerName = "wrong-final.example"
	case "wrong-exit-address":
		exit.Endpoint = "198.51.100.241"
		proxy.Host = exit.Endpoint
	case "wrong-exit":
		exit.External.ExpectedPublicIP = "203.0.113.89"
	}
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal("SS CONNECT entry rejected before native execution", err)
	}
	return &entry
}
func macOSExternalNativeSSCONNECTAuthority(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult) {
	t.Helper()
	host := "198.51.100.240"
	if p.fault == "wrong-exit-address" {
		host = "198.51.100.241"
	}
	if live.OuterTag != "external-entry" || live.OuterType != "shadowsocks" || live.PhysicalNetwork != "tcp" || live.PhysicalAddress != p.entryAddress.String() || live.InnerDetour != "external-entry" || live.InnerHost != host || len(live.PhysicalDestinations) != 1 {
		t.Fatal("CONNECT acquired final or UDP physical authority", live)
	}
	d := live.PhysicalDestinations[0]
	if d.Network != "tcp" || d.Host != p.physical.String() || d.Port != int(p.entryAddress.Port()) {
		t.Fatal("CONNECT replaced original physical SS tuple")
	}
}
func macOSExternalNativeSSCONNECTProved(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult, observed macOSExternalPeerReply) {
	t.Helper()
	macOSExternalNativeSSCONNECTAuthority(t, p, live)
	entry := observed.ShadowsocksEntry
	ipv6 := "off"
	if p.policy == "always" {
		ipv6 = "on"
	}
	if entry == nil || entry.PhysicalTCP < 2 || entry.Streams < 2 || entry.PublicReplies < 1 || entry.PhysicalUDP != 0 || entry.Packets != 0 || observed.Connections < 2 || observed.Streams < 2 || observed.DNSQueries < 1 || observed.PublicReplies < 1 || observed.PhysicalUDP != 0 || !live.Proof.EntryProven || live.Proof.EntryID != macOSExternalNativeEntryID(p) || live.Proof.EntryNodeID != "" || live.Proof.ExitID != "installed-macos-external" || live.Proof.IP != "203.0.113.88" || live.DNSProtocol != "tcp" || live.DNSHost != "203.0.113.53" || live.DNSPort != 5353 || live.Network.MTU != 1376 || live.IPv6 != ipv6 || live.HomeLAN != (p.policy == "always") {
		t.Fatal("CONNECT lost original entry/final/DNS or device policy")
	}
}
func macOSExternalNativeSSCONNECTRefused(t *testing.T, ctx context.Context, client *http.Client, p *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("SS CONNECT negative did not complete original refusal", status, failure, string(raw))
	}
	observed := p.stats(t)
	entry := observed.ShadowsocksEntry
	if entry == nil || entry.PhysicalTCP < 1 || entry.PhysicalUDP != 0 || observed.PhysicalUDP != 0 {
		t.Fatal("CONNECT negative missed original TCP-only entry")
	}
	switch p.fault {
	case "wrong-entry-key", "wrong-entry-method":
		if entry.Streams != 0 || entry.PublicReplies != 0 || observed.Connections != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("CONNECT acquired wrong authenticated entry")
		}
	case "wrong-trust":
		if entry.Streams < 1 || entry.PublicReplies != 0 || observed.Connections != 0 || observed.DNSQueries != 0 {
			t.Fatal("CONNECT entry TLS refusal missed boundary")
		}
	case "wrong-entry-public":
		if entry.PublicReplies < 1 || observed.Connections != 0 || observed.DNSQueries != 0 {
			t.Fatal("CONNECT acquired unproved entry")
		}
	case "wrong-exit-username", "wrong-exit-key":
		if entry.PublicReplies < 1 || observed.Connections < 1 || observed.AuthFailures < 1 || observed.Streams != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("CONNECT independent auth refusal missed actual final")
		}
	case "wrong-exit-server-name":
		if entry.PublicReplies < 1 || observed.Connections < 1 || observed.Streams != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("CONNECT SNI refusal missed original final TLS")
		}
	case "wrong-exit-address":
		if entry.PublicReplies < 1 || observed.Connections != 0 || observed.DNSQueries != 0 {
			t.Fatal("CONNECT final route escaped original entry")
		}
	case "wrong-dns":
		if entry.PublicReplies < 1 || observed.DNSQueries < 1 || observed.PublicReplies != 0 {
			t.Fatal("CONNECT selected DNS refusal missed resolver")
		}
	case "wrong-exit":
		if entry.PublicReplies < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 {
			t.Fatal("CONNECT final mismatch missed proof")
		}
	default:
		t.Fatal(errors.New("unknown SS CONNECT negative"))
	}
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired || retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present {
		t.Fatal("CONNECT refusal lost original child/native cleanup", status, failure, string(raw))
	}
	macOSExternalNativeSSCONNECTAuthority(t, p, retired)
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}
