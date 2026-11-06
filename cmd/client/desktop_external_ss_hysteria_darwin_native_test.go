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

var macOSExternalSSHysteriaCases = []string{
	"ss-entry-aes128-hysteria",
	"ss-entry-aes128-hysteria-always",
	"ss-entry-aes256-hysteria",
	"ss-entry-aes256-hysteria-always",
	"ss-entry-chacha-hysteria",
	"ss-entry-chacha-hysteria-always",
	"ss-entry-aes256-hysteria-wrong-entry-key",
	"ss-entry-aes256-hysteria-wrong-entry-method",
	"ss-entry-aes256-hysteria-wrong-entry-public",
	"ss-entry-aes256-hysteria-wrong-exit-key",
	"ss-entry-aes256-hysteria-wrong-exit-address",
	"ss-entry-aes256-hysteria-wrong-exit-server-name",
	"ss-entry-aes256-hysteria-wrong-final-trust",
	"ss-entry-aes256-hysteria-wrong-dns",
	"ss-entry-aes256-hysteria-wrong-exit",
}

func macOSExternalSSHysteriaScenario(scenario string) (entry, protocol, fault string, found bool) {
	for _, candidate := range macOSExternalSSHysteriaCases {
		if candidate != scenario {
			continue
		}
		parts := strings.Split(scenario, "-")
		entry = macOSExternalSSEntryMethod(parts[2])
		protocol = "hysteria2"
		if len(parts) > 4 && parts[4] != "always" {
			fault = strings.Join(parts[4:], "-")
		}
		return entry, protocol, fault, true
	}
	return "", "", "", false
}
func macOSExternalNativeSSHysteriaProfile(t *testing.T, p *macOSExternalNativePeer, exit *common.RouterProfile) *common.RouterProfile {
	t.Helper()
	exit.Endpoint = p.address.Addr().String()
	exit.MultihopEnabled, exit.MultihopEntryID, exit.MultihopExitID = true, macOSExternalNativeEntryID(p), exit.ID
	exit.MultihopExecution, exit.MultihopEntryMode = "local", ""
	exit.DNSProtocol = "udp"
	entry := common.RouterProfile{ID: macOSExternalNativeEntryID(p), Name: "Original SS2022 HY2 entry", NodeKind: "external", Endpoint: p.physical.String(), DNSMode: "custom", DNSProtocol: "udp", DNSHost: "203.0.113.53", DNSPort: 5353, IPv6Mode: "on", HomeLANAccess: true, StartLayer: common.StartLayerOff, MTUPolicy: "auto", External: &common.ExternalNodeConfig{Protocol: "shadowsocks", ExpectedPublicIP: "203.0.113.77", Shadowsocks: &common.ExternalShadowsocksConfig{Server: p.physical.String(), Port: int(p.entryAddress.Port()), Method: p.ssEntryMethod, Password: p.ssEntryPassword}}}
	proxy := exit.External.Hysteria2
	switch p.fault {
	case "wrong-entry-key":
		entry.External.Shadowsocks.Password = macOSExternalNativeSSKey(t, p.ssEntryMethod)
	case "wrong-entry-method":
		entry.External.Shadowsocks.Method = macOSExternalSSEntryMethod("chacha")
	case "wrong-entry-public":
		entry.External.ExpectedPublicIP = "203.0.113.78"
	case "wrong-exit-key":
		proxy.Password += "-different"
	case "wrong-exit-server-name":
		proxy.TLSServerName = "wrong-final.example"
	case "wrong-exit-address":
		exit.Endpoint = "198.51.100.241"
		proxy.Server = exit.Endpoint
	case "wrong-exit":
		exit.External.ExpectedPublicIP = "203.0.113.89"
	}
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal("SS HY2 entry rejected before native execution", err)
	}
	return &entry
}
func macOSExternalNativeSSHysteriaAuthority(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult) {
	t.Helper()
	host := "198.51.100.240"
	if p.fault == "wrong-exit-address" {
		host = "198.51.100.241"
	}
	if live.OuterTag != "external-entry" || live.OuterType != "shadowsocks" || live.PhysicalNetwork != "tcp+udp" || live.PhysicalAddress != p.entryAddress.String() || live.InnerDetour != "external-entry" || live.InnerHost != host || len(live.PhysicalDestinations) != 2 {
		t.Fatal("HY2 escaped original SS physical authority", live)
	}
	seen := map[string]bool{}
	for _, d := range live.PhysicalDestinations {
		if d.Network != "tcp" && d.Network != "udp" || seen[d.Network] || d.Host != p.physical.String() || d.Port != int(p.entryAddress.Port()) {
			t.Fatal("HY2 replaced original entry tuple", d)
		}
		seen[d.Network] = true
	}
}

func macOSExternalNativeSSHysteriaProved(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult, observed macOSExternalPeerReply) {
	t.Helper()
	macOSExternalNativeSSHysteriaAuthority(t, p, live)
	entry := observed.ShadowsocksEntry
	ipv6 := "off"
	if p.policy == "always" {
		ipv6 = "on"
	}
	if entry == nil || entry.PhysicalTCP < 1 || entry.Streams < 1 || entry.PublicReplies < 1 || entry.PhysicalUDP < 1 || entry.Packets < 1 || observed.PhysicalUDP < 1 || observed.Packets < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 || !live.Proof.EntryProven || live.Proof.EntryID != macOSExternalNativeEntryID(p) || live.Proof.EntryNodeID != "" || live.Proof.ExitID != "installed-macos-external" || live.Proof.IP != "203.0.113.88" || live.DNSProtocol != "udp" || live.DNSHost != "203.0.113.53" || live.DNSPort != 5353 || live.Network.MTU != 1376 || live.IPv6 != ipv6 || live.HomeLAN != (p.policy == "always") {
		t.Fatal("HY2 lost independent entry/final/DNS or device policy", observed)
	}

}
func macOSExternalNativeSSHysteriaRefused(t *testing.T, ctx context.Context, client *http.Client, p *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("SS HY2 negative did not complete original refusal", status, failure, string(raw))
	}
	observed := p.stats(t)
	entry := observed.ShadowsocksEntry
	if entry == nil || entry.PhysicalTCP < 1 {
		t.Fatal("HY2 negative omitted original encrypted entry", observed)
	}
	switch p.fault {
	case "wrong-entry-key", "wrong-entry-method":
		if entry.AuthTCP == 0 || entry.PublicReplies != 0 || entry.PhysicalUDP != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 {
			t.Fatal("bad entry reached HY2", observed)
		}
	case "wrong-entry-public":
		if entry.PublicReplies < 1 || entry.PhysicalUDP != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 {
			t.Fatal("unproved entry reached HY2", observed)
		}
	case "wrong-exit-key":
		if entry.PublicReplies < 1 || entry.PhysicalUDP < 1 || observed.PhysicalUDP < 1 || observed.AuthFailures < 1 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("wrong final HY2 credential missed native rejection", observed)
		}
	case "wrong-exit-server-name", "wrong-final-trust":
		expected := "x509: certificate signed by unknown authority"
		if p.fault == "wrong-exit-server-name" {
			expected = "not wrong-final.example"
		}
		if entry.PublicReplies < 1 || entry.PhysicalUDP < 1 || observed.PhysicalUDP < 1 || observed.DNSQueries != 0 || observed.PublicReplies != 0 || !strings.Contains(string(raw), "tls: failed to verify certificate") || !strings.Contains(string(raw), expected) {
			t.Fatal("HY2 final trust negative missed original verifier or independent peers", observed, string(raw))
		}
	case "wrong-exit-address":
		if entry.PublicReplies < 1 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 {
			t.Fatal("foreign final route reached HY2", observed)
		}
	case "wrong-dns":
		if entry.PublicReplies < 1 || observed.DNSQueries < 1 || observed.PublicReplies != 0 {
			t.Fatal("HY2 selected DNS refusal missed resolver", observed)
		}
	case "wrong-exit":
		if entry.PublicReplies < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 {
			t.Fatal("HY2 final mismatch omitted proof", observed)
		}
	default:
		t.Fatal(errors.New("unknown SS HY2 negative"))
	}

	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired || retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present {
		t.Fatal("HY2 refusal lost original child/native cleanup", status, failure, string(raw))
	}
	macOSExternalNativeSSHysteriaAuthority(t, p, retired)
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}
