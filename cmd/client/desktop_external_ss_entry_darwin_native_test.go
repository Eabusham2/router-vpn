//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/netip"
	"router-vpn/internal/common"
	"strings"
	"testing"
)

var macOSExternalSSEntryCases = []string{
	"ss-entry-aes128-ss-aes128",
	"ss-entry-aes128-ss-aes128-always",
	"ss-entry-aes128-ss-aes256",
	"ss-entry-aes128-ss-aes256-always",
	"ss-entry-aes128-ss-chacha",
	"ss-entry-aes128-ss-chacha-always",
	"ss-entry-aes256-ss-aes128",
	"ss-entry-aes256-ss-aes128-always",
	"ss-entry-aes256-ss-aes256",
	"ss-entry-aes256-ss-aes256-always",
	"ss-entry-aes256-ss-chacha",
	"ss-entry-aes256-ss-chacha-always",
	"ss-entry-chacha-ss-aes128",
	"ss-entry-chacha-ss-aes128-always",
	"ss-entry-chacha-ss-aes256",
	"ss-entry-chacha-ss-aes256-always",
	"ss-entry-chacha-ss-chacha",
	"ss-entry-chacha-ss-chacha-always",
	"ss-entry-aes256-ss-aes256-wrong-entry-key",
	"ss-entry-aes256-ss-aes256-wrong-entry-method",
	"ss-entry-aes256-ss-aes256-wrong-entry-public",
	"ss-entry-aes256-ss-aes256-wrong-exit-key",
	"ss-entry-aes256-ss-aes256-wrong-exit-method",
	"ss-entry-aes256-ss-aes256-wrong-exit-address",
	"ss-entry-aes256-ss-aes256-wrong-dns",
	"ss-entry-aes256-ss-aes256-wrong-trust",
	"ss-entry-aes256-ss-aes256-wrong-exit",
}

func macOSExternalSSEntryMethod(name string) string {
	switch name {
	case "aes128":
		return "2022-blake3-aes-128-gcm"
	case "aes256":
		return "2022-blake3-aes-256-gcm"
	case "chacha":
		return "2022-blake3-chacha20-poly1305"
	}
	return ""
}
func macOSExternalSSEntryScenario(scenario string) (entry, final, fault string, found bool) {
	for _, candidate := range macOSExternalSSEntryCases {
		if candidate != scenario {
			continue
		}
		parts := strings.Split(scenario, "-")
		entry, final = macOSExternalSSEntryMethod(parts[2]), macOSExternalSSEntryMethod(parts[4])
		if len(parts) > 5 && parts[5] != "always" {
			fault = strings.Join(parts[5:], "-")
		}
		return entry, final, fault, true
	}
	return "", "", "", false
}

type macOSExternalSSEntryReceipt struct {
	Method        string `json:"method"`
	Address       string `json:"address"`
	PhysicalTCP   int64  `json:"physical_tcp"`
	PhysicalUDP   int64  `json:"physical_udp"`
	Streams       int64  `json:"streams"`
	Packets       int64  `json:"packets"`
	PublicReplies uint32 `json:"public_replies"`
	AuthTCP       uint32 `json:"auth_tcp"`
	AuthUDP       uint32 `json:"auth_udp"`
}

func macOSExternalNativeSSKey(t *testing.T, method string) string {
	t.Helper()
	size := 32
	if method == macOSExternalSSEntryMethod("aes128") {
		size = 16
	}
	raw := make([]byte, size)
	if _, e := rand.Read(raw); e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	return base64.StdEncoding.EncodeToString(raw)
}
func macOSExternalNativeSSEntryRead(t *testing.T, p *macOSExternalNativePeer, reply macOSExternalPeerReply) {
	t.Helper()
	entry := reply.ShadowsocksEntry
	if !p.ssEntry {
		if entry != nil {
			t.Fatal("ordinary peer acquired SS entry")
		}
		return
	}
	if entry == nil || entry.Method != p.ssEntryMethod || reply.Address != "198.51.100.240:8388" || entry.PhysicalTCP < 0 || entry.PhysicalUDP < 0 || entry.Streams < 0 || entry.Packets < 0 {
		t.Fatal("SS entry lost its exact response")
	}
	address, e := netip.ParseAddrPort(entry.Address)
	if e != nil || address.Addr() != p.physical || address.Port() == 0 || p.entryAddress.IsValid() && p.entryAddress != address {
		t.Fatal("SS entry changed its original physical tuple")
	}
	if entry.PhysicalTCP == 0 && entry.PhysicalUDP == 0 && (entry.AuthTCP != 0 || entry.AuthUDP != 0) {
		t.Fatal("SS entry claimed authentication before original native traffic")
	}
	p.entryAddress = address
}
func macOSExternalNativeSSEntryProfile(t *testing.T, p *macOSExternalNativePeer, exit *common.RouterProfile) *common.RouterProfile {
	t.Helper()
	if !p.ssEntry {
		return nil
	}
	exit.Endpoint = p.address.Addr().String()
	exit.MultihopEnabled, exit.MultihopEntryID, exit.MultihopExitID = true, macOSExternalNativeEntryID(p), exit.ID
	exit.MultihopExecution, exit.MultihopEntryMode = "local", ""
	exit.External.Shadowsocks.Method = p.ssFinalMethod
	if p.policy == "always" {
		exit.DNSProtocol = "udp"
	}
	entry := common.RouterProfile{ID: macOSExternalNativeEntryID(p), Name: "Original ordinary SS2022 entry", NodeKind: "external", Endpoint: p.physical.String(), DNSMode: "custom", DNSProtocol: "tcp", DNSHost: "203.0.113.53", DNSPort: 5353, IPv6Mode: "on", HomeLANAccess: true, StartLayer: common.StartLayerOff, MTUPolicy: "auto", External: &common.ExternalNodeConfig{Protocol: "shadowsocks", ExpectedPublicIP: "203.0.113.77", Shadowsocks: &common.ExternalShadowsocksConfig{Server: p.physical.String(), Port: int(p.entryAddress.Port()), Method: p.ssEntryMethod, Password: p.ssEntryPassword}}}
	switch p.fault {
	case "wrong-entry-key":
		entry.External.Shadowsocks.Password = macOSExternalNativeSSKey(t, p.ssEntryMethod)
	case "wrong-entry-method":
		entry.External.Shadowsocks.Method = macOSExternalSSEntryMethod("chacha")
	case "wrong-entry-public":
		entry.External.ExpectedPublicIP = "203.0.113.78"
	case "wrong-exit-key":
		exit.External.Shadowsocks.Password = macOSExternalNativeSSKey(t, p.ssFinalMethod)
	case "wrong-exit-method":
		exit.External.Shadowsocks.Method = macOSExternalSSEntryMethod("chacha")
	case "wrong-exit-address":
		exit.Endpoint = "198.51.100.241"
		exit.External.Shadowsocks.Server = exit.Endpoint
	case "wrong-exit":
		exit.External.ExpectedPublicIP = "203.0.113.89"
	}
	if err := common.NormalizeRouterProfile(&entry); err != nil {
		t.Fatal("SS entry source rejected before native execution", err)
	}
	return &entry
}
func macOSExternalNativeSSEntryAuthority(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult) {
	t.Helper()
	if live.OuterTag != "external-entry" || live.OuterType != "shadowsocks" || live.PhysicalNetwork != "tcp+udp" || live.PhysicalAddress != p.entryAddress.String() || live.InnerDetour != "external-entry" || len(live.PhysicalDestinations) != 2 {
		t.Fatal("SS final acquired physical authority", live)
	}
	host := "198.51.100.240"
	if p.fault == "wrong-exit-address" {
		host = "198.51.100.241"
	}
	if live.InnerHost != host {
		t.Fatal("SS final changed captured inner host")
	}
	seen := map[string]bool{}
	for _, d := range live.PhysicalDestinations {
		if d.Host != p.physical.String() || d.Port != int(p.entryAddress.Port()) || d.Network != "tcp" && d.Network != "udp" || seen[d.Network] {
			t.Fatal("SS entry lost original two physical transports")
		}
		seen[d.Network] = true
	}
}
func macOSExternalNativeSSEntryProved(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult, observed macOSExternalPeerReply) {
	t.Helper()
	macOSExternalNativeSSEntryAuthority(t, p, live)
	entry := observed.ShadowsocksEntry
	dns, ipv6 := "tcp", "off"
	if p.policy == "always" {
		dns, ipv6 = "udp", "on"
	}
	if entry == nil || entry.AuthTCP != 0 || entry.AuthUDP != 0 || entry.PhysicalTCP < 2 || entry.Streams < 2 || entry.PublicReplies < 1 || observed.Connections < 1 || observed.Streams < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 || !live.Proof.EntryProven || live.Proof.EntryID != macOSExternalNativeEntryID(p) || live.Proof.EntryNodeID != "" || live.Proof.ExitID != "installed-macos-external" || live.Proof.IP != "203.0.113.88" || live.DNSProtocol != dns || live.DNSHost != "203.0.113.53" || live.DNSPort != 5353 || live.Network.MTU != 1376 || live.IPv6 != ipv6 || live.HomeLAN != (p.policy == "always") {
		t.Fatal("SS chain lost original entry/final proof or device policy")
	}
	if dns == "udp" && (entry.PhysicalUDP < 1 || entry.Packets < 1 || observed.PhysicalUDP < 1 || observed.Packets < 1) {
		t.Fatal("SS UDP DNS bypassed either encrypted peer")
	}
}
func macOSExternalNativeSSEntryRefused(t *testing.T, ctx context.Context, client *http.Client, p *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("SS entry negative did not complete actual refusal", status, failure, string(raw))
	}
	observed := p.stats(t)
	entry := observed.ShadowsocksEntry
	if entry == nil || entry.PhysicalTCP < 1 {
		t.Fatal("SS negative never reached independent encrypted entry")
	}
	switch p.fault {
	case "wrong-entry-key", "wrong-entry-method":
		if entry.AuthTCP == 0 || observed.AuthFailures != 0 || entry.Streams != 0 || entry.PublicReplies != 0 || observed.Connections != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("SS entry authentication negative acquired final path")
		}
	case "wrong-trust":
		if entry.Streams < 1 || entry.PublicReplies != 0 || observed.Connections != 0 || observed.DNSQueries != 0 {
			t.Fatal("SS entry TLS negative missed actual boundary")
		}
	case "wrong-entry-public":
		if entry.PublicReplies < 1 || observed.Connections != 0 || observed.DNSQueries != 0 {
			t.Fatal("SS entry public mismatch acquired final proof")
		}
	case "wrong-exit-key", "wrong-exit-method":
		if observed.AuthFailures == 0 || entry.AuthTCP != 0 || entry.AuthUDP != 0 || entry.PublicReplies < 1 || observed.Connections < 1 || observed.Streams != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("SS final authentication negative missed original provider")
		}
	case "wrong-exit-address":
		if entry.PublicReplies < 1 || observed.Connections != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 {
			t.Fatal("SS final route escaped entry's fixed routing")
		}
	case "wrong-dns":
		if entry.PublicReplies < 1 || observed.DNSQueries < 1 || observed.PublicReplies != 0 {
			t.Fatal("SS DNS negative missed selected resolver")
		}
	case "wrong-exit":
		if entry.PublicReplies < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 {
			t.Fatal("SS final mismatch missed real final proof")
		}
	default:
		t.Fatal("unknown SS entry negative")
	}
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired || retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present {
		t.Fatal("SS refusal lost original child/native cleanup", status, failure, string(raw))
	}
	macOSExternalNativeSSEntryAuthority(t, p, retired)
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}
