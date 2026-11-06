//go:build darwin && routervpn_controller_privileged

package main

import (
	"net/netip"
	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/multihoprelay"
	"strings"
	"testing"
)

var macOSExternalSSLayerCases = []string{
	"ss-entry-aes256-ss-chacha-layers00-always",
	"ss-entry-aes256-ss-chacha-layers01-always",
	"ss-entry-aes256-ss-chacha-layers02-always",
	"ss-entry-aes256-ss-chacha-layers10-always",
	"ss-entry-aes256-ss-chacha-layers11-always",
	"ss-entry-aes256-ss-chacha-layers12-always",
	"ss-entry-aes256-ss-chacha-layers20-always",
	"ss-entry-aes256-ss-chacha-layers21-always",
	"ss-entry-aes256-ss-chacha-layers22-always",
	"ss-entry-aes256-ss-chacha-layers22-wrong-entry-layer",
	"ss-entry-aes256-ss-chacha-layers22-wrong-final-layer",
	"ss-entry-aes256-ss-chacha-layers22-wrong-entry-whitening",
	"ss-entry-aes256-ss-chacha-layers22-wrong-final-whitening",
	"ss-entry-aes256-ss-chacha-layers22-wrong-entry-public",
	"ss-entry-aes256-ss-chacha-layers22-wrong-dns",
	"ss-entry-aes256-ss-chacha-layers22-wrong-exit",
	"ss-entry-aes256-ss-chacha-layers22-wrong-trust",
}

type macOSSSLayerSelection struct {
	mode, key string
	address   netip.AddrPort
}

func macOSSSLayerToken(scenario string) (int, int, bool) {
	parts := strings.Split(scenario, "-")
	if len(parts) < 6 || !strings.HasPrefix(parts[5], "layers") {
		return 0, 0, false
	}
	digits := strings.TrimPrefix(parts[5], "layers")
	if len(digits) != 2 || digits[0] < '0' || digits[0] > '2' || digits[1] < '0' || digits[1] > '2' {
		return 0, 0, false
	}
	return int(digits[0] - '0'), int(digits[1] - '0'), true
}
func macOSSSLayerPrepare(t *testing.T, p *macOSExternalNativePeer) {
	a, b, ok := macOSSSLayerToken(p.name)
	if !ok {
		return
	}
	modes := []string{common.StartLayerOff, common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR}
	p.ssEntryLayer = macOSSSLayerSelection{mode: modes[a], key: macOSExternalNativeSSKey(t, common.StartLayerAES256GCMTransport)}
	p.ssFinalLayer = macOSSSLayerSelection{mode: modes[b], key: macOSExternalNativeSSKey(t, common.StartLayerAES256GCMTransport)}
}
func macOSSSLayerRequest(p *macOSExternalNativePeer, request map[string]any) {
	for _, item := range []struct {
		name  string
		layer macOSSSLayerSelection
	}{{"ss_entry_layer", p.ssEntryLayer}, {"ss_final_layer", p.ssFinalLayer}} {
		if item.layer.mode == "" || item.layer.mode == common.StartLayerOff {
			continue
		}
		fault := ""
		if item.name == "ss_entry_layer" && p.fault == "wrong-entry-whitening" || item.name == "ss_final_layer" && p.fault == "wrong-final-whitening" {
			fault = "whitening"
		}
		request[item.name] = map[string]any{"mode": item.layer.mode, "password": item.layer.key, "fault": fault}
	}
}
func macOSSSLayerRead(t *testing.T, p *macOSExternalNativePeer, reply macOSExternalPeerReply) {
	t.Helper()
	for _, item := range []struct {
		layer *macOSSSLayerSelection
		r     *macOSExternalSSEntryReceipt
		entry bool
	}{{&p.ssEntryLayer, reply.SSEntryLayer, true}, {&p.ssFinalLayer, reply.SSFinalLayer, false}} {
		layer, r := item.layer, item.r
		if layer.mode == "" || layer.mode == common.StartLayerOff {
			if r != nil {
				t.Fatal("Off acquired SS wrapper")
			}
			continue
		}
		if !p.ssEntry || r == nil || r.Method != common.StartLayerAES256GCMTransport {
			t.Fatal("unrequested SS layer receipt")
		}
		address, err := netip.ParseAddrPort(r.Address)
		if err != nil || address.Port() == 0 || item.entry && address.Addr() != p.physical || !item.entry && !address.Addr().IsLoopback() || layer.address.IsValid() && layer.address != address {
			t.Fatal("SS layer changed original captured listener")
		}
		if item.entry && layer.mode == common.StartLayerAES256GCMXOR && address.Port() != 8389 {
			t.Fatal("SS entry XOR port changed")
		}
		layer.address = address
	}
}
func macOSSSLayerProfiles(t *testing.T, p *macOSExternalNativePeer, entry, final *common.RouterProfile) {
	t.Helper()
	for i, item := range []struct {
		profile *common.RouterProfile
		layer   macOSSSLayerSelection
		private string
	}{{entry, p.ssEntryLayer, "10.94.0.1"}, {final, p.ssFinalLayer, "10.93.0.1"}} {
		if item.layer.mode == "" || item.layer.mode == common.StartLayerOff {
			continue
		}
		port := int(item.layer.address.Port())
		if i == 1 {
			port = int(p.address.Port())
			item.profile.External.Shadowsocks.Port = 8388
		}
		item.profile.StartLayer = item.layer.mode
		item.profile.External.StartLayer = &common.ExternalStartLayer{Mode: item.layer.mode, API: "http://" + item.private + ":8787", Transport: map[string]any{"type": "shadowsocks", "tag": "captured-layer", "server": item.profile.External.Shadowsocks.Server, "server_port": port, "method": common.StartLayerAES256GCMTransport, "password": item.layer.key}}
		if i == 0 && p.fault == "wrong-entry-layer" || i == 1 && p.fault == "wrong-final-layer" {
			item.profile.External.StartLayer.Transport["password"] = macOSExternalNativeSSKey(t, common.StartLayerAES256GCMTransport)
		}
	}
}
func macOSSSLayerAuthority(t *testing.T, p *macOSExternalNativePeer, live macOSExternalNativeResult) {
	tag, kind, address := "external-entry", "shadowsocks", p.entryAddress
	if p.ssEntryLayer.mode != "" && p.ssEntryLayer.mode != common.StartLayerOff {
		tag = mobilemultihop.ExternalEntryStartLayerTag
		address = p.ssEntryLayer.address
		if p.ssEntryLayer.mode == common.StartLayerAES256GCMXOR {
			kind = "routervpn-aes-xor"
		}
	}
	detour, host := "external-entry", "198.51.100.240"
	if p.ssFinalLayer.mode != "" && p.ssFinalLayer.mode != common.StartLayerOff {
		detour, host = multihoprelay.ExitStartLayerTag, "10.93.0.1"
	}
	if live.OuterTag != tag || live.OuterType != kind || live.PhysicalNetwork != "tcp+udp" || live.PhysicalAddress != address.String() || live.InnerDetour != detour || live.InnerHost != host || len(live.PhysicalDestinations) != 2 {
		t.Fatal("SS layers changed original physical root or private final", live)
	}
	seen := map[string]bool{}
	for _, d := range live.PhysicalDestinations {
		if d.Host != address.Addr().String() || d.Port != int(address.Port()) || d.Network != "tcp" && d.Network != "udp" || seen[d.Network] {
			t.Fatal("SS inner acquired outer grant")
		}
		seen[d.Network] = true
	}
}
func macOSSSLayerProved(t *testing.T, p *macOSExternalNativePeer, reply macOSExternalPeerReply) {
	for _, item := range []struct {
		layer macOSSSLayerSelection
		r     *macOSExternalSSEntryReceipt
	}{{p.ssEntryLayer, reply.SSEntryLayer}, {p.ssFinalLayer, reply.SSFinalLayer}} {
		if item.layer.mode == "" || item.layer.mode == common.StartLayerOff {
			continue
		}
		r := item.r
		if r == nil || r.AuthTCP != 0 || r.AuthUDP != 0 || r.PhysicalTCP == 0 || r.Streams == 0 || p.policy == "always" && (r.PhysicalUDP == 0 || r.Packets == 0) {
			t.Fatal("SS layer never independently decrypted both transports", reply)
		}
	}
}
func macOSSSLayerRefused(t *testing.T, p *macOSExternalNativePeer, reply macOSExternalPeerReply) {
	entry := p.fault == "wrong-entry-layer" || p.fault == "wrong-entry-whitening"
	r := reply.SSFinalLayer
	if entry {
		r = reply.SSEntryLayer
	}
	if r == nil || r.AuthTCP+r.AuthUDP == 0 || r.Streams != 0 || r.Packets != 0 || reply.Streams != 0 || reply.Packets != 0 || reply.DNSQueries != 0 || reply.PublicReplies != 0 {
		t.Fatal("SS layer refusal lacked actual independent authentication", reply)
	}
	if entry && (reply.ShadowsocksEntry.PhysicalTCP != 0 || reply.ShadowsocksEntry.PhysicalUDP != 0 || reply.Connections != 0 || reply.PhysicalUDP != 0) {
		t.Fatal("failed entry layer reached inner owner")
	}
	if !entry && reply.ShadowsocksEntry.PublicReplies == 0 {
		t.Fatal("final layer refusal bypassed independent entry proof")
	}
}
