//go:build darwin && routervpn_controller_privileged

package main

import (
	"net/netip"
	"router-vpn/internal/common"
	"strings"
	"testing"
)

// Every admitted scenario names one original packet entry and one independently
// keyed final layer. The unlayered inventory remains unchanged.
var macOSExternalHysteriaLayerEntryCases = []string{
	"wg-entry-hysteria2-aes",
	"wg-entry-hysteria2-aes-always",
	"wg-entry-hysteria2-aes-xor",
	"wg-entry-hysteria2-aes-xor-always",
	"awg-entry-hysteria2-fast-aes",
	"awg-entry-hysteria2-fast-aes-always",
	"awg-entry-hysteria2-fast-aes-xor",
	"awg-entry-hysteria2-fast-aes-xor-always",
	"awg-entry-hysteria2-strong-aes",
	"awg-entry-hysteria2-strong-aes-always",
	"awg-entry-hysteria2-strong-aes-xor",
	"awg-entry-hysteria2-strong-aes-xor-always",
	"wg-entry-hysteria2-aes-wrong-entry-key",
	"wg-entry-hysteria2-aes-wrong-layer-key",
	"wg-entry-hysteria2-aes-wrong-inner-key",
	"wg-entry-hysteria2-aes-wrong-dns",
	"wg-entry-hysteria2-aes-wrong-trust",
	"wg-entry-hysteria2-aes-wrong-exit",
	"wg-entry-hysteria2-aes-xor-wrong-entry-public",
	"wg-entry-hysteria2-aes-xor-wrong-layer-key",
	"wg-entry-hysteria2-aes-xor-wrong-inner-key",
	"wg-entry-hysteria2-aes-xor-wrong-whitening",
	"wg-entry-hysteria2-aes-xor-wrong-layer-route",
	"awg-entry-hysteria2-fast-aes-wrong-entry-parameters",
	"awg-entry-hysteria2-fast-aes-wrong-layer-key",
	"awg-entry-hysteria2-strong-aes-xor-wrong-entry-psk",
	"awg-entry-hysteria2-strong-aes-xor-wrong-layer-key",
	"awg-entry-hysteria2-strong-aes-xor-wrong-whitening",
}

func macOSExternalHysteriaLayerEntryScenario(scenario string) (variant, layer, fault string, found bool) {
	for _, candidate := range macOSExternalHysteriaLayerEntryCases {
		if candidate != scenario {
			continue
		}
		variant, layer = "wireguard", common.StartLayerAES256GCM
		if strings.HasPrefix(scenario, "awg-entry-") {
			variant = "strong"
			if strings.Contains(scenario, "-fast-") {
				variant = "fast"
			}
		}
		if strings.Contains(scenario, "-aes-xor") {
			layer = common.StartLayerAES256GCMXOR
		}
		if index := strings.Index(scenario, "-wrong-"); index >= 0 {
			fault = scenario[index+1:]
		}
		return variant, layer, fault, true
	}
	return "", "", "", false
}
func macOSExternalNativeLayerInnerAddress(p *macOSExternalNativePeer) netip.Addr {
	if p.packetEntry {
		return netip.MustParseAddr("127.0.0.1")
	}
	return p.physical
}
func macOSExternalNativePacketEntryFinalAddress(p *macOSExternalNativePeer) string {
	if p.layer == common.StartLayerAES256GCMXOR {
		return "198.51.100.240:8389"
	}
	return "198.51.100.240:8388"
}
func macOSExternalNativePacketEntryFinalHost(p *macOSExternalNativePeer) string {
	if p.layer != "" {
		return "10.93.0.1"
	}
	return "198.51.100.240"
}
func macOSExternalNativePacketEntryFinalDetour(p *macOSExternalNativePeer) string {
	if p.layer != "" {
		return "routervpn-exit-start-layer"
	}
	return "external-entry"
}
func macOSExternalNativePacketEntryLayerAuthority(t *testing.T, p *macOSExternalNativePeer, value macOSExternalNativeResult, kind string) {
	t.Helper()
	layerHost := "198.51.100.240"
	if p.fault == "wrong-layer-route" {
		layerHost = "198.51.100.241"
	}
	expected, _ := netip.ParseAddrPort(macOSExternalNativePacketEntryFinalAddress(p))
	if value.Layer != p.layer || value.OuterTag != "external-entry" || value.OuterType != macOSExternalNativeEntryType(p) ||
		value.PhysicalNetwork != "udp" || value.PhysicalAddress != p.entryAddress.String() ||
		value.LayerType != kind || value.LayerHost != layerHost || value.LayerPort != int(expected.Port()) || value.LayerDetour != "external-entry" ||
		value.InnerHost != "10.93.0.1" || value.InnerDetour != "routervpn-exit-start-layer" {
		t.Fatal("layered packet entry lost its original sole physical root or captured private final path", value)
	}
}
func macOSExternalNativeHysteriaLayerEntryRefusalWitness(t *testing.T, p *macOSExternalNativePeer, entry *macOSExternalPacketEntryReceipt, observed macOSExternalPeerReply) {
	t.Helper()
	layer := observed.Layer
	if layer == nil || layer.Mode != p.layer || observed.Connections != 0 {
		t.Fatal("layered QUIC negative lost original independent peers")
	}
	noFinal := func() bool {
		return layer.Raw == 0 && layer.Authenticated == 0 && layer.Forwarded == 0 && layer.Rejected == 0 && observed.Streams == 0 && observed.Packets == 0 && observed.DNSQueries == 0 && observed.PublicReplies == 0
	}
	switch p.fault {
	case "wrong-entry-key", "wrong-entry-psk", "wrong-entry-parameters":
		if entry.Streams != 0 || entry.Packets != 0 || entry.PublicReplies != 0 || !noFinal() {
			t.Fatal("wrong original entry reached final layer")
		}
	case "wrong-trust":
		if entry.Streams < 1 || entry.PublicReplies != 0 || entry.Packets != 0 || !noFinal() {
			t.Fatal("entry trust failure reached final layer")
		}
	case "wrong-entry-public", "wrong-layer-route":
		if entry.PublicReplies < 1 || entry.Packets != 0 || !noFinal() {
			t.Fatal("entry identity or exact layer route failure reached final carrier")
		}
	case "wrong-layer-key", "wrong-whitening":
		if entry.PublicReplies < 1 || entry.Packets < 1 || layer.Raw < 1 || layer.Rejected < 1 || layer.Authenticated != 0 || layer.Forwarded != 0 || observed.Streams != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("outer key/XOR negative did not stop at the independent layer")
		}
	case "wrong-inner-key":
		if entry.PublicReplies < 1 || entry.Packets < 1 || layer.Raw < 1 || layer.Authenticated < 1 || layer.Forwarded < 1 || layer.Rejected != 0 || observed.Streams != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("inner HY2 key negative missed actual authenticated outer layer")
		}
	case "wrong-dns", "wrong-exit":
		if entry.PublicReplies < 1 || entry.Packets < 1 || layer.Authenticated < 1 || layer.Forwarded < 1 || layer.Rejected != 0 || observed.Packets < 1 || observed.DNSQueries < 1 || p.fault == "wrong-dns" && observed.PublicReplies != 0 || p.fault == "wrong-exit" && observed.PublicReplies < 1 {
			t.Fatal("final DNS/public negative missed actual two-hop layered path")
		}
	default:
		t.Fatal("unowned layered-entry negative")
	}
}
