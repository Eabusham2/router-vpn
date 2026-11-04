//go:build darwin && routervpn_controller_privileged

package main

import (
	"strings"
	"testing"
)

// Exact native scenarios retain one unlayered final QUIC endpoint.
var macOSExternalHysteriaEntryCases = []string{
	"wg-entry-hysteria2",
	"wg-entry-hysteria2-always",
	"awg-entry-hysteria2-fast",
	"awg-entry-hysteria2-fast-always",
	"awg-entry-hysteria2-strong",
	"awg-entry-hysteria2-strong-always",
	"wg-entry-hysteria2-wrong-entry-key",
	"wg-entry-hysteria2-wrong-entry-public",
	"wg-entry-hysteria2-wrong-exit-key",
	"wg-entry-hysteria2-wrong-exit-server-name",
	"wg-entry-hysteria2-wrong-exit-address",
	"wg-entry-hysteria2-wrong-dns",
	"wg-entry-hysteria2-wrong-trust",
	"wg-entry-hysteria2-wrong-exit",
	"awg-entry-hysteria2-fast-wrong-entry-parameters",
	"awg-entry-hysteria2-strong-wrong-entry-parameters",
	"awg-entry-hysteria2-strong-wrong-entry-psk",
}

func macOSExternalHysteriaEntryScenario(scenario string) (variant, fault string, found bool) {
	for _, candidate := range macOSExternalHysteriaEntryCases {
		if candidate != scenario {
			continue
		}
		variant = "wireguard"
		if strings.HasPrefix(scenario, "awg-entry-") {
			variant = "strong"
			if strings.Contains(scenario, "-fast") {
				variant = "fast"
			}
		}
		if index := strings.Index(scenario, "-wrong-"); index >= 0 {
			fault = scenario[index+1:]
		}
		return variant, fault, true
	}
	return "", "", false
}

func macOSExternalNativeHysteriaEntryRefusalWitness(t *testing.T, p *macOSExternalNativePeer, entry *macOSExternalPacketEntryReceipt, observed macOSExternalPeerReply) {
	t.Helper()
	if observed.Connections != 0 {
		t.Fatal("QUIC exit acquired an unrequested TCP listener")
	}
	switch p.fault {
	case "wrong-entry-key", "wrong-entry-psk", "wrong-entry-parameters":
		if entry.Streams != 0 || entry.Packets != 0 || entry.PublicReplies != 0 || observed.PhysicalUDP != 0 || observed.Streams != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("wrong packet entry acquired final QUIC authority")
		}
	case "wrong-trust":
		if entry.Streams < 1 || entry.PublicReplies != 0 || entry.Packets != 0 || observed.PhysicalUDP != 0 {
			t.Fatal("entry TLS trust failure reached final QUIC")
		}
	case "wrong-entry-public", "wrong-exit-address":
		if entry.PublicReplies < 1 || entry.Packets != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("entry proof/virtual route rejection reached an unowned QUIC tuple")
		}
	case "wrong-exit-key", "wrong-exit-server-name":
		if entry.PublicReplies < 1 || entry.Packets < 1 || observed.PhysicalUDP < 1 || observed.Streams != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("QUIC credential/TLS negative missed its independent encrypted final peer")
		}
	case "wrong-dns":
		if entry.PublicReplies < 1 || entry.Packets < 1 || observed.PhysicalUDP < 1 || observed.Packets < 1 || observed.DNSQueries < 1 || observed.PublicReplies != 0 {
			t.Fatal("QUIC DNS refusal missed its selected authenticated UDP resolver")
		}
	case "wrong-exit":
		if entry.PublicReplies < 1 || entry.Packets < 1 || observed.PhysicalUDP < 1 || observed.Packets < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 {
			t.Fatal("QUIC public identity refusal missed actual final proof")
		}
	default:
		t.Fatal("unowned captured QUIC negative")
	}
}
