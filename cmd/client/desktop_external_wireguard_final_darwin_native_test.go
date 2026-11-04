//go:build darwin && routervpn_controller_privileged

package main

import (
	"strings"
	"testing"
)

var macOSExternalWireGuardFinalCases = []string{
	"wg-entry-wireguard", "wg-entry-wireguard-always",
	"awg-entry-wireguard-fast", "awg-entry-wireguard-fast-always",
	"awg-entry-wireguard-strong", "awg-entry-wireguard-strong-always",
	"wg-entry-wireguard-wrong-entry-key", "wg-entry-wireguard-wrong-entry-psk", "wg-entry-wireguard-wrong-entry-public",
	"wg-entry-wireguard-wrong-exit-key", "wg-entry-wireguard-wrong-exit-peer-key", "wg-entry-wireguard-wrong-exit-psk",
	"wg-entry-wireguard-wrong-exit-address", "wg-entry-wireguard-wrong-dns", "wg-entry-wireguard-wrong-trust", "wg-entry-wireguard-wrong-exit",
	"awg-entry-wireguard-fast-wrong-entry-parameters", "awg-entry-wireguard-strong-wrong-entry-parameters", "awg-entry-wireguard-strong-wrong-entry-psk",
	"awg-entry-wireguard-strong-wrong-exit-key", "awg-entry-wireguard-strong-wrong-exit-peer-key", "awg-entry-wireguard-strong-wrong-exit-psk",
}

func macOSExternalWireGuardFinalScenario(scenario string) (variant, fault string, found bool) {
	for _, candidate := range macOSExternalWireGuardFinalCases {
		if scenario != candidate {
			continue
		}
		variant, prefix := "wireguard", "wg-entry-wireguard"
		if strings.HasPrefix(scenario, "awg-entry-") {
			variant = "strong"
			if strings.Contains(scenario, "-fast") {
				variant = "fast"
			}
			prefix = "awg-entry-wireguard-" + variant
		}
		suffix := strings.TrimPrefix(scenario, prefix)
		if suffix != "" && suffix != "-always" {
			fault = strings.TrimPrefix(suffix, "-")
		}
		return variant, fault, true
	}
	return "", "", false
}

func macOSExternalNativeWireGuardFinalRefusalWitness(t *testing.T, p *macOSExternalNativePeer, entry *macOSExternalPacketEntryReceipt, observed macOSExternalPeerReply) {
	t.Helper()
	if observed.Connections != 0 || observed.AuthFailures != 0 {
		t.Fatal("packet final borrowed a proxy credential witness")
	}
	switch p.fault {
	case "wrong-entry-key", "wrong-entry-psk", "wrong-entry-parameters":
		if entry.Streams != 0 || entry.Packets != 0 || entry.PublicReplies != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("wrong original entry reached the independent final WireGuard owner")
		}
	// Native packet endpoints may authenticate an idle keepalive during startup.
	// Entry proof refusal must still prevent all final DNS/public plaintext.
	case "wrong-trust":
		if entry.Streams < 1 || entry.PublicReplies != 0 || observed.Streams != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("entry trust refusal reached the independent final WireGuard owner")
		}
	case "wrong-entry-public":
		if entry.PublicReplies < 1 || observed.Streams != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("entry proof mismatch reached final DNS/public plaintext")
		}
	case "wrong-exit-address":
		if entry.PublicReplies < 1 || observed.PhysicalUDP != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("unowned final destination escaped the entry's fixed decrypted route")
		}
	default:
		if entry.PublicReplies < 1 || entry.Packets < 1 || observed.PhysicalUDP < 1 {
			t.Fatal("final refusal never reached its independent encrypted peer through the proved entry")
		}
		switch p.fault {
		case "wrong-exit-key", "wrong-exit-peer-key", "wrong-exit-psk":
			if observed.Streams != 0 || observed.Packets != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("invalid final key acquired plaintext DNS or public proof")
			}
		case "wrong-dns":
			if observed.Packets < 1 || observed.DNSQueries < 1 || observed.PublicReplies != 0 {
				t.Fatal("final refusal missed its selected independent resolver")
			}
		case "wrong-exit":
			if observed.Streams < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 {
				t.Fatal("final mismatch missed actual final public proof")
			}
		default:
			t.Fatal("unowned two-packet-endpoint refusal")
		}
	}
}
