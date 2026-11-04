//go:build darwin && routervpn_controller_privileged

package main

import (
	"net/netip"
	"strings"
	"testing"
)

var macOSExternalSOCKSEntryCases = []string{
	"wg-entry-socks5",
	"wg-entry-socks5-always",
	"awg-entry-socks5-fast",
	"awg-entry-socks5-fast-always",
	"awg-entry-socks5-strong",
	"awg-entry-socks5-strong-always",
	"wg-entry-socks5-wrong-entry-key",
	"wg-entry-socks5-wrong-entry-public",
	"wg-entry-socks5-wrong-exit-username",
	"wg-entry-socks5-wrong-exit-key",
	"wg-entry-socks5-auth-downgrade",
	"wg-entry-socks5-relay-domain",
	"wg-entry-socks5-control-eof",
	"wg-entry-socks5-relay-route",
	"wg-entry-socks5-wrong-exit-address",
	"wg-entry-socks5-wrong-dns",
	"wg-entry-socks5-wrong-trust",
	"wg-entry-socks5-wrong-exit",
	"awg-entry-socks5-fast-wrong-entry-parameters",
	"awg-entry-socks5-strong-wrong-entry-parameters",
	"awg-entry-socks5-strong-wrong-entry-psk",
}

func macOSExternalSOCKSEntryScenario(scenario string) (variant, fault string, found bool) {
	for _, candidate := range macOSExternalSOCKSEntryCases {
		if scenario != candidate {
			continue
		}
		variant, prefix := "wireguard", "wg-entry-socks5"
		if strings.HasPrefix(scenario, "awg-entry-") {
			variant = "strong"
			if strings.Contains(scenario, "-fast") {
				variant = "fast"
			}
			prefix = "awg-entry-socks5-" + variant
		}
		suffix := strings.TrimPrefix(scenario, prefix)
		if suffix != "" && suffix != "-always" {
			fault = strings.TrimPrefix(suffix, "-")
		}
		return variant, fault, true
	}
	return "", "", false
}
func macOSExternalNativeSOCKSEntryRelays(t *testing.T, p *macOSExternalNativePeer, observed macOSExternalPeerReply) {
	t.Helper()
	if len(observed.SOCKSRelays) == 0 {
		t.Fatal("tunneled SOCKS never authenticated an actual UDP association")
	}
	for _, raw := range observed.SOCKSRelays {
		relay, err := netip.ParseAddrPort(raw)
		if err != nil || relay.String() != raw || relay.Addr().String() != "198.51.100.240" || relay.Port() == 0 || relay == p.address {
			t.Fatal("tunneled SOCKS replaced its independent virtual relay", raw)
		}
	}
}
func macOSExternalNativeSOCKSEntryRefusalWitness(t *testing.T, p *macOSExternalNativePeer, entry *macOSExternalPacketEntryReceipt, observed macOSExternalPeerReply) {
	t.Helper()
	switch p.fault {
	case "wrong-entry-key", "wrong-entry-psk", "wrong-entry-parameters":
		if entry.Streams != 0 || entry.Packets != 0 || entry.PublicReplies != 0 || observed.Connections != 0 || len(observed.SOCKSRelays) != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
			t.Fatal("wrong encrypted entry acquired SOCKS authority")
		}
	case "wrong-trust":
		if entry.Streams < 1 || entry.PublicReplies != 0 || entry.Packets != 0 || observed.Connections != 0 {
			t.Fatal("entry TLS trust failure reached SOCKS control")
		}
	case "wrong-entry-public", "wrong-exit-address":
		if entry.PublicReplies < 1 || entry.Packets != 0 || observed.Connections != 0 || observed.PhysicalUDP != 0 {
			t.Fatal("entry proof/control route rejection reached final SOCKS")
		}
	default:
		if entry.PublicReplies < 1 || entry.Streams < 2 || observed.Connections < 1 {
			t.Fatal("SOCKS negative missed its independent authenticated control")
		}
		switch p.fault {
		case "wrong-exit-key", "wrong-exit-username":
			if observed.AuthFailures < 1 || len(observed.SOCKSRelays) != 0 || entry.Packets != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("unauthenticated tunneled SOCKS acquired relay authority")
			}
		case "auth-downgrade", "relay-domain":
			if observed.SOCKSRejectedReplies < 1 || len(observed.SOCKSRelays) != 0 || entry.Packets != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("tunneled SOCKS accepted invalid authentication or domain relay")
			}
		case "relay-route":
			macOSExternalNativeSOCKSEntryRelays(t, p, observed)
			if entry.Packets != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("unowned negotiated relay bypassed the encrypted entry route")
			}
		case "control-eof":
			macOSExternalNativeSOCKSEntryRelays(t, p, observed)
			if entry.Packets < 1 || observed.PhysicalUDP < 1 || observed.DNSQueries != 0 || observed.PublicReplies != 0 {
				t.Fatal("retired original SOCKS control retained useful relay/proof authority")
			}
		case "wrong-dns":
			macOSExternalNativeSOCKSEntryRelays(t, p, observed)
			if entry.Packets < 1 || observed.PhysicalUDP < 1 || observed.Packets < 1 || observed.DNSQueries < 1 || observed.PublicReplies != 0 {
				t.Fatal("SOCKS DNS refusal missed selected authenticated UDP resolver")
			}
		case "wrong-exit":
			macOSExternalNativeSOCKSEntryRelays(t, p, observed)
			if entry.Packets < 1 || observed.PhysicalUDP < 1 || observed.DNSQueries < 1 || observed.PublicReplies < 1 {
				t.Fatal("SOCKS public mismatch missed actual final proof")
			}
		default:
			t.Fatal("unowned tunneled SOCKS negative")
		}
	}
}
