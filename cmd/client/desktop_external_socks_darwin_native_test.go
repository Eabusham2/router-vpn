//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
)

// These counters come from the independent authenticated SOCKS server. Its UDP
// listeners are created only by actual UDP ASSOCIATE and use distinct real ports.
// Original guardian/PF retirement is independently checked after the child joins.
func macOSExternalNativeSOCKSRelays(t *testing.T, peer *macOSExternalNativePeer, observed macOSExternalPeerReply) {
	t.Helper()
	if len(observed.SOCKSRelays) == 0 {
		t.Fatal("native SOCKS never negotiated its actual UDP relay")
	}
	for _, value := range observed.SOCKSRelays {
		relay, err := netip.ParseAddrPort(value)
		if err != nil || relay.String() != value || relay.Addr() != peer.physical || relay.Port() == 0 || relay == peer.address {
			t.Fatal("native SOCKS peer substituted a relay or reused its TCP control tuple", value, err)
		}
	}
}

func macOSExternalNativeSOCKSProved(t *testing.T, peer *macOSExternalNativePeer, live macOSExternalNativeResult, observed macOSExternalPeerReply) {
	t.Helper()
	expectedIPv6 := "off"
	if peer.policy == "always" {
		expectedIPv6 = "on"
	}
	if live.IPv6 != expectedIPv6 || live.HomeLAN != (peer.policy == "always") || live.DNSProtocol != "udp" || live.DNSHost != "203.0.113.53" ||
		live.DNSPort != 5353 || live.PhysicalNetwork != "tcp" || live.PhysicalAddress != peer.address.String() ||
		live.Baseline.Capture.Policy != peer.policy || observed.PhysicalUDP < 1 || observed.Packets < 1 || observed.SOCKSRejectedReplies != 0 {
		t.Fatal("SOCKS changed selected DNS, device policy or exact TCP/UDP physical ownership", live, observed)
	}
	macOSExternalNativeSOCKSRelays(t, peer, observed)
}

func macOSExternalNativeSOCKSRefused(t *testing.T, ctx context.Context, client *http.Client, peer *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("SOCKS negative did not complete actual native refusal", status, failure, string(raw))
	}
	observed := peer.stats(t)
	if observed.Connections < 1 {
		t.Fatal("SOCKS negative never reached its independent TCP control peer", observed)
	}
	switch peer.fault {
	case "wrong-password":
		if observed.AuthFailures < 1 || len(observed.SOCKSRelays) != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("unauthenticated SOCKS control acquired relay or proof authority", observed)
		}
	case "auth-downgrade", "relay-domain":
		if observed.SOCKSRejectedReplies < 1 || len(observed.SOCKSRelays) != 0 || observed.PhysicalUDP != 0 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("SOCKS accepted an unoffered authentication method or unresolved relay", observed)
		}
	case "control-eof":
		macOSExternalNativeSOCKSRelays(t, peer, observed)
		if observed.PhysicalUDP < 1 || observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("retired SOCKS control retained usable UDP or exit proof", observed)
		}
	case "wrong-dns":
		macOSExternalNativeSOCKSRelays(t, peer, observed)
		if observed.PhysicalUDP < 1 || observed.Packets < 1 || observed.DNSQueries < 1 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("SOCKS DNS refusal missed selected UDP DNS or reached exit proof", observed)
		}
	case "wrong-trust":
		if observed.DNSQueries < 1 || observed.Streams < 1 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("SOCKS TLS refusal missed selected DNS or admitted untrusted proof", observed)
		}
	case "wrong-exit":
		if observed.DNSQueries < 1 || observed.PublicAttempts < 1 || observed.PublicReplies < 1 {
			t.Fatal("SOCKS exit mismatch did not reach actual public proof", observed)
		}
	default:
		t.Fatal("unknown native SOCKS refusal")
	}
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired ||
		retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Capture.Session != retired.Session || retired.Baseline.Capture.Source != retired.Source ||
		retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present || retired.Protocol != "socks5" || retired.PhysicalNetwork != "tcp" || retired.PhysicalAddress != peer.address.String() {
		t.Fatal("SOCKS refusal lost its original joined control, relay, native child or PF owner", status, failure, string(raw))
	}
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}
