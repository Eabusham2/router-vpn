//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"router-vpn/internal/awgpolicy"
)

// The labels select two independent captured test imports. They never select a
// preset in the shipping compiler or replace an imported eleven-field map.
func macOSExternalNativeAmneziaParameters(t *testing.T, variant string) map[string]string {
	t.Helper()
	parameters := map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32",
		"h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
	if variant == "fast" {
		parameters["jc"], parameters["jmin"], parameters["jmax"], parameters["s4"] = "0", "20", "40", "8"
	} else if variant != "strong" {
		t.Fatal("unknown captured AWG variant")
	}
	if _, err := awgpolicy.ParametersUAPI(parameters); err != nil {
		t.Fatal(err)
	}
	return parameters
}
func macOSExternalNativeAmneziaDigest(t *testing.T, variant string) string {
	t.Helper()
	parameters, err := awgpolicy.ParametersUAPI(macOSExternalNativeAmneziaParameters(t, variant))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parameters))
	return hex.EncodeToString(digest[:])
}

func macOSExternalNativeAmneziaRefused(t *testing.T, ctx context.Context, client *http.Client, peer *macOSExternalNativePeer, status int, raw []byte, failure error, controllerPID int, before map[int]macOSExternalTunnelIdentity) {
	t.Helper()
	if failure != nil || status != http.StatusConflict && status != http.StatusBadGateway {
		t.Fatal("AmneziaWG negative did not complete actual native refusal", status, failure, string(raw))
	}
	observed := peer.stats(t) // Every reply checks actual AWG UAPI readback, including zero Jc.
	if observed.PhysicalUDP < 1 {
		t.Fatal("AmneziaWG negative never reached its independent encrypted peer", observed)
	}
	switch peer.fault {
	case "wrong-client-key", "wrong-psk", "wrong-parameters":
		if observed.DNSQueries != 0 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 || observed.Streams != 0 || observed.Packets != 0 {
			t.Fatal("AWG mismatched keys or parameters acquired inner proof", observed)
		}
	case "wrong-dns":
		if observed.DNSQueries < 1 || observed.Packets < 1 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("AWG DNS refusal missed selected DNS or reached exit", observed)
		}
	case "wrong-trust":
		if observed.DNSQueries < 1 || observed.Streams < 1 || observed.PublicAttempts != 0 || observed.PublicReplies != 0 {
			t.Fatal("AWG TLS refusal missed TLS or admitted untrusted proof", observed)
		}
	case "wrong-exit":
		if observed.DNSQueries < 1 || observed.PublicAttempts < 1 || observed.PublicReplies < 1 {
			t.Fatal("AWG exit mismatch did not reach actual public proof", observed)
		}
	default:
		t.Fatal("unknown native AWG refusal")
	}
	status, raw, failure = macOSExternalNativeHTTP(ctx, client, http.MethodGet, "/api/native-external-observation", "")
	var retired macOSExternalNativeResult
	if failure != nil || status != http.StatusOK || decodeRelayControlJSON(raw, &retired) != nil || !retired.Closed || retired.Connected || !retired.NativeJoined || !retired.WorkspaceRetired ||
		retired.ProcessID <= 0 || retired.ProcessID == controllerPID || retired.Baseline == nil || retired.Baseline.Capture.Session != retired.Session || retired.Baseline.Capture.Source != retired.Source ||
		retired.Baseline.Phase != "retired" || retired.Baseline.Baseline.Present || retired.Protocol != "amneziawg" || retired.PhysicalNetwork != "udp" || retired.PhysicalAddress != peer.address.String() {
		t.Fatal("AWG refusal lost original joined native source, child, PF or UDP owner", status, failure, string(raw))
	}
	macOSExternalNativeRetiredKernel(t, ctx, retired.Baseline.Token, before)
}
