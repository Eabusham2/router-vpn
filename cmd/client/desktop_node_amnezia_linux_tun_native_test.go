//go:build linux && routervpn_controller_privileged

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"router-vpn/internal/awgpolicy"
)

// These explicit Off scenarios use the pinned real AWG device, including its
// complete captured parameters. They retain all installed native host checks.
var linuxHostTUNAmneziaCases = []string{
	"awg2-fast-public-connect", "awg2-fast-home-lan", "awg2-fast-wrong-key", "awg2-fast-wrong-header", "awg2-fast-wrong-padding",
	"awg2-fast-resolver-failure", "awg2-fast-wrong-node", "awg2-fast-active-network-change", "awg2-fast-cancelled-proof",
	"awg2-fast-restore-sealed", "awg2-fast-always", "awg2-fast-cover-connect", "awg2-fast-cover-restore", "awg2-fast-mtu-rollback", "awg2-fast-mtu-commit",
	"awg2-strong-public-connect", "awg2-strong-home-lan", "awg2-strong-wrong-key", "awg2-strong-wrong-header", "awg2-strong-wrong-padding",
	"awg2-strong-resolver-failure", "awg2-strong-wrong-node", "awg2-strong-active-network-change", "awg2-strong-cancelled-proof",
	"awg2-strong-restore-sealed", "awg2-strong-always", "awg2-strong-cover-connect", "awg2-strong-cover-restore", "awg2-strong-mtu-rollback", "awg2-strong-mtu-commit",
}

func linuxHostTUNAmneziaCase(scenario string) bool {
	for _, value := range linuxHostTUNAmneziaCases {
		if value == scenario {
			return true
		}
	}
	return linuxHostTUNAmneziaLayerCase(scenario)
}

func linuxHostTUNIsAmnezia(mode string) bool { return awgpolicy.IsMode(mode) }

func linuxHostTUNAmneziaMode(scenario string) string {
	if !linuxHostTUNAmneziaCase(scenario) {
		return ""
	}
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		if strings.HasPrefix(scenario, mode+"-") {
			return mode
		}
	}
	return ""
}

func linuxHostTUNAmneziaParameters(t *testing.T, mode string) map[string]string {
	t.Helper()
	if !awgpolicy.IsMode(mode) {
		t.Fatal("installed AWG peer has no captured mode")
	}
	parameters := map[string]string{"jc": "3", "jmin": "40", "jmax": "900", "s1": "56", "s2": "48", "s3": "24", "s4": "32",
		"h1": "10000000-19999999", "h2": "20000000-29999999", "h3": "30000000-39999999", "h4": "40000000-49999999"}
	if mode == "awg2-strong" {
		parameters["jc"], parameters["jmax"] = "8", "1200"
	}
	return parameters
}

func linuxHostTUNAmneziaDigest(t *testing.T, parameters map[string]string) string {
	t.Helper()
	ipc, err := awgpolicy.ParametersUAPI(parameters)
	if err != nil {
		t.Fatal("installed AWG lost its bounded native parameters", err)
	}
	digest := sha256.Sum256([]byte(ipc))
	return hex.EncodeToString(digest[:])
}

func linuxHostTUNAmneziaAsset(t *testing.T, peer *linuxHostTUNPeer, scenario string) []byte {
	t.Helper()
	if !linuxHostTUNAmneziaCase(scenario) || linuxHostTUNAmneziaMode(scenario) != peer.mode || peer.layer != linuxHostTUNAmneziaLayer(scenario) ||
		peer.parametersSHA256 == "" || linuxHostTUNAmneziaDigest(t, peer.parameters) != peer.parametersSHA256 {
		t.Fatal("installed AWG lost its original complete peer/source capture")
	}
	parameters := make(map[string]string, len(peer.parameters))
	for name, value := range peer.parameters {
		parameters[name] = value
	}
	private, psk := peer.clientKey, peer.password
	switch linuxHostTUNAction(scenario) {
	case "wrong-key":
		private = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))
	case "wrong-psk":
		psk = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x28}, 32))
	case "wrong-header":
		parameters["h1"] = "50000000-59999999"
	case "wrong-padding":
		parameters["s1"] = "57"
	}
	ipc, err := awgpolicy.ParametersUAPI(parameters)
	if err != nil {
		t.Fatal("installed AWG negative source became malformed rather than a real mismatched native peer", err)
	}
	endpoint := peer.address
	if peer.layer != "" {
		endpoint = peer.baseAddress
	}
	return []byte(fmt.Sprintf("[Interface]\nAddress=10.78.0.2/32,fd78:78::2/128\nPrivateKey=%s\nDNS=192.168.50.133\nMTU=1280\n%s[Peer]\nPublicKey=%s\nPresharedKey=%s\nEndpoint=%s\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n",
		private, ipc, peer.serverPublic, psk, endpoint.String()))
}
