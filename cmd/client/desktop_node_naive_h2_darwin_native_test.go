//go:build darwin && routervpn_controller_privileged

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopUnixNaiveH2NativeInventory(t *testing.T) {
	raw, err := json.Marshal(macOSPairedNaiveH2NativeCases())
	if err != nil {
		t.Fatal(err)
	}
	t.Log("compiled installed Naive H2 cases: " + string(raw))
}

func macOSPairedNaiveH2NativeCases() []string {
	var result []string
	for _, layer := range []string{"off", common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
		for _, policy := range []string{"off", "on-connect", "always"} {
			result = append(result, strings.Join([]string{"naive-h2", layer, policy, "connect"}, "/"))
		}
		for _, action := range []string{"home-lan-wrong-node", "resolver-failure", "wrong-key", "wrong-user", "wrong-trust", "wrong-server-name", "restore-sealed", "mtu-rollback"} {
			result = append(result, strings.Join([]string{"naive-h2", layer, "on-connect", action}, "/"))
		}
	}
	return append(result, "naive-h2/aes-256-gcm/on-connect/wrong-layer-key", "naive-h2/aes-256-gcm+xor-whitening/on-connect/wrong-layer-key", "naive-h2/aes-256-gcm+xor-whitening/on-connect/wrong-whitening")
}

func TestMacOSRetainedPairedNaiveH2NativePublicGraphs(t *testing.T) {
	for _, scenario := range macOSPairedNaiveH2NativeCases() {
		t.Run(scenario, func(t *testing.T) { macOSPairedNodeNativeCaseRun(t, scenario) })
	}
}

func macOSPairedNaiveH2Rejected(action string, reply macOSPairedNodePeerReply) bool {
	if !pairedNaiveH2WrongKeyAction(action) || reply.RawTCP == 0 || reply.RawUDP != 0 || reply.ProtocolTCP != 0 || reply.ProtocolUDP != 0 || reply.DNSQueries != 0 || reply.RouterQueries != 0 {
		return false
	}
	if action == "wrong-layer-key" || action == "wrong-whitening" {
		return reply.PlainTCP == 0 && reply.PlainUDP == 0 && reply.ProtocolRawTCP == 0 && reply.ProtocolTLSHTTP == 0
	}
	return reply.ProtocolRawTCP > 0
}
