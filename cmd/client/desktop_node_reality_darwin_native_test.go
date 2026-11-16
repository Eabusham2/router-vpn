//go:build darwin && routervpn_controller_privileged

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

func TestDesktopUnixREALITYNativeInventory(t *testing.T) {
	raw, err := json.Marshal(macOSPairedREALITYNativeCases())
	if err != nil {
		t.Fatal(err)
	}
	t.Log("compiled installed REALITY cases: " + string(raw))
}

func macOSPairedREALITYNativeCases() []string {
	var result []string
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, layer := range []string{"off", common.StartLayerAES256GCM, common.StartLayerAES256GCMXOR} {
			for _, policy := range []string{"off", "on-connect", "always"} {
				result = append(result, strings.Join([]string{mode, layer, policy, "connect"}, "/"))
			}
			for _, action := range []string{"home-lan-wrong-node", "resolver-failure", "wrong-key", "wrong-user", "wrong-server-name", "wrong-short-id", "restore-sealed", "mtu-rollback"} {
				result = append(result, strings.Join([]string{mode, layer, "on-connect", action}, "/"))
			}
			if mode != "reality-vision" {
				result = append(result, strings.Join([]string{mode, layer, "on-connect", "wrong-pq-key"}, "/"))
			}
			if mode == "reality-xhttp" {
				result = append(result, strings.Join([]string{mode, layer, "on-connect", "wrong-path"}, "/"))
			}
		}
		result = append(result, mode+"/aes-256-gcm/on-connect/wrong-layer-key", mode+"/aes-256-gcm+xor-whitening/on-connect/wrong-layer-key", mode+"/aes-256-gcm+xor-whitening/on-connect/wrong-whitening")
	}
	return result
}

func TestMacOSRetainedPairedREALITYNativePublicGraphs(t *testing.T) {
	for _, scenario := range macOSPairedREALITYNativeCases() {
		t.Run(scenario, func(t *testing.T) { macOSPairedNodeNativeCaseRun(t, scenario) })
	}
}

func macOSPairedREALITYRejected(action string, reply macOSPairedNodePeerReply) bool {
	if !pairedREALITYWrongKeyAction(action) || reply.RawTCP == 0 || reply.RawUDP != 0 || reply.ProtocolTCP != 0 || reply.ProtocolUDP != 0 || reply.DNSQueries != 0 || reply.RouterQueries != 0 {
		return false
	}
	if action == "wrong-layer-key" || action == "wrong-whitening" {
		return reply.PlainTCP == 0 && reply.PlainUDP == 0 && reply.ProtocolRawTCP == 0
	}
	return reply.ProtocolRawTCP > 0
}
