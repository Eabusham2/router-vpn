//go:build linux && routervpn_controller_privileged

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

var linuxHostTUNREALITYCases = func() []string {
	var result []string
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, layer := range []string{"off", "aes", "whitening"} {
			for _, action := range []string{"public-connect", "public-off", "home-lan", "wrong-key", "wrong-user", "wrong-server-name", "wrong-short-id", "resolver-failure", "wrong-node", "active-network-change", "cancelled-proof", "restore-sealed", "always", "mtu-rollback", "mtu-commit"} {
				result = append(result, mode+"-"+layer+"-"+action)
			}
			if mode != "reality-vision" {
				result = append(result, mode+"-"+layer+"-wrong-pq-key")
			}
			if mode == "reality-xhttp" {
				result = append(result, mode+"-"+layer+"-wrong-path")
			}
		}
		result = append(result, mode+"-aes-wrong-layer-key", mode+"-whitening-wrong-layer-key", mode+"-whitening-wrong-whitening")
	}
	return result
}()

func TestDesktopUnixREALITYNativeInventory(t *testing.T) {
	raw, err := json.Marshal(linuxHostTUNREALITYCases)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("compiled installed REALITY cases: " + string(raw))
}

func linuxHostTUNREALITYCase(scenario string) bool {
	for _, value := range linuxHostTUNREALITYCases {
		if value == scenario {
			return true
		}
	}
	return false
}

func linuxHostTUNREALITYParts(scenario string) (mode, layer, action string) {
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, layer := range []string{"off", "aes", "whitening"} {
			prefix := mode + "-" + layer + "-"
			if strings.HasPrefix(scenario, prefix) {
				return mode, layer, strings.TrimPrefix(scenario, prefix)
			}
		}
	}
	return "", "", ""
}

func linuxHostTUNREALITYLayer(scenario string) string {
	_, layer, _ := linuxHostTUNREALITYParts(scenario)
	if layer == "aes" {
		return common.StartLayerAES256GCM
	}
	if layer == "whitening" {
		return common.StartLayerAES256GCMXOR
	}
	return ""
}

func linuxHostTUNREALITYDNS(reply linuxHostTUNPeerReply) bool {
	return reply.RawTCP > 0 && reply.RawUDP == 0 && reply.ProtocolRawTCP > 0 && reply.ProtocolRawUDP == 0 && reply.ProtocolTLSHTTP == 0 && reply.ProtocolUDP > 0 && reply.DNSQueries > 0
}

func linuxHostTUNREALITYRejected(scenario string, reply linuxHostTUNPeerReply) bool {
	_, _, action := linuxHostTUNREALITYParts(scenario)
	if !pairedREALITYWrongKeyAction(action) || reply.RawTCP == 0 || reply.RawUDP != 0 || reply.ProtocolTCP != 0 || reply.ProtocolUDP != 0 || reply.DNSQueries != 0 || reply.RouterQueries != 0 {
		return false
	}
	if action == "wrong-layer-key" || action == "wrong-whitening" {
		return reply.PlainTCP == 0 && reply.PlainUDP == 0 && reply.ProtocolRawTCP == 0
	}
	return reply.ProtocolRawTCP > 0
}
