//go:build linux && routervpn_controller_privileged

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router-vpn/internal/common"
)

// Run in a separate required native phase. The existing installed-host cases
// keep their inventory and deadlines; these cases use the same original
// controller, namespace, physical broker, proof, MTU and retirement assertions.
var linuxHostTUNNaiveH2Cases = func() []string {
	var result []string
	for _, layer := range []string{"off", "aes", "whitening"} {
		for _, action := range []string{"public-connect", "public-off", "home-lan", "wrong-key", "wrong-user", "wrong-trust", "wrong-server-name", "resolver-failure", "wrong-node", "active-network-change", "cancelled-proof", "restore-sealed", "always", "mtu-rollback", "mtu-commit"} {
			result = append(result, "naive-h2-"+layer+"-"+action)
		}
	}
	return append(result, "naive-h2-aes-wrong-layer-key", "naive-h2-whitening-wrong-layer-key", "naive-h2-whitening-wrong-whitening")
}()

func TestDesktopUnixNaiveH2NativeInventory(t *testing.T) {
	raw, err := json.Marshal(linuxHostTUNNaiveH2Cases)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("compiled installed Naive H2 cases: " + string(raw))
}

func linuxHostTUNNaiveH2Case(scenario string) bool {
	for _, value := range linuxHostTUNNaiveH2Cases {
		if value == scenario {
			return true
		}
	}
	return false
}

func linuxHostTUNNaiveH2Action(scenario string) string {
	for _, prefix := range []string{"naive-h2-off-", "naive-h2-aes-", "naive-h2-whitening-"} {
		if strings.HasPrefix(scenario, prefix) {
			return strings.TrimPrefix(scenario, prefix)
		}
	}
	return scenario
}

func linuxHostTUNNaiveH2Layer(scenario string) string {
	if strings.HasPrefix(scenario, "naive-h2-aes-") {
		return common.StartLayerAES256GCM
	}
	if strings.HasPrefix(scenario, "naive-h2-whitening-") {
		return common.StartLayerAES256GCMXOR
	}
	return ""
}

func linuxHostTUNNaiveH2DNS(reply linuxHostTUNPeerReply) bool {
	return reply.RawTCP > 0 && reply.RawUDP == 0 && reply.ProtocolRawTCP > 0 && reply.ProtocolRawUDP == 0 && reply.ProtocolTLSHTTP > 0 && reply.ProtocolUDP > 0 && reply.DNSQueries > 0
}

func linuxHostTUNNaiveH2Rejected(scenario string, reply linuxHostTUNPeerReply) bool {
	if !pairedNaiveH2WrongKeyAction(linuxHostTUNNaiveH2Action(scenario)) || reply.RawTCP == 0 || reply.RawUDP != 0 || reply.ProtocolTCP != 0 || reply.ProtocolUDP != 0 || reply.DNSQueries != 0 || reply.RouterQueries != 0 {
		return false
	}
	if action := linuxHostTUNNaiveH2Action(scenario); action == "wrong-layer-key" || action == "wrong-whitening" {
		return reply.PlainTCP == 0 && reply.PlainUDP == 0 && reply.ProtocolRawTCP == 0 && reply.ProtocolTLSHTTP == 0
	}
	return reply.ProtocolRawTCP > 0
}
