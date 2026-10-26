package mobilemultihop

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/awgpolicy"
	"router-vpn/internal/mobilepq"
	"router-vpn/internal/multihoprelay"
)

// This desktop node-to-node subset deliberately excludes the distinct complete
// MAX helper graphs. A Rosenpass endpoint always retains mandatory negotiation.
func NodeMultihopPacketExitMode(mode string) bool {
	return awgpolicy.WireGuardFamily(mode) || IsPQMode(mode)
}

func (p *NodeProfile) PQClientIdentity() (string, error) {
	bad := errors.New("native PQ exit has no exact captured negotiation identity")
	if p == nil || (!IsPQMode(p.mode) && !MAXMode(p.mode)) {
		return "", bad
	}
	mode := p.mode
	var graph map[string]any
	if exactJSON([]byte(p.config), &graph, 4<<20) != nil {
		return "", bad
	}
	endpoints, ok := graph["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return "", bad
	}
	endpoint, ok := endpoints[0].(map[string]any)
	if MAXMode(mode) {
		captured, err := nodeMAXCapture(p)
		if err != nil {
			return "", bad
		}
		endpoint = captured.final
		mode = multihoprelay.MAXBaseMode(mode)
	}
	if !ok || endpoint["tag"] != "proxy" || endpoint["type"] != PQType || endpoint["mode"] != mode || endpoint["node_id"] != p.profile["node_proof_id"] {
		return "", bad
	}
	encoded, _ := json.Marshal(endpoint)
	runtime, err := PQRuntimeConfig(string(encoded))
	defer runtime.PQ.Erase()
	if err != nil {
		return "", bad
	}
	return mobilepq.ClientIdentity(runtime.PQ)
}

// Return only the validated underlying packet options for MTU arithmetic.
// This disposable object is never installed in place of the mandatory PQ owner.
func nodePQBase(endpoint map[string]any, mode string) (map[string]any, error) {
	bad := errors.New("native PQ exit lost its captured packet and negotiation owners")
	if endpoint == nil || endpoint["type"] != PQType || endpoint["mode"] != mode || !IsPQMode(mode) {
		return nil, bad
	}
	encoded, _ := json.Marshal(endpoint)
	runtime, err := PQRuntimeConfig(string(encoded))
	defer runtime.PQ.Erase()
	if err != nil {
		return nil, err
	}
	var base map[string]any
	if json.Unmarshal([]byte(runtime.BaseJSON), &base) != nil {
		return nil, bad
	}
	base["type"], base["tag"] = "wireguard", endpoint["tag"]
	if mode == "awg2-pq" {
		base["type"] = AmneziaType
	}
	return base, nil
}

func nodeMultihopMTU(entry, exit *externalPredecessor, selection externalPolicyCapture, envelope int, mode string) error {
	if MAXMode(mode) {
		return nodeMAXMTU(entry, exit, selection, mode)
	}
	packet := exit.final
	if packet["type"] == PQType {
		var err error
		packet, err = nodePQBase(packet, predecessorText(packet, "mode"))
		if err != nil {
			return err
		}
	}
	if _, _, _, err := entry.applyMTUWithPacketEnvelope(exit.tun, packet, selection, envelope); err != nil {
		return err
	}
	if exit.final["type"] == PQType {
		exit.final["mtu"] = packet["mtu"]
	}
	return nil
}
