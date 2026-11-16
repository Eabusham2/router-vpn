package mobilemultihop

import (
	"encoding/json"

	"router-vpn/internal/multihoprelay"
	"router-vpn/internal/nativeopenvpn"
)

// A Local ordered capture remains usable without remote credentials. Only the
// distinct execution caller requires this original, independent provider pair.
func nodeChainOpenVPNLocalPair(m *nodeChainOpenVPNMember) (nativeopenvpn.PublicDescriptor, nativeopenvpn.PublicDescriptor, string, error) {
	var empty nativeopenvpn.PublicDescriptor
	profile, external, err := nodeChainOpenVPNProfile(m)
	if err != nil {
		return empty, empty, "", err
	}
	raw, err := json.Marshal(external["openvpn_pairing"])
	var pair nativeopenvpn.Pairing
	if err != nil || json.Unmarshal(raw, &pair) != nil {
		return empty, empty, "", nodeChainExecutionError
	}
	local, err := nativeopenvpn.ValidatePairing(profile, pair)
	if err != nil {
		return empty, empty, "", err
	}
	digest, err := multihoprelay.NodeChainOpenVPNPairDigest(local, pair.Server)
	return local, pair.Server, digest, err
}

func nodeChainOpenVPNPlanMember(value map[string]any) (string, string, *NodeChainOpenVPNServerPairing, error) {
	bad := nodeChainServerPlanError
	if !nodeChainPlanKeys(value, []string{"local", "server", "pairing"}, nil) {
		return "", "", nil, bad
	}
	inputs := make([]string, 0, 2)
	for _, role := range []string{"local", "server"} {
		capture, ok := value[role].(map[string]any)
		if !ok || !nodeChainPlanKeys(capture, []string{"config", "capture"}, nil) {
			return "", "", nil, bad
		}
		config, configOK := capture["config"].(string)
		source, sourceOK := capture["capture"].(string)
		if !configOK || !sourceOK {
			return "", "", nil, bad
		}
		input, err := NodeChainImportedOpenVPNMemberInput(config, source)
		if err != nil {
			return "", "", nil, bad
		}
		inputs = append(inputs, input)
	}
	raw, err := json.Marshal(value["pairing"])
	var pair NodeChainOpenVPNServerPairing
	if err != nil || exactJSON(raw, &pair, NodeChainInputLimit) != nil {
		return "", "", nil, bad
	}
	local, err := parseNodeChainOpenVPNMember(inputs[0])
	if err != nil {
		return "", "", nil, bad
	}
	server, err := parseNodeChainOpenVPNMember(inputs[1])
	if err != nil {
		return "", "", nil, bad
	}
	_, _, localSHA, err := nodeChainOpenVPNLocalPair(local)
	if err != nil {
		return "", "", nil, bad
	}
	serverSHA, err := nodeChainOpenVPNServerPair(server, &pair)
	if err != nil || localSHA != serverSHA || local.id() != server.id() || local.selection.ExpectedPublicIP != server.selection.ExpectedPublicIP {
		return "", "", nil, bad
	}
	return inputs[0], inputs[1], &pair, nil
}
