package mobilemultihop

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"

	"router-vpn/internal/multihoprelay"
)

// A wrapped NodeProfile includes its selected DNS, device and cover policy.
// Revalidate that whole captured source before exposing either public peer
// identity; a valid PQ endpoint alone does not establish a complete MAX chain.
func nodeMAXCapture(node *NodeProfile) (*externalPredecessor, error) {
	bad := errors.New("complete MAX requires its entire captured node and encryption chain")
	if node == nil || !MAXMode(node.mode) {
		return nil, bad
	}
	captured, err := nodeMultihopPredecessor(node)
	if err != nil || captured == nil || captured.finalTag != "proxy" {
		return nil, bad
	}
	endpoints, ok := captured.graph["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return nil, bad
	}
	outputs, ok := captured.graph["outbounds"].([]any)
	if !ok || multihoprelay.ValidateMAXChain(captured.final, outputs, node.mode,
		predecessorText(node.profile, "node_proof_id"), predecessorText(node.profile, "start_layer"), generatedMAXTags(), "") != nil {
		return nil, bad
	}
	return captured, nil
}

// Relabel only the validated exit chain. The complete predecessor is attached
// to the outermost encrypted edge; the mandatory PQ and middle SS2022 edges
// retain their captured owners and private credentials.
func nodeMAXExit(exit *externalPredecessor, node *NodeProfile) (map[string]any, error) {
	bad := errors.New("complete MAX exit lost its captured chain")
	if exit == nil || node == nil || !MAXMode(node.mode) {
		return nil, bad
	}
	outputs, ok := exit.graph["outbounds"].([]any)
	endpoints, endpointOK := exit.graph["endpoints"].([]any)
	if !ok || !endpointOK || len(endpoints) != 1 || exit.finalTag != "proxy" {
		return nil, bad
	}
	layer := predecessorText(node.profile, "start_layer")
	names := maxTags("proxy", false)
	base, children, err := multihoprelay.RelabelMAXChain(exit.final, outputs, node.mode,
		predecessorText(node.profile, "node_proof_id"), layer, generatedMAXTags(), names, "", "entry-wg")
	if err != nil {
		return nil, err
	}
	// RelabelMAXChain has checked the exact owned inventory; replacing these
	// managers cannot delete an unrelated entry, resolver or service owner.
	exit.graph["endpoints"] = []any{base}
	exit.graph["outbounds"] = children
	exit.final = base
	exit.nodes = map[string]map[string]any{"proxy": base}
	for _, raw := range children {
		child := raw.(map[string]any)
		exit.nodes[predecessorText(child, "tag")] = child
	}
	relabels := map[string]string{MAXShadowsocksTag: names.Middle, MAXOuterTag: names.Outer, MAXStartLayerTag: names.Start}
	for _, resolver := range exit.resolvers {
		if name := relabels[predecessorText(resolver, "detour")]; name != "" {
			resolver["detour"] = name
		}
	}
	outer := names.Outer
	if layer != "" && layer != "off" {
		outer = names.Start
	}
	return exit.nodes[outer], nil
}

// MAX carries logical WG/AWG datagrams through an authenticated stream or a
// fragmenting QUIC transport. Its inner interface is not a second raw packet
// envelope placed directly on the entry interface. Keep its configured bound
// and require enough entry capacity for QUIC's minimum wire datagram instead.
// These are configuration limits; they are never fresh path-MTU measurements.
func nodeMAXMTU(entry, exit *externalPredecessor, selection externalPolicyCapture, mode string) error {
	bad := errors.New("complete MAX lost its captured interface or outer transport capacity")
	if entry == nil || exit == nil || !MAXMode(mode) {
		return bad
	}
	layer := predecessorText(selection.Profile, "start_layer")
	names := maxTags("proxy", false)
	outputs, ok := exit.graph["outbounds"].([]any)
	if !ok || multihoprelay.ValidateMAXChain(exit.final, outputs, mode,
		predecessorText(selection.Profile, "node_proof_id"), layer, names, "entry-wg") != nil {
		return bad
	}
	packetMTU, err := mtuNumber(exit.final["mtu"])
	if err != nil {
		return err
	}
	tunMTU, err := mtuNumber(exit.tun["mtu"])
	if err != nil {
		return err
	}
	fixed, err := fixedMTU(selection.Profile)
	if err != nil {
		return err
	}
	entryFixed, err := fixedMTU(selection.Entry)
	if err != nil {
		return err
	}
	entryMTU := 0
	switch entry.final["type"] {
	case "wireguard", AmneziaType, PQType:
		entryMTU, err = mtuNumber(entry.final["mtu"])
		if err != nil {
			return err
		}
		if entryFixed != 0 {
			entryMTU = entryFixed
		}
		entry.final["mtu"] = float64(entryMTU)
	default:
		if entryFixed != 0 {
			if fixed != 0 && fixed != entryFixed {
				return errors.New("entry and complete MAX exit fixed MTUs conflict for the one OS TUN")
			}
			fixed = entryFixed
		}
	}
	if strings.HasPrefix(mode, "max-quic-") && entryMTU != 0 {
		minimum, err := nodeMAXQUICMinimum(exit, names, layer)
		if err != nil || entryMTU < minimum {
			return errors.New("entry interface cannot carry the captured MAX QUIC datagram and Start Layer")
		}
	}
	if fixed != 0 {
		packetMTU, tunMTU = fixed, fixed
	} else if tunMTU > packetMTU {
		tunMTU = packetMTU
	}
	exit.final["mtu"], exit.tun["mtu"] = float64(packetMTU), float64(tunMTU)
	return nil
}

func nodeMAXQUICMinimum(exit *externalPredecessor, names multihoprelay.MAXTags, layer string) (int, error) {
	bad := errors.New("complete MAX QUIC has no exact captured datagram envelope")
	outer := exit.nodes[names.Outer]
	if outer == nil || outer["type"] != "hysteria2" {
		return 0, bad
	}
	host, err := netip.ParseAddr(predecessorText(outer, "server"))
	if err != nil || host.Is4In6() || host.Zone() != "" {
		return 0, bad
	}
	minimum, transport := 1200, host
	if layer != "" && layer != "off" {
		start := exit.nodes[names.Start]
		if start == nil || (start["type"] != "shadowsocks" && start["type"] != "routervpn-aes-xor") || start["method"] != NativeStartLayerMethod {
			return 0, bad
		}
		transport, err = netip.ParseAddr(predecessorText(start, "server"))
		if err != nil || transport.Is4In6() || transport.Zone() != "" {
			return 0, bad
		}
		keys := strings.Split(predecessorText(start, "password"), ":")
		if len(keys) == 0 || len(keys) > 64 {
			return 0, bad
		}
		for _, value := range keys {
			key, err := base64.StdEncoding.Strict().DecodeString(value)
			valid := err == nil && len(key) == 32
			clear(key)
			if !valid {
				return 0, bad
			}
		}
		addressBytes := 7
		if host.Is6() {
			addressBytes = 19
		}
		request, response := 43+addressBytes+16*(len(keys)-1), 51+addressBytes
		if response > request {
			request = response
		}
		minimum += request
	}
	if transport.Is6() {
		return minimum + 48, nil
	}
	return minimum + 28, nil
}
