package mobilemultihop

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
)

// Only this unfinished Local purpose admits a retained proxy stop. Ordinary
// packet-prefix and complete/selected source classifiers remain independent.
func nodeChainAppendProxyMode(mode string) bool {
	return mode == "shadowsocks" || mode == "hysteria2"
}

func nodeChainAppendHysteriaClosure(node *NodeProfile, closure *externalPredecessor) bool {
	return nodeChainCapturedHysteriaClosure(node, closure)
}

// Pure captured transport validation; execution authority belongs to the
// caller's distinct original append or complete-source owner.
func nodeChainCapturedHysteriaClosure(node *NodeProfile, closure *externalPredecessor) bool {
	if node == nil || node.mode != "hysteria2" || closure == nil || len(closure.nodes) != 1 ||
		!nodeChainFinalClosure(node, closure) ||
		predecessorText(node.profile, "start_layer") != "" && predecessorText(node.profile, "start_layer") != "off" {
		return false
	}
	out := closure.final
	ip, err := netip.ParseAddr(predecessorText(out, "server"))
	tls, ok := out["tls"].(map[string]any)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() ||
		!externalPort(out["server_port"]) || out["type"] != "hysteria2" || out["detour"] != nil ||
		out["domain_resolver"] != nil || out["server_ports"] != nil || out["realm"] != nil || out["network"] != nil ||
		!ok || tls["enabled"] != true || tls["insecure"] != nil && tls["insecure"] != false {
		return false
	}
	_, err = nodeChainAppendHysteriaKeys(out)
	return err == nil
}

// Keep both the actual string secret and a canonical decoded-key identity when
// present. Reusing a packet/SS key as HY2 authentication or obfuscation must not
// acquire another independent route merely because its wire encoding differs.
func nodeChainAppendHysteriaKeys(out map[string]any) (map[string]bool, error) {
	return nodeChainCapturedHysteriaKeys(out)
}

// Pure captured transport validation; execution authority belongs to the
// caller's distinct original append or complete-source owner.
func nodeChainCapturedHysteriaKeys(out map[string]any) (map[string]bool, error) {
	if out == nil || out["type"] != "hysteria2" || predecessorText(out, "password") == "" {
		return nil, nodeChainCandidateAppendError
	}
	values := []string{predecessorText(out, "password")}
	if raw := out["obfs"]; raw != nil {
		obfs, ok := raw.(map[string]any)
		if !ok || predecessorText(obfs, "type") != "salamander" && predecessorText(obfs, "type") != "gecko" || predecessorText(obfs, "password") == "" {
			return nil, nodeChainCandidateAppendError
		}
		values = append(values, predecessorText(obfs, "password"))
	}
	keys := make(map[string]bool)
	for _, value := range values {
		keys[base64.StdEncoding.EncodeToString([]byte(value))] = true
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		if err == nil && len(decoded) != 0 {
			keys[base64.StdEncoding.EncodeToString(decoded)] = true
		}
		clear(decoded)
	}
	return keys, nil
}

func (s *NodeChainCandidateAppendSource) hasHysteriaPrefix() bool {
	for _, node := range s.nodes {
		if node != nil && node.mode == "hysteria2" {
			return true
		}
	}
	return false
}

func validateNodeChainAppendProxyTargets(closures []*externalPredecessor, targets map[netip.AddrPort]bool) error {
	return validateNodeChainCapturedProxyTargets(closures, targets)
}

// Pure captured transport validation; execution authority belongs to the
// caller's distinct original append or complete-source owner.
func validateNodeChainCapturedProxyTargets(closures []*externalPredecessor, targets map[netip.AddrPort]bool) error {
	var streams []*externalPredecessor
	for _, closure := range closures {
		if closure == nil || closure.final == nil {
			return nodeChainCandidateAppendError
		}
		if closure.final["type"] == "shadowsocks" {
			streams = append(streams, closure)
			continue
		}
		out := closure.final
		ip, err := netip.ParseAddr(predecessorText(out, "server"))
		port, ok := out["server_port"].(float64)
		if out["type"] != "hysteria2" || err != nil || !ok || !externalPort(port) {
			return nodeChainCandidateAppendError
		}
		target := netip.AddrPortFrom(ip, uint16(port))
		if targets[target] {
			return pairedStreamConflict
		}
		targets[target] = true
	}
	return validateExtendedStreamTargets(streams, targets, nil)
}

// Apply the added HY2 secret independence check to a genuinely hybrid capture.
// Legacy packet/SS-only graphs retain their existing source validators.
func validateNodeChainAppendHybridKeys(closures []*externalPredecessor) error {
	return validateNodeChainCapturedHybridKeys(closures)
}

// Pure captured transport validation; execution authority belongs to the
// caller's distinct original append or complete-source owner.
func validateNodeChainCapturedHybridKeys(closures []*externalPredecessor) error {
	hasHysteria := false
	for _, closure := range closures {
		if closure != nil && closure.final != nil && closure.final["type"] == "hysteria2" {
			hasHysteria = true
		}
	}
	if !hasHysteria {
		return nil
	}
	owners := make(map[string]int)
	for position, closure := range closures {
		keys := make(map[string]bool)
		for _, row := range closure.nodes {
			switch predecessorText(row, "type") {
			case "hysteria2":
				captured, err := nodeChainAppendHysteriaKeys(row)
				if err != nil {
					return err
				}
				for key := range captured {
					keys[key] = true
				}
			case "shadowsocks", "routervpn-aes-xor":
				for _, password := range strings.Split(predecessorText(row, "password"), ":") {
					key := importedSS2022KeyIdentity(predecessorText(row, "method"), password)
					if key == "" {
						return nodeChainCandidateAppendError
					}
					keys[key] = true
				}
			case "wireguard", AmneziaType:
				values := []string{predecessorText(row, "private_key")}
				peers, ok := row["peers"].([]any)
				if !ok || len(peers) != 1 {
					return nodeChainCandidateAppendError
				}
				peer, ok := peers[0].(map[string]any)
				if !ok {
					return nodeChainCandidateAppendError
				}
				values = append(values, predecessorText(peer, "public_key"), predecessorText(peer, "pre_shared_key"))
				for _, value := range values {
					if value == "" {
						continue
					}
					raw, err := base64.StdEncoding.Strict().DecodeString(value)
					valid := err == nil && len(raw) == 32
					if valid {
						keys[base64.StdEncoding.EncodeToString(raw)] = true
					}
					clear(raw)
					if !valid {
						return nodeChainCandidateAppendError
					}
				}
			}
		}
		for key := range keys {
			if owner, exists := owners[key]; exists && owner != position {
				return pairedStreamConflict
			}
			owners[key] = position
		}
	}
	return nil
}

func (s *NodeChainCandidateAppendSource) candidateHysteriaResponse(input string) (candidateResponseSource, error) {
	var empty candidateResponseSource
	if s.validate() != nil || s.record.NextKind != "" || s.record.NextMode != "hysteria2" {
		return empty, nodeChainCandidateAppendError
	}
	response, err := parseCandidateNativeResponseSource(input, "hysteria2")
	if err != nil {
		return empty, err
	}
	node, err := ParseNodeLaunchInput(input)
	if err != nil || node == nil {
		return empty, nodeChainCandidateAppendError
	}
	closure, err := nodeMultihopPredecessor(node)
	if err != nil || !nodeChainAppendHysteriaClosure(node, closure) {
		return empty, nodeChainCandidateAppendError
	}
	config, proofs, err := s.candidateConfig(input)
	if err != nil {
		return empty, err
	}
	proof := proofs[len(s.proofs)]
	if proof.ProfileID != response.Target.ID || proof.SourceSHA256 != response.Target.SourceSHA256 ||
		proof.NodeID != response.NodeID || proof.Mode != "hysteria2" || proof.StartLayer != "off" || proof.NodeKind != "" || proof.Kind != "" {
		return empty, nodeChainCandidateAppendError
	}
	projected, err := candidatePrefixClosure(config, proofs)
	expected := predecessorCopy(closure.final)
	expected["tag"], expected["detour"] = proof.Tag, s.proofs[len(s.proofs)-1].Tag
	var captured map[string]any
	if err != nil || !reflect.DeepEqual(projected["outbounds/"+proof.Tag], expected) ||
		json.Unmarshal([]byte(response.Hysteria2Options), &captured) != nil || !reflect.DeepEqual(captured, closure.final) {
		return empty, nodeChainCandidateAppendError
	}
	return response, nil
}
