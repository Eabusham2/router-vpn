package mobilemultihop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"router-vpn/internal/mobilemtu"
)

type nodeChainProjection struct {
	TargetOS             string `json:"target_os,omitempty"`
	RestoredMTU          int    `json:"restored_mtu,omitempty"`
	Kind                 string `json:"kind,omitempty"`
	SessionID            string `json:"session_id,omitempty"`
	PhysicalSourceSHA256 string `json:"physical_source_sha256,omitempty"`
	BaseConfigSHA256     string `json:"base_config_sha256,omitempty"`
}

type NodeChainMTUBound struct {
	Position int    `json:"position"`
	Tag      string `json:"tag"`
	Ceiling  int    `json:"ceiling"`
}

// This is a configured ceiling, never a measured path MTU. Native Auto/Retest
// must honor every prefix bound and retain its actual probe/readback ownership.
type NodeChainMTUPlan struct {
	Original int                 `json:"original"`
	Ceiling  int                 `json:"ceiling"`
	TUNTag   string              `json:"tun_tag"`
	Prefixes []NodeChainMTUBound `json:"prefixes"`
}

func (c *NodeChain) MTUPlan() (NodeChainMTUPlan, error) {
	if c.validateCapture() != nil {
		return NodeChainMTUPlan{}, nodeChainError
	}
	return nodeChainProjectedMTUPlan(c.config, c.proofs, c.projection)
}

// ProjectNodeChain derives interface naming and an explicitly captured system
// TUN restore from the original immutable source. Endpoint MTUs, every source,
// all detours and DNS stay unchanged. Child parsing repeats this exact derivation.
func ProjectNodeChain(original *NodeChain, targetOS string, restoredMTU int) (*NodeChain, error) {
	if original == nil || original.validateCapture() != nil ||
		targetOS != "linux" && targetOS != "windows" && targetOS != "darwin" &&
			targetOS != "ios" && targetOS != "android" {
		return nil, nodeChainError
	}
	derived, err := NewNodeChain(original.sourceJSON)
	if err != nil {
		return nil, err
	}
	config, err := projectNodeChainTUN(derived.config, derived.nodes[len(derived.nodes)-1].profile, targetOS, restoredMTU)
	if err != nil {
		return nil, err
	}
	derived.config = config
	derived.projection = nodeChainProjection{TargetOS: targetOS, RestoredMTU: restoredMTU}
	derived.dns.ConfigSHA256 = externalDigest([]byte(config))
	if err := derived.refreshMetadata(); err != nil {
		return nil, err
	}
	derived.seal = derived.captureSeal()
	if _, err := derived.LaunchInput(); err != nil {
		return nil, err
	}
	return derived, nil
}

// Derive only the system TUN naming/restore from the captured graph. Both
// typed desktop families retain the same original Fixed/Jumbo restrictions.
func projectNodeChainTUN(config string, finalProfile map[string]any, targetOS string, restoredMTU int) (string, error) {
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil {
		return "", nodeChainError
	}
	tun := graph["inbounds"].([]any)[0].(map[string]any)
	if restoredMTU != 0 {
		if _, err := mtuNumber(float64(restoredMTU)); err != nil {
			return "", nodeChainError
		}
		// Prefix packet Fixed values belong to their own endpoints and are not
		// changed here. Only the final proxy's Fixed/Jumbo owns the shared TUN.
		fixed, err := fixedMTU(finalProfile)
		jumbo, jumboErr := externalJumboPreference(finalProfile)
		configured, mtuErr := mtuNumber(tun["mtu"])
		if err != nil || jumboErr != nil || mtuErr != nil ||
			fixed != 0 && restoredMTU != fixed ||
			jumbo && (configured != 9000 || restoredMTU != configured) {
			return "", errors.New("ordered chain restore conflicts with original Fixed or Jumbo policy")
		}
		tun["mtu"] = float64(restoredMTU)
	}
	switch targetOS {
	case "windows", "linux":
		tun["interface_name"] = "router-vpn"
	case "darwin":
		delete(tun, "interface_name")
	}
	raw, err := json.Marshal(graph)
	if err != nil || len(raw) > 4<<20 {
		return "", nodeChainError
	}
	return string(raw), nil
}

func nodeChainMTUPlan(config string, proofs []NodeChainProof) (NodeChainMTUPlan, error) {
	bad := errors.New("ordered chain MTU requires every original selected prefix and its exact single-choice selector")
	var graph map[string]any
	if exactJSON([]byte(config), &graph, 4<<20) != nil || len(proofs) < 2 || len(proofs) > NodeChainMaximumNodes {
		return NodeChainMTUPlan{}, bad
	}
	inbounds, ok := graph["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		return NodeChainMTUPlan{}, bad
	}
	tun, ok := inbounds[0].(map[string]any)
	if !ok || tun["type"] != "tun" || tun["auto_route"] != true || tun["strict_route"] != true {
		return NodeChainMTUPlan{}, bad
	}
	actual, err := mtuNumber(tun["mtu"])
	if err != nil {
		return NodeChainMTUPlan{}, bad
	}
	route, ok := graph["route"].(map[string]any)
	if !ok || route["final"] != SelectorTag {
		return NodeChainMTUPlan{}, bad
	}
	all := map[string]map[string]any{}
	for _, family := range []string{"endpoints", "outbounds"} {
		rows, ok := graph[family].([]any)
		if !ok {
			return NodeChainMTUPlan{}, bad
		}
		for _, raw := range rows {
			value, ok := raw.(map[string]any)
			tag := predecessorText(value, "tag")
			if !ok || !exactID.MatchString(tag) || all[tag] != nil {
				return NodeChainMTUPlan{}, bad
			}
			all[tag] = value
		}
	}
	selector := all[SelectorTag]
	if selector == nil || len(selector) != 5 || selector["type"] != "selector" ||
		selector["default"] != proofs[len(proofs)-1].Tag || selector["interrupt_exist_connections"] != true {
		return NodeChainMTUPlan{}, bad
	}
	choices, ok := selector["outbounds"].([]any)
	if !ok || len(choices) != 1 || choices[0] != proofs[len(proofs)-1].Tag {
		return NodeChainMTUPlan{}, bad
	}
	// Every prefix must join the immediately preceding selected prefix. Merely
	// leaving a middle endpoint in an unused branch cannot satisfy this bound.
	for i, proof := range proofs {
		if proof.Position != i || !proofID.MatchString(proof.SourceSHA256) || all[proof.Tag] == nil {
			return NodeChainMTUPlan{}, bad
		}
		owner := fmt.Sprintf("routervpn-chain-%d-%s-node-", i, proof.SourceSHA256[:12])
		tag := proof.Tag
		for depth := 0; ; depth++ {
			value := all[tag]
			if depth > 2 || value == nil || !strings.HasPrefix(tag, owner) {
				return NodeChainMTUPlan{}, bad
			}
			next := predecessorText(value, "detour")
			if next == "" {
				if i != 0 {
					return NodeChainMTUPlan{}, bad
				}
				break
			}
			if i != 0 && next == proofs[i-1].Tag {
				break
			}
			tag = next
		}
	}
	result := NodeChainMTUPlan{Original: actual, Ceiling: 9000, TUNTag: predecessorText(tun, "tag"),
		Prefixes: make([]NodeChainMTUBound, 0, len(proofs))}
	for _, proof := range proofs {
		// Read-only validation projection: the shipped selector and graph
		// remain byte-for-byte unchanged. NewPlan sees each complete prefix.
		route["final"] = proof.Tag
		raw, err := json.Marshal(graph)
		if err != nil {
			return NodeChainMTUPlan{}, bad
		}
		plan, err := mobilemtu.NewPlan(string(raw), actual)
		if err != nil {
			return NodeChainMTUPlan{}, err
		}
		if plan.Ceiling < result.Ceiling {
			result.Ceiling = plan.Ceiling
		}
		result.Prefixes = append(result.Prefixes, NodeChainMTUBound{proof.Position, proof.Tag, plan.Ceiling})
	}
	return result, nil
}
