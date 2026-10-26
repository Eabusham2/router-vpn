package mobilemultihop

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/mobileperf"
)

// NodeMultihopExitModes lists the complete native exit graphs accepted by both
// Local and Server node-to-node execution. WireGuard retains its packet
// endpoint; it is never represented as a proxy in the Local graph.
func NodeMultihopExitModes() []string {
	return []string{"shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "wg", "awg2-fast", "awg2-strong", "ss-v2ray", "split", "max", "wg-pq", "awg2-pq"}
}

func NodeMultihopExitMode(mode string) bool {
	for _, candidate := range NodeMultihopExitModes() {
		if candidate == mode {
			return true
		}
	}
	return false
}

// NodeMultihopConfig composes two immutable, fully validated node captures.
// The desktop's existing entry-wg tag identifies its proof lane. The complete
// predecessor keeps its exact packet/proxy/PQ/MAX owners and dependencies.
// It performs no I/O and does not establish either node's live proof.
func NodeMultihopConfig(entry, exit *NodeProfile) (string, error) {
	bad := errors.New("native node multihop requires two complete captured native entry and exit graphs")
	if entry == nil || exit == nil || entry.profile == nil || exit.profile == nil ||
		!NodeMultihopEntryMode(entry.mode) ||
		(!NodeMultihopExitMode(exit.mode) && !MAXMode(exit.mode)) ||
		entry.profile["id"] == exit.profile["id"] || entry.profile["node_proof_id"] == exit.profile["node_proof_id"] {
		return "", bad
	}
	predecessor, err := nodeMultihopPredecessor(entry)
	if err != nil {
		return "", err
	}
	last, err := nodeMultihopPredecessor(exit)
	if err != nil {
		return "", err
	}
	// The final transport may already route through its authenticated Start
	// Layer. Attach the complete exit's outer edge to the entry, never overwrite
	// that edge on the inner transport and silently bypass the saved layer.
	outer := last.final
	if MAXMode(exit.mode) {
		outer, err = nodeMAXExit(last, exit)
		if err != nil {
			return "", err
		}
	} else if CompositeMode(exit.mode) {
		outer, err = nodeCompositeExit(last, exit)
		if err != nil {
			return "", err
		}
	} else {
		for depth := 0; outer["detour"] != nil; depth++ {
			if depth > 1 {
				return "", bad
			}
			outer = last.nodes[predecessorText(outer, "detour")]
			if outer == nil || outer["tag"] != NativeStartLayerTag {
				return "", bad
			}
		}
	}
	selection := externalPolicyCapture{Profile: predecessorCopy(exit.profile), Entry: predecessorCopy(entry.profile)}
	envelope, err := nodePacketEnvelope(last, exit.mode)
	if err != nil {
		return "", err
	}
	if err := nodeMultihopMTU(predecessor, last, selection, envelope, exit.mode); err != nil {
		return "", err
	}
	// The merger moves the entry's checked cover owner to the entry role. The
	// performance compiler recreates the already-validated exit role below.
	delete(last.graph, "services")
	if err := predecessor.mergeAs(last.graph, last.tun, outer, "entry-wg"); err != nil {
		return "", err
	}
	// An exit's captured resolver bootstrap is part of the exit path too.
	// In particular Naive needs an explicit resolver even for a literal node.
	// Its standalone bootstrap has no detour; attach that edge to the same
	// entry instead of letting DNS escape on the physical network. Resolvers
	// already owned by the exit or its Start Layer retain those exact routes.
	for _, resolver := range last.resolvers {
		if resolver["detour"] == nil {
			resolver["detour"] = "entry-wg"
		}
	}
	encoded, err := json.Marshal(last.graph)
	if err != nil {
		return "", err
	}
	pair, _ := json.Marshal(map[string]any{"entry": entry.profile, "exit": exit.profile})
	return mobileperf.Apply(string(encoded), string(pair))
}
