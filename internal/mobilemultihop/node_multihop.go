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
	return []string{"shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "naive-h2", "naive-h3", "wg"}
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
// The desktop's existing entry-wg tag identifies its proof lane; the endpoint
// itself retains its exact WireGuard or AmneziaWG type and captured parameters.
// It performs no I/O and does not establish either node's live proof.
func NodeMultihopConfig(entry, exit *NodeProfile) (string, error) {
	bad := errors.New("native node multihop requires a captured WG/AWG entry and a complete supported native exit")
	if entry == nil || exit == nil || entry.profile == nil || exit.profile == nil ||
		(entry.mode != "wg" && entry.mode != "awg2-fast" && entry.mode != "awg2-strong") ||
		!NodeMultihopExitMode(exit.mode) ||
		entry.profile["id"] == exit.profile["id"] || entry.profile["node_proof_id"] == exit.profile["node_proof_id"] {
		return "", bad
	}
	prepare := func(node *NodeProfile) (*externalPredecessor, error) {
		return newExternalPredecessor(externalPolicyCapture{
			Entry: predecessorCopy(node.profile), EntryTag: externalEntryTag,
			Profile: map[string]any{"multihop_entry_mode": node.mode}, PredecessorConfig: node.config,
		})
	}
	predecessor, err := prepare(entry)
	if err != nil {
		return "", err
	}
	last, err := prepare(exit)
	if err != nil {
		return "", err
	}
	// The final proxy may already route through its own authenticated Start
	// Layer. Attach the complete exit's outer edge to the entry, never overwrite
	// that edge on the inner proxy and silently bypass the saved layer.
	outer := last.final
	for depth := 0; outer["detour"] != nil; depth++ {
		if depth > 1 {
			return "", bad
		}
		outer = last.nodes[predecessorText(outer, "detour")]
		if outer == nil || outer["tag"] != NativeStartLayerTag {
			return "", bad
		}
	}
	selection := externalPolicyCapture{Profile: predecessorCopy(exit.profile), Entry: predecessorCopy(entry.profile)}
	envelope, err := nodeWireGuardPacketEnvelope(last, exit.mode)
	if err != nil {
		return "", err
	}
	if _, _, _, err := predecessor.applyMTUWithPacketEnvelope(last.tun, last.final, selection, envelope); err != nil {
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
