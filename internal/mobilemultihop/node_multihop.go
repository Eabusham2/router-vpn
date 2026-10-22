package mobilemultihop

import (
	"encoding/json"
	"errors"

	"router-vpn/internal/mobileperf"
)

// NodeMultihopConfig composes two immutable, fully validated node captures.
// The desktop's existing entry-wg tag identifies its proof lane; the endpoint
// itself retains its exact WireGuard or AmneziaWG type and captured parameters.
// It performs no I/O and does not establish either node's live proof.
func NodeMultihopConfig(entry, exit *NodeProfile) (string, error) {
	bad := errors.New("native node multihop requires captured WG/AWG and Shadowsocks/Hysteria2 nodes")
	if entry == nil || exit == nil || entry.profile == nil || exit.profile == nil ||
		(entry.mode != "wg" && entry.mode != "awg2-fast" && entry.mode != "awg2-strong") ||
		(exit.mode != "shadowsocks" && exit.mode != "hysteria2") ||
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
	if _, _, _, err := predecessor.applyMTU(last.tun, last.final, selection); err != nil {
		return "", err
	}
	// The merger moves the entry's checked cover owner to the entry role. The
	// performance compiler recreates the already-validated exit role below.
	delete(last.graph, "services")
	if err := predecessor.mergeAs(last.graph, last.tun, outer, "entry-wg"); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(last.graph)
	if err != nil {
		return "", err
	}
	pair, _ := json.Marshal(map[string]any{"entry": entry.profile, "exit": exit.profile})
	return mobileperf.Apply(string(encoded), string(pair))
}
