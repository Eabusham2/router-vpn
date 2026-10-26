package mobilemultihop

import (
	"errors"
	"sort"

	"router-vpn/internal/nativecomposite"
)

// NodeMultihopEntryModes returns the exact saved Router transports whose full
// native graph can own the first hop. The returned slice is independent so an
// adapter cannot change another caller's accepted catalog.
func NodeMultihopEntryModes() []string {
	return []string{
		"wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq",
		"shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp",
		"naive-h2", "naive-h3", "ss-v2ray", "split", "max",
		"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg",
	}
}

// NodeMultihopEntryMode deliberately accepts only canonical raw identities.
// A logical label, case variant, or unrecognized selection must not be turned
// into a different encrypted graph by an adapter.
func NodeMultihopEntryMode(mode string) bool {
	for _, candidate := range NodeMultihopEntryModes() {
		if candidate == mode {
			return true
		}
	}
	return false
}

func nodeMultihopPredecessor(node *NodeProfile) (*externalPredecessor, error) {
	if node == nil || node.profile == nil || !NodeProfileMode(node.mode) {
		return nil, errors.New("native multihop has no complete captured node")
	}
	return newExternalPredecessor(externalPolicyCapture{
		Entry: predecessorCopy(node.profile), EntryTag: externalEntryTag,
		Profile: map[string]any{"multihop_entry_mode": node.mode}, PredecessorConfig: node.config,
	})
}

// NodeEntryOwners carries only the public owner tags of one captured graph.
// Resolver names include the explicitly captured bootstrap dependency tree.
type NodeEntryOwners struct {
	Nodes     []string `json:"nodes"`
	Resolvers []string `json:"resolvers"`
}

// MultihopEntryOwners identifies the entire validated predecessor closure
// after namespacing. A Server lease can remove its independent exit owners
// without treating an entry's packet endpoint, AES layer, MAX or composite
// child as a dormant exit. This carries public owner tags only.
func (p *NodeProfile) MultihopEntryOwners() (NodeEntryOwners, error) {
	if p == nil || !NodeMultihopEntryMode(p.mode) {
		return NodeEntryOwners{}, errors.New("native multihop requires an exact captured entry transport")
	}
	predecessor, err := nodeMultihopPredecessor(p)
	if err != nil {
		return NodeEntryOwners{}, err
	}
	owners := NodeEntryOwners{Nodes: make([]string, 0, len(predecessor.nodes)), Resolvers: make([]string, 0, len(predecessor.resolvers))}
	for _, owner := range predecessor.nodeOwnerNames("entry-wg") {
		owners.Nodes = append(owners.Nodes, owner)
	}
	for tag := range predecessor.resolvers {
		owners.Resolvers = append(owners.Resolvers, predecessorNamespace("dns", tag))
	}
	sort.Strings(owners.Nodes)
	sort.Strings(owners.Resolvers)
	return owners, nil
}

// nodeOwnerNames keeps the existing opaque external-node namespace. Internal
// Router composites use the already validated entry role's canonical lane tags
// so both the native factory and the unchanged cover proof can validate the
// complete TCP/UDP/Start closure with nativecomposite.Extract. Source validation
// precedes this relabel; names never confer trust on an unvalidated graph.
func (p *externalPredecessor) nodeOwnerNames(entryTag string) map[string]string {
	names := make(map[string]string, len(p.nodes))
	for tag := range p.nodes {
		names[tag] = predecessorNamespace("node", tag)
	}
	if entryTag == "entry-wg" && p.final["type"] == nativecomposite.Type {
		for _, name := range []string{"tcp", "udp", "start"} {
			if p.nodes[nativecomposite.SourcePrefix+name] != nil {
				names[nativecomposite.SourcePrefix+name] = "routervpn-entry-composite-" + name
			}
		}
	}
	names[p.finalTag] = entryTag
	return names
}
