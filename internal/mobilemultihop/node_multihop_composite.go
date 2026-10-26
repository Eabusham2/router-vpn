package mobilemultihop

import (
	"errors"

	"router-vpn/internal/nativecomposite"
)

// A NodeProfile already includes its selected DNS, device and cover policy.
// Extract validates that larger graph's exact captured transport closure; the
// standalone Plan wrapper intentionally does not accept those policy fields.
// A composite root has no detour. Both real lanes traverse the entry directly,
// or traverse their one captured AES owner which itself traverses that entry.
func nodeCompositeExit(exit *externalPredecessor, captured *NodeProfile) (map[string]any, error) {
	bad := errors.New("native composite exit lost its captured TCP/UDP owners")
	if exit == nil || captured == nil || !CompositeMode(captured.mode) {
		return nil, bad
	}
	layer := predecessorText(captured.profile, "start_layer")
	if layer == "off" {
		layer = ""
	}
	node := predecessorText(captured.profile, "node_proof_id")
	plan, err := nativecomposite.Extract(exit.graph, captured.mode, node, layer, "proxy", nativecomposite.SourcePrefix, "")
	if err != nil {
		return nil, err
	}
	root, children, err := nativecomposite.Relabel(plan, captured.mode, node, layer, "proxy", CompositeExitPrefix, "entry-wg")
	if err != nil {
		return nil, err
	}
	names := map[string]string{
		nativecomposite.TCPTag: CompositeExitPrefix + "tcp",
		nativecomposite.UDPTag: CompositeExitPrefix + "udp",
	}
	if layer != "" {
		names[nativecomposite.StartTag] = CompositeExitPrefix + "start"
	}
	retained := make([]any, 0, len(exit.graph["outbounds"].([]any)))
	for _, raw := range exit.graph["outbounds"].([]any) {
		out := raw.(map[string]any)
		tag := predecessorText(out, "tag")
		if tag == "proxy" {
			retained = append(retained, root)
		} else if names[tag] != "" {
			delete(exit.nodes, tag)
		} else {
			retained = append(retained, out)
		}
	}
	exit.graph["outbounds"] = append(retained, children...)
	exit.final, exit.nodes["proxy"] = root, root
	for _, raw := range children {
		out := raw.(map[string]any)
		exit.nodes[predecessorText(out, "tag")] = out
	}
	for _, resolver := range exit.resolvers {
		if tag := names[predecessorText(resolver, "detour")]; tag != "" {
			resolver["detour"] = tag
		}
	}
	if _, err := nativecomposite.Extract(exit.graph, captured.mode, node, layer, "proxy", CompositeExitPrefix, "entry-wg"); err != nil {
		return nil, err
	}
	// mergeAs attaches this already-owned physical edge while namespacing the
	// complete entry. The other lane's edge was set by Relabel above; the root
	// must never be passed to mergeAs and gain a forbidden generic detour.
	outer := CompositeExitPrefix + "tcp"
	if layer != "" {
		outer = CompositeExitPrefix + "start"
	}
	return exit.nodes[outer], nil
}
