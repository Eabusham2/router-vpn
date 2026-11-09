package mobilemultihop

import (
	"encoding/json"
	"errors"
)

// ImportedPhysicalEgress projects only a constructor-owned imported graph onto
// its actual outer sockets. An ordinary SOCKS UDP relay remains dynamic: its
// control address never grants an unrelated datagram destination permission.
func (c *Controller) ImportedPhysicalEgress() ([]PhysicalEgress, error) {
	return c.importedPhysicalEgress(nil)
}

func (c *Controller) importedPhysicalEgress(desktop *externalDesktopRecorder) ([]PhysicalEgress, error) {
	if c == nil || c.validateImportedDesktopCapture() != nil || c.meta.EntryKind != "external" || c.meta.Execution != "local" || c.generation.Load() != 1 {
		return nil, errors.New("desktop imported path has no captured Local graph")
	}
	var graph map[string]any
	if exactJSON([]byte(c.config), &graph, 4<<20) != nil {
		return nil, nodePhysicalEgressError
	}
	// The imported compiler emits one immutable Local selector. Collapse that
	// alias only in the private projection; the executable graph stays exact.
	rows, ok := graph["outbounds"].([]any)
	if !ok {
		return nil, nodePhysicalEgressError
	}
	kept := make([]any, 0, len(rows))
	found := false
	for _, raw := range rows {
		node, ok := raw.(map[string]any)
		if !ok {
			return nil, nodePhysicalEgressError
		}
		if node["tag"] == "proxy" {
			children, ok := node["outbounds"].([]any)
			if found || node["type"] != "selector" || len(node) != 5 || !ok || len(children) != 1 || children[0] != LocalTag || node["default"] != LocalTag || node["interrupt_exist_connections"] != true {
				return nil, nodePhysicalEgressError
			}
			found = true
			continue
		}
		if node["tag"] == LocalTag {
			node["tag"] = "proxy"
		}
		kept = append(kept, node)
	}
	if !found {
		return nil, nodePhysicalEgressError
	}
	endpoints, _ := graph["endpoints"].([]any)
	for _, raw := range endpoints {
		node, ok := raw.(map[string]any)
		if !ok {
			return nil, nodePhysicalEgressError
		}
		if node["tag"] == LocalTag {
			node["tag"] = "proxy"
		}
	}
	graph["outbounds"] = kept
	encoded, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}
	networks := []string{"tcp", "udp"}
	if c.meta.TransportCapability == "tcp-only" {
		networks = []string{"tcp"}
	}
	return compiledPhysicalEgressWithDesktopProof(string(encoded), networks, desktop, c.meta.EntryTag)
}
