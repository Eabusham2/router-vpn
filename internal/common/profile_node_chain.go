package common

import (
	"errors"
	"fmt"
)

const MultihopMaximumNodes = 8

// MultihopNodeSelection records forwarding order and the exact requested raw
// mode. It is a reference to a linked node, never a second credential store.
// Legacy Entry/Exit profiles retain their existing representation.
type MultihopNodeSelection struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
}

// ValidateMultihopNodes checks the saved selection independently of transport
// admission. The native compiler must also prove each complete selected source.
func ValidateMultihopNodes(nodes []MultihopNodeSelection) error {
	if len(nodes) < 2 || len(nodes) > MultihopMaximumNodes {
		return fmt.Errorf("ordered multihop requires 2..%d selected nodes", MultihopMaximumNodes)
	}
	seen := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		if len(node.ID) == 0 || len(node.ID) > 64 || seen[node.ID] {
			return errors.New("ordered multihop contains a missing, oversized, or duplicate node id")
		}
		for _, c := range node.ID {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return errors.New("ordered multihop requires canonical linked node ids")
			}
		}
		seen[node.ID] = true
		if len(node.Mode) == 0 || len(node.Mode) > 64 {
			return errors.New("ordered multihop requires an explicit bounded mode for every node")
		}
		for _, c := range node.Mode {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("ordered multihop requires canonical runtime mode identifiers")
			}
		}
	}
	return nil
}

func validateRouterProfileNodeChain(p *RouterProfile) error {
	if len(p.MultihopNodes) != 0 {
		if err := ValidateMultihopNodes(p.MultihopNodes); err != nil {
			return err
		}
		if p.MultihopExecution != "local" {
			return errors.New("ordered multihop requires explicit Local execution")
		}
		if p.MultihopEntryID != "" || p.MultihopExitID != "" || p.MultihopEntryMode != "" {
			return errors.New("ordered multihop cannot also contain legacy entry/exit selection fields")
		}
		if p.NodeKind != "router-vpn" || p.External != nil {
			return errors.New("ordered multihop currently requires a Router VPN control profile")
		}
		return nil
	}
	return nil
}
