package common

import (
	"errors"
	"fmt"
)

const MultihopMaximumNodes = 8

// MultihopPhysicalTraversalDepth is the public selection limit. A shared test
// checks it against the native physical recursion limit without pulling the
// measurement implementation into small server-side profile readers.
const MultihopPhysicalTraversalDepth = 96

// MultihopNodeSelection records forwarding order and the exact requested raw
// mode. It is a reference to a linked node, never a second credential store.
// Legacy Entry/Exit profiles retain their existing representation.
type MultihopNodeSelection struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`
}

// ExtendedLocalMultihopSelection checks only the saved modes. Actual launch
// requires independent private source, endpoint and key validation for every
// imported interior and paired control of the first and final Router nodes.
func ExtendedLocalMultihopSelection(nodes []MultihopNodeSelection) bool {
	if len(nodes) <= MultihopMaximumNodes || len(nodes) > MultihopPhysicalTraversalDepth || nodes[0].Mode != "wg" {
		return false
	}
	for _, node := range nodes[1:] {
		if node.Mode != "shadowsocks" {
			return false
		}
	}
	return true
}

// This reference shape may request the separate AWG2 selected family. The
// native compiler must still prove that every interior is an original literal
// import, with no private stream or hostname and no active Start Layer.
func ExtendedAWGSelectedMultihopSelection(nodes []MultihopNodeSelection) bool {
	return ExtendedMixedLocalPacketCount(nodes) == 1 && (nodes[0].Mode == "awg2-fast" || nodes[0].Mode == "awg2-strong")
}

// ExtendedPairedLocalMultihopSelection describes the Local packet family.
// Full WG identity assets and per-prefix MTU envelopes are checked at launch.
func ExtendedPairedLocalMultihopSelection(nodes []MultihopNodeSelection) bool {
	if len(nodes) <= MultihopMaximumNodes || len(nodes) > MultihopPhysicalTraversalDepth || nodes[len(nodes)-1].Mode != "shadowsocks" {
		return false
	}
	for _, n := range nodes[:len(nodes)-1] {
		if n.Mode != "wg" {
			return false
		}
	}
	return true
}

// ExtendedMixedLocalPacketCount describes the contiguous packet prefix of an
// extended Local selection. Actual launch validates each private companion,
// literal imported source and the paired final against the original path.
func ExtendedMixedLocalPacketCount(nodes []MultihopNodeSelection) int {
	n := len(nodes)
	if n <= MultihopMaximumNodes || n > MultihopPhysicalTraversalDepth || nodes[n-1].Mode != "shadowsocks" {
		return 0
	}
	p := 0
	for p < n-1 && (nodes[p].Mode == "wg" || nodes[p].Mode == "awg2-fast" || nodes[p].Mode == "awg2-strong") {
		p++
	}
	if p == 0 || p >= n-1 || p == 1 && nodes[0].Mode == "wg" {
		return 0
	}
	for _, node := range nodes[p : n-1] {
		if node.Mode != "shadowsocks" {
			return 0
		}
	}
	return p
}

// ValidateMultihopNodes checks the saved selection independently of transport
// admission. The native compiler must also prove each complete selected source.
func ValidateMultihopNodes(nodes []MultihopNodeSelection) error {
	if len(nodes) < 2 || len(nodes) > MultihopMaximumNodes && !ExtendedLocalMultihopSelection(nodes) && !ExtendedPairedLocalMultihopSelection(nodes) && ExtendedMixedLocalPacketCount(nodes) == 0 {
		return fmt.Errorf("ordered multihop requires at least two nodes; paths beyond %d require independent packet prefixes followed by supported Shadowsocks members", MultihopMaximumNodes)
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
		if (ExtendedPairedLocalMultihopSelection(p.MultihopNodes) || ExtendedMixedLocalPacketCount(p.MultihopNodes) > 0) && !ExtendedAWGSelectedMultihopSelection(p.MultihopNodes) && p.MultihopExecution != "local" {
			return errors.New("extended packet routes with paired intermediates or AmneziaWG require Local execution")
		}
		if p.MultihopExecution != "local" && p.MultihopExecution != "server" && p.MultihopExecution != "auto" {
			return errors.New("ordered multihop requires explicit Local, Server or Compare execution")
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
